package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mtnaskari/goraz/internal/fsutil"
)

// Errors from the chained log.
var (
	// ErrTampered means an entry failed verification.
	ErrTampered = errors.New("audit: the log failed verification")
	// ErrTruncated means entries recorded in the vault's anchor are missing.
	ErrTruncated = errors.New("audit: the log is shorter than its anchor")
	// ErrUnavailable means the log can't be written.
	ErrUnavailable = errors.New("audit: the log can't be written")
)

const maxLogSize = 1 << 30

// Anchor is a log position stored in the authenticated vault manifest.
type Anchor struct {
	Seq uint64 `json:"seq"`
	MAC []byte `json:"mac"`
}

// Keys holds the log's keys. Retired keys verify old entries only.
type Keys struct {
	Active uint32
	All    map[uint32][]byte
}

type line struct {
	Seq     uint64    `json:"seq"`
	Time    int64     `json:"ts"`
	KeyID   uint32    `json:"key_id"`
	Event   EventType `json:"event"`
	Outcome Outcome   `json:"outcome"`
	Actor   Actor     `json:"actor"`
	Object  string    `json:"object"`
	Prev    string    `json:"prev"`
	MAC     string    `json:"mac"`
}

func (l *line) mac(key []byte) ([]byte, error) {
	obj, err := hex.DecodeString(l.Object)
	if err != nil {
		return nil, err
	}
	prev, err := hex.DecodeString(l.Prev)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("goraz/v1/audit"))
	var fixed [20]byte
	binary.BigEndian.PutUint64(fixed[0:], l.Seq)
	binary.BigEndian.PutUint64(fixed[8:], uint64(l.Time)) // #nosec G115 -- a bit pattern, not a quantity.
	binary.BigEndian.PutUint32(fixed[16:], l.KeyID)
	h.Write(fixed[:])
	for _, part := range [][]byte{[]byte(l.Event), []byte(l.Outcome), []byte(l.Actor), obj, prev} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part))) // #nosec G115 -- bounded by the line size.
		h.Write(n[:])
		h.Write(part)
	}
	return h.Sum(nil), nil
}

// parseLine decodes one line strictly.
func parseLine(b []byte) (*line, error) {
	var l line
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, ErrTampered
	}
	if dec.More() {
		return nil, ErrTampered
	}
	e := Event{Type: l.Event, Outcome: l.Outcome, Actor: l.Actor}
	if e.Validate() != nil {
		return nil, ErrTampered
	}
	return &l, nil
}

// Result summarizes a verified log.
type Result struct {
	Entries  int
	Head     Anchor
	Gap      bool
	FirstSeq uint64
}

// verifyBytes checks a whole log: every MAC, contiguous sequence numbers, the
// chain, and key IDs that never go backwards. A log may begin only at sequence 1
// or with a recorded gap.
func verifyBytes(data []byte, keys Keys) (*Result, []*line, error) {
	r := &Result{}
	var entries []*line
	var prevMAC []byte
	var keyID uint32
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return nil, nil, ErrTampered
		}
		l, err := parseLine(data[:i])
		data = data[i+1:]
		if err != nil {
			return nil, nil, err
		}
		key, ok := keys.All[l.KeyID]
		if !ok {
			return nil, nil, ErrTampered
		}
		want, err := l.mac(key)
		if err != nil {
			return nil, nil, ErrTampered
		}
		got, err := hex.DecodeString(l.MAC)
		if err != nil || !hmac.Equal(got, want) {
			return nil, nil, ErrTampered
		}
		prev, err := hex.DecodeString(l.Prev)
		if err != nil {
			return nil, nil, ErrTampered
		}
		if len(entries) == 0 {
			r.FirstSeq = l.Seq
			switch {
			case l.Event == EventAuditGap:
				r.Gap = true
			case l.Seq != 1:
				return nil, nil, ErrTampered
			}
			if len(prev) != 0 {
				return nil, nil, ErrTampered
			}
		} else {
			if l.Seq != entries[len(entries)-1].Seq+1 || !hmac.Equal(prev, prevMAC) || l.KeyID < keyID {
				return nil, nil, ErrTampered
			}
		}
		keyID = l.KeyID
		prevMAC = got
		entries = append(entries, l)
	}
	r.Entries = len(entries)
	if len(entries) > 0 {
		r.Head = Anchor{Seq: entries[len(entries)-1].Seq, MAC: prevMAC}
	}
	return r, entries, nil
}

func checkAnchor(r *Result, entries []*line, a Anchor) error {
	if a.Seq == 0 {
		return nil
	}
	if r.Gap && r.FirstSeq > a.Seq {
		return nil
	}
	for _, l := range entries {
		if l.Seq == a.Seq {
			got, err := hex.DecodeString(l.MAC)
			if err != nil || !hmac.Equal(got, a.MAC) {
				return ErrTampered
			}
			return nil
		}
	}
	return ErrTruncated
}

// Verify checks the log at path against its keys and anchor.
func Verify(path string, keys Keys, anchor Anchor) (*Result, error) {
	data, err := fsutil.ReadFile(path, maxLogSize, fsutil.Policy{})
	if errors.Is(err, fs.ErrNotExist) {
		data = nil
	} else if err != nil {
		return nil, err
	}
	r, entries, err := verifyBytes(data, keys)
	if err != nil {
		return nil, err
	}
	if err := checkAnchor(r, entries, anchor); err != nil {
		return r, err
	}
	return r, nil
}

// Entry is a verified log entry, safe to display.
type Entry struct {
	Seq     uint64
	Time    time.Time
	Type    EventType
	Outcome Outcome
	Actor   Actor
	Object  string
}

// Read returns verified entries.
func Read(path string, keys Keys, anchor Anchor) ([]Entry, error) {
	data, err := fsutil.ReadFile(path, maxLogSize, fsutil.Policy{})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r, lines, err := verifyBytes(data, keys)
	if err != nil {
		return nil, err
	}
	if err := checkAnchor(r, lines, anchor); err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(lines))
	for _, l := range lines {
		out = append(out, Entry{
			Seq: l.Seq, Time: time.Unix(0, l.Time).UTC(), Type: l.Event,
			Outcome: l.Outcome, Actor: l.Actor, Object: l.Object,
		})
	}
	return out, nil
}

// Log is a hash-chained file log. It is tamper-evident, not tamper-proof: anyone
// holding the key can rewrite it. Each device has its own file, so a synced folder
// can't produce conflicting appends.
type Log struct {
	mu        sync.Mutex
	path      string
	keys      Keys
	anchor    Anchor
	head      Anchor
	acceptGap bool
	now       func() time.Time
	// Guard runs under the log lock before each append. The vault uses it to
	// refuse appending under a stale key after the file has changed.
	Guard func() error
}

// LogOptions configures OpenLog.
type LogOptions struct {
	Keys      Keys
	Anchor    Anchor
	AcceptGap bool
	Now       func() time.Time
}

// OpenLog prepares the log at path. The file is created on first append.
func OpenLog(path string, o LogOptions) *Log {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Log{path: path, keys: o.Keys, anchor: o.Anchor, head: o.Anchor, acceptGap: o.AcceptGap, now: now}
}

// SetKeys replaces the keys, after a key rotation.
func (l *Log) SetKeys(k Keys) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = k
}

// Head returns the position of the last entry appended by this process, or the
// anchor if there is none.
func (l *Log) Head() Anchor {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Record implements Sink. It holds an exclusive lock across reading the tail,
// verifying the chain, appending and syncing, so concurrent processes can't fork
// the chain.
func (l *Log) Record(e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := fsutil.EnsurePrivateDir(filepath.Dir(l.path)); err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	lock, err := fsutil.AcquireLock(l.path+".lock", false)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer lock.Release()

	// The guard runs first: a stale process must see that the vault changed, rather
	// than a false tamper alarm from a key it doesn't know yet.
	if l.Guard != nil {
		if err := l.Guard(); err != nil {
			return err
		}
	}
	data, err := fsutil.ReadFile(l.path, maxLogSize, fsutil.Policy{})
	if errors.Is(err, fs.ErrNotExist) {
		data = nil
	} else if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	// A crash or a full disk can leave an incomplete last line. It was never a whole
	// entry, so removing it loses nothing, and the anchor still catches real removal.
	if i := bytes.LastIndexByte(data, '\n'); i != len(data)-1 {
		if err := os.Truncate(l.path, int64(i+1)); err != nil {
			return fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		data = data[:i+1]
	}
	r, entries, verr := verifyBytes(data, l.keys)
	if verr == nil {
		verr = checkAnchor(r, entries, l.anchor)
	}
	var prev []byte
	seq := uint64(1)
	gap := false
	switch {
	case verr != nil && !l.acceptGap:
		return verr
	case verr != nil:
		// Keep the damaged file for investigation and start a new chain whose
		// first entry records the gap.
		if len(data) > 0 {
			stamp := strconv.FormatInt(l.now().UnixNano(), 10)
			if err := os.Rename(l.path, l.path+".damaged-"+stamp); err != nil {
				return fmt.Errorf("%w: %w", ErrUnavailable, err)
			}
		}
		seq = l.anchor.Seq + 1
		if r != nil {
			seq = max(seq, r.Head.Seq+1)
		}
		gap = true
	case r.Entries > 0:
		prev = r.Head.MAC
		seq = r.Head.Seq + 1
	}
	key, ok := l.keys.All[l.keys.Active]
	if !ok {
		return ErrUnavailable
	}

	var buf []byte
	if gap {
		g := &line{
			Seq: seq, Time: l.now().UnixNano(), KeyID: l.keys.Active,
			Event: EventAuditGap, Outcome: OK, Actor: ActorSystem,
		}
		out, m, err := encode(g, key)
		if err != nil {
			return err
		}
		buf = append(buf, out...)
		prev = m
		seq++
	}
	n := &line{
		Seq: seq, Time: l.now().UnixNano(), KeyID: l.keys.Active,
		Event: e.Type, Outcome: e.Outcome, Actor: e.Actor,
		Object: hex.EncodeToString(e.Object), Prev: hex.EncodeToString(prev),
	}
	out, m, err := encode(n, key)
	if err != nil {
		return err
	}
	buf = append(buf, out...)
	if err := appendSync(l.path, buf); err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	l.head = Anchor{Seq: seq, MAC: m}
	l.acceptGap = false
	l.anchor = l.head
	return nil
}

func encode(n *line, key []byte) ([]byte, []byte, error) {
	m, err := n.mac(key)
	if err != nil {
		return nil, nil, err
	}
	n.MAC = hex.EncodeToString(m)
	b, err := json.Marshal(n)
	if err != nil {
		return nil, nil, err
	}
	return append(b, '\n'), m, nil
}

func appendSync(path string, b []byte) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path) // #nosec G115 -- fd is non-negative here.
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Truncate(st.Size()) // Don't leave a partial line behind.
		return err
	}
	return f.Sync()
}
