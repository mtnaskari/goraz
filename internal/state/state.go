// Package state implements local rollback and fork detection, per
// docs/security-design.md, section 7. An AEAD can't tell that a valid file is old,
// so each device remembers what it last accepted.
package state

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/mtnaskari/goraz/internal/fsutil"
)

// Lineage records the hash of one earlier generation of a file.
type Lineage struct {
	Generation uint64 `json:"generation"`
	SHA256     []byte `json:"sha256"`
}

// Record is what a device remembers about one vault.
type Record struct {
	High       uint64
	PinnedGen  uint64
	PinnedHash [32]byte
	DeviceID   [16]byte
}

// Decision is the outcome of comparing a file with a Record.
type Decision int

// Decisions.
const (
	Accept Decision = iota
	// AcceptUnverified means the file is newer than the lineage window, so
	// continuity can't be checked.
	AcceptUnverified
	Rollback
	Fork
)

// Decide applies the rules in the design's section 7 table. A nil record means
// the device has never seen this vault, which is trust on first use.
func Decide(r *Record, gen uint64, hash [32]byte, lineage []Lineage) Decision {
	if r == nil {
		return Accept
	}
	if hash == r.PinnedHash {
		return Accept
	}
	if gen < r.High {
		return Rollback
	}
	if gen <= r.PinnedGen {
		return Fork
	}
	// The file claims to be newer than the pinned one. Its lineage must agree.
	if len(lineage) == 0 {
		return Fork
	}
	oldest := lineage[0].Generation
	for _, l := range lineage {
		if l.Generation < oldest {
			oldest = l.Generation
		}
		if l.Generation == r.PinnedGen {
			if bytes.Equal(l.SHA256, r.PinnedHash[:]) {
				return Accept
			}
			return Fork
		}
	}
	if oldest > r.PinnedGen {
		return AcceptUnverified
	}
	return Fork
}

// Store persists records.
type Store interface {
	// Load returns the record, or nil if none exists. The key authenticates it.
	Load(vaultID [16]byte, key []byte) (*Record, error)
	// Pin records an accepted file. The high generation never goes down.
	Pin(vaultID [16]byte, key []byte, gen uint64, hash [32]byte) (*Record, error)
	// Reset forgets a vault, returning it to trust on first use.
	Reset(vaultID [16]byte) error
}

// ErrInvalid means the state file failed authentication.
var ErrInvalid = errors.New("state: the local state file failed authentication")

// Memory is a Store for one process, used where no persistent state exists, such
// as read-only containers.
type Memory struct {
	mu sync.Mutex
	m  map[[16]byte]Record
}

// NewMemory returns an empty Memory store.
func NewMemory() *Memory { return &Memory{m: make(map[[16]byte]Record)} }

// Load implements Store.
func (s *Memory) Load(id [16]byte, _ []byte) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.m[id]; ok {
		return &r, nil
	}
	return nil, nil
}

// Pin implements Store.
func (s *Memory) Pin(id [16]byte, _ []byte, gen uint64, hash [32]byte) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.m[id]
	r.High = max(r.High, gen)
	r.PinnedGen, r.PinnedHash = gen, hash
	s.m[id] = r
	return &r, nil
}

// Reset implements Store.
func (s *Memory) Reset(id [16]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

// File stores each record in its own authenticated file.
type File struct{ Dir string }

type fileRecord struct {
	High       uint64 `json:"high"`
	PinnedGen  uint64 `json:"pinned_generation"`
	PinnedHash string `json:"pinned_hash"`
	DeviceID   string `json:"device_id"`
	MAC        string `json:"mac"`
}

const maxStateSize = 4096

func (s *File) path(id [16]byte) string {
	return filepath.Join(s.Dir, "vaults", hex.EncodeToString(id[:])+".state")
}

func mac(key []byte, id [16]byte, r *Record) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("goraz/v1/state"))
	h.Write(id[:])
	_ = binary.Write(h, binary.BigEndian, r.High)
	_ = binary.Write(h, binary.BigEndian, r.PinnedGen)
	h.Write(r.PinnedHash[:])
	h.Write(r.DeviceID[:])
	return h.Sum(nil)
}

// Load implements Store.
func (s *File) Load(id [16]byte, key []byte) (*Record, error) {
	if err := fsutil.EnsurePrivateDir(filepath.Dir(s.path(id))); err != nil {
		return nil, err
	}
	l, err := fsutil.AcquireLock(s.path(id)+".lock", true)
	if err != nil {
		return nil, err
	}
	defer l.Release()
	return s.read(id, key)
}

func (s *File) read(id [16]byte, key []byte) (*Record, error) {
	b, err := fsutil.ReadFile(s.path(id), maxStateSize, fsutil.Policy{})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f fileRecord
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, ErrInvalid
	}
	r := &Record{High: f.High, PinnedGen: f.PinnedGen}
	hash, err1 := hex.DecodeString(f.PinnedHash)
	dev, err2 := hex.DecodeString(f.DeviceID)
	got, err3 := hex.DecodeString(f.MAC)
	if err1 != nil || err2 != nil || err3 != nil || len(hash) != 32 || len(dev) != 16 {
		return nil, ErrInvalid
	}
	copy(r.PinnedHash[:], hash)
	copy(r.DeviceID[:], dev)
	if !hmac.Equal(got, mac(key, id, r)) {
		return nil, ErrInvalid
	}
	return r, nil
}

// Pin implements Store.
func (s *File) Pin(id [16]byte, key []byte, gen uint64, hash [32]byte) (*Record, error) {
	if err := fsutil.EnsurePrivateDir(filepath.Dir(s.path(id))); err != nil {
		return nil, err
	}
	l, err := fsutil.AcquireLock(s.path(id)+".lock", false)
	if err != nil {
		return nil, err
	}
	defer l.Release()
	r, err := s.read(id, key)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = &Record{}
		if _, err := rand.Read(r.DeviceID[:]); err != nil {
			return nil, err
		}
	}
	r.High = max(r.High, gen)
	r.PinnedGen, r.PinnedHash = gen, hash
	out, err := json.Marshal(fileRecord{
		High:       r.High,
		PinnedGen:  r.PinnedGen,
		PinnedHash: hex.EncodeToString(r.PinnedHash[:]),
		DeviceID:   hex.EncodeToString(r.DeviceID[:]),
		MAC:        hex.EncodeToString(mac(key, id, r)),
	})
	if err != nil {
		return nil, err
	}
	if err := fsutil.AtomicWrite(s.path(id), out, nil); err != nil {
		return nil, err
	}
	return r, nil
}

// Reset implements Store.
func (s *File) Reset(id [16]byte) error {
	err := os.Remove(s.path(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
