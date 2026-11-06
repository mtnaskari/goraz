// Package service lets a production service read its secrets and verify its tokens
// without a person present. It adds no server and no network listener. It opens a
// service vault read-only, and reloads it when the file changes. See
// docs/security-design.md, section 14A.
package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/internal/fsutil"
	"github.com/mtnaskari/goraz/internal/state"
	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/token"
	"github.com/mtnaskari/goraz/vault"
)

// Errors.
var (
	// ErrStale means reloads have been failing for longer than MaxStale.
	ErrStale = errors.New("service: the vault file can't be reloaded and the last good copy is too old")
	// ErrClosed means the client has been closed.
	ErrClosed = errors.New("service: closed")
)

// ErrExpired means the file's authenticated validity window has passed.
var ErrExpired = vault.ErrExpired

// NoStaleLimit turns the stale limit off. It must be set explicitly.
const NoStaleLimit = time.Duration(-1)

// Defaults.
const (
	DefaultInterval = 30 * time.Second
	DefaultMaxStale = 15 * time.Minute
	maxKeyFile      = 4096
	maxKeysPerFile  = 4
)

const keyFileHelp = "the machine key file must be a regular file owned by you or root, " +
	"not writable by group or others, and not readable by others. " +
	"Docker: secrets: [{source: goraz, uid: \"1000\", mode: 0400}]. " +
	"Kubernetes: defaultMode: 0440 with securityContext.fsGroup set. " +
	"systemd: LoadCredential="

// KeySource provides machine keys. Each call returns fresh copies.
type KeySource interface {
	Keys() ([][]byte, error)
}

// KeyFile reads keys from a file holding one key per line, up to four. It is read at
// each reload, so a rotation can add a key without a restart. Symlinks are followed,
// because Kubernetes mounts secrets through them.
func KeyFile(path string) KeySource { return keyFile(path) }

type keyFile string

// Keys implements KeySource.
func (k keyFile) Keys() ([][]byte, error) {
	b, err := fsutil.ReadFile(string(k), maxKeyFile, fsutil.Policy{FollowSymlinks: true, AllowRootOwner: true, DenyOtherRead: true})
	if errors.Is(err, fsutil.ErrUnsafeFile) {
		return nil, errors.New("service: " + keyFileHelp)
	}
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return ParseKeys(b)
}

// KeyFD reads keys once from an inherited file descriptor, and keeps them in memory.
// A rotation with this method needs a restart.
func KeyFD(fd uintptr) KeySource { return &keyFD{fd: fd} }

type keyFD struct {
	fd   uintptr
	once sync.Once
	keys [][]byte
	err  error
}

// Keys implements KeySource.
func (k *keyFD) Keys() ([][]byte, error) {
	k.once.Do(func() {
		f := os.NewFile(k.fd, "machine-key")
		if f == nil {
			k.err = errors.New("service: invalid file descriptor")
			return
		}
		defer func() { _ = f.Close() }()
		b, err := io.ReadAll(io.LimitReader(f, maxKeyFile))
		if err != nil {
			k.err = err
			return
		}
		defer clear(b)
		k.keys, k.err = ParseKeys(b)
	})
	if k.err != nil {
		return nil, k.err
	}
	out := make([][]byte, len(k.keys))
	for i, x := range k.keys {
		out[i] = bytes.Clone(x)
	}
	return out, nil
}

// StaticKeys uses keys held by the caller.
func StaticKeys(keys ...[]byte) KeySource { return staticKeys(keys) }

type staticKeys [][]byte

// Keys implements KeySource.
func (k staticKeys) Keys() ([][]byte, error) {
	out := make([][]byte, len(k))
	for i, x := range k {
		out[i] = bytes.Clone(x)
	}
	return out, nil
}

// ParseKeys splits key material into one key per line.
func ParseKeys(b []byte) ([][]byte, error) {
	var out [][]byte
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		out = append(out, bytes.Clone(line))
	}
	if len(out) == 0 || len(out) > maxKeysPerFile {
		return nil, errors.New("service: a key file must hold between one and four keys")
	}
	return out, nil
}

// Options configures Open.
type Options struct {
	Path string
	Key  KeySource
	// Audit receives events. It is required when the vault requires audit, which is
	// the default. audit.NewJSONSink writes to stdout for containers.
	Audit audit.Sink
	// Interval is how often the file is checked. It defaults to DefaultInterval.
	Interval time.Duration
	// MaxStale is how long reloads may fail before Value returns ErrStale. It
	// defaults to DefaultMaxStale. NoStaleLimit turns it off.
	MaxStale time.Duration
	// MinGeneration refuses older files, including after a restart.
	MinGeneration uint64
	// OnReload is called after a new file has been accepted. It must not call Close.
	OnReload func(generation uint64)
	// OnReloadError reports a rejected file or a failed read. It never receives a
	// secret. The current snapshot stays in place. It must not call Close.
	OnReloadError func(error)
	// Now replaces the clock.
	Now func() time.Time
}

// Client is a running service client. It is safe for concurrent use.
type Client struct {
	o       Options
	st      *state.Memory
	current atomic.Pointer[vault.Vault]
	hash    atomic.Pointer[[32]byte]
	lastOK  atomic.Int64 // Unix nanoseconds of the last successful check.
	stop    chan struct{}
	done    chan struct{}
	closed  atomic.Bool
	mu      sync.Mutex // Serializes reloads and Close.
}

// Open reads the vault and starts watching it. It fails if the first read fails.
func Open(ctx context.Context, o Options) (*Client, error) {
	if o.Path == "" || o.Key == nil {
		return nil, errors.New("service: Path and Key are required")
	}
	if o.Interval == 0 {
		o.Interval = DefaultInterval
	}
	if o.Interval < 0 {
		return nil, errors.New("service: Interval can't be negative")
	}
	if o.MaxStale == 0 {
		o.MaxStale = DefaultMaxStale
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	c := &Client{o: o, st: state.NewMemory(), stop: make(chan struct{}), done: make(chan struct{})}
	if err := c.reload(); err != nil {
		return nil, err
	}
	go c.watch(ctx)
	return c, nil
}

func (c *Client) watch(ctx context.Context) {
	defer close(c.done)
	t := time.NewTicker(c.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case <-t.C:
			if err := c.reload(); err != nil && c.o.OnReloadError != nil {
				c.o.OnReloadError(err)
			}
		}
	}
}

// Reload checks the file now.
func (c *Client) Reload() error { return c.reload() }

func (c *Client) reload() error {
	generation, changed, err := c.reloadLocked()
	if err != nil {
		return err
	}
	// Callbacks run outside the lock, so they can use the client.
	if changed && c.o.OnReload != nil {
		c.o.OnReload(generation)
	}
	return nil
}

func (c *Client) reloadLocked() (uint64, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, false, ErrClosed
	}
	data, err := fsutil.ReadFile(c.o.Path, format.MaxFileSize, fsutil.Policy{FollowSymlinks: true, AllowRootOwner: true})
	if err != nil {
		return 0, false, fmt.Errorf("service: reading the vault file: %w", err)
	}
	sum := sha256.Sum256(data)
	if prev := c.hash.Load(); prev != nil && *prev == sum {
		c.lastOK.Store(c.o.Now().UnixNano())
		return 0, false, nil
	}
	keys, err := c.o.Key.Keys()
	if err != nil {
		return 0, false, fmt.Errorf("service: reading the machine key: %w", err)
	}
	defer func() {
		for _, k := range keys {
			clear(k)
		}
	}()
	next, err := vault.OpenService(data, vault.WithMachineKeys(keys...), vault.Options{
		Audit: c.o.Audit, State: c.st, MinGeneration: c.o.MinGeneration, Now: c.o.Now,
	})
	if err != nil {
		return 0, false, err
	}
	old := c.current.Swap(next)
	c.hash.Store(&sum)
	c.lastOK.Store(c.o.Now().UnixNano())
	if old != nil {
		// In-flight readers hold only values they already copied out, and a closed
		// vault returns an error, so a racing Get is retried against the new one.
		old.Close()
	}
	return next.Generation(), true, nil
}

// Close stops the watcher and clears keys.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed.Swap(true) {
		c.mu.Unlock()
		return
	}
	close(c.stop)
	c.mu.Unlock()
	<-c.done
	if v := c.current.Swap(nil); v != nil {
		v.Close()
	}
}

// check applies the fail-closed rules. Staleness comes from the time of the last
// successful check, so a blocked reload can't stop the timer.
func (c *Client) check() (*vault.Vault, error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}
	v := c.current.Load()
	if v == nil {
		return nil, ErrClosed
	}
	now := c.o.Now()
	if until := v.ValidUntil(); until != nil && !now.Before(*until) {
		return nil, ErrExpired
	}
	if c.o.MaxStale != NoStaleLimit && now.Sub(time.Unix(0, c.lastOK.Load())) > c.o.MaxStale {
		return nil, ErrStale
	}
	return v, nil
}

// Get returns an item from the current snapshot.
func (c *Client) Get(name string) (*vault.Item, error) {
	for range 3 {
		v, err := c.check()
		if err != nil {
			return nil, err
		}
		it, err := v.Get(name)
		if errors.Is(err, vault.ErrClosed) {
			continue // A reload swapped the snapshot during this call.
		}
		return it, err
	}
	return nil, ErrClosed
}

// Value returns an item's value. The caller may wipe it.
func (c *Client) Value(name string) (secret.Secret, error) {
	it, err := c.Get(name)
	if err != nil {
		return secret.Secret{}, err
	}
	it.OTP.Wipe()
	return it.Value, nil
}

// Generation returns the current file's generation.
func (c *Client) Generation() uint64 {
	if v := c.current.Load(); v != nil {
		return v.Generation()
	}
	return 0
}

// snapshotStore serves token records from whichever snapshot is current.
type snapshotStore struct{ c *Client }

func (s snapshotStore) retry(f func(token.Store) error) error {
	for range 3 {
		v, err := s.c.check()
		if err != nil {
			return err
		}
		if err := f(v.TokenStore()); !errors.Is(err, vault.ErrClosed) {
			return err
		}
	}
	return ErrClosed
}

// Get implements token.Store.
func (s snapshotStore) Get(ctx context.Context, id token.ID) (token.Record, error) {
	var r token.Record
	err := s.retry(func(st token.Store) error {
		var err error
		r, err = st.Get(ctx, id)
		return err
	})
	return r, err
}

// Put implements token.Store. A service file is read-only.
func (s snapshotStore) Put(context.Context, token.Record) error { return token.ErrReadOnly }

// List implements token.Store.
func (s snapshotStore) List(ctx context.Context) ([]token.Record, error) {
	var out []token.Record
	err := s.retry(func(st token.Store) error {
		var err error
		out, err = st.List(ctx)
		return err
	})
	return out, err
}

// Verifier checks this service's own tokens against the current snapshot, including
// after a rotation changes the verifier keys.
type Verifier struct {
	c    *Client
	sink audit.Sink
}

// Verifier returns a token verifier. A nil sink means the client's own. Stale or
// expired data fails closed. Revocation reaches it through a sync, a deployment and
// a reload, so it isn't immediate. A service needing immediate revocation should
// implement token.Store on its own database and use token.NewVerifier.
func (c *Client) Verifier(sink audit.Sink) (*Verifier, error) {
	if sink == nil {
		sink = c.o.Audit
	}
	if sink == nil {
		return nil, errors.New("service: an audit sink is required; use audit.Discard to opt out")
	}
	return &Verifier{c: c, sink: sink}, nil
}

// Verify checks a presented token and its required scopes.
func (t *Verifier) Verify(ctx context.Context, presented []byte, required ...string) (token.Record, error) {
	v, err := t.c.check()
	if err != nil {
		return token.Record{}, token.ErrUnavailable
	}
	m, err := token.New(token.Config{Keys: v.VerifierKeys(), Store: snapshotStore{t.c}, Sink: t.sink, Now: t.c.o.Now})
	if err != nil {
		return token.Record{}, err
	}
	return m.Verify(ctx, presented, required...)
}
