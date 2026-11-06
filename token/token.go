// Package token issues and verifies opaque bearer tokens. Tokens carry at least 256
// bits of randomness, have a required expiry and can be revoked. Only a keyed hash
// is stored. See docs/security-design.md, section 14.
package token

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/envelope"
	"github.com/mtnaskari/goraz/internal/tokfmt"
	"github.com/mtnaskari/goraz/secret"
)

// Errors returned to callers. All credential failures share ErrInvalidToken, so a
// caller can't learn why a token failed. The audit log records the event.
var (
	ErrInvalidToken = errors.New("token: invalid token")
	ErrForbidden    = errors.New("token: missing required scope")
	ErrUnavailable  = errors.New("token: the token store is unavailable")
	ErrNotFound     = errors.New("token: not found")
	ErrReadOnly     = errors.New("token: this store is read-only")
)

// Lifetime limits.
const (
	DefaultTTL = 24 * time.Hour
	MaxTTL     = 90 * 24 * time.Hour
)

// ID is a token's public identifier. It can list and revoke a token but can't
// authenticate as it.
type ID [tokfmt.IDSize]byte

// Key is a verifier key. A key past RetireAt no longer verifies anything.
type Key struct {
	ID       uint32     `json:"id"`
	Key      []byte     `json:"key"`
	RetireAt *time.Time `json:"retire_at,omitempty"`
}

// Record is what a store holds. It never contains a token's secret.
type Record struct {
	ID      []byte    `json:"id"`
	KeyID   uint32    `json:"key_id"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Prefix  string    `json:"prefix"`
	Scopes  []string  `json:"scopes,omitempty"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
	MAC     []byte    `json:"mac"`
	// The fields below may change after issue, so the MAC doesn't cover them.
	Revoked    bool       `json:"revoked,omitempty"`
	RevokeAt   *time.Time `json:"revoke_at,omitempty"`
	ReplacedBy []byte     `json:"replaced_by,omitempty"`
}

// Store holds records. Implementations must return an error, not an empty record,
// when they can't answer, and ErrNotFound when a record doesn't exist.
//
// A party that can write to a store can't forge a token or change its scopes or
// expiry, but it can clear a revocation or delete a record. The store must be
// trusted for revocation.
type Store interface {
	Get(ctx context.Context, id ID) (Record, error)
	Put(ctx context.Context, r Record) error
	List(ctx context.Context) ([]Record, error)
}

// Config configures a Manager.
type Config struct {
	Keys   []Key
	Store  Store
	Sink   audit.Sink // Required. Use audit.Discard to opt out explicitly.
	Prefix string     // Defaults to "goraz".
	Now    func() time.Time
	MaxTTL time.Duration // Defaults to MaxTTL.
}

// Manager issues, verifies and revokes tokens.
type Manager struct {
	keys   []Key
	store  Store
	sink   audit.Sink
	prefix string
	now    func() time.Time
	maxTTL time.Duration
}

// New returns a Manager.
func New(c Config) (*Manager, error) {
	if c.Store == nil {
		return nil, errors.New("token: a store is required")
	}
	if c.Sink == nil {
		return nil, errors.New("token: an audit sink is required; use audit.Discard to opt out")
	}
	if len(c.Keys) == 0 {
		return nil, errors.New("token: at least one verifier key is required")
	}
	for _, k := range c.Keys {
		if len(k.Key) != 32 {
			return nil, errors.New("token: verifier keys must be 32 bytes")
		}
	}
	m := &Manager{keys: c.Keys, store: c.Store, sink: c.Sink, prefix: c.Prefix, now: c.Now, maxTTL: c.MaxTTL}
	if m.prefix == "" {
		m.prefix = tokfmt.DefaultPrefix
	}
	if !tokfmt.ValidPrefix(m.prefix) {
		return nil, errors.New("token: a prefix must match [a-z]{2,10}")
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.maxTTL == 0 {
		m.maxTTL = MaxTTL
	}
	return m, nil
}

// NewVerifier returns a Manager for a service that holds only verifier keys and its
// own store. It needs neither a vault master key nor an audit key.
func NewVerifier(keys []Key, store Store, sink audit.Sink) (*Manager, error) {
	return New(Config{Keys: keys, Store: store, Sink: sink})
}

func (m *Manager) activeKey() (Key, bool) {
	var best Key
	found := false
	for _, k := range m.keys {
		if k.RetireAt != nil {
			continue
		}
		if !found || k.ID > best.ID {
			best, found = k, true
		}
	}
	return best, found
}

func (m *Manager) keyByID(id uint32, now time.Time) (Key, bool) {
	for _, k := range m.keys {
		if k.ID == id {
			if k.RetireAt != nil && !now.Before(*k.RetireAt) {
				return Key{}, false
			}
			return k, true
		}
	}
	return Key{}, false
}

func computeMAC(key []byte, r *Record, sec []byte) []byte {
	sorted := slices.Clone(r.Scopes)
	slices.Sort(sorted)
	var scopes []byte
	for _, s := range sorted {
		scopes = envelope.LP(scopes, []byte(s))
	}
	h := hmac.New(sha256.New, key)
	var msg []byte
	msg = append(msg, "goraz/v1/token"...)
	msg = envelope.LP(msg, []byte(r.Kind))
	msg = envelope.LP(msg, []byte(r.Prefix))
	msg = envelope.LP(msg, r.ID)
	msg = envelope.LP(msg, sec)
	msg = envelope.LP(msg, scopes)
	msg = binary.BigEndian.AppendUint64(msg, uint64(r.Issued.Unix()))  // #nosec G115 -- a bit pattern.
	msg = binary.BigEndian.AppendUint64(msg, uint64(r.Expires.Unix())) // #nosec G115 -- a bit pattern.
	h.Write(msg)
	clear(msg)
	return h.Sum(nil)
}

// IssueRequest describes a new token.
type IssueRequest struct {
	Name   string
	Scopes []string
	TTL    time.Duration // Defaults to DefaultTTL. There is no "never expires".
}

func validScope(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(":._-/", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// Issue creates a token. The returned secret is the only copy: it can't be
// recovered later.
func (m *Manager) Issue(ctx context.Context, q IssueRequest) (secret.Secret, Record, error) {
	if q.TTL == 0 {
		q.TTL = DefaultTTL
	}
	if q.TTL < 0 || q.TTL > m.maxTTL {
		return secret.Secret{}, Record{}, errors.New("token: TTL is outside the allowed range")
	}
	if q.Name == "" || len(q.Name) > 128 {
		return secret.Secret{}, Record{}, errors.New("token: a name of up to 128 bytes is required")
	}
	for _, s := range q.Scopes {
		if !validScope(s) {
			return secret.Secret{}, Record{}, errors.New("token: invalid scope")
		}
	}
	now := m.now().UTC().Truncate(time.Second)
	key, ok := m.activeKey()
	if !ok {
		return secret.Secret{}, Record{}, errors.New("token: no active verifier key")
	}
	var id [tokfmt.IDSize]byte
	var sec [tokfmt.SecretSize]byte
	if _, err := rand.Read(id[:]); err != nil {
		return secret.Secret{}, Record{}, err
	}
	if _, err := rand.Read(sec[:]); err != nil {
		return secret.Secret{}, Record{}, err
	}
	defer clear(sec[:])
	r := Record{
		ID: id[:], KeyID: key.ID, Name: q.Name, Kind: tokfmt.KindService, Prefix: m.prefix,
		Scopes: slices.Clone(q.Scopes), Issued: now, Expires: now.Add(q.TTL),
	}
	r.MAC = computeMAC(key.Key, &r, sec[:])
	tok, err := tokfmt.Encode(m.prefix, tokfmt.KindService, id[:], sec[:])
	if err != nil {
		return secret.Secret{}, Record{}, err
	}
	if err := m.sink.Record(audit.Event{Type: audit.EventTokenIssue, Outcome: audit.OK, Actor: audit.ActorSystem, Object: id[:]}); err != nil {
		clear(tok)
		return secret.Secret{}, Record{}, err
	}
	if err := m.store.Put(ctx, r); err != nil {
		clear(tok)
		return secret.Secret{}, Record{}, err
	}
	return secret.Adopt(tok), r, nil
}

func (m *Manager) logVerify(o audit.Outcome, id []byte) error {
	return m.sink.Record(audit.Event{Type: audit.EventTokenVerify, Outcome: o, Actor: audit.ActorToken, Object: id})
}

// Verify checks a presented token, and that it holds every required scope. A store
// or audit failure fails closed with ErrUnavailable.
func (m *Manager) Verify(ctx context.Context, presented []byte, required ...string) (Record, error) {
	p, err := tokfmt.Parse(presented)
	if err != nil || p.Kind != tokfmt.KindService || p.Prefix != m.prefix {
		// A machine key pasted by mistake stops here, and never reaches a store.
		if lerr := m.logVerify(audit.Denied, nil); lerr != nil {
			return Record{}, ErrUnavailable
		}
		return Record{}, ErrInvalidToken
	}
	defer clear(p.Secret[:])
	now := m.now()

	rec, err := m.store.Get(ctx, ID(p.ID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		_ = m.logVerify(audit.Failed, p.ID[:])
		return Record{}, ErrUnavailable
	}
	found := err == nil
	key, keyOK := Key{}, false
	if found {
		key, keyOK = m.keyByID(rec.KeyID, now)
	}
	if !found || !keyOK {
		// Do the same work on the failure path. A record built from the presented
		// values gives a well-formed computation against an active key.
		dummy := Record{ID: p.ID[:], Kind: p.Kind, Prefix: p.Prefix, Issued: now, Expires: now}
		if k, ok := m.activeKey(); ok {
			_ = hmac.Equal(computeMAC(k.Key, &dummy, p.Secret[:]), make([]byte, sha256.Size))
		}
		if lerr := m.logVerify(audit.Denied, p.ID[:]); lerr != nil {
			return Record{}, ErrUnavailable
		}
		return Record{}, ErrInvalidToken
	}
	valid := hmac.Equal(computeMAC(key.Key, &rec, p.Secret[:]), rec.MAC)
	if valid {
		valid = !rec.Revoked && now.Before(rec.Expires) && (rec.RevokeAt == nil || now.Before(*rec.RevokeAt))
	}
	if !valid {
		if lerr := m.logVerify(audit.Denied, p.ID[:]); lerr != nil {
			return Record{}, ErrUnavailable
		}
		return Record{}, ErrInvalidToken
	}
	for _, need := range required {
		if !slices.Contains(rec.Scopes, need) {
			if lerr := m.logVerify(audit.Denied, p.ID[:]); lerr != nil {
				return Record{}, ErrUnavailable
			}
			return Record{}, ErrForbidden
		}
	}
	if err := m.logVerify(audit.OK, p.ID[:]); err != nil {
		return Record{}, ErrUnavailable
	}
	return rec, nil
}

// Revoke marks a token revoked, which takes effect on the next check against the
// store.
func (m *Manager) Revoke(ctx context.Context, id ID) error {
	rec, err := m.store.Get(ctx, id)
	if err != nil {
		return err
	}
	rec.Revoked = true
	if err := m.sink.Record(audit.Event{Type: audit.EventTokenRevoke, Outcome: audit.OK, Actor: audit.ActorSystem, Object: id[:]}); err != nil {
		return err
	}
	return m.store.Put(ctx, rec)
}

// Rotate issues a successor with the same scopes and lifetime, and makes the old
// token stop working after the overlap period.
func (m *Manager) Rotate(ctx context.Context, id ID, overlap time.Duration) (secret.Secret, Record, error) {
	old, err := m.store.Get(ctx, id)
	if err != nil {
		return secret.Secret{}, Record{}, err
	}
	if overlap < 0 {
		return secret.Secret{}, Record{}, errors.New("token: overlap can't be negative")
	}
	now := m.now().UTC()
	if old.Revoked || !now.Before(old.Expires) || (old.RevokeAt != nil && !now.Before(*old.RevokeAt)) {
		return secret.Secret{}, Record{}, errors.New("token: a revoked or expired token can't be rotated")
	}
	tok, rec, err := m.Issue(ctx, IssueRequest{Name: old.Name, Scopes: old.Scopes, TTL: old.Expires.Sub(old.Issued)})
	if err != nil {
		return secret.Secret{}, Record{}, err
	}
	// A later rotation can only bring the end forward, never move it back.
	at := now.Add(overlap)
	if old.RevokeAt == nil || at.Before(*old.RevokeAt) {
		old.RevokeAt = &at
	}
	old.ReplacedBy = rec.ID
	if err := m.sink.Record(audit.Event{Type: audit.EventTokenRotate, Outcome: audit.OK, Actor: audit.ActorSystem, Object: id[:]}); err != nil {
		tok.Wipe()
		return secret.Secret{}, Record{}, err
	}
	if err := m.store.Put(ctx, old); err != nil {
		tok.Wipe()
		return secret.Secret{}, Record{}, err
	}
	return tok, rec, nil
}

// ParseID converts a public ID from its hexadecimal form.
func ParseID(b []byte) (ID, bool) {
	var id ID
	if len(b) != len(id) {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// MemoryStore keeps records in memory. It is meant for tests.
type MemoryStore struct {
	mu sync.Mutex
	m  map[ID]Record
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{m: make(map[ID]Record)} }

// Get implements Store.
func (s *MemoryStore) Get(_ context.Context, id ID) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}

// Put implements Store.
func (s *MemoryStore) Put(_ context.Context, r Record) error {
	id, ok := ParseID(r.ID)
	if !ok {
		return errors.New("token: invalid record ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = r
	return nil
}

// List implements Store.
func (s *MemoryStore) List(context.Context) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.m))
	for _, r := range s.m {
		out = append(out, r)
	}
	return out, nil
}

// DefaultCacheLimit is how long a cached record may be used without a fresh check.
const DefaultCacheLimit = 60 * time.Second

type cached struct {
	r       Record
	fetched time.Time
}

// CachedStore caches a slow store's records for at most a fixed limit. Past the
// limit it asks the store again, and a store failure fails closed.
type CachedStore struct {
	Store
	limit time.Duration
	now   func() time.Time
	mu    sync.Mutex
	m     map[ID]cached
}

// NewCachedStore wraps a store. A zero limit means DefaultCacheLimit.
func NewCachedStore(s Store, limit time.Duration, now func() time.Time) *CachedStore {
	if limit == 0 {
		limit = DefaultCacheLimit
	}
	if now == nil {
		now = time.Now
	}
	return &CachedStore{Store: s, limit: limit, now: now, m: make(map[ID]cached)}
}

// Get implements Store.
func (c *CachedStore) Get(ctx context.Context, id ID) (Record, error) {
	now := c.now()
	c.mu.Lock()
	e, ok := c.m[id]
	c.mu.Unlock()
	if ok && now.Sub(e.fetched) < c.limit {
		return e.r, nil
	}
	r, err := c.Store.Get(ctx, id)
	if err != nil {
		c.mu.Lock()
		delete(c.m, id)
		c.mu.Unlock()
		return Record{}, err
	}
	c.mu.Lock()
	c.m[id] = cached{r: r, fetched: now}
	c.mu.Unlock()
	return r, nil
}

// Put implements Store. It updates this process's view immediately.
func (c *CachedStore) Put(ctx context.Context, r Record) error {
	if err := c.Store.Put(ctx, r); err != nil {
		return err
	}
	if id, ok := ParseID(r.ID); ok {
		c.mu.Lock()
		delete(c.m, id)
		c.mu.Unlock()
	}
	return nil
}
