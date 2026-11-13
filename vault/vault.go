// Package vault implements the encrypted store. A vault is one authenticated file,
// so nothing derived from stored data ever becomes a file path. The design and its
// limits are in docs/security-design.md and docs/threat-model.md.
package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/envelope"
	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/internal/fsutil"
	"github.com/mtnaskari/goraz/internal/harden"
	"github.com/mtnaskari/goraz/internal/kdf"
	"github.com/mtnaskari/goraz/internal/names"
	"github.com/mtnaskari/goraz/internal/state"
	"github.com/mtnaskari/goraz/internal/tokfmt"
	"github.com/mtnaskari/goraz/password"
	"github.com/mtnaskari/goraz/secret"
)

// Errors. None of them includes a secret, a value or a name.
var (
	ErrWrongCredential  = errors.New("vault: wrong credential, or the unlock data has been altered")
	ErrTampered         = errors.New("vault: the file failed authentication: it is corrupted or has been tampered with")
	ErrRollback         = errors.New("vault: this file is older than one already seen on this device")
	ErrFork             = errors.New("vault: this file has a different history from the one on this device, possibly a sync conflict")
	ErrStateInvalid     = errors.New("vault: the local state file failed authentication")
	ErrExpired          = errors.New("vault: this file is past its validity window and needs a new sync")
	ErrNotFound         = errors.New("vault: item not found")
	ErrExists           = errors.New("vault: an item with this name, or one differing only by case, already exists")
	ErrChanged          = errors.New("vault: the file changed since it was opened; open it again")
	ErrAuditUnavailable = errors.New("vault: the audit log can't be written, so the operation was refused")
	ErrReadOnly         = errors.New("vault: this vault was opened read-only")
	ErrNeedsRotation    = errors.New("vault: the main vault was rekeyed, so this service's key may be exposed; run service rotate first")
	ErrTooLarge         = errors.New("vault: a value is limited to 1 MiB")
	ErrClosed           = errors.New("vault: closed")
	ErrLimit            = errors.New("vault: this change would exceed a format limit")
	ErrInvalidInput     = errors.New("vault: invalid input")
	ErrNotDurable       = errors.New("vault: the change was written, but its directory couldn't be synced, so it may not survive a power loss")
	ErrNotVault         = errors.New("vault: this is not a goraz vault file, or it is from a newer format version")
	ErrNotServiceVault  = errors.New("vault: this file has a passphrase slot, so it is a main vault and can't be opened in service mode")
)

// ItemType classifies an item.
type ItemType string

// Item types.
const (
	TypeSecret ItemType = "secret"
	TypeLogin  ItemType = "login"
	TypeToken  ItemType = "token"
	TypeTOTP   ItemType = "totp"
)

func (t ItemType) valid() bool {
	switch t {
	case TypeSecret, TypeLogin, TypeToken, TypeTOTP:
		return true
	}
	return false
}

// Item is a stored item. Username, URLs and notes are Go strings, which can't be
// wiped. Value and OTP are wipeable.
type Item struct {
	Name     string
	Type     ItemType
	Tags     []string
	Expires  *time.Time
	Value    secret.Secret
	OTP      secret.Secret
	Username string
	URLs     []string
	Notes    string

	Version uint32
	Created time.Time
	Updated time.Time
}

// Wipe clears the wipeable fields.
func (it *Item) Wipe() {
	it.Value.Wipe()
	it.OTP.Wipe()
}

// content is the storage encoding of an item version. Encoding []byte through JSON
// uses base64, so values that aren't valid UTF-8 survive.
type content struct {
	Value    []byte   `json:"value,omitempty"`
	OTP      []byte   `json:"otp,omitempty"`
	Username string   `json:"username,omitempty"`
	URLs     []string `json:"urls,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

// Wipe clears the credential's bytes. Call it once the vault is open.
func (c *Credential) Wipe() {
	clear(c.passphrase)
	clear(c.keyfile)
	clear(c.recovery)
	for _, k := range c.machine {
		clear(k)
	}
}

// Credential unlocks a vault.
type Credential struct {
	kind       byte
	passphrase []byte
	keyfile    []byte
	recovery   []byte
	machine    [][]byte
}

// WithPassphrase returns a passphrase credential. keyfile may be nil.
func WithPassphrase(passphrase, keyfile []byte) Credential {
	return Credential{kind: format.SlotPassphrase, passphrase: passphrase, keyfile: keyfile}
}

// WithRecoveryCode returns a credential from a typed recovery code.
func WithRecoveryCode(code []byte) Credential {
	return Credential{kind: format.SlotRecovery, recovery: code}
}

// WithMachineKeys returns a credential from one or more machine keys. The key whose
// ID matches the file's slot is used, which allows a rotation without an outage.
func WithMachineKeys(keys ...[]byte) Credential {
	return Credential{kind: format.SlotMachine, machine: keys}
}

func (c *Credential) actor() audit.Actor {
	switch c.kind {
	case format.SlotPassphrase:
		return audit.ActorPassphrase
	case format.SlotRecovery:
		return audit.ActorRecovery
	}
	return audit.ActorMachine
}

// unlock returns the vault master key.
func (c *Credential) unlock(h *format.Header) ([]byte, error) {
	switch c.kind {
	case format.SlotPassphrase:
		for i := range h.Slots {
			s := &h.Slots[i]
			if s.Type != format.SlotPassphrase {
				continue
			}
			if s.HasKeyfile != (len(c.keyfile) > 0) {
				return nil, ErrWrongCredential
			}
			var key []byte
			var err error
			harden.SecretDo(func() {
				key, err = kdf.PassphraseKey(c.passphrase, c.keyfile, s.Salt[:], h.VaultID[:], s.Params)
			})
			if err != nil {
				return nil, ErrWrongCredential
			}
			vmk, err := openSlot(key, h.VaultID, s)
			clear(key)
			return vmk, err
		}
	case format.SlotRecovery:
		code, err := tokfmt.ParseRecovery(c.recovery)
		if err != nil {
			return nil, ErrWrongCredential
		}
		defer clear(code)
		key, err := kdf.RecoveryKey(code, h.VaultID[:])
		if err != nil {
			return nil, ErrWrongCredential
		}
		defer clear(key)
		for i := range h.Slots {
			if h.Slots[i].Type == format.SlotRecovery {
				if vmk, err := openSlot(key, h.VaultID, &h.Slots[i]); err == nil {
					return vmk, nil
				}
			}
		}
	case format.SlotMachine:
		for _, raw := range c.machine {
			p, err := tokfmt.Parse(raw)
			if err != nil || p.Kind != tokfmt.KindMachine || p.Prefix != tokfmt.DefaultPrefix {
				continue
			}
			for i := range h.Slots {
				s := &h.Slots[i]
				if s.Type != format.SlotMachine || subtle.ConstantTimeCompare(s.ID[:], p.ID[:]) != 1 {
					continue
				}
				key, err := kdf.MachineKey(p.Secret[:], h.VaultID[:])
				clear(p.Secret[:])
				if err != nil {
					return nil, ErrWrongCredential
				}
				vmk, err := openSlot(key, h.VaultID, s)
				clear(key)
				return vmk, err
			}
			clear(p.Secret[:])
		}
	}
	return nil, ErrWrongCredential
}

func openSlot(key []byte, id [format.IDSize]byte, s *format.Slot) ([]byte, error) {
	vmk, err := envelope.Open(key, envelope.DomainSlot, s.Context(id), s.Blob)
	if err != nil {
		return nil, ErrWrongCredential
	}
	return vmk, nil
}

// Options configures Open.
type Options struct {
	// StateDir holds local state and the audit log. It defaults to DefaultStateDir.
	StateDir string
	// Audit replaces the chained file log. A service uses this.
	Audit audit.Sink
	// Memory keeps rollback state in this process only, instead of on disk. A
	// service shares one across reloads, so it never accepts an older file.
	Memory *MemoryState
	// AcceptRollback and AcceptFork pin this exact file, discarding the other
	// history. They are audited.
	AcceptRollback bool
	AcceptFork     bool
	// AcceptAuditGap continues after a damaged or truncated audit log, recording a
	// gap entry.
	AcceptAuditGap bool
	// MinGeneration refuses any file older than this.
	MinGeneration uint64
	// Now replaces the clock.
	Now func() time.Time
	// Warn receives non-fatal notices. It must not be given secrets.
	Warn func(string)
	// hook injects faults in tests.
	hook fsutil.Hook
}

// IDSize is the size of a vault ID.
const IDSize = 16

// Both differences must be non-negative, so the build fails if the sizes differ.
const (
	_ uint = IDSize - format.IDSize
	_ uint = format.IDSize - IDSize
)

// MemoryState remembers, within one process, the newest file seen for each vault.
type MemoryState struct{ m *state.Memory }

// NewMemoryState returns an empty MemoryState.
func NewMemoryState() *MemoryState { return &MemoryState{m: state.NewMemory()} }

// DefaultStateDir returns $GORAZ_STATE_DIR, $XDG_STATE_HOME/goraz or
// ~/.local/state/goraz.
func DefaultStateDir() (string, error) {
	if d := os.Getenv("GORAZ_STATE_DIR"); d != "" {
		return d, nil
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "goraz"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "goraz"), nil
}

// Vault is an open vault. It is safe for concurrent use by one process.
type Vault struct {
	mu       sync.RWMutex
	path     string
	readOnly bool
	opts     Options
	now      func() time.Time

	hdr   *format.Header
	m     *manifest
	blobs map[string][]byte
	hash  [32]byte
	// current mirrors hash for the audit guard, which can run outside mu.
	current atomic.Pointer[[32]byte]

	keys  *harden.Locked // VMK, manifest key and item key, 32 bytes each.
	actor audit.Actor

	st     state.Store
	high   uint64
	sink   audit.Sink
	log    *audit.Log
	device string
	closed bool
}

func (v *Vault) vmk() []byte         { return v.keys.Bytes()[:32] }
func (v *Vault) manifestKey() []byte { return v.keys.Bytes()[32:64] }
func (v *Vault) itemKey() []byte     { return v.keys.Bytes()[64:96] }

func newKeyMem(vmk []byte, id [format.IDSize]byte) (*harden.Locked, error) {
	mk, err := kdf.Subkey(vmk, id[:], kdf.LabelManifest)
	if err != nil {
		return nil, err
	}
	defer clear(mk)
	ik, err := kdf.Subkey(vmk, id[:], kdf.LabelItem)
	if err != nil {
		return nil, err
	}
	defer clear(ik)
	l := harden.NewLocked(96)
	copy(l.Bytes()[:32], vmk)
	copy(l.Bytes()[32:64], mk)
	copy(l.Bytes()[64:96], ik)
	return l, nil
}

func blobKey(id []byte, ver uint32) string {
	return fmt.Sprintf("%x/%d", id, ver)
}

func itemContext(vaultID [format.IDSize]byte, id []byte, ver uint32) []byte {
	b := make([]byte, 0, 2*format.IDSize+4)
	b = append(b, vaultID[:]...)
	b = append(b, id...)
	return binary.BigEndian.AppendUint32(b, ver)
}

// decode runs the authenticated part of the open sequence.
func decode(data []byte, cred *Credential) (*format.Header, *manifest, map[string][]byte, *harden.Locked, error) {
	if !bytes.HasPrefix(data, []byte(format.Magic)) {
		return nil, nil, nil, nil, ErrNotVault
	}
	h, n, err := format.Parse(data)
	if err != nil {
		return nil, nil, nil, nil, ErrTampered
	}
	vmk, err := cred.unlock(h)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer clear(vmk)
	if len(vmk) != 32 {
		return nil, nil, nil, nil, ErrTampered
	}
	keys, err := newKeyMem(vmk, h.VaultID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	fail := func(err error) (*format.Header, *manifest, map[string][]byte, *harden.Locked, error) {
		keys.Close()
		return nil, nil, nil, nil, err
	}
	headerHash := sha256.Sum256(data[:n])
	end := n + int(h.ManifestLen)
	plain, err := envelope.Open(keys.Bytes()[32:64], envelope.DomainManifest, headerHash[:], data[n:end])
	if err != nil {
		return fail(ErrTampered)
	}
	defer clear(plain)
	m, err := decodeManifest(plain)
	if err != nil {
		return fail(ErrTampered)
	}
	blobs := make(map[string][]byte)
	off := int64(end)
	total := int64(len(data))
	for i := range m.Items {
		for _, ver := range m.Items[i].Versions {
			if ver.Length > total-off {
				return fail(ErrTampered)
			}
			blobs[blobKey(m.Items[i].ID, ver.Version)] = data[off : off+ver.Length]
			off += ver.Length
		}
	}
	if off != total {
		return fail(ErrTampered)
	}
	return h, m, blobs, keys, nil
}

func (v *Vault) warn(msg string) {
	if v.opts.Warn != nil {
		v.opts.Warn(msg)
	}
}

// checkLocal compares the file with local state.
func (v *Vault) checkLocal() error {
	key := v.m.Keys.State
	rec, err := v.st.Load(v.hdr.VaultID, key)
	if errors.Is(err, state.ErrInvalid) {
		return ErrStateInvalid
	}
	if err != nil {
		return fmt.Errorf("vault: reading local state: %w", err)
	}
	dec := state.Decide(rec, v.hdr.Generation, v.hash, v.m.Lineage)
	accepted := audit.EventType("")
	switch dec {
	case state.Accept:
	case state.AcceptUnverified:
		v.warn("this file is more than 32 generations newer than the last one seen, so its history can't be checked")
	case state.Rollback:
		if !v.opts.AcceptRollback {
			return ErrRollback
		}
		accepted = audit.EventRollbackAccept
	case state.Fork:
		if !v.opts.AcceptFork {
			return ErrFork
		}
		accepted = audit.EventForkAccept
	}
	// An override must be audited before it takes effect. If it were pinned first, a
	// failed audit write would still leave the file accepted on the next open.
	if rec != nil {
		v.device = hex.EncodeToString(rec.DeviceID[:])
		v.setupAudit()
		if accepted != "" {
			if err := v.record(audit.Event{Type: accepted, Outcome: audit.OK, Actor: v.actor}); err != nil {
				return err
			}
		}
	}
	updated, err := v.st.Pin(v.hdr.VaultID, key, v.hdr.Generation, v.hash)
	if err != nil {
		return fmt.Errorf("vault: writing local state: %w", err)
	}
	v.high = updated.High
	if rec == nil {
		// The device identifier is created with the first record.
		v.device = hex.EncodeToString(updated.DeviceID[:])
		v.setupAudit()
	}
	return nil
}

func (v *Vault) setupAudit() {
	if v.opts.Audit != nil {
		v.sink = v.opts.Audit
		return
	}
	if v.opts.StateDir == "" {
		return // Read-only, and audit isn't required: nothing is written anywhere.
	}
	v.log = audit.OpenLog(v.auditPath(), audit.LogOptions{
		Keys: v.m.auditKeys(), Anchor: v.m.AuditAnchors[v.device],
		AcceptGap: v.opts.AcceptAuditGap, Now: v.now,
	})
	if v.path != "" {
		v.log.Guard = v.guard
	}
	v.sink = v.log
}

func (v *Vault) auditPath() string {
	dir := v.opts.StateDir
	return filepath.Join(dir, "audit", hex.EncodeToString(v.hdr.VaultID[:]), v.device+".log")
}

// guard refuses an append under a stale key after the file has changed.
func (v *Vault) guard() error {
	data, err := fsutil.ReadFile(v.path, format.MaxFileSize, fsutil.Policy{})
	if err != nil {
		return err
	}
	if sha256.Sum256(data) != *v.current.Load() {
		return ErrChanged
	}
	return nil
}

// record writes an audit event. When audit is required, a failure is returned so
// that the caller can refuse to release anything.
func (v *Vault) record(e audit.Event) error {
	if v.sink == nil {
		if v.m.AuditRequired {
			return ErrAuditUnavailable
		}
		return nil
	}
	err := v.sink.Record(e)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrChanged) || errors.Is(err, audit.ErrTampered) || errors.Is(err, audit.ErrTruncated) {
		return err
	}
	if v.m.AuditRequired {
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}
	return nil
}

func (v *Vault) objectHash(name string) []byte {
	return audit.ObjectHash(v.m.activeAuditKey(), name)
}

// Open opens a vault for reading and writing.
func Open(path string, cred Credential, o Options) (*Vault, error) {
	if o.StateDir == "" {
		d, err := DefaultStateDir()
		if err != nil {
			return nil, err
		}
		o.StateDir = d
	}
	lock, err := fsutil.AcquireLock(path+".lock", true)
	if err != nil {
		return nil, err
	}
	defer lock.Release()
	data, err := fsutil.ReadFile(path, format.MaxFileSize, fsutil.Policy{})
	if err != nil {
		return nil, err
	}
	v, err := fromBytes(data, cred, o)
	if err != nil {
		return nil, err
	}
	v.path = path
	if v.st == nil {
		v.st = &state.File{Dir: o.StateDir}
	}
	if err := v.checkLocal(); err != nil {
		v.Close()
		return nil, err
	}
	if err := v.record(audit.Event{Type: audit.EventVaultOpen, Outcome: audit.OK, Actor: v.actor}); err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

// OpenService opens a service vault from bytes already read. It takes no lock and
// writes no state. A sink is required if the vault requires audit. A main vault is
// refused, because these exceptions to the file rules apply only to service vaults.
func OpenService(data []byte, cred Credential, o Options) (*Vault, error) {
	if !bytes.HasPrefix(data, []byte(format.Magic)) {
		return nil, ErrNotVault
	}
	h, _, err := format.Parse(data)
	if err != nil {
		return nil, ErrTampered
	}
	for i := range h.Slots {
		if h.Slots[i].Type == format.SlotPassphrase {
			return nil, ErrNotServiceVault
		}
	}
	return openReadOnly(data, cred, o)
}

func openReadOnly(data []byte, cred Credential, o Options) (*Vault, error) {
	v, err := fromBytes(data, cred, o)
	if err != nil {
		return nil, err
	}
	v.readOnly = true
	if o.Memory != nil {
		v.st = o.Memory.m
	} else {
		v.st = state.NewMemory()
	}
	if v.m.AuditRequired && o.Audit == nil {
		v.Close()
		return nil, ErrAuditUnavailable
	}
	if err := v.checkLocal(); err != nil {
		v.Close()
		return nil, err
	}
	if err := v.record(audit.Event{Type: audit.EventVaultOpen, Outcome: audit.OK, Actor: v.actor}); err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

func fromBytes(data []byte, cred Credential, o Options) (*Vault, error) {
	h, m, blobs, keys, err := decode(data, &cred)
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	v := &Vault{
		readOnly: false, opts: o, now: now, hdr: h, m: m, blobs: blobs,
		hash: sha256.Sum256(data), keys: keys, actor: cred.actor(),
	}
	stored := v.hash
	v.current.Store(&stored)
	if h.Generation < o.MinGeneration {
		v.Close()
		return nil, ErrRollback
	}
	if m.ValidUntil != nil && !now().Before(*m.ValidUntil) {
		v.Close()
		return nil, ErrExpired
	}
	return v, nil
}

// Close clears keys held by the vault. Using a closed vault returns ErrClosed.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return
	}
	v.closed = true
	v.keys.Close()
	v.m.wipe()
}

// Generation returns the file's generation.
func (v *Vault) Generation() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.hdr.Generation
}

// ID returns the vault ID.
func (v *Vault) ID() [IDSize]byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.hdr.VaultID
}

// ValidUntil returns the end of the file's validity window, if it has one.
func (v *Vault) ValidUntil() *time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.m.ValidUntil
}

// Metadata describes an item without decrypting it.
type Metadata struct {
	Name     string
	Type     ItemType
	Tags     []string
	Created  time.Time
	Updated  time.Time
	Expires  *time.Time
	Deleted  bool
	Versions []uint32
}

func metadata(e *itemEntry) Metadata {
	vs := make([]uint32, len(e.Versions))
	for i, x := range e.Versions {
		vs[i] = x.Version
	}
	return Metadata{
		Name: e.Name, Type: e.Type, Tags: slices.Clone(e.Tags), Created: e.Created, Updated: e.Updated,
		Expires: e.Expires, Deleted: e.Deleted != nil, Versions: vs,
	}
}

// List returns metadata for all items that aren't deleted, sorted by name.
func (v *Vault) List() ([]Metadata, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	out := make([]Metadata, 0, len(v.m.Items))
	for i := range v.m.Items {
		if v.m.Items[i].Deleted == nil {
			out = append(out, metadata(&v.m.Items[i]))
		}
	}
	slices.SortFunc(out, func(a, b Metadata) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out, nil
}

// History returns metadata for one item, including a deleted one.
func (v *Vault) History(name string) (Metadata, error) {
	if err := names.Validate(name); err != nil {
		return Metadata{}, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return Metadata{}, ErrClosed
	}
	e := v.m.find(name)
	if e == nil {
		return Metadata{}, ErrNotFound
	}
	return metadata(e), nil
}

func (v *Vault) decryptVersion(keys []byte, e *itemEntry, ver *version, blobs map[string][]byte) (*content, error) {
	blob, ok := blobs[blobKey(e.ID, ver.Version)]
	if !ok {
		return nil, ErrTampered
	}
	sum := sha256.Sum256(blob)
	if subtle.ConstantTimeCompare(sum[:], ver.SHA256) != 1 {
		return nil, ErrTampered
	}
	padded, err := envelope.Open(keys, envelope.DomainItem, itemContext(v.hdr.VaultID, e.ID, ver.Version), blob)
	if err != nil {
		return nil, ErrTampered
	}
	defer clear(padded)
	raw, err := unpad(padded)
	if err != nil {
		return nil, ErrTampered
	}
	var c content
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, ErrTampered
	}
	return &c, nil
}

const padBlock = 256

func pad(b []byte) []byte {
	total := 4 + len(b)
	if r := total % padBlock; r != 0 {
		total += padBlock - r
	}
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out, uint32(len(b))) // #nosec G115 -- bounded by the item size limit.
	copy(out[4:], b)
	return out
}

func unpad(p []byte) ([]byte, error) {
	if len(p) < 4 || len(p)%padBlock != 0 {
		return nil, ErrTampered
	}
	n := uint64(binary.BigEndian.Uint32(p))
	if n > uint64(len(p)-4) { // #nosec G115 -- the length was checked above.
		return nil, ErrTampered
	}
	end := 4 + int(n) // #nosec G115 -- bounded by the check above.
	for _, x := range p[end:] {
		if x != 0 {
			return nil, ErrTampered
		}
	}
	return p[4:end], nil
}

// Get returns the latest version of an item. The read is audited before the value
// is returned, and if the audit entry can't be written, nothing is returned.
func (v *Vault) Get(name string) (*Item, error) {
	return v.GetVersion(name, 0)
}

// GetVersion returns one version of an item. Zero means the latest.
func (v *Vault) GetVersion(name string, ver uint32) (*Item, error) {
	if err := names.Validate(name); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	e := v.m.find(name)
	if e == nil || (e.Deleted != nil && ver == 0) {
		return nil, ErrNotFound
	}
	sel := &e.Versions[len(e.Versions)-1]
	if ver != 0 {
		sel = nil
		for i := range e.Versions {
			if e.Versions[i].Version == ver {
				sel = &e.Versions[i]
			}
		}
		if sel == nil {
			return nil, ErrNotFound
		}
	}
	c, err := v.decryptVersion(v.itemKey(), e, sel, v.blobs)
	if err != nil {
		_ = v.record(audit.Event{Type: audit.EventItemRead, Outcome: audit.Failed, Actor: v.actor, Object: v.objectHash(name)})
		return nil, err
	}
	if err := v.record(audit.Event{Type: audit.EventItemRead, Outcome: audit.OK, Actor: v.actor, Object: v.objectHash(name)}); err != nil {
		clear(c.Value)
		clear(c.OTP)
		return nil, err
	}
	return &Item{
		Name: e.Name, Type: e.Type, Tags: slices.Clone(e.Tags), Expires: e.Expires,
		Value: secret.Adopt(c.Value), OTP: secret.Adopt(c.OTP),
		Username: c.Username, URLs: c.URLs, Notes: c.Notes,
		Version: sel.Version, Created: sel.Created, Updated: e.Updated,
	}, nil
}

// tx is one write transaction.
type tx struct {
	m     *manifest
	blobs map[string][]byte
	hdr   format.Header
	keys  *harden.Locked // Non-nil when the VMK changes.
	// before runs once the changes are final, and before the old file is replaced.
	before func() error
}

func (t *tx) itemKey(v *Vault) []byte {
	if t.keys != nil {
		return t.keys.Bytes()[64:96]
	}
	return v.itemKey()
}

// assemble produces the bytes of a file.
func assemble(h *format.Header, m *manifest, manifestKey []byte, blobs map[string][]byte) ([]byte, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain)+envelope.Overhead > format.MaxManifestSize {
		return nil, fmt.Errorf("%w: the manifest exceeds its size limit", ErrLimit)
	}
	h.ManifestLen = uint32(len(plain) + envelope.Overhead) // #nosec G115 -- bounded above.
	head, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(head)
	sealed, err := envelope.Seal(manifestKey, envelope.DomainManifest, sum[:], plain)
	if err != nil {
		return nil, err
	}
	out := append(head, sealed...)
	for i := range m.Items {
		for _, ver := range m.Items[i].Versions {
			blob, ok := blobs[blobKey(m.Items[i].ID, ver.Version)]
			if !ok {
				return nil, ErrTampered
			}
			out = append(out, blob...)
		}
	}
	if len(out) > format.MaxFileSize {
		return nil, fmt.Errorf("%w: the file exceeds its size limit", ErrLimit)
	}
	return out, nil
}

// commit runs one write: it locks, confirms the file hasn't changed, verifies all
// blobs, applies fn to a copy, audits, writes atomically and updates local state.
func (v *Vault) commit(ev audit.Event, fn func(t *tx) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	if v.readOnly {
		return ErrReadOnly
	}
	lock, err := fsutil.AcquireLock(v.path+".lock", false)
	if err != nil {
		return err
	}
	defer lock.Release()
	// A crash can leave a temporary copy, which holds old slots and old data.
	fsutil.RemoveStaleTemps(v.path)

	cur, err := fsutil.ReadFile(v.path, format.MaxFileSize, fsutil.Policy{})
	if err != nil {
		return err
	}
	if sha256.Sum256(cur) != v.hash {
		return ErrChanged
	}
	for i := range v.m.Items {
		e := &v.m.Items[i]
		for j := range e.Versions {
			sum := sha256.Sum256(v.blobs[blobKey(e.ID, e.Versions[j].Version)])
			if subtle.ConstantTimeCompare(sum[:], e.Versions[j].SHA256) != 1 {
				return ErrTampered
			}
		}
	}

	clone, err := v.m.clone()
	if err != nil {
		return err
	}
	t := &tx{m: clone, blobs: make(map[string][]byte, len(v.blobs)), hdr: *v.hdr}
	t.hdr.Slots = slices.Clone(v.hdr.Slots)
	maps.Copy(t.blobs, v.blobs)
	if err := fn(t); err != nil {
		if t.keys != nil {
			t.keys.Close()
		}
		clone.wipe()
		return err
	}
	abort := func(err error) error {
		if t.keys != nil {
			t.keys.Close()
		}
		clone.wipe()
		return err
	}
	if t.before != nil {
		if err := t.before(); err != nil {
			return abort(err)
		}
	}
	if err := v.record(ev); err != nil {
		return abort(err)
	}
	// The entry above says the change happened. If it doesn't, say so too.
	recorded := abort
	abort = func(err error) error {
		_ = v.record(audit.Event{Type: ev.Type, Outcome: audit.Failed, Actor: ev.Actor, Object: ev.Object})
		return recorded(err)
	}
	t.m.Lineage = append(t.m.Lineage, state.Lineage{Generation: v.hdr.Generation, SHA256: slices.Clone(v.hash[:])})
	if len(t.m.Lineage) > maxLineage {
		t.m.Lineage = t.m.Lineage[len(t.m.Lineage)-maxLineage:]
	}
	if v.log != nil {
		if t.m.AuditAnchors == nil {
			t.m.AuditAnchors = make(map[string]audit.Anchor)
		}
		if _, known := t.m.AuditAnchors[v.device]; !known && len(t.m.AuditAnchors) >= maxAnchors {
			return abort(fmt.Errorf("%w: too many devices have written to this vault", ErrLimit))
		}
		t.m.AuditAnchors[v.device] = v.log.Head()
	}
	// A write must never produce a file that a later open would refuse.
	if err := t.m.validate(); err != nil {
		return abort(ErrLimit)
	}
	t.hdr.Generation = max(v.hdr.Generation, v.high) + 1
	manifestKey := v.manifestKey()
	if t.keys != nil {
		manifestKey = t.keys.Bytes()[32:64]
	}
	file, err := assemble(&t.hdr, t.m, manifestKey, t.blobs)
	if err != nil {
		return abort(err)
	}
	var notDurable error
	if err := fsutil.AtomicWrite(v.path, file, v.opts.hook); err != nil {
		if !errors.Is(err, fsutil.ErrNotDurable) {
			return abort(err)
		}
		// The file was replaced, so the rest of the commit must still happen.
		notDurable = fmt.Errorf("%w: %w", ErrNotDurable, err)
	}

	hash := sha256.Sum256(file)
	rec, err := v.st.Pin(v.hdr.VaultID, t.m.Keys.State, t.hdr.Generation, hash)
	if err != nil {
		return abort(fmt.Errorf("vault: writing local state: %w", err))
	}
	// Reparse so that in-memory slices refer to exactly what was written.
	parsed, n, err := format.Parse(file)
	if err != nil {
		return abort(err)
	}
	blobs := make(map[string][]byte, len(t.blobs))
	off := n + int(parsed.ManifestLen)
	for i := range t.m.Items {
		for _, ver := range t.m.Items[i].Versions {
			blobs[blobKey(t.m.Items[i].ID, ver.Version)] = file[off : off+int(ver.Length)]
			off += int(ver.Length)
		}
	}
	previous := v.m
	v.hdr, v.m, v.blobs, v.hash, v.high = parsed, t.m, blobs, hash, rec.High
	stored := hash
	v.current.Store(&stored)
	if t.keys != nil {
		v.keys.Close()
		v.keys = t.keys
	}
	if v.log != nil {
		v.log.SetKeys(v.m.auditKeys())
	}
	previous.wipe()
	return notDurable
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Put stores a new version of an item, creating it if needed.
func (v *Vault) Put(it *Item) error {
	if err := names.Validate(it.Name); err != nil {
		return err
	}
	if it.Type == "" {
		it.Type = TypeSecret
	}
	if !it.Type.valid() {
		return fmt.Errorf("%w: unknown item type", ErrInvalidInput)
	}
	if len(it.Tags) > maxItemTags {
		return errors.New("vault: too many tags")
	}
	for _, tag := range it.Tags {
		if len(tag) > maxTagLength {
			return errors.New("vault: a tag is limited to 64 bytes")
		}
	}
	raw, err := json.Marshal(content{
		Value: it.Value.Bytes(), OTP: it.OTP.Bytes(), Username: it.Username, URLs: it.URLs, Notes: it.Notes,
	})
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) > 2*format.MaxValueSize || it.Value.Len() > format.MaxValueSize {
		return ErrTooLarge
	}
	return v.commit(audit.Event{Type: audit.EventItemWrite, Outcome: audit.OK, Actor: v.actor, Object: v.objectHashLocked(it.Name)}, func(t *tx) error {
		return v.applyPut(t, it, raw)
	})
}

// objectHashLocked reads the manifest without holding the write lock.
func (v *Vault) objectHashLocked(name string) []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil
	}
	return v.objectHash(name)
}

func (v *Vault) applyPut(t *tx, it *Item, raw []byte) error {
	now := v.now().UTC()
	e := t.m.find(it.Name)
	if e == nil {
		fold := names.FoldKey(it.Name)
		for i := range t.m.Items {
			if names.FoldKey(t.m.Items[i].Name) == fold {
				return ErrExists
			}
		}
		id, err := randomBytes(format.IDSize)
		if err != nil {
			return err
		}
		t.m.Items = append(t.m.Items, itemEntry{ID: id, Name: it.Name, Created: now})
		e = &t.m.Items[len(t.m.Items)-1]
	}
	next := uint32(1)
	if n := len(e.Versions); n > 0 {
		next = e.Versions[n-1].Version + 1
	}
	padded := pad(raw)
	defer clear(padded)
	blob, err := envelope.Seal(t.itemKey(v), envelope.DomainItem, itemContext(t.hdr.VaultID, e.ID, next), padded)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(blob)
	t.blobs[blobKey(e.ID, next)] = blob
	e.Versions = append(e.Versions, version{Version: next, Length: int64(len(blob)), SHA256: sum[:], Created: now})
	for len(e.Versions) > maxVersions {
		delete(t.blobs, blobKey(e.ID, e.Versions[0].Version))
		e.Versions = e.Versions[1:]
	}
	e.Type, e.Tags, e.Expires, e.Updated, e.Deleted = it.Type, slices.Clone(it.Tags), it.Expires, now, nil
	return nil
}

// Delete hides an item. Its history remains, and Restore brings it back.
func (v *Vault) Delete(name string) error {
	if err := names.Validate(name); err != nil {
		return err
	}
	return v.commit(audit.Event{Type: audit.EventItemDelete, Outcome: audit.OK, Actor: v.actor, Object: v.objectHashLocked(name)}, func(t *tx) error {
		e := t.m.find(name)
		if e == nil || e.Deleted != nil {
			return ErrNotFound
		}
		now := v.now().UTC()
		e.Deleted, e.Updated = &now, now
		return nil
	})
}

// Destroy removes an item and all its versions from the file. Backups and
// filesystem snapshots may still hold old copies.
func (v *Vault) Destroy(name string) error {
	if err := names.Validate(name); err != nil {
		return err
	}
	return v.commit(audit.Event{Type: audit.EventItemDestroy, Outcome: audit.OK, Actor: v.actor, Object: v.objectHashLocked(name)}, func(t *tx) error {
		for i := range t.m.Items {
			e := &t.m.Items[i]
			if e.Name != name {
				continue
			}
			for _, ver := range e.Versions {
				delete(t.blobs, blobKey(e.ID, ver.Version))
			}
			t.m.Items = slices.Delete(t.m.Items, i, i+1)
			return nil
		}
		return ErrNotFound
	})
}

// Restore makes an earlier version the latest, as a new version, and clears any
// deletion. Zero means the latest existing version.
func (v *Vault) Restore(name string, ver uint32) error {
	if err := names.Validate(name); err != nil {
		return err
	}
	return v.commit(audit.Event{Type: audit.EventItemRestore, Outcome: audit.OK, Actor: v.actor, Object: v.objectHashLocked(name)}, func(t *tx) error {
		e := t.m.find(name)
		if e == nil {
			return ErrNotFound
		}
		sel := &e.Versions[len(e.Versions)-1]
		if ver != 0 {
			sel = nil
			for i := range e.Versions {
				if e.Versions[i].Version == ver {
					sel = &e.Versions[i]
				}
			}
			if sel == nil {
				return ErrNotFound
			}
		}
		c, err := v.decryptVersion(v.itemKey(), e, sel, t.blobs)
		if err != nil {
			return err
		}
		defer clear(c.Value)
		defer clear(c.OTP)
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		defer clear(raw)
		return v.applyPut(t, &Item{Name: name, Type: e.Type, Tags: e.Tags, Expires: e.Expires}, raw)
	})
}

// SetAuditRequired changes whether reads fail when audit can't be written. The
// setting lives in the authenticated manifest, so an outside edit can't change it.
func (v *Vault) SetAuditRequired(on bool) error {
	return v.commit(audit.Event{Type: audit.EventSettingChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		t.m.AuditRequired = on
		return nil
	})
}

// AuditRequired reports the setting.
func (v *Vault) AuditRequired() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.m.AuditRequired
}

// AuditHash returns the value the log holds for a name, for searching.
func (v *Vault) AuditHash(name string) (string, error) {
	if err := names.Validate(name); err != nil {
		return "", err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return "", ErrClosed
	}
	return hex.EncodeToString(v.objectHash(name)), nil
}

// VerifyAudit checks this device's log and returns the result.
func (v *Vault) VerifyAudit() (*audit.Result, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	if v.log == nil {
		return nil, errors.New("vault: this vault doesn't use a chained log")
	}
	return audit.Verify(v.auditPath(), v.m.auditKeys(), v.m.AuditAnchors[v.device])
}

// ReadAudit returns this device's verified log entries.
func (v *Vault) ReadAudit() ([]audit.Entry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	if v.log == nil {
		return nil, errors.New("vault: this vault doesn't use a chained log")
	}
	return audit.Read(v.auditPath(), v.m.auditKeys(), v.m.AuditAnchors[v.device])
}

// RotateAuditKey adds a new active audit key. Old keys remain, for verifying old
// entries only.
func (v *Vault) RotateAuditKey() error {
	return v.commit(audit.Event{Type: audit.EventKeyRotate, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		return rotateAudit(&t.m.Keys)
	})
}

func rotateAudit(k *keySet) error {
	key, err := randomBytes(keyLength)
	if err != nil {
		return err
	}
	var top uint32
	for i := range k.Audit {
		k.Audit[i].Active = false
		top = max(top, k.Audit[i].ID)
	}
	k.Audit = append(k.Audit, auditKey{ID: top + 1, Key: key, Active: true})
	return nil
}

// FullCheck verifies every blob in memory, for diagnostics.
func (v *Vault) FullCheck() (bad []string, err error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	for i := range v.m.Items {
		e := &v.m.Items[i]
		for j := range e.Versions {
			c, err := v.decryptVersion(v.itemKey(), e, &e.Versions[j], v.blobs)
			if err != nil {
				bad = append(bad, e.Name)
				break
			}
			clear(c.Value)
			clear(c.OTP)
		}
	}
	return bad, nil
}

// CheckPassphrase applies the master passphrase policy.
func CheckPassphrase(p []byte) error { return password.CheckMaster(p) }
