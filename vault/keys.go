package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/envelope"
	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/internal/fsutil"
	"github.com/mtnaskari/goraz/internal/kdf"
	"github.com/mtnaskari/goraz/internal/state"
	"github.com/mtnaskari/goraz/internal/tokfmt"
	"github.com/mtnaskari/goraz/password"
	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/token"
)

// CreateOptions configures Create.
type CreateOptions struct {
	Passphrase []byte
	Keyfile    []byte // Optional: exactly 32 random bytes.
	Profile    kdf.Profile
	// AcceptWeakPassphrase skips the passphrase policy.
	AcceptWeakPassphrase bool
	Options              Options
}

func newKeySet() (keySet, error) {
	st, err := randomBytes(keyLength)
	if err != nil {
		return keySet{}, err
	}
	au, err := randomBytes(keyLength)
	if err != nil {
		return keySet{}, err
	}
	ve, err := randomBytes(keyLength)
	if err != nil {
		return keySet{}, err
	}
	return keySet{
		State:         st,
		Audit:         []auditKey{{ID: 1, Key: au, Active: true}},
		TokenVerifier: []token.Key{{ID: 1, Key: ve}},
	}, nil
}

func passphraseSlot(vaultID [format.IDSize]byte, vmk, pass, keyfile []byte, p kdf.Params) (format.Slot, error) {
	s := format.Slot{Type: format.SlotPassphrase, Params: p, HasKeyfile: len(keyfile) > 0}
	id, err := randomBytes(format.IDSize)
	if err != nil {
		return s, err
	}
	copy(s.ID[:], id)
	salt, err := randomBytes(kdf.SaltSize)
	if err != nil {
		return s, err
	}
	copy(s.Salt[:], salt)
	key, err := kdf.PassphraseKey(pass, keyfile, s.Salt[:], vaultID[:], p)
	if err != nil {
		return s, err
	}
	defer clear(key)
	s.Blob, err = envelope.Seal(key, envelope.DomainSlot, s.Context(vaultID), vmk)
	return s, err
}

func recoverySlot(vaultID [format.IDSize]byte, vmk []byte) (format.Slot, string, error) {
	s := format.Slot{Type: format.SlotRecovery}
	id, err := randomBytes(format.IDSize)
	if err != nil {
		return s, "", err
	}
	copy(s.ID[:], id)
	code, err := randomBytes(32)
	if err != nil {
		return s, "", err
	}
	defer clear(code)
	key, err := kdf.RecoveryKey(code, vaultID[:])
	if err != nil {
		return s, "", err
	}
	defer clear(key)
	s.Blob, err = envelope.Seal(key, envelope.DomainSlot, s.Context(vaultID), vmk)
	if err != nil {
		return s, "", err
	}
	text, err := tokfmt.EncodeRecovery(code)
	return s, text, err
}

func machineSlot(vaultID [format.IDSize]byte, vmk, slotID, sec []byte) (format.Slot, error) {
	s := format.Slot{Type: format.SlotMachine}
	copy(s.ID[:], slotID)
	key, err := kdf.MachineKey(sec, vaultID[:])
	if err != nil {
		return s, err
	}
	defer clear(key)
	s.Blob, err = envelope.Seal(key, envelope.DomainSlot, s.Context(vaultID), vmk)
	return s, err
}

func newMachineSlot(vaultID [format.IDSize]byte, vmk []byte) (format.Slot, secret.Secret, error) {
	id, err := randomBytes(format.IDSize)
	if err != nil {
		return format.Slot{}, secret.Secret{}, err
	}
	sec, err := randomBytes(tokfmt.SecretSize)
	if err != nil {
		return format.Slot{}, secret.Secret{}, err
	}
	defer clear(sec)
	s, err := machineSlot(vaultID, vmk, id, sec)
	if err != nil {
		return format.Slot{}, secret.Secret{}, err
	}
	tok, err := tokfmt.Encode(tokfmt.DefaultPrefix, tokfmt.KindMachine, id, sec)
	if err != nil {
		return format.Slot{}, secret.Secret{}, err
	}
	return s, secret.Adopt(tok), nil
}

// Create makes a new vault and returns it with its recovery code. The code is shown
// once, and it is the only way back in if the passphrase is lost.
func Create(path string, o CreateOptions) (*Vault, secret.Secret, error) {
	if !o.AcceptWeakPassphrase {
		if err := password.CheckMaster(o.Passphrase); err != nil {
			return nil, secret.Secret{}, err
		}
	}
	if len(o.Keyfile) != 0 && len(o.Keyfile) != kdf.KeyfileSize {
		return nil, secret.Secret{}, errors.New("vault: a key file must be exactly 32 bytes")
	}
	if o.Profile == (kdf.Profile{}) {
		o.Profile = kdf.Default
	}
	opts := o.Options
	if opts.StateDir == "" {
		d, err := DefaultStateDir()
		if err != nil {
			return nil, secret.Secret{}, err
		}
		opts.StateDir = d
	}
	if err := fsutil.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, secret.Secret{}, err
	}
	lock, err := fsutil.AcquireLock(path+".lock", false)
	if err != nil {
		return nil, secret.Secret{}, err
	}
	defer lock.Release()
	if _, err := os.Lstat(path); err == nil {
		return nil, secret.Secret{}, errors.New("vault: a file already exists at this path")
	}

	var h format.Header
	id, err := randomBytes(format.IDSize)
	if err != nil {
		return nil, secret.Secret{}, err
	}
	copy(h.VaultID[:], id)
	h.Generation = 1
	vmk, err := randomBytes(32)
	if err != nil {
		return nil, secret.Secret{}, err
	}
	defer clear(vmk)
	ps, err := passphraseSlot(h.VaultID, vmk, o.Passphrase, o.Keyfile, o.Profile.Params)
	if err != nil {
		return nil, secret.Secret{}, err
	}
	rs, code, err := recoverySlot(h.VaultID, vmk)
	if err != nil {
		return nil, secret.Secret{}, err
	}
	h.Slots = []format.Slot{ps, rs}
	keys, err := newKeySet()
	if err != nil {
		return nil, secret.Secret{}, err
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	m := &manifest{Created: now().UTC(), AuditRequired: true, Keys: keys}
	mem, err := newKeyMem(vmk, h.VaultID)
	if err != nil {
		return nil, secret.Secret{}, err
	}
	defer mem.Close()
	file, err := assemble(&h, m, mem.Bytes()[32:64], map[string][]byte{})
	if err != nil {
		return nil, secret.Secret{}, err
	}
	if err := fsutil.AtomicWrite(path, file, nil); err != nil {
		return nil, secret.Secret{}, err
	}
	lock.Release()
	// From here the file exists, so the recovery code is returned even with an error.
	shown := secret.New([]byte(code))
	v, err := Open(path, WithPassphrase(o.Passphrase, o.Keyfile), opts)
	if err != nil {
		return nil, shown, err
	}
	if err := v.record(audit.Event{Type: audit.EventVaultCreate, Outcome: audit.OK, Actor: v.actor}); err != nil {
		v.Close()
		return nil, shown, err
	}
	return v, shown, nil
}

// ChangePassphrase replaces the passphrase slot. It does not revoke the old
// passphrase: anyone holding it and an old copy of the file still gets the master
// key, which reads and can forge current files. Use Rekey after a suspected exposure.
func (v *Vault) ChangePassphrase(pass, keyfile []byte, p kdf.Profile, acceptWeak bool) error {
	if !acceptWeak {
		if err := password.CheckMaster(pass); err != nil {
			return err
		}
	}
	if p == (kdf.Profile{}) {
		p = kdf.Default
	}
	return v.commit(audit.Event{Type: audit.EventSlotChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		s, err := passphraseSlot(t.hdr.VaultID, v.vmk(), pass, keyfile, p.Params)
		if err != nil {
			return err
		}
		for i := range t.hdr.Slots {
			if t.hdr.Slots[i].Type == format.SlotPassphrase {
				t.hdr.Slots[i] = s
				return nil
			}
		}
		t.hdr.Slots = append(t.hdr.Slots, s)
		return nil
	})
}

// SlotInfo describes an unlock slot.
type SlotInfo struct {
	ID   string
	Type string
}

func slotTypeName(b byte) string {
	switch b {
	case format.SlotPassphrase:
		return "passphrase"
	case format.SlotRecovery:
		return "recovery"
	case format.SlotMachine:
		return "machine"
	}
	return "unknown"
}

// Slots lists the unlock slots.
func (v *Vault) Slots() []SlotInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]SlotInfo, len(v.hdr.Slots))
	for i, s := range v.hdr.Slots {
		out[i] = SlotInfo{ID: hex.EncodeToString(s.ID[:]), Type: slotTypeName(s.Type)}
	}
	return out
}

// AddMachineKey adds a machine slot and returns its key. The key is shown once, and
// it opens the whole vault. A service should use a service vault instead.
func (v *Vault) AddMachineKey() (secret.Secret, error) {
	var key secret.Secret
	err := v.commit(audit.Event{Type: audit.EventSlotChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		if len(t.hdr.Slots) >= format.MaxSlots {
			return errors.New("vault: too many slots")
		}
		s, k, err := newMachineSlot(t.hdr.VaultID, v.vmk())
		if err != nil {
			return err
		}
		t.hdr.Slots = append(t.hdr.Slots, s)
		key = k
		return nil
	})
	return key, err
}

// AddRecoveryCode adds a recovery slot and returns its code.
func (v *Vault) AddRecoveryCode() (secret.Secret, error) {
	var code secret.Secret
	err := v.commit(audit.Event{Type: audit.EventSlotChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		if len(t.hdr.Slots) >= format.MaxSlots {
			return errors.New("vault: too many slots")
		}
		s, c, err := recoverySlot(t.hdr.VaultID, v.vmk())
		if err != nil {
			return err
		}
		t.hdr.Slots = append(t.hdr.Slots, s)
		code = secret.New([]byte(c))
		return nil
	})
	return code, err
}

// RemoveSlot removes a slot. It does not revoke the credential: anyone holding it
// and an old copy of the file still gets the master key. Use Rekey for that.
func (v *Vault) RemoveSlot(id string) error {
	return v.commit(audit.Event{Type: audit.EventSlotChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		if len(t.hdr.Slots) == 1 {
			return errors.New("vault: can't remove the last slot")
		}
		for i := range t.hdr.Slots {
			if hex.EncodeToString(t.hdr.Slots[i].ID[:]) == id {
				t.hdr.Slots = slices.Delete(t.hdr.Slots, i, i+1)
				return nil
			}
		}
		return errors.New("vault: no such slot")
	})
}

// RekeyOptions configures Rekey.
type RekeyOptions struct {
	Passphrase []byte
	Keyfile    []byte
	Profile    kdf.Profile
	// AcceptWeakPassphrase skips the passphrase policy.
	AcceptWeakPassphrase bool
	// KeepTokens keeps the verifier keys, for a routine rekey with no suspected
	// compromise. By default they rotate, which invalidates issued tokens.
	KeepTokens bool
	// ReissueMachine is how many new machine keys to create. Old ones are dropped.
	ReissueMachine int
	// Confirm receives the new credentials before the old file is replaced. If it
	// returns an error, nothing changes, so a crash can't lose them.
	Confirm func(RekeyResult) error
}

// RekeyResult holds the credentials created by Rekey.
type RekeyResult struct {
	RecoveryCode secret.Secret
	MachineKeys  []secret.Secret
}

// Rekey replaces the vault master key and re-encrypts every item. It is the only
// operation that ends access for old credentials. Copies of the old file still open
// with the old credentials. It marks every service as needing rotation.
func (v *Vault) Rekey(o RekeyOptions) error {
	if !o.AcceptWeakPassphrase {
		if err := password.CheckMaster(o.Passphrase); err != nil {
			return err
		}
	}
	if o.Confirm == nil {
		return errors.New("vault: a Rekey needs Confirm, so the new recovery code can't be lost")
	}
	if o.Profile == (kdf.Profile{}) {
		o.Profile = kdf.Default
	}
	return v.commit(audit.Event{Type: audit.EventRekey, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		newVMK, err := randomBytes(32)
		if err != nil {
			return err
		}
		defer clear(newVMK)
		mem, err := newKeyMem(newVMK, t.hdr.VaultID)
		if err != nil {
			return err
		}
		t.keys = mem

		ps, err := passphraseSlot(t.hdr.VaultID, newVMK, o.Passphrase, o.Keyfile, o.Profile.Params)
		if err != nil {
			return err
		}
		rs, code, err := recoverySlot(t.hdr.VaultID, newVMK)
		if err != nil {
			return err
		}
		t.hdr.Slots = []format.Slot{ps, rs}
		res := RekeyResult{RecoveryCode: secret.New([]byte(code))}
		for range o.ReissueMachine {
			s, k, err := newMachineSlot(t.hdr.VaultID, newVMK)
			if err != nil {
				return err
			}
			t.hdr.Slots = append(t.hdr.Slots, s)
			res.MachineKeys = append(res.MachineKeys, k)
		}

		for i := range t.m.Items {
			e := &t.m.Items[i]
			for j := range e.Versions {
				ver := &e.Versions[j]
				blob, err := v.resealItem(t, e, ver)
				if err != nil {
					return err
				}
				t.blobs[blobKey(e.ID, ver.Version)] = blob
				sum := sha256Sum(blob)
				ver.SHA256, ver.Length = sum, int64(len(blob))
			}
		}

		if err := rotateAudit(&t.m.Keys); err != nil {
			return err
		}
		if !o.KeepTokens {
			if err := rotateVerifier(&t.m.Keys, v.now(), 0); err != nil {
				return err
			}
		}
		for i := range t.m.Services {
			t.m.Services[i].NeedsRotation = true
		}
		t.before = func() error { return o.Confirm(res) }
		return nil
	})
}

func (v *Vault) resealItem(t *tx, e *itemEntry, ver *version) ([]byte, error) {
	old, ok := t.blobs[blobKey(e.ID, ver.Version)]
	if !ok {
		return nil, ErrTampered
	}
	ctx := itemContext(t.hdr.VaultID, e.ID, ver.Version)
	padded, err := envelope.Open(v.itemKey(), envelope.DomainItem, ctx, old)
	if err != nil {
		return nil, ErrTampered
	}
	defer clear(padded)
	return envelope.Seal(t.itemKey(v), envelope.DomainItem, ctx, padded)
}

func rotateVerifier(k *keySet, now time.Time, overlap time.Duration) error {
	key, err := randomBytes(keyLength)
	if err != nil {
		return err
	}
	retire := now.UTC().Add(overlap)
	var top uint32
	kept := k.TokenVerifier[:0]
	for _, old := range k.TokenVerifier {
		top = max(top, old.ID)
		if overlap == 0 {
			continue
		}
		if old.RetireAt == nil {
			old.RetireAt = &retire
		}
		if now.Before(*old.RetireAt) {
			kept = append(kept, old)
		}
	}
	k.TokenVerifier = append(kept, token.Key{ID: top + 1, Key: key})
	return nil
}

// RotateVerifierKey adds a new verifier key. Tokens under older keys keep working
// for the overlap period, and stop at once with an overlap of zero.
func (v *Vault) RotateVerifierKey(overlap time.Duration) error {
	if overlap < 0 {
		return errors.New("vault: overlap can't be negative")
	}
	return v.commit(audit.Event{Type: audit.EventKeyRotate, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		return rotateVerifier(&t.m.Keys, v.now(), overlap)
	})
}

// Tokens returns a token manager backed by this vault. A read-only vault can verify
// tokens, and it can't issue or revoke them.
func (v *Vault) Tokens(sink audit.Sink) (*token.Manager, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	if sink == nil {
		sink = v.sink
	}
	return token.New(token.Config{Keys: cloneTokenKeys(v.m.Keys.TokenVerifier), Store: &tokenStore{v: v}, Sink: sink, Now: v.now})
}

// ServiceTokens returns a token manager for one service's tokens. They use that
// service's verifier key, and reach it with the next sync.
func (v *Vault) ServiceTokens(name string, sink audit.Sink) (*token.Manager, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	def := v.m.service(name)
	if def == nil {
		return nil, ErrNotFound
	}
	if sink == nil {
		sink = v.sink
	}
	return token.New(token.Config{Keys: cloneTokenKeys(def.Keys.TokenVerifier), Store: &tokenStore{v: v, service: name}, Sink: sink, Now: v.now})
}

// ServiceTokenRecords lists one service's token records.
func (v *Vault) ServiceTokenRecords(name string) ([]token.Record, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	def := v.m.service(name)
	if def == nil {
		return nil, ErrNotFound
	}
	return slices.Clone(def.Tokens), nil
}

// TokenStore returns the store for this vault's own tokens.
func (v *Vault) TokenStore() token.Store { return &tokenStore{v: v} }

// VerifierKeys returns copies of the verifier keys, for a service that keeps its own
// token store.
func (v *Vault) VerifierKeys() []token.Key {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return cloneTokenKeys(v.m.Keys.TokenVerifier)
}

// tokenStore keeps records in the manifest, where revocation is authenticated.
type tokenStore struct {
	v       *Vault
	service string
}

func (s *tokenStore) records(m *manifest) *[]token.Record {
	if s.service == "" {
		return &m.Tokens
	}
	if d := m.service(s.service); d != nil {
		return &d.Tokens
	}
	return nil
}

// Get implements token.Store.
func (s *tokenStore) Get(_ context.Context, id token.ID) (token.Record, error) {
	s.v.mu.RLock()
	defer s.v.mu.RUnlock()
	if s.v.closed {
		return token.Record{}, ErrClosed
	}
	list := s.records(s.v.m)
	if list == nil {
		return token.Record{}, token.ErrNotFound
	}
	for _, r := range *list {
		if string(r.ID) == string(id[:]) {
			return r, nil
		}
	}
	return token.Record{}, token.ErrNotFound
}

// Put implements token.Store.
func (s *tokenStore) Put(_ context.Context, r token.Record) error {
	if s.v.readOnly {
		return token.ErrReadOnly
	}
	return s.v.commit(audit.Event{Type: audit.EventTokenStore, Outcome: audit.OK, Actor: s.v.actor}, func(t *tx) error {
		list := s.records(t.m)
		if list == nil {
			return ErrNotFound
		}
		for i := range *list {
			if string((*list)[i].ID) == string(r.ID) {
				(*list)[i] = r
				return nil
			}
		}
		*list = append(*list, r)
		return nil
	})
}

// List implements token.Store.
func (s *tokenStore) List(context.Context) ([]token.Record, error) {
	s.v.mu.RLock()
	defer s.v.mu.RUnlock()
	if s.v.closed {
		return nil, ErrClosed
	}
	list := s.records(s.v.m)
	if list == nil {
		return nil, nil
	}
	return slices.Clone(*list), nil
}

// ExpiringTokens lists stored third-party tokens that expire within d.
func (v *Vault) ExpiringTokens(d time.Duration) ([]Metadata, error) {
	all, err := v.List()
	if err != nil {
		return nil, err
	}
	limit := v.now().Add(d)
	var out []Metadata
	for _, m := range all {
		if m.Expires != nil && m.Expires.Before(limit) {
			out = append(out, m)
		}
	}
	return out, nil
}

// ResetLocalState forgets this device's record of a vault.
func ResetLocalState(stateDir string, id [format.IDSize]byte) error {
	return (&state.File{Dir: stateDir}).Reset(id)
}

// VaultIDFromFile reads a vault's ID without unlocking it. The value isn't
// authenticated.
func VaultIDFromFile(path string) ([format.IDSize]byte, error) {
	data, err := fsutil.ReadFile(path, format.MaxFileSize, fsutil.Policy{})
	if err != nil {
		return [format.IDSize]byte{}, err
	}
	h, _, err := format.Parse(data)
	if err != nil {
		return [format.IDSize]byte{}, fmt.Errorf("vault: %w", ErrTampered)
	}
	return h.VaultID, nil
}
