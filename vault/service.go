package vault

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"slices"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/envelope"
	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/internal/fsutil"
	"github.com/mtnaskari/goraz/internal/names"
	"github.com/mtnaskari/goraz/internal/state"
	"github.com/mtnaskari/goraz/internal/tokfmt"
	"github.com/mtnaskari/goraz/secret"
)

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// ServiceOptions configures a service vault.
type ServiceOptions struct {
	Prefixes []string
	// ValidFor writes an authenticated expiry into each service file. It needs a
	// scheduled sync. Without it, only a token's TTL limits how long a revoked token
	// can keep working if someone holds back the file.
	ValidFor time.Duration
	// SaveKey stores the new machine key before anything is committed. If it fails,
	// nothing changes, so a key can't be lost. It may be nil if the caller takes the
	// returned key instead.
	SaveKey func(key []byte) error
}

// ServiceInfo describes a service.
type ServiceInfo struct {
	Name          string
	Prefixes      []string
	Generation    uint64
	Tokens        int
	NeedsRotation bool
	ValidFor      time.Duration
}

// Services lists the services.
func (v *Vault) Services() []ServiceInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]ServiceInfo, 0, len(v.m.Services))
	for i := range v.m.Services {
		s := &v.m.Services[i]
		out = append(out, ServiceInfo{
			Name: s.Name, Prefixes: slices.Clone(s.Prefixes), Generation: s.Generation, Tokens: len(s.Tokens),
			NeedsRotation: s.NeedsRotation, ValidFor: time.Duration(s.ValidFor) * time.Second,
		})
	}
	return out
}

func newServiceSecrets(d *serviceDef) (secret.Secret, error) {
	vmk, err := randomBytes(keyLength)
	if err != nil {
		return secret.Secret{}, err
	}
	slotID, err := randomBytes(format.IDSize)
	if err != nil {
		return secret.Secret{}, err
	}
	sec, err := randomBytes(tokfmt.SecretSize)
	if err != nil {
		return secret.Secret{}, err
	}
	keys, err := newKeySet()
	if err != nil {
		return secret.Secret{}, err
	}
	tok, err := tokfmt.Encode(tokfmt.DefaultPrefix, tokfmt.KindMachine, slotID, sec)
	if err != nil {
		return secret.Secret{}, err
	}
	d.VMK, d.SlotID, d.MachineSecret, d.Keys = vmk, slotID, sec, keys
	return secret.Adopt(tok), nil
}

// buildService produces the bytes of a service file and advances its state in def.
// It only reads the latest version of items below the service's prefixes.
func (v *Vault) buildService(t *tx, def *serviceDef) ([]byte, error) {
	var id [format.IDSize]byte
	copy(id[:], def.VaultID)
	mem, err := newKeyMem(def.VMK, id)
	if err != nil {
		return nil, err
	}
	defer mem.Close()

	now := v.now().UTC()
	child := &manifest{
		Created: def.Created, AuditRequired: true, Keys: def.Keys,
		Lineage: slices.Clone(def.Lineage), Tokens: slices.Clone(def.Tokens), Items: []itemEntry{},
	}
	if def.ValidFor > 0 {
		until := now.Add(time.Duration(def.ValidFor) * time.Second)
		child.ValidUntil = &until
	}
	if def.Generation > 0 {
		child.Lineage = append(child.Lineage, state.Lineage{Generation: def.Generation, SHA256: slices.Clone(def.LastHash)})
		if len(child.Lineage) > maxLineage {
			child.Lineage = child.Lineage[len(child.Lineage)-maxLineage:]
		}
	}
	blobs := make(map[string][]byte)
	for i := range t.m.Items {
		e := &t.m.Items[i]
		if e.Deleted != nil || !matchesAny(e.Name, def.Prefixes) {
			continue
		}
		last := &e.Versions[len(e.Versions)-1]
		parent, ok := t.blobs[blobKey(e.ID, last.Version)]
		if !ok || subtleHashMismatch(parent, last.SHA256) {
			return nil, ErrTampered
		}
		padded, err := envelope.Open(v.itemKey(), envelope.DomainItem, itemContext(t.hdr.VaultID, e.ID, last.Version), parent)
		if err != nil {
			return nil, ErrTampered
		}
		blob, err := envelope.Seal(mem.Bytes()[64:96], envelope.DomainItem, itemContext(id, e.ID, last.Version), padded)
		clear(padded)
		if err != nil {
			return nil, err
		}
		blobs[blobKey(e.ID, last.Version)] = blob
		child.Items = append(child.Items, itemEntry{
			ID: slices.Clone(e.ID), Name: e.Name, Type: e.Type, Tags: slices.Clone(e.Tags),
			Created: e.Created, Updated: e.Updated, Expires: e.Expires,
			Versions: []version{{Version: last.Version, Length: int64(len(blob)), SHA256: sha256Sum(blob), Created: last.Created}},
		})
	}
	slot, err := machineSlot(id, def.VMK, def.SlotID, def.MachineSecret)
	if err != nil {
		return nil, err
	}
	if err := child.validate(); err != nil {
		return nil, ErrLimit
	}
	h := format.Header{VaultID: id, Generation: def.Generation + 1, Slots: []format.Slot{slot}}
	file, err := assemble(&h, child, mem.Bytes()[32:64], blobs)
	if err != nil {
		return nil, err
	}
	def.Lineage = child.Lineage
	def.Generation = h.Generation
	def.LastHash = sha256Sum(file)
	return file, nil
}

func subtleHashMismatch(b, want []byte) bool {
	return subtle.ConstantTimeCompare(sha256Sum(b), want) != 1
}

func matchesAny(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if names.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// writeServiceFile runs after the main vault has committed. If a crash happens first,
// the next sync uses a later generation whose lineage still contains the last
// delivered file, so running services accept it.
func writeServiceFile(out string, file []byte) error {
	return fsutil.AtomicWrite(out, file, nil)
}

// CreateService adds a service and writes its file to out. The path isn't stored.
// The returned machine key is shown once.
func (v *Vault) CreateService(name, out string, o ServiceOptions) (secret.Secret, error) {
	if err := names.Validate(name); err != nil {
		return secret.Secret{}, err
	}
	if len(o.Prefixes) == 0 || len(o.Prefixes) > maxPrefixCount {
		return secret.Secret{}, fmt.Errorf("%w: a service needs at least one prefix", ErrInvalidInput)
	}
	for _, p := range o.Prefixes {
		if err := names.Validate(p); err != nil {
			return secret.Secret{}, err
		}
	}
	if o.ValidFor < 0 {
		return secret.Secret{}, fmt.Errorf("%w: a validity window can't be negative", ErrInvalidInput)
	}
	var key secret.Secret
	var file []byte
	err := v.commit(audit.Event{Type: audit.EventServiceChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		if t.m.service(name) != nil {
			return ErrExists
		}
		if len(t.m.Services) >= maxServices {
			return ErrLimit
		}
		vaultID, err := randomBytes(format.IDSize)
		if err != nil {
			return err
		}
		def := serviceDef{
			Name: name, Prefixes: slices.Clone(o.Prefixes), VaultID: vaultID, Created: v.now().UTC(),
			ValidFor: int64(o.ValidFor / time.Second),
		}
		key, err = newServiceSecrets(&def)
		if err != nil {
			return err
		}
		file, err = v.buildService(t, &def)
		if err != nil {
			return err
		}
		t.m.Services = append(t.m.Services, def)
		if o.SaveKey != nil {
			t.before = func() error { return o.SaveKey(key.Bytes()) }
		}
		return nil
	})
	if err != nil {
		return secret.Secret{}, err
	}
	// The key is returned even if this write fails, and a sync can produce the file.
	return key, writeServiceFile(out, file)
}

// SyncService writes a fresh service file to out. It refuses a service whose key may
// be exposed.
func (v *Vault) SyncService(name, out string) error {
	var file []byte
	err := v.commit(audit.Event{Type: audit.EventServiceChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		def := t.m.service(name)
		if def == nil {
			return ErrNotFound
		}
		if def.NeedsRotation {
			return ErrNeedsRotation
		}
		var err error
		file, err = v.buildService(t, def)
		return err
	})
	if err != nil {
		return err
	}
	return writeServiceFile(out, file)
}

// RotateService gives a service a new master key, machine key, audit key, state key
// and verifier key. It is the only way to revoke a leaked service key. Tokens issued
// for this service stop working, because a compromise means they should. saveKey may
// be nil. If it's given and fails, nothing changes.
func (v *Vault) RotateService(name, out string, saveKey func(key []byte) error) (secret.Secret, error) {
	var key secret.Secret
	var file []byte
	err := v.commit(audit.Event{Type: audit.EventServiceChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		def := t.m.service(name)
		if def == nil {
			return ErrNotFound
		}
		var err error
		key, err = newServiceSecrets(def)
		if err != nil {
			return err
		}
		def.Tokens = nil
		def.NeedsRotation = false
		file, err = v.buildService(t, def)
		if err != nil {
			return err
		}
		if saveKey != nil {
			t.before = func() error { return saveKey(key.Bytes()) }
		}
		return nil
	})
	if err != nil {
		return secret.Secret{}, err
	}
	// The key is returned even if this write fails, and a sync can produce the file.
	return key, writeServiceFile(out, file)
}

// RemoveService forgets a service. Files already delivered stay readable with their
// key.
func (v *Vault) RemoveService(name string) error {
	return v.commit(audit.Event{Type: audit.EventServiceChange, Outcome: audit.OK, Actor: v.actor}, func(t *tx) error {
		for i := range t.m.Services {
			if t.m.Services[i].Name == name {
				t.m.Services = slices.Delete(t.m.Services, i, i+1)
				return nil
			}
		}
		return ErrNotFound
	})
}
