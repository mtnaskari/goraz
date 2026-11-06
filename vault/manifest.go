package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/internal/names"
	"github.com/mtnaskari/goraz/internal/state"
	"github.com/mtnaskari/goraz/token"
)

type auditKey struct {
	ID     uint32 `json:"id"`
	Key    []byte `json:"key"`
	Active bool   `json:"active"`
}

type keySet struct {
	State         []byte      `json:"state"`
	TokenVerifier []token.Key `json:"token_verifier"`
	Audit         []auditKey  `json:"audit"`
}

type version struct {
	Version uint32    `json:"version"`
	Length  int64     `json:"length"`
	SHA256  []byte    `json:"sha256"`
	Created time.Time `json:"created"`
}

type itemEntry struct {
	ID       []byte     `json:"id"`
	Name     string     `json:"name"`
	Type     ItemType   `json:"type"`
	Tags     []string   `json:"tags,omitempty"`
	Created  time.Time  `json:"created"`
	Updated  time.Time  `json:"updated"`
	Expires  *time.Time `json:"expires,omitempty"`
	Deleted  *time.Time `json:"deleted,omitempty"`
	Versions []version  `json:"versions"`
}

// serviceDef is the full state of one service vault, so that a sync works from any
// device that can open the main vault.
type serviceDef struct {
	Name          string          `json:"name"`
	Prefixes      []string        `json:"prefixes"`
	VaultID       []byte          `json:"vault_id"`
	Generation    uint64          `json:"generation"`
	LastHash      []byte          `json:"last_hash,omitempty"`
	Lineage       []state.Lineage `json:"lineage,omitempty"`
	VMK           []byte          `json:"vmk"`
	SlotID        []byte          `json:"slot_id"`
	MachineSecret []byte          `json:"machine_secret"`
	Keys          keySet          `json:"keys"`
	Tokens        []token.Record  `json:"tokens,omitempty"`
	ValidFor      int64           `json:"valid_for_seconds,omitempty"`
	NeedsRotation bool            `json:"needs_rotation,omitempty"`
	Created       time.Time       `json:"created"`
}

type manifest struct {
	Created       time.Time               `json:"created"`
	AuditRequired bool                    `json:"audit_required"`
	ValidUntil    *time.Time              `json:"valid_until,omitempty"`
	Keys          keySet                  `json:"keys"`
	Lineage       []state.Lineage         `json:"lineage,omitempty"`
	AuditAnchors  map[string]audit.Anchor `json:"audit_anchors,omitempty"`
	Items         []itemEntry             `json:"items"`
	Tokens        []token.Record          `json:"tokens,omitempty"`
	Services      []serviceDef            `json:"services,omitempty"`
}

const (
	maxLineage     = 32
	maxAnchors     = 64
	maxVersions    = 10
	maxItemTags    = 32
	maxServices    = 256
	maxTagLength   = 64
	keyLength      = 32
	hashLength     = 32
	maxPrefixCount = 32
)

// decodeManifest parses authenticated bytes. It still validates everything, so a
// bug or a holder of the key can't cause inconsistent state or a crash later.
func decodeManifest(b []byte) (*manifest, error) {
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, errBadManifest
	}
	if dec.More() {
		return nil, errBadManifest
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

var errBadManifest = errors.New("vault: invalid manifest")

func validKeys(k *keySet) bool {
	if len(k.State) != keyLength || len(k.TokenVerifier) == 0 || len(k.Audit) == 0 {
		return false
	}
	active := 0
	for _, a := range k.Audit {
		if len(a.Key) != keyLength {
			return false
		}
		if a.Active {
			active++
		}
	}
	for _, v := range k.TokenVerifier {
		if len(v.Key) != keyLength {
			return false
		}
	}
	return active == 1
}

func validLineage(l []state.Lineage) bool {
	if len(l) > maxLineage {
		return false
	}
	for _, e := range l {
		if len(e.SHA256) != hashLength {
			return false
		}
	}
	return true
}

func (m *manifest) validate() error {
	if !validKeys(&m.Keys) || !validLineage(m.Lineage) || len(m.AuditAnchors) > maxAnchors || len(m.Services) > maxServices {
		return errBadManifest
	}
	ids := make(map[string]bool, len(m.Items))
	seen := make(map[string]bool, len(m.Items))
	for i := range m.Items {
		it := &m.Items[i]
		if len(it.ID) != format.IDSize || names.Validate(it.Name) != nil || !it.Type.valid() {
			return errBadManifest
		}
		fold := names.FoldKey(it.Name)
		if ids[string(it.ID)] || seen[fold] || len(it.Versions) == 0 || len(it.Versions) > maxVersions || len(it.Tags) > maxItemTags {
			return errBadManifest
		}
		ids[string(it.ID)] = true
		seen[fold] = true
		var last uint32
		for _, v := range it.Versions {
			if v.Version <= last || v.Length <= 0 || v.Length > format.MaxFileSize || len(v.SHA256) != hashLength {
				return errBadManifest
			}
			last = v.Version
		}
	}
	svc := make(map[string]bool, len(m.Services))
	for i := range m.Services {
		s := &m.Services[i]
		if svc[s.Name] || names.Validate(s.Name) != nil || len(s.VaultID) != format.IDSize || len(s.SlotID) != format.IDSize ||
			len(s.VMK) != keyLength || len(s.MachineSecret) != keyLength || !validKeys(&s.Keys) || !validLineage(s.Lineage) ||
			len(s.Prefixes) == 0 || len(s.Prefixes) > maxPrefixCount {
			return errBadManifest
		}
		svc[s.Name] = true
		for _, p := range s.Prefixes {
			if names.Validate(p) != nil {
				return errBadManifest
			}
		}
	}
	return nil
}

func (k *keySet) wipe() {
	clear(k.State)
	for i := range k.TokenVerifier {
		clear(k.TokenVerifier[i].Key)
	}
	for i := range k.Audit {
		clear(k.Audit[i].Key)
	}
}

// wipe clears the key material a manifest holds. It is best effort: see section 10
// of the security design.
func (m *manifest) wipe() {
	m.Keys.wipe()
	for i := range m.Services {
		s := &m.Services[i]
		clear(s.VMK)
		clear(s.MachineSecret)
		s.Keys.wipe()
	}
}

func cloneTokenKeys(in []token.Key) []token.Key {
	out := make([]token.Key, len(in))
	for i, k := range in {
		k.Key = bytes.Clone(k.Key)
		out[i] = k
	}
	return out
}

func (m *manifest) clone() (*manifest, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	var c manifest
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (m *manifest) find(name string) *itemEntry {
	for i := range m.Items {
		if m.Items[i].Name == name {
			return &m.Items[i]
		}
	}
	return nil
}

func (m *manifest) service(name string) *serviceDef {
	for i := range m.Services {
		if m.Services[i].Name == name {
			return &m.Services[i]
		}
	}
	return nil
}

func (m *manifest) auditKeys() audit.Keys {
	k := audit.Keys{All: make(map[uint32][]byte, len(m.Keys.Audit))}
	for _, a := range m.Keys.Audit {
		k.All[a.ID] = a.Key
		if a.Active {
			k.Active = a.ID
		}
	}
	return k
}

func (m *manifest) activeAuditKey() []byte {
	for _, a := range m.Keys.Audit {
		if a.Active {
			return a.Key
		}
	}
	return nil
}
