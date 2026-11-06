// Package audit records what goraz did without recording any secret. Events are
// typed: they have no free-form field, no error text and no value field, which
// makes accidental secret logging structurally difficult.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// EventType names an action.
type EventType string

// The allowed events. A value outside this list is refused.
const (
	EventVaultCreate    EventType = "vault.create"
	EventVaultOpen      EventType = "vault.open"
	EventItemRead       EventType = "item.read"
	EventItemWrite      EventType = "item.write"
	EventItemDelete     EventType = "item.delete"
	EventItemDestroy    EventType = "item.destroy"
	EventItemRestore    EventType = "item.restore"
	EventItemExport     EventType = "item.export"
	EventSlotChange     EventType = "slot.change"
	EventRekey          EventType = "vault.rekey"
	EventSettingChange  EventType = "setting.change"
	EventRollbackAccept EventType = "state.accept_rollback"
	EventForkAccept     EventType = "state.accept_fork"
	EventTokenIssue     EventType = "token.issue"
	EventTokenVerify    EventType = "token.verify"
	EventTokenRevoke    EventType = "token.revoke"
	EventTokenRotate    EventType = "token.rotate"
	EventTokenStore     EventType = "token.store"
	EventKeyRotate      EventType = "key.rotate"
	EventServiceChange  EventType = "service.change"
	EventAuditGap       EventType = "audit.gap"
)

var knownEvents = map[EventType]bool{
	EventVaultCreate: true, EventVaultOpen: true, EventItemRead: true, EventItemWrite: true,
	EventItemDelete: true, EventItemDestroy: true, EventItemRestore: true, EventItemExport: true,
	EventSlotChange: true, EventRekey: true, EventSettingChange: true, EventRollbackAccept: true,
	EventForkAccept: true, EventTokenIssue: true, EventTokenVerify: true, EventTokenRevoke: true,
	EventTokenRotate: true, EventTokenStore: true, EventKeyRotate: true, EventServiceChange: true, EventAuditGap: true,
}

// Outcome is the result of an action.
type Outcome string

// Outcomes.
const (
	OK     Outcome = "ok"
	Denied Outcome = "denied"
	Failed Outcome = "failed"
)

// Actor is the kind of credential behind an action.
type Actor string

// Actors.
const (
	ActorPassphrase Actor = "passphrase"
	ActorRecovery   Actor = "recovery"
	ActorMachine    Actor = "machine"
	ActorToken      Actor = "token"
	ActorSystem     Actor = "system"
)

// MaxObjectSize limits Event.Object. It holds an HMAC or a public token ID, so a
// secret of ordinary size can't fit by accident without being an obvious bug.
const MaxObjectSize = 32

// Event is one audited action.
type Event struct {
	Type    EventType
	Outcome Outcome
	Actor   Actor
	// Object is an HMAC of an item name, or a public token ID. Never a value.
	Object []byte
}

// Validate refuses anything outside the closed lists.
func (e Event) Validate() error {
	if !knownEvents[e.Type] {
		return errors.New("audit: unknown event type")
	}
	switch e.Outcome {
	case OK, Denied, Failed:
	default:
		return errors.New("audit: unknown outcome")
	}
	switch e.Actor {
	case ActorPassphrase, ActorRecovery, ActorMachine, ActorToken, ActorSystem:
	default:
		return errors.New("audit: unknown actor")
	}
	if len(e.Object) > MaxObjectSize {
		return errors.New("audit: object is too long")
	}
	return nil
}

// Sink receives events. A sink that fails must return an error, so that the
// caller can refuse to release a secret.
type Sink interface {
	Record(Event) error
}

// Discard is a Sink that drops every event. Using it must be an explicit choice.
var Discard Sink = discard{}

type discard struct{}

func (discard) Record(e Event) error { return e.Validate() }

// ObjectHash returns the value logged in place of an item name.
func ObjectHash(key []byte, name string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("goraz/v1/audit/object\x00"))
	h.Write([]byte(name))
	return h.Sum(nil)
}

// JSONSink writes one typed JSON event per line. It is meant for containers that
// send logs to stdout. It has no hash chain, so integrity depends on the log
// system that receives the stream.
type JSONSink struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

// NewJSONSink returns a sink writing to w.
func NewJSONSink(w io.Writer) *JSONSink { return &JSONSink{w: w, now: time.Now} }

type jsonEvent struct {
	Time    time.Time `json:"time"`
	Event   EventType `json:"event"`
	Outcome Outcome   `json:"outcome"`
	Actor   Actor     `json:"actor"`
	Object  string    `json:"object,omitempty"`
}

// Record implements Sink.
func (s *JSONSink) Record(e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(jsonEvent{
		Time: s.now().UTC(), Event: e.Type, Outcome: e.Outcome, Actor: e.Actor,
		Object: hex.EncodeToString(e.Object),
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("audit: writing event: %w", err)
	}
	return nil
}
