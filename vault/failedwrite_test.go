package vault

import (
	"errors"
	"testing"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/fsutil"
	"github.com/mtnaskari/goraz/secret"
)

// A write that fails after its audit entry must be followed by a "failed" entry, so
// the log never shows a change that didn't happen as if it had.
func TestFailedWriteIsAudited(t *testing.T) {
	e, v := newEnv(t)
	v.Close()
	boom := errors.New("crash")
	w, err := Open(e.path, WithPassphrase([]byte(testPass), nil), Options{StateDir: e.stateDir, hook: func(s fsutil.Stage) error {
		if s == fsutil.StageAfterWrite {
			return boom
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Put(&Item{Name: "a", Value: secret.New([]byte("x"))}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	entries, err := w.ReadAudit()
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if last.Type != audit.EventItemWrite || last.Outcome != audit.Failed {
		t.Errorf("last entry %+v", last)
	}
}
