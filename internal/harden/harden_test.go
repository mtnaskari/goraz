package harden

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLockedLifecycle(t *testing.T) {
	l := NewLocked(32)
	b := l.Bytes()
	if len(b) != 32 {
		t.Fatalf("len %d", len(b))
	}
	for _, x := range b {
		if x != 0 {
			t.Fatal("not zeroed")
		}
	}
	b[0] = 1
	l.Close()
	if l.Bytes() != nil {
		t.Error("Close kept the slice")
	}
	l.Close()
	var none *Locked
	none.Close()
}

func TestProcessDisablesCoreDumps(t *testing.T) {
	Process()
	s := Status()
	if !s.CoreDumpsDisabled {
		t.Error("core dumps still enabled")
	}
	if s.Platform == "" {
		t.Error("platform missing")
	}
}

func TestRestoreBeforeExec(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &before); err != nil {
		t.Fatal(err)
	}
	if before.Max == 0 {
		t.Skip("the hard limit is already zero")
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 1, Max: before.Max}); err != nil {
		t.Skip("can't set the limit here")
	}
	Process()
	RestoreBeforeExec()
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &after); err != nil {
		t.Fatal(err)
	}
	if after.Cur != 1 {
		t.Errorf("limit not restored: %d", after.Cur)
	}
	Process()
}

func TestSecretDoRuns(t *testing.T) {
	ran := false
	SecretDo(func() { ran = true })
	if !ran {
		t.Error("function did not run")
	}
}
