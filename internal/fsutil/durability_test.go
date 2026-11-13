package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLockTimesOut(t *testing.T) {
	saved := lockTimeout
	lockTimeout = 200 * time.Millisecond
	t.Cleanup(func() { lockTimeout = saved })
	p := filepath.Join(t.TempDir(), "lock")
	held, err := AcquireLock(p, false)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	start := time.Now()
	if _, err := AcquireLock(p, true); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the wait ignored its deadline")
	}
}

func TestLockWaitsForRelease(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	held, err := AcquireLock(p, false)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		held.Release()
	}()
	l, err := AcquireLock(p, false)
	if err != nil {
		t.Fatalf("waiting for a released lock: %v", err)
	}
	l.Release()
}

func TestEnsurePrivateDir(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "a", "b", "c")
	if err := EnsurePrivateDir(nested); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b"), nested} {
		st, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %o", d, st.Mode().Perm())
		}
	}
	if err := EnsurePrivateDir(nested); err != nil {
		t.Errorf("existing directory: %v", err)
	}
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(open); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("world-writable directory: %v", err)
	}
	file := filepath.Join(base, "file")
	write(t, file, 0o600)
	if err := EnsurePrivateDir(file); !errors.Is(err, ErrUnsafeFile) {
		t.Errorf("a file: %v", err)
	}
}
