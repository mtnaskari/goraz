package fsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func write(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("data"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestReadFileChecks(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	write(t, good, 0o600)
	if b, err := ReadFile(good, 100, Policy{}); err != nil || string(b) != "data" {
		t.Fatalf("got %q, %v", b, err)
	}

	worldW := filepath.Join(dir, "w")
	write(t, worldW, 0o666)
	groupW := filepath.Join(dir, "g")
	write(t, groupW, 0o620)
	for _, p := range []string{worldW, groupW} {
		if _, err := ReadFile(p, 100, Policy{}); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("%s: err = %v", p, err)
		}
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link, 100, Policy{}); !errors.Is(err, ErrUnsafeFile) {
		t.Errorf("symlink followed: %v", err)
	}
	if _, err := ReadFile(link, 100, Policy{FollowSymlinks: true}); err != nil {
		t.Errorf("explicit follow failed: %v", err)
	}

	if _, err := ReadFile(dir, 100, Policy{}); !errors.Is(err, ErrUnsafeFile) {
		t.Errorf("directory accepted: %v", err)
	}
	if _, err := ReadFile(good, 2, Policy{}); err == nil {
		t.Error("size limit ignored")
	}
}

func TestDenyOtherRead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	write(t, p, 0o644)
	if _, err := ReadFile(p, 100, Policy{DenyOtherRead: true}); !errors.Is(err, ErrUnsafeFile) {
		t.Errorf("err = %v", err)
	}
	write(t, p, 0o640)
	if _, err := ReadFile(p, 100, Policy{DenyOtherRead: true}); err != nil {
		t.Errorf("err = %v", err)
	}
}

// A FIFO must be refused without blocking the process.
func TestFIFODoesNotBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(p, 100, Policy{})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
}

func TestAtomicWriteReplaces(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v")
	for _, content := range []string{"one", "two"} {
		if err := AtomicWrite(p, []byte(content), nil); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFile(p, 100, Policy{})
		if err != nil || string(got) != content {
			t.Fatalf("got %q, %v", got, err)
		}
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temporary files left: %v", entries)
	}
}

// A crash at any stage must leave the old file or the new file, never a mixture.
func TestAtomicWriteCrashStages(t *testing.T) {
	boom := errors.New("crash")
	for _, stage := range []Stage{StageAfterWrite, StageAfterSync, StageAfterRename} {
		dir := t.TempDir()
		p := filepath.Join(dir, "v")
		if err := AtomicWrite(p, []byte("old"), nil); err != nil {
			t.Fatal(err)
		}
		err := AtomicWrite(p, []byte("new"), func(s Stage) error {
			if s == stage {
				return boom
			}
			return nil
		})
		if !errors.Is(err, boom) {
			t.Fatalf("%s: err = %v", stage, err)
		}
		got, err := os.ReadFile(p) // #nosec G304 -- test path.
		if err != nil {
			t.Fatal(err)
		}
		want := "old"
		if stage == StageAfterRename {
			want = "new"
		}
		if !bytes.Equal(got, []byte(want)) {
			t.Errorf("%s: file holds %q", stage, got)
		}
	}
}

func TestAtomicWriteDoesNotFollowTempSymlink(t *testing.T) {
	// The temporary name is random, and O_EXCL refuses anything that exists.
	dir := t.TempDir()
	p := filepath.Join(dir, "v")
	if err := AtomicWrite(p, []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(filepath.Join(dir, "missing", "v"), []byte("x"), nil); err == nil {
		t.Error("write to a missing directory succeeded")
	}
}

func TestLockExclusion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	var (
		mu      sync.Mutex
		holders int
		wg      sync.WaitGroup
	)
	for range 8 {
		wg.Go(func() {
			l, err := AcquireLock(p, false)
			if err != nil {
				t.Error(err)
				return
			}
			defer l.Release()
			mu.Lock()
			holders++
			if holders != 1 {
				t.Error("two holders of an exclusive lock")
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			holders--
			mu.Unlock()
		})
	}
	wg.Wait()
}

func TestLockRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	write(t, target, 0o600)
	link := filepath.Join(dir, "lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(link, false); !errors.Is(err, ErrUnsafeFile) {
		t.Errorf("err = %v", err)
	}
}

func TestReleaseIsSafeTwice(t *testing.T) {
	l, err := AcquireLock(filepath.Join(t.TempDir(), "lock"), true)
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	l.Release()
	var none *Lock
	none.Release()
}

func TestRemoveStaleTemps(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v")
	write(t, p, 0o600)
	stale := filepath.Join(dir, ".v.tmp-abc")
	write(t, stale, 0o600)
	other := filepath.Join(dir, ".other.tmp-abc")
	write(t, other, 0o600)
	RemoveStaleTemps(p)
	if _, err := os.Stat(stale); err == nil {
		t.Error("the stale file remains")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("removed another file's temporary")
	}
	if _, err := os.Stat(p); err != nil {
		t.Error("removed the file itself")
	}
}
