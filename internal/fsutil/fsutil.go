// Package fsutil holds the only code that opens goraz's own files. It checks the
// open descriptor rather than the path, which closes the gap between a check and
// a use, and it never follows a symlink unless a caller explicitly reads a
// read-only input.
//
// Only macOS and Linux are supported in v0.1.
package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ErrUnsafeFile is returned when a file's type, owner or mode is unsafe.
var ErrUnsafeFile = errors.New("fsutil: file is unsafe: it must be a regular file owned by you, and not writable by others")

// Policy says which files are acceptable.
type Policy struct {
	// FollowSymlinks allows the final path element to be a symlink. It is used
	// only for read-only inputs whose contents are authenticated or whose path
	// is chosen by a deployment, such as Kubernetes secret mounts.
	FollowSymlinks bool
	// AllowRootOwner also accepts files owned by root.
	AllowRootOwner bool
	// DenyOtherRead also refuses files readable by others.
	DenyOtherRead bool
}

func checkFd(fd int, p Policy) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrUnsafeFile
	}
	uid := uint32(os.Geteuid()) // #nosec G115 -- a uid always fits.
	if st.Uid != uid && (!p.AllowRootOwner || st.Uid != 0) {
		return ErrUnsafeFile
	}
	if st.Mode&0o022 != 0 {
		return ErrUnsafeFile
	}
	if p.DenyOtherRead && st.Mode&0o004 != 0 {
		return ErrUnsafeFile
	}
	return nil
}

// ReadFile reads a file with a size limit after checking the open descriptor.
func ReadFile(path string, limit int64, p Policy) ([]byte, error) {
	flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC
	if !p.FollowSymlinks {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
			return nil, ErrUnsafeFile
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path) // #nosec G115 -- fd is non-negative here.
	defer func() { _ = f.Close() }()
	if err := checkFd(fd, p); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("fsutil: file exceeds the size limit")
	}
	return b, nil
}

// Lock is an advisory lock on a dedicated lock file.
type Lock struct{ f *os.File }

// AcquireLock takes a lock, creating the lock file if needed. shared selects a
// shared lock. Locks are advisory and apply only on one host.
func AcquireLock(path string, shared bool) (*Lock, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
			return nil, ErrUnsafeFile
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path) // #nosec G115 -- fd is non-negative here.
	if err := checkFd(fd, Policy{}); err != nil {
		_ = f.Close()
		return nil, err
	}
	how := unix.LOCK_EX
	if shared {
		how = unix.LOCK_SH
	}
	for {
		err = unix.Flock(fd, how)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN) // #nosec G115 -- fd fits an int.
	_ = l.f.Close()
	l.f = nil
}

// Stage names a point inside AtomicWrite, for fault injection in tests.
type Stage string

// Stages of AtomicWrite, in order.
const (
	StageAfterWrite  Stage = "after-write"
	StageAfterSync   Stage = "after-sync"
	StageAfterRename Stage = "after-rename"
)

// Hook is called at each stage. A returned error aborts the write as a crash
// would at that point: no cleanup runs after StageAfterRename.
type Hook func(Stage) error

// AtomicWrite replaces path with data: a temporary file in the same directory is
// written with mode 0600 and fsynced, renamed into place, and then the directory
// is fsynced. A reader sees the old file or the new file, never a mixture.
func AtomicWrite(path string, data []byte, hook Hook) (err error) {
	if hook == nil {
		hook = func(Stage) error { return nil }
	}
	dir := filepath.Dir(path)
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(suffix[:]))
	fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "create", Path: tmp, Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp) // #nosec G115 -- fd is non-negative here.
	renamed := false
	defer func() {
		if !renamed {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := hook(StageAfterWrite); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := hook(StageAfterSync); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	renamed = true
	if err := hook(StageAfterRename); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so that a rename survives a crash.
func SyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the directory of a file goraz is writing.
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		// Some filesystems don't support directory fsync. The rename itself has
		// still happened, so this isn't treated as a failed write.
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return nil
		}
		return fmt.Errorf("fsutil: syncing directory: %w", err)
	}
	return nil
}

// EnsurePrivateDir creates dir with mode 0700 if it doesn't exist.
func EnsurePrivateDir(dir string) error {
	return os.MkdirAll(dir, 0o700)
}
