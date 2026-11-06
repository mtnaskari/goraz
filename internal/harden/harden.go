// Package harden applies best-effort process and memory protections. None of them
// is a guarantee. See docs/security-design.md, section 10.
package harden

import (
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Report describes the protections that are actually active.
type Report struct {
	CoreDumpsDisabled bool
	NotDumpable       bool // Linux only.
	MemoryLocked      bool
	SecretMode        bool
	Platform          string
}

var (
	savedCore    unix.Rlimit
	coreSaved    bool
	lockedMemory atomic.Bool
)

// Process disables core dumps. It should be called early in main.
func Process() {
	var cur unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &cur); err == nil {
		savedCore, coreSaved = cur, true
	}
	// Only the soft limit is lowered, so RestoreBeforeExec can put it back.
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: cur.Max})
	platformProcess()
}

// RestoreBeforeExec restores the core limit before starting another program, so that
// the limit doesn't silently apply to it.
func RestoreBeforeExec() {
	if !coreSaved {
		return
	}
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &savedCore)
}

// Status reports the current protections.
func Status() Report {
	r := Report{SecretMode: secretEnabled(), MemoryLocked: lockedMemory.Load(), Platform: platformName}
	var cur unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &cur); err == nil {
		r.CoreDumpsDisabled = cur.Cur == 0
	}
	r.NotDumpable = platformNotDumpable()
	return r
}

// Locked is a page-aligned memory region that is locked where possible. It lives
// outside the Go heap, so the garbage collector and stack growth never copy it.
type Locked struct {
	b      []byte
	mapped []byte
	locked bool
}

// NewLocked returns a zeroed region of n bytes. If locking fails, the region is
// still usable and Status reports that memory isn't locked.
func NewLocked(n int) *Locked {
	page := os.Getpagesize()
	size := (n + page - 1) / page * page
	if size == 0 {
		size = page
	}
	mapped, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return &Locked{b: make([]byte, n)}
	}
	l := &Locked{b: mapped[:n:n], mapped: mapped}
	if unix.Mlock(mapped) == nil {
		l.locked = true
		lockedMemory.Store(true)
	}
	platformDontDump(mapped)
	return l
}

// Bytes returns the region.
func (l *Locked) Bytes() []byte { return l.b }

// IsLocked reports whether the region is locked into memory.
func (l *Locked) IsLocked() bool { return l.locked }

// Close clears and releases the region.
func (l *Locked) Close() {
	if l == nil {
		return
	}
	clear(l.b)
	if l.mapped != nil {
		if l.locked {
			_ = unix.Munlock(l.mapped)
		}
		_ = unix.Munmap(l.mapped)
		l.mapped = nil
	}
	l.b = nil
}
