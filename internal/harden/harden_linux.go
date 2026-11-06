//go:build linux

package harden

import "golang.org/x/sys/unix"

const platformName = "linux"

func platformProcess() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func platformNotDumpable() bool {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return err == nil && v == 0
}

func platformDontDump(b []byte) {
	_ = unix.Madvise(b, unix.MADV_DONTDUMP)
}
