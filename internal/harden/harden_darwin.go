//go:build darwin

package harden

const platformName = "darwin"

func platformProcess() {}

func platformNotDumpable() bool { return false }

func platformDontDump([]byte) {}
