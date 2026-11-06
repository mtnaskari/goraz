//go:build !goexperiment.runtimesecret

package harden

// SecretDo runs f directly. Go's secret mode isn't part of this build.
func SecretDo(f func()) { f() }

func secretEnabled() bool { return false }
