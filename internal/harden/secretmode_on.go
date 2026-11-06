//go:build goexperiment.runtimesecret

package harden

import "runtime/secret"

// SecretDo runs f in Go's experimental secret mode.
func SecretDo(f func()) { secret.Do(f) }

func secretEnabled() bool {
	on := false
	secret.Do(func() { on = secret.Enabled() })
	return on
}
