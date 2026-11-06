// Package names is the single place item names are validated. Every operation
// must call it before any check or lookup. Non-canonical input is rejected, never
// corrected, because normalization differences between code paths are the root
// cause of a repeated class of bypass in other secret managers.
package names

import (
	"errors"
	"strings"
)

// Limits on item names.
const (
	MaxLength   = 255
	MaxSegments = 16
)

// ErrInvalid is returned for a name outside the grammar.
var ErrInvalid = errors.New("names: invalid name: use segments of A-Z, a-z, 0-9, '.', '_' or '-', separated by '/'")

// Validate reports whether name is canonical.
func Validate(name string) error {
	if name == "" || len(name) > MaxLength {
		return ErrInvalid
	}
	segments := 1
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '/' {
			seg := name[start:i]
			if seg == "" || seg == "." || seg == ".." {
				return ErrInvalid
			}
			if i < len(name) {
				segments++
				if segments > MaxSegments {
					return ErrInvalid
				}
			}
			start = i + 1
			continue
		}
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return ErrInvalid
		}
	}
	return nil
}

// FoldKey returns the key used to refuse names that differ only by case.
func FoldKey(name string) string { return strings.ToLower(name) }

// HasPrefix reports whether name equals prefix or lies below it, comparing whole
// segments: "prod/api" matches "prod/api/x" and never "prod/apiary".
func HasPrefix(name, prefix string) bool {
	if name == prefix {
		return true
	}
	return strings.HasPrefix(name, prefix+"/")
}
