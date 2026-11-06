package vault

import (
	"encoding/base64"
	"encoding/hex"
)

// encodings returns a value in the forms a leak is likely to take.
func encodings(s string) []string {
	return []string{
		s,
		hex.EncodeToString([]byte(s)),
		base64.StdEncoding.EncodeToString([]byte(s)),
		base64.RawURLEncoding.EncodeToString([]byte(s)),
	}
}
