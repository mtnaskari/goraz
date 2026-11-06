package password

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- Required by the HIBP range API. Never used for integrity.
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const hibpBase = "https://api.pwnedpasswords.com/range/"

// HIBP checks passwords against the Have I Been Pwned range API by k-anonymity:
// only the first five hexadecimal characters of the SHA-1 hash leave the machine,
// and padded responses are requested. It is never called unless asked for.
type HIBP struct {
	Client *http.Client
	Base   string
}

// NewHIBP returns a client for the public API.
func NewHIBP() *HIBP {
	return &HIBP{Client: &http.Client{Timeout: 15 * time.Second}, Base: hibpBase}
}

// Count returns how many times a password appears in known breaches.
func (h *HIBP) Count(ctx context.Context, password []byte) (int, error) {
	sum := sha1.Sum(password) // #nosec G401 -- Required by the HIBP range API.
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.Base+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "goraz")
	resp, err := h.Client.Do(req)
	if err != nil {
		return 0, errors.New("password: the breach check request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("password: the breach check returned status %d", resp.StatusCode)
	}
	count := 0
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		s, c, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(s), []byte(suffix)) == 1 {
			if n, err := strconv.Atoi(c); err == nil && n > count {
				count = n
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, errors.New("password: reading the breach check response failed")
	}
	return count, nil
}
