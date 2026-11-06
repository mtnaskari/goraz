package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const pass = "violet granite ocean drift lantern"

type harness struct {
	t     *testing.T
	dir   string
	vault string
	seen  bytes.Buffer // Everything printed by any command, for the canary test.
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GORAZ_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("GORAZ_VAULT", filepath.Join(dir, "v.goraz"))
	h := &harness{t: t, dir: dir, vault: filepath.Join(dir, "v.goraz")}
	return h
}

// fd returns a descriptor holding s, as a parent process would pass one.
func (h *harness) fd(s string) string {
	h.t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := w.WriteString(s); err != nil {
		h.t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		h.t.Fatal(err)
	}
	// A duplicate has no finalizer, so the garbage collector can't close it before
	// the command takes ownership.
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		h.t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		h.t.Fatal(err)
	}
	return strconv.Itoa(fd)
}

func (h *harness) raw(stdin string, args ...string) (string, string, int) {
	h.t.Helper()
	var out, errb bytes.Buffer
	a := &app{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, now: time.Now}
	code := a.run(args)
	h.seen.Write(out.Bytes())
	h.seen.Write(errb.Bytes())
	return out.String(), errb.String(), code
}

// ok runs a command that opens the vault with the passphrase.
func (h *harness) ok(stdin string, args ...string) string {
	h.t.Helper()
	full := append(append([]string{}, args...), "--passphrase-fd", h.fd(pass+"\n"))
	out, errb, code := h.raw(stdin, full...)
	if code != 0 {
		h.t.Fatalf("%v: exit %d: %s", args, code, errb)
	}
	return out
}

func (h *harness) fail(stdin string, args ...string) string {
	h.t.Helper()
	full := append(append([]string{}, args...), "--passphrase-fd", h.fd(pass+"\n"))
	_, errb, code := h.raw(stdin, full...)
	if code == 0 {
		h.t.Fatalf("%v: expected failure", args)
	}
	return errb
}

func (h *harness) init() string {
	h.t.Helper()
	return h.ok("", "init", "--kdf", "interactive")
}

func TestBasicFlow(t *testing.T) {
	h := newHarness(t)
	out := h.init()
	if !strings.Contains(out, "GORAZ-RC-") {
		t.Fatalf("no recovery code: %s", out)
	}
	h.ok("s3cret-value\n", "put", "prod/db")
	if got := h.ok("", "get", "prod/db"); got != "s3cret-value" {
		t.Errorf("get: %q", got)
	}
	if got := h.ok("", "read", "goraz://prod/db"); got != "s3cret-value" {
		t.Errorf("read: %q", got)
	}
	if got := h.ok("", "ls"); !strings.HasPrefix(got, "prod/db\tsecret\tv1") {
		t.Errorf("ls: %q", got)
	}
	h.ok("second\n", "put", "prod/db")
	if got := h.ok("", "history", "prod/db"); got != "v1\nv2\n" {
		t.Errorf("history: %q", got)
	}
	if got := h.ok("", "get", "prod/db", "--version", "1"); got != "s3cret-value" {
		t.Errorf("version: %q", got)
	}
	h.ok("", "restore", "prod/db", "--version", "1")
	if got := h.ok("", "get", "prod/db"); got != "s3cret-value" {
		t.Errorf("restore: %q", got)
	}
	h.ok("", "rm", "prod/db")
	if got := h.ok("", "ls"); got != "" {
		t.Errorf("ls after rm: %q", got)
	}
	h.fail("", "get", "prod/db")
	h.ok("", "restore", "prod/db")
	h.ok("", "destroy", "prod/db")
	h.fail("", "history", "prod/db")
}

func TestLoginFieldsAndReferences(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("pw-value\n", "put", "site", "--type", "login", "--username", "alice", "--url", "https://example.com")
	if got := h.ok("", "read", "goraz://site#username"); got != "alice" {
		t.Errorf("%q", got)
	}
	if got := h.ok("", "read", "goraz://site#url"); got != "https://example.com" {
		t.Errorf("%q", got)
	}
	for _, bad := range []string{"site", "goraz://", "goraz://site#nope", "goraz://../x", "http://site"} {
		h.fail("", "read", bad)
	}
}

func TestPassphraseFD(t *testing.T) {
	for in, want := range map[string]string{"a\n": "a", "a\r\n": "a", "a": "a", "a\n\n": "a\n", " a ": " a "} {
		got, err := cleanPassphrase([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := cleanPassphrase([]byte("a\x00b")); err == nil {
		t.Error("NUL accepted")
	}
	if _, err := cleanPassphrase(bytes.Repeat([]byte("a"), 513)); err == nil {
		t.Error("oversized accepted")
	}
}

func TestNoSecretOnCommandLine(t *testing.T) {
	// There is no flag that accepts a value or passphrase directly.
	a := &app{stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, now: time.Now}
	fs, _ := a.flags("x")
	for _, name := range []string{"passphrase", "password", "value", "secret", "machine-key", "token"} {
		if fs.Lookup(name) != nil {
			t.Errorf("flag --%s must not exist", name)
		}
	}
}

func TestWeakPassphraseRefused(t *testing.T) {
	h := newHarness(t)
	_, errb, code := h.raw("", "init", "--kdf", "interactive", "--passphrase-fd", h.fd("short\n"))
	if code == 0 || !strings.Contains(errb, "15 characters") {
		t.Errorf("%d %s", code, errb)
	}
}

func TestGenerate(t *testing.T) {
	h := newHarness(t)
	out, _, code := h.raw("", "generate", "--length", "30")
	if code != 0 || len(strings.TrimSpace(out)) != 30 {
		t.Errorf("%d %q", code, out)
	}
	out, _, code = h.raw("", "generate", "--words", "6", "--separator", "_")
	if code != 0 || strings.Count(out, "_") < 5 {
		t.Errorf("%d %q", code, out)
	}
	if _, _, code := h.raw("", "generate", "--length", "3"); code == 0 {
		t.Error("short length accepted")
	}
}

func TestTOTP(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n", "put", "site/otp", "--otp")
	got := strings.TrimSpace(h.ok("", "totp", "site/otp"))
	if len(got) != 6 {
		t.Errorf("code %q", got)
	}
	h.fail("not a uri\n", "put", "bad/otp", "--otp")
	h.ok("plain\n", "put", "plain")
	h.fail("", "totp", "plain")
}

func TestTokenFlow(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.fail("", "token", "issue") // A name is required.
	tok := strings.TrimSpace(h.ok("", "token", "issue", "--name", "ci", "--scope", "deploy", "--ttl", "1h"))
	if !strings.HasPrefix(tok, "goraz_st_") {
		t.Fatalf("token %q", tok)
	}
	if got := h.ok(tok+"\n", "token", "verify", "--scope", "deploy"); !strings.HasPrefix(got, "valid\tci") {
		t.Errorf("verify: %q", got)
	}
	h.fail(tok+"\n", "token", "verify", "--scope", "admin")
	h.fail("garbage\n", "token", "verify")

	list := h.ok("", "token", "list")
	id := strings.Split(list, "\t")[0]
	if strings.Contains(list, tok) {
		t.Error("list shows the token")
	}
	next := strings.TrimSpace(h.ok("", "token", "rotate", id, "--overlap", "1h"))
	h.ok(next+"\n", "token", "verify")
	h.ok(tok+"\n", "token", "verify")
	h.ok("", "token", "revoke", id)
	h.fail(tok+"\n", "token", "verify")
	h.fail("", "token", "revoke", "zz")

	h.ok("v\n", "put", "stripe", "--type", "token", "--expires-in", "24h")
	if got := h.ok("", "token", "expiring", "--within", "48h"); !strings.HasPrefix(got, "stripe\t") {
		t.Errorf("expiring: %q", got)
	}
	if got := h.ok("", "token", "expiring", "--within", "1h"); got != "" {
		t.Errorf("expiring: %q", got)
	}
	h.ok("", "token", "rotate-verifier")
	h.fail(next+"\n", "token", "verify")
}

func TestPasswdAndRekeyWarnings(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v\n", "put", "a")

	next := "amber canyon whisper meadow copper"
	_, errb, code := h.raw("", "passwd", "--kdf", "interactive", "--passphrase-fd", h.fd(pass+"\n"), "--new-passphrase-fd", h.fd(next+"\n"))
	if code != 0 || !strings.Contains(errb, "does not revoke") {
		t.Fatalf("%d %s", code, errb)
	}
	if _, _, code := h.raw("", "ls", "--passphrase-fd", h.fd(pass+"\n")); code == 0 {
		t.Error("old passphrase still opens the current file")
	}

	// Without confirmation, nothing changes.
	before, err := os.ReadFile(h.vault)
	if err != nil {
		t.Fatal(err)
	}
	_, _, code = h.raw("no\n", "rekey", "--kdf", "interactive", "--passphrase-fd", h.fd(next+"\n"), "--new-passphrase-fd", h.fd(pass+"\n"))
	if code == 0 {
		t.Fatal("unconfirmed rekey succeeded")
	}
	after, err := os.ReadFile(h.vault)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("an unconfirmed rekey changed the file")
	}

	out, _, code := h.raw("SAVED\n", "rekey", "--kdf", "interactive", "--passphrase-fd", h.fd(next+"\n"), "--new-passphrase-fd", h.fd(pass+"\n"))
	if code != 0 || !strings.Contains(out, "GORAZ-RC-") {
		t.Fatalf("%d %s", code, out)
	}
	if got := h.ok("", "get", "a"); got != "v" {
		t.Errorf("value after rekey: %q", got)
	}
}

func TestSlots(t *testing.T) {
	h := newHarness(t)
	h.init()
	key := strings.TrimSpace(h.ok("", "slot", "add-machine"))
	if !strings.HasPrefix(key, "goraz_mk_") {
		t.Fatalf("%q", key)
	}
	h.ok("v\n", "put", "a")
	out, errb, code := h.raw("", "get", "a", "--machine-key-fd", h.fd(key+"\n"))
	if code != 0 || out != "v" {
		t.Fatalf("%d %s %s", code, out, errb)
	}
	list := h.ok("", "slot", "list")
	if strings.Count(list, "\n") != 3 {
		t.Errorf("%q", list)
	}
	id := ""
	for line := range strings.SplitSeq(list, "\n") {
		if strings.HasSuffix(line, "machine") {
			id = strings.Fields(line)[0]
		}
	}
	h.ok("", "slot", "remove", id)
	if _, _, code := h.raw("", "get", "a", "--machine-key-fd", h.fd(key+"\n")); code == 0 {
		t.Error("removed key still opens the current file")
	}
}

func TestServiceFlowAndReadOnlyCLI(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("sk-api\n", "put", "prod/api/stripe")
	h.ok("web\n", "put", "prod/web/secret")
	out, keyOut := filepath.Join(h.dir, "api.goraz"), filepath.Join(h.dir, "api.key")
	h.ok("", "service", "create", "api", "--prefix", "prod/api", "--out", out, "--key-out", keyOut)
	if st, err := os.Stat(keyOut); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if got := h.ok("", "service", "list"); !strings.Contains(got, "api\tgeneration 1") {
		t.Errorf("%q", got)
	}

	// A container: read-only, audit on stderr, no state directory needed.
	stdout, stderr, code := h.raw("", "get", "prod/api/stripe", "--vault", out, "--machine-key-file", keyOut, "--audit", "stderr")
	if code != 0 || stdout != "sk-api" {
		t.Fatalf("%d %q %s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, `"item.read"`) || strings.Contains(stderr, "sk-api") || strings.Contains(stderr, "stripe") {
		t.Errorf("audit stream: %s", stderr)
	}
	if _, _, code := h.raw("", "get", "prod/web/secret", "--vault", out, "--machine-key-file", keyOut, "--audit", "stderr"); code == 0 {
		t.Error("service read another service's item")
	}
	if _, _, code := h.raw("x\n", "put", "new", "--vault", out, "--machine-key-file", keyOut, "--audit", "stderr"); code == 0 {
		t.Error("read-only open allowed a write")
	}
	if _, _, code := h.raw("", "ls", "--machine-key-file", keyOut, "--audit", "nowhere"); code == 0 {
		t.Error("unknown sink accepted")
	}

	h.ok("sk-new\n", "put", "prod/api/stripe")
	h.ok("", "service", "sync", "api", "--out", out)
	stdout, _, _ = h.raw("", "get", "prod/api/stripe", "--vault", out, "--machine-key-file", keyOut, "--audit", "stderr")
	if stdout != "sk-new" {
		t.Errorf("after sync: %q", stdout)
	}

	// A service token, and the warning about a missing validity window.
	tok := strings.TrimSpace(h.ok("", "token", "issue", "--service", "api", "--name", "billing"))
	if !strings.HasPrefix(tok, "goraz_st_") {
		t.Errorf("%q", tok)
	}
	if got := h.ok("", "token", "list", "--service", "api"); !strings.Contains(got, "billing") {
		t.Errorf("%q", got)
	}
	_, errb, code := h.raw("", "service", "sync", "api", "--out", out, "--passphrase-fd", h.fd(pass+"\n"))
	if code != 0 || !strings.Contains(errb, "--valid-for") {
		t.Errorf("%d %s", code, errb)
	}

	// Rotation appends the new key, so both can be deployed.
	h.ok("", "service", "rotate", "api", "--out", out, "--key-out", keyOut)
	b, err := os.ReadFile(keyOut)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), "goraz_mk_") != 2 {
		t.Errorf("key file should hold both keys")
	}
	if _, _, code := h.raw("", "get", "prod/api/stripe", "--vault", out, "--machine-key-file", keyOut, "--audit", "stderr"); code != 0 {
		t.Error("the new file should open with the two-line key file")
	}
	h.ok("", "service", "remove", "api")
}

func TestKeyFileMustBePrivate(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v\n", "put", "a/b")
	out, keyOut := filepath.Join(h.dir, "s.goraz"), filepath.Join(h.dir, "s.key")
	h.ok("", "service", "create", "s", "--prefix", "a", "--out", out, "--key-out", keyOut)
	if err := os.Chmod(keyOut, 0o644); err != nil {
		t.Fatal(err)
	}
	_, errb, code := h.raw("", "get", "a/b", "--vault", out, "--machine-key-file", keyOut, "--audit", "stderr")
	if code == 0 || !strings.Contains(errb, "defaultMode") {
		t.Errorf("%d %s", code, errb)
	}
}

func TestAuditCommands(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v\n", "put", "a")
	h.ok("", "get", "a")
	if got := h.ok("", "audit", "verify"); !strings.HasPrefix(got, "valid:") {
		t.Errorf("%q", got)
	}
	hash := strings.TrimSpace(h.ok("", "audit", "hash", "a"))
	if got := h.ok("", "audit", "tail"); !strings.Contains(got, "item.read") || !strings.Contains(got, hash) {
		t.Errorf("%q", got)
	}
	h.ok("", "audit", "rotate-key")
	h.ok("", "audit", "verify")
}

func TestDoctor(t *testing.T) {
	h := newHarness(t)
	out, _, code := h.raw("", "doctor", "--no-vault")
	if code != 0 || !strings.Contains(out, "independent security audit: none") {
		t.Errorf("%d %s", code, out)
	}
	h.init()
	h.ok("v\n", "put", "a")
	got := h.ok("", "doctor")
	if !strings.Contains(got, "all items verified") || !strings.Contains(got, "audit log verified") {
		t.Errorf("%s", got)
	}
}

func TestReportOffline(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("same-password-value\n", "put", "a", "--type", "login")
	h.ok("same-password-value\n", "put", "b", "--type", "login")
	h.ok("short\n", "put", "c", "--type", "login")
	got := h.ok("", "report")
	if !strings.Contains(got, "reused\t") || !strings.Contains(got, "short\tc") {
		t.Errorf("%q", got)
	}
	if strings.Contains(got, "same-password-value") {
		t.Error("the report shows a value")
	}
}

func TestImportExport(t *testing.T) {
	h := newHarness(t)
	h.init()
	envFile := filepath.Join(h.dir, ".env")
	if err := os.WriteFile(envFile, []byte("# c\nA=1\nexport B=\"two words\"\nC='x=y'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ok("", "import", envFile, "--prefix", "app")
	if got := h.ok("", "get", "app/B"); got != "two words" {
		t.Errorf("%q", got)
	}
	if got := h.ok("", "get", "app/C"); got != "x=y" {
		t.Errorf("%q", got)
	}
	exp := filepath.Join(h.dir, "out.json")
	h.ok("", "export", "--out", exp)
	st, err := os.Stat(exp)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	h.fail("", "export", "--out", exp) // It won't overwrite.
	h.fail("", "export")
}

func TestParseDotEnvRejects(t *testing.T) {
	for _, in := range []string{"novalue", "=x", "1A=x", "A B=x", "A=", "A=\"x", "A='x\"", "A=1\nA=2"} {
		if _, err := parseDotEnv([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseDotEnvErrorsHideContent(t *testing.T) {
	_, err := parseDotEnv([]byte("TOPSECRETVALUE"))
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Errorf("err = %v", err)
	}
}

func FuzzParseDotEnv(f *testing.F) {
	f.Add([]byte("A=1\nexport B=\"x\"\n# c\n"))
	f.Add([]byte{})
	f.Add([]byte("=\n'\""))
	f.Fuzz(func(t *testing.T, b []byte) {
		es, err := parseDotEnv(b)
		if err != nil {
			return
		}
		for _, e := range es {
			if !envName.MatchString(e.Key) || len(e.Value) == 0 {
				t.Fatalf("invalid entry %q", e.Key)
			}
		}
	})
}

func FuzzParseRef(f *testing.F) {
	f.Add("goraz://a/b#username")
	f.Add("goraz://")
	f.Fuzz(func(t *testing.T, s string) {
		name, _, err := parseRef(s)
		if err == nil && (strings.Contains(name, "..") && strings.Contains(name, "/../")) {
			t.Fatalf("accepted %q", s)
		}
	})
}

// The canary test: run many commands with a known secret, then search everything
// printed and every file the audit log and state wrote, in several encodings.
func TestCanaryNeverLeaks(t *testing.T) {
	h := newHarness(t)
	const canary = "CANARY-9f8e7d6c5b4a"
	h.init()
	h.ok(canary+"\n", "put", "canary/item")
	h.ok("", "ls")
	h.ok("", "history", "canary/item")
	h.ok("", "report")
	h.ok("", "doctor")
	h.ok("", "audit", "tail")
	h.ok("", "audit", "verify")
	h.ok("", "token", "issue", "--name", "n")
	h.ok("", "token", "list")
	h.ok("", "get", "canary/item") // Deliberate output, removed below.
	h.fail("", "get", "canary/../item")
	h.fail(canary+"\n", "token", "verify")
	h.fail("", "read", "goraz://"+canary)
	h.fail("", "get", canary)

	forms := []string{
		canary, strings.ToLower(canary),
		hex.EncodeToString([]byte(canary)),
		base64.StdEncoding.EncodeToString([]byte(canary)),
		base64.RawURLEncoding.EncodeToString([]byte(canary)),
	}
	// Only the deliberate output of "get" may hold the value, and an error may echo
	// nothing. Remove that one output, then the rest must be clean.
	printed := strings.Replace(h.seen.String(), canary, "", 1)
	for _, f := range forms {
		if strings.Contains(printed, f) {
			t.Errorf("output contains %q", f)
		}
	}
	err := filepath.WalkDir(h.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 -- test path.
		if err != nil {
			return err
		}
		for _, f := range forms {
			if bytes.Contains(b, []byte(f)) {
				t.Errorf("%s contains %q", p, f)
			}
		}
		if bytes.Contains(b, []byte("canary/item")) {
			t.Errorf("%s contains the item name", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUsageAndUnknown(t *testing.T) {
	h := newHarness(t)
	if _, _, code := h.raw(""); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if _, _, code := h.raw("", "nope"); code != 2 {
		t.Errorf("unknown: %d", code)
	}
	if out, _, code := h.raw("", "help"); code != 0 || !strings.Contains(out, "not had an independent security audit") {
		t.Errorf("help: %d", code)
	}
	if _, _, code := h.raw("", "init", "--kdf", "nope", "--passphrase-fd", h.fd(pass)); code == 0 {
		t.Error("unknown KDF accepted")
	}
}

func TestFilterEnvRemovesMappedKeys(t *testing.T) {
	got := filterEnv([]string{"K=old", "KEEP=1", "K2=x", "NOEQUALS"}, map[string]bool{"K": true})
	if strings.Join(got, ",") != "KEEP=1,K2=x,NOEQUALS" {
		t.Errorf("%v", got)
	}
}

func TestPositionalAfterDoubleDash(t *testing.T) {
	a := &app{stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, now: time.Now}
	fs, _ := a.flags("x")
	pos, err := parse(fs, []string{"one", "--", "--vault", "two"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pos, " ") != "one --vault two" {
		t.Errorf("%v", pos)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// If the new recovery code can't be written, the rekey must not go ahead.
func TestRekeyOutputFailureChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.init()
	before, err := os.ReadFile(h.vault)
	if err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: failWriter{}, stderr: &errb, now: time.Now}
	code := a.run([]string{"rekey", "--kdf", "interactive", "--confirm-saved", "--passphrase-fd", h.fd(pass + "\n"), "--new-passphrase-fd", h.fd(pass + "\n")})
	if code == 0 {
		t.Fatal("rekey reported success")
	}
	after, err := os.ReadFile(h.vault)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the vault changed")
	}
}

func TestRotateVerifierRefusesService(t *testing.T) {
	h := newHarness(t)
	h.init()
	errb := h.fail("", "token", "rotate-verifier", "--service", "api")
	if !strings.Contains(errb, "service rotate") {
		t.Errorf("%s", errb)
	}
	h.fail("", "token", "expiring", "--service", "api")
}

// A key file that can't be written must leave the service and its file unchanged.
func TestServiceRotateWithUnwritableKeyChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v\n", "put", "a/b")
	out, keyOut := filepath.Join(h.dir, "s.goraz"), filepath.Join(h.dir, "s.key")
	h.ok("", "service", "create", "s", "--prefix", "a", "--out", out, "--key-out", keyOut)
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyOut, 0o644); err != nil {
		t.Fatal(err)
	}
	errb := h.fail("", "service", "rotate", "s", "--out", out, "--key-out", keyOut)
	if !strings.Contains(errb, "nothing was changed") {
		t.Errorf("%s", errb)
	}
	after, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the service file changed")
	}
}

func TestServiceFlagsOnlyOnCreate(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v\n", "put", "a/b")
	out, keyOut := filepath.Join(h.dir, "s.goraz"), filepath.Join(h.dir, "s.key")
	h.ok("", "service", "create", "s", "--prefix", "a", "--out", out, "--key-out", keyOut)
	h.fail("", "service", "sync", "s", "--out", out, "--valid-for", "1h")
	h.fail("", "service", "sync", "s", "--out", out, "--prefix", "b")
}

func TestMainVaultRefusedInReadOnlyMode(t *testing.T) {
	h := newHarness(t)
	h.init()
	key := strings.TrimSpace(h.ok("", "slot", "add-machine"))
	_, errb, code := h.raw("", "ls", "--machine-key-fd", h.fd(key+"\n"), "--audit", "stderr")
	if code == 0 || !strings.Contains(errb, "main vault") {
		t.Errorf("%d %s", code, errb)
	}
}

func TestClipClearRefusesBadHash(t *testing.T) {
	for _, in := range []string{"", "zz", "abcd"} {
		a := &app{stdin: strings.NewReader(in), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, now: time.Now}
		if err := a.cmdClipClear([]string{"--after", "0s"}); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestClipRefusesUnknownField(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.fail("", "clip", "a", "--field", "bogus")
}

func TestWeakPassphraseOverrideWarns(t *testing.T) {
	h := newHarness(t)
	_, errb, code := h.raw("", "init", "--kdf", "interactive", "--accept-weak-passphrase", "--passphrase-fd", h.fd("short\n"))
	if code != 0 || !strings.Contains(errb, "doesn't meet the policy") {
		t.Errorf("%d %s", code, errb)
	}
}
