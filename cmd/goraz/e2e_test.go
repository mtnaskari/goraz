package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// When the test binary is started as the clipboard helper, it behaves as the real
// program with fake clipboard tools, so the detached clearing process can be tested
// without touching the developer's real clipboard.
func TestMain(m *testing.M) {
	if dir := os.Getenv("GORAZ_TEST_CLIP_DIR"); dir != "" && len(os.Args) > 1 && os.Args[1] == "__clipclear" {
		clipCandidates = fakeClip(dir)
		a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, now: time.Now}
		os.Exit(a.run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeClip(dir string) []clipTool {
	return []clipTool{{[]string{filepath.Join(dir, "copy")}, []string{filepath.Join(dir, "paste")}}}
}

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { // #nosec G306 -- a test script.
		t.Fatal(err)
	}
}

func setupFakeClip(t *testing.T) (dir, store string) {
	t.Helper()
	dir = t.TempDir()
	store = filepath.Join(dir, "clipboard")
	writeScript(t, filepath.Join(dir, "copy"), `cat > "`+store+`"`)
	writeScript(t, filepath.Join(dir, "paste"), `cat "`+store+`"`)
	saved := clipCandidates
	clipCandidates = fakeClip(dir)
	t.Cleanup(func() { clipCandidates = saved })
	t.Setenv("GORAZ_TEST_CLIP_DIR", dir)
	return dir, store
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestClipboardIsClearedAfterTimeout(t *testing.T) {
	_, store := setupFakeClip(t)
	h := newHarness(t)
	h.init()
	h.ok("clip-secret\n", "put", "a")
	h.ok("", "clip", "a", "--clear-after", "1s")
	b, err := os.ReadFile(store) // #nosec G304 -- test path.
	if err != nil || string(b) != "clip-secret" {
		t.Fatalf("not copied: %q %v", b, err)
	}
	waitFor(t, "the clipboard to clear", func() bool {
		b, err := os.ReadFile(store) // #nosec G304 -- test path.
		return err == nil && len(b) == 0
	})
}

func TestClipboardKeepsOtherContent(t *testing.T) {
	dir, store := setupFakeClip(t)
	_ = dir
	h := newHarness(t)
	h.init()
	h.ok("clip-secret\n", "put", "a")
	h.ok("", "clip", "a", "--clear-after", "1s")
	if err := os.WriteFile(store, []byte("copied later by the user"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond)
	b, err := os.ReadFile(store) // #nosec G304 -- test path.
	if err != nil || string(b) != "copied later by the user" {
		t.Errorf("the user's later copy was lost: %q %v", b, err)
	}
}

func TestClipboardLimits(t *testing.T) {
	setupFakeClip(t)
	h := newHarness(t)
	h.init()
	h.ok("x\n", "put", "a")
	for _, d := range []string{"0s", "-1s", "6m"} {
		h.fail("", "clip", "a", "--clear-after", d)
	}
}

func TestClearProcessHashIsNotOnCommandLine(t *testing.T) {
	// The helper reads its hash from stdin, so a hash of a weak password can't be read
	// from the process list. A wrong hash must not clear anything.
	_, store := setupFakeClip(t)
	if err := os.WriteFile(store, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("different"))
	a := &app{stdin: strings.NewReader(hex.EncodeToString(sum[:])), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, now: time.Now}
	if err := a.cmdClipClear([]string{"--after", "0s"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(store) // #nosec G304 -- test path.
	if string(b) != "keep" {
		t.Error("cleared content that wasn't ours")
	}
}

// The tests below run the real program as separate processes.

var (
	binOnce  sync.Once
	binPath  string
	errBuild error
)

func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the real program")
	}
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "goraz-e2e")
		if err != nil {
			errBuild = err
			return
		}
		binPath = filepath.Join(dir, "goraz")
		out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
		if err != nil {
			errBuild = fmt.Errorf("%w: %s", err, out)
		}
	})
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	return binPath
}

// command prepares the program with the passphrase on descriptor 3.
func command(t *testing.T, bin string, env []string, stdin string, args ...string) *exec.Cmd {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(pass + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	c := exec.Command(bin, append(args, "--passphrase-fd", "3")...) // #nosec G204 -- the program under test.
	c.ExtraFiles = []*os.File{r}
	c.Env = env
	c.Stdin = strings.NewReader(stdin)
	return c
}

func e2eEnv(t *testing.T) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	return append(os.Environ(), "GORAZ_STATE_DIR="+filepath.Join(dir, "state"), "GORAZ_VAULT="+filepath.Join(dir, "v.goraz")), dir
}

func mustRun(t *testing.T, c *exec.Cmd) string {
	t.Helper()
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		t.Fatalf("%v: %v: %s", c.Args, err, errb.String())
	}
	return out.String()
}

func TestProcessRunGivesChildTheSecret(t *testing.T) {
	bin := buildBinary(t)
	env, _ := e2eEnv(t)
	mustRun(t, command(t, bin, env, "", "init", "--kdf", "interactive"))
	mustRun(t, command(t, bin, env, "the-real-secret\n", "put", "a"))

	// An inherited value of the same name must not win.
	childEnv := append(env, "MY_TOKEN=inherited-old-value")
	c := exec.Command(bin, "run", "--no-warn", "--env", "MY_TOKEN=goraz://a", "--passphrase-fd", "3", "--", "/usr/bin/env") // #nosec G204 -- the program under test.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(pass + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	c.ExtraFiles = []*os.File{r}
	c.Env = childEnv
	out := mustRun(t, c)
	if !strings.Contains(out, "MY_TOKEN=the-real-secret\n") {
		t.Error("the child didn't get the secret")
	}
	if strings.Contains(out, "inherited-old-value") {
		t.Error("the child still sees the inherited value")
	}
}

func TestProcessRunPassesExitCode(t *testing.T) {
	bin := buildBinary(t)
	env, _ := e2eEnv(t)
	mustRun(t, command(t, bin, env, "", "init", "--kdf", "interactive"))
	c := exec.Command(bin, "run", "--no-warn", "--passphrase-fd", "3", "--", "/bin/sh", "-c", "exit 7") // #nosec G204 -- the program under test.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(pass + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	c.ExtraFiles = []*os.File{r}
	c.Env = env
	var ee *exec.ExitError
	if err := c.Run(); !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Errorf("exit: %v", err)
	}
}

// Real crashes: SIGKILL at random moments while a process writes. The vault must
// always open, every item must verify, and the audit log must stay usable.
func TestProcessKilledDuringWrites(t *testing.T) {
	bin := buildBinary(t)
	env, dir := e2eEnv(t)
	mustRun(t, command(t, bin, env, "", "init", "--kdf", "interactive"))
	mustRun(t, command(t, bin, env, "first\n", "put", "stable"))

	rounds := 40
	killed := 0
	for i := range rounds {
		c := command(t, bin, env, strings.Repeat("v", 2000)+"\n", "put", fmt.Sprintf("item%d", i%5))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		// Argon2 takes most of the run, so aim near its end and vary widely.
		time.Sleep(time.Duration(40+rand.IntN(160)) * time.Millisecond) // #nosec G404 -- test timing only.
		if err := c.Process.Signal(syscall.SIGKILL); err == nil {
			killed++
		}
		_ = c.Wait()

		out, errb := bytes.Buffer{}, bytes.Buffer{}
		check := command(t, bin, env, "", "doctor")
		check.Stdout, check.Stderr = &out, &errb
		if err := check.Run(); err != nil {
			t.Fatalf("round %d: the vault is unusable after a kill: %v\n%s\n%s", i, err, out.String(), errb.String())
		}
	}
	if killed == 0 {
		t.Fatal("no process was killed, so this test proved nothing")
	}
	if got := mustRun(t, command(t, bin, env, "", "get", "stable")); got != "first" {
		t.Errorf("value lost: %q", got)
	}
	// A successful write cleans up any temporary copy that a crash left behind.
	mustRun(t, command(t, bin, env, "x\n", "put", "cleanup"))
	left, err := filepath.Glob(filepath.Join(dir, ".v.goraz.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("temporary files remain: %v", left)
	}
}

// Separate processes write at the same time. No acknowledged write may be lost.
func TestProcessesWritingConcurrently(t *testing.T) {
	bin := buildBinary(t)
	env, _ := e2eEnv(t)
	mustRun(t, command(t, bin, env, "", "init", "--kdf", "interactive"))
	const writers = 6
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			name := fmt.Sprintf("w%d", i)
			for range 60 {
				c := command(t, bin, env, name+"\n", "put", name)
				var errb bytes.Buffer
				c.Stderr = &errb
				if err := c.Run(); err == nil {
					return
				} else if !strings.Contains(errb.String(), "changed since") && !strings.Contains(errb.String(), "different history") &&
					!strings.Contains(errb.String(), "older than") {
					t.Errorf("%s: %s", name, errb.String())
					return
				}
				time.Sleep(time.Duration(rand.IntN(60)) * time.Millisecond) // #nosec G404 -- test timing only.
			}
			t.Errorf("%s never succeeded", name)
		})
	}
	wg.Wait()
	for i := range writers {
		name := fmt.Sprintf("w%d", i)
		if got := mustRun(t, command(t, bin, env, "", "get", name)); got != name {
			t.Errorf("%s: %q", name, got)
		}
	}
	mustRun(t, command(t, bin, env, "", "audit", "verify"))
}

func TestVersionCommand(t *testing.T) {
	h := newHarness(t)
	for _, arg := range []string{"version", "--version"} {
		out, _, code := h.raw("", arg)
		if code != 0 || !strings.HasPrefix(out, "goraz ") {
			t.Errorf("%s: %d %q", arg, code, out)
		}
	}
}
