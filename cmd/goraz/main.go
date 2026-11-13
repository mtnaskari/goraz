//go:debug dataindependenttiming=1

// Command goraz is a local secrets tool. See README.md and docs/threat-model.md.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/internal/format"
	"github.com/mtnaskari/goraz/internal/fsutil"
	"github.com/mtnaskari/goraz/internal/harden"
	"github.com/mtnaskari/goraz/internal/kdf"
	"github.com/mtnaskari/goraz/internal/names"
	"github.com/mtnaskari/goraz/password"
	"github.com/mtnaskari/goraz/password/hibp"
	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/service"
	"github.com/mtnaskari/goraz/token"
	"github.com/mtnaskari/goraz/vault"
)

const usage = `goraz: a local vault, token manager and password manager.

Usage: goraz <command> [flags]

Vault:
  init                     create a vault
  put NAME                 store a value (from stdin or a hidden prompt)
  get NAME                 print a value
  read goraz://NAME[#FIELD]  print a value or field from a reference
  ls                       list items
  rm NAME                  hide an item (history remains)
  destroy NAME             remove an item and its history from the file
  history NAME             list versions
  restore NAME             make a version the latest
  run [--env K=REF] -- CMD run a program with secrets in its environment
  import FILE              import a .env file
  export --out FILE        write everything in plain text

Keys:
  passwd                   replace the passphrase (does NOT revoke the old one)
  slot list|add-machine|add-recovery|remove
  rekey                    new master key: the only way to revoke old credentials
  state reset              forget this device's record of the vault

Passwords:
  generate                 generate a password or passphrase
  totp NAME                print a one-time code
  clip NAME                copy a value to the clipboard, cleared automatically
  report [--hibp]          report weak, reused and old passwords

Tokens:
  token issue|list|revoke|rotate|verify|expiring|rotate-verifier

Services:
  service create|sync|rotate|remove|list

Audit:
  audit verify|hash|tail|rotate-key

Diagnostics:
  doctor                   report active protections and vault integrity
  version                  print the version

Common flags (after the command): --vault PATH, --passphrase-fd N, --keyfile PATH,
--recovery, --machine-key-file PATH, --machine-key-fd N, --audit stderr,
--accept-rollback, --accept-fork, --accept-audit-gap

Secrets are never read from arguments or environment variables.
goraz has not had an independent security audit.
`

// app holds the process's streams, so tests can run commands in-process.
type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	now            func() time.Time
}

func main() {
	harden.Process()
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, now: time.Now}
	os.Exit(a.run(os.Args[1:]))
}

// exitCodeError carries a child's exit code.
type exitCodeError int

func (e exitCodeError) Error() string { return "exit " + strconv.Itoa(int(e)) }

func (a *app) run(args []string) int {
	if len(args) == 0 {
		_, _ = io.WriteString(a.stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	handlers := map[string]func([]string) error{
		"init": a.cmdInit, "put": a.cmdPut, "get": a.cmdGet, "read": a.cmdRead, "ls": a.cmdList,
		"rm": a.cmdDelete, "destroy": a.cmdDestroy, "history": a.cmdHistory, "restore": a.cmdRestore,
		"run": a.cmdRun, "import": a.cmdImport, "export": a.cmdExport, "passwd": a.cmdPasswd,
		"slot": a.cmdSlot, "rekey": a.cmdRekey, "state": a.cmdState, "generate": a.cmdGenerate,
		"totp": a.cmdTOTP, "clip": a.cmdClip, "report": a.cmdReport, "token": a.cmdToken,
		"service": a.cmdService, "audit": a.cmdAudit, "doctor": a.cmdDoctor,
		"__clipclear": a.cmdClipClear, "version": a.cmdVersion,
	}
	if cmd == "--version" {
		cmd = "version"
	}
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		_, _ = io.WriteString(a.stdout, usage)
		return 0
	}
	h, ok := handlers[cmd]
	if !ok {
		fmt.Fprintf(a.stderr, "goraz: unknown command %q\n", cmd)
		return 2
	}
	if err := h(rest); err != nil {
		if ex, ok := errors.AsType[exitCodeError](err); ok {
			return int(ex)
		}
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		if ue, ok := errors.AsType[*usageError](err); ok {
			// The flag package has already printed its own parse errors.
			if !ue.printed {
				fmt.Fprintf(a.stderr, "goraz: %v\n", err)
			}
			return exitUsage
		}
		fmt.Fprintf(a.stderr, "goraz: %v\n", err)
		return exitError
	}
	return 0
}

// common holds flags shared by commands that open a vault.
type common struct {
	vaultPath      string
	passphraseFD   int
	keyfile        string
	recovery       bool
	machineKeyFile string
	machineKeyFD   int
	auditSink      string
	acceptRollback bool
	acceptFork     bool
	acceptAuditGap bool
	minGeneration  uint64
}

func (a *app) flags(name string) (*flag.FlagSet, *common) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	c := &common{}
	fs.StringVar(&c.vaultPath, "vault", "", "vault path (default: $GORAZ_VAULT or ~/.local/share/goraz/vault.goraz)")
	fs.IntVar(&c.passphraseFD, "passphrase-fd", -1, "read the passphrase from this file descriptor")
	fs.StringVar(&c.keyfile, "keyfile", "", "path to a 32-byte key file")
	fs.BoolVar(&c.recovery, "recovery", false, "unlock with a recovery code")
	fs.StringVar(&c.machineKeyFile, "machine-key-file", "", "read machine keys from this file")
	fs.IntVar(&c.machineKeyFD, "machine-key-fd", -1, "read machine keys from this file descriptor")
	fs.StringVar(&c.auditSink, "audit", "", `send audit events to "stderr" and open read-only, for containers`)
	fs.BoolVar(&c.acceptRollback, "accept-rollback", false, "accept an older file, discarding newer history (audited)")
	fs.BoolVar(&c.acceptFork, "accept-fork", false, "accept a file with a different history, discarding this device's (audited)")
	fs.BoolVar(&c.acceptAuditGap, "accept-audit-gap", false, "continue after a damaged or truncated audit log (recorded)")
	fs.Uint64Var(&c.minGeneration, "min-generation", 0, "refuse a file older than this generation")
	return fs, c
}

func (c *common) path() (string, error) {
	if c.vaultPath != "" {
		return c.vaultPath, nil
	}
	if p := os.Getenv("GORAZ_VAULT"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "goraz", "vault.goraz"), nil
}

// Exit codes: 0 for success, 1 for an error, 2 for wrong usage.
const (
	exitError = 1
	exitUsage = 2
)

// usageError marks wrong usage, which exits with code 2.
type usageError struct {
	err     error
	printed bool
}

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usagef(format string, args ...any) error {
	return &usageError{err: fmt.Errorf(format, args...)}
}

// parseFlags parses flags, marking a parse error as wrong usage that the flag
// package has already printed.
func parseFlags(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		return &usageError{err: err, printed: true}
	}
	return err
}

// parseNoArgs is parse for a command that takes no positional arguments.
func parseNoArgs(fs *flag.FlagSet, args []string) error {
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("goraz %s takes no arguments, but got %q", fs.Name(), pos[0])
	}
	return nil
}

// checkArgs refuses a subcommand's positional arguments unless it is one that takes
// exactly one. It runs before the vault is unlocked, so a typo costs no KDF run.
func checkArgs(cmd, sub string, pos []string, withOne ...string) error {
	for _, w := range withOne {
		if sub == w {
			if len(pos) != 1 {
				return usagef("usage: goraz %s %s NAME", cmd, sub)
			}
			return nil
		}
	}
	if len(pos) > 0 {
		return usagef("goraz %s %s takes no arguments, but got %q", cmd, sub, pos[0])
	}
	return nil
}

// parse allows flags and positional arguments in any order.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := parseFlags(fs, args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		// After "--", everything is positional, even if it looks like a flag.
		if len(args) > len(rest) && args[len(args)-len(rest)-1] == "--" {
			return append(pos, rest...), nil
		}
		args = rest
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func (a *app) stdinFile() *os.File {
	f, _ := a.stdin.(*os.File)
	return f
}

func isTTY(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd())) // #nosec G115 -- fd fits an int.
}

func (a *app) stdoutIsTTY() bool {
	f, _ := a.stdout.(*os.File)
	return isTTY(f)
}

// readHidden reads one secret line from the terminal without echo.
func (a *app) readHidden(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no terminal available; use a file descriptor flag")
	}
	defer func() { _ = tty.Close() }()
	_, _ = fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd())) // #nosec G115 -- fd fits an int.
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return nil, err
	}
	// Terminals can silently cut lines at about 1 KiB, far above this limit.
	if len(b) > kdf.MaxPassphraseBytes {
		clear(b)
		return nil, errors.New("input is too long: the limit is 512 bytes")
	}
	return b, nil
}

// readFD reads a passphrase from a descriptor. Exactly one trailing newline is
// removed and nothing else is changed. A NUL byte is refused.
func readFD(fd int) ([]byte, error) {
	if fd < 0 {
		return nil, errors.New("invalid file descriptor")
	}
	f := os.NewFile(uintptr(fd), "passphrase") // #nosec G115 -- checked above.
	if f == nil {
		return nil, errors.New("invalid file descriptor")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, kdf.MaxPassphraseBytes+3))
	if err != nil {
		return nil, err
	}
	return cleanPassphrase(b)
}

func cleanPassphrase(b []byte) ([]byte, error) {
	switch {
	case bytes.HasSuffix(b, []byte("\r\n")):
		b = b[:len(b)-2]
	case bytes.HasSuffix(b, []byte("\n")):
		b = b[:len(b)-1]
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, errors.New("a passphrase can't contain a NUL byte")
	}
	if len(b) > kdf.MaxPassphraseBytes {
		return nil, errors.New("a passphrase is limited to 512 bytes")
	}
	return b, nil
}

func readKeyfile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := fsutil.ReadFile(path, kdf.KeyfileSize+1, fsutil.Policy{DenyOtherRead: true})
	if err != nil {
		return nil, fmt.Errorf("reading the key file: %w", err)
	}
	if len(b) != kdf.KeyfileSize {
		return nil, errors.New("a key file must be exactly 32 bytes")
	}
	return b, nil
}

func (a *app) credential(c *common) (vault.Credential, error) {
	switch {
	case c.machineKeyFile != "":
		keys, err := service.KeyFile(c.machineKeyFile).Keys()
		if err != nil {
			return vault.Credential{}, err
		}
		return vault.WithMachineKeys(keys...), nil
	case c.machineKeyFD >= 0:
		keys, err := service.KeyFD(uintptr(c.machineKeyFD)).Keys()
		if err != nil {
			return vault.Credential{}, err
		}
		return vault.WithMachineKeys(keys...), nil
	case c.recovery:
		code, err := a.readHidden("Recovery code: ")
		if err != nil {
			return vault.Credential{}, err
		}
		return vault.WithRecoveryCode(code), nil
	}
	var pass []byte
	var err error
	if c.passphraseFD >= 0 {
		pass, err = readFD(c.passphraseFD)
	} else {
		pass, err = a.readHidden("Passphrase: ")
	}
	if err != nil {
		return vault.Credential{}, err
	}
	kf, err := readKeyfile(c.keyfile)
	if err != nil {
		return vault.Credential{}, err
	}
	return vault.WithPassphrase(pass, kf), nil
}

func (a *app) warn(msg string) { fmt.Fprintln(a.stderr, "goraz: warning: "+msg) }

func (a *app) open(c *common) (*vault.Vault, error) {
	p, err := c.path()
	if err != nil {
		return nil, err
	}
	cred, err := a.credential(c)
	if err != nil {
		return nil, err
	}
	defer cred.Wipe()
	o := vault.Options{
		AcceptRollback: c.acceptRollback, AcceptFork: c.acceptFork, AcceptAuditGap: c.acceptAuditGap,
		MinGeneration: c.minGeneration, Warn: a.warn, Now: a.now,
	}
	switch c.auditSink {
	case "":
		return vault.Open(p, cred, o)
	case "stderr":
		data, err := fsutil.ReadFile(p, format.MaxFileSize, fsutil.Policy{FollowSymlinks: true, AllowRootOwner: true})
		if err != nil {
			return nil, err
		}
		o.Audit = audit.NewJSONSink(a.stderr)
		return vault.OpenService(data, cred, o)
	}
	return nil, fmt.Errorf(`unknown audit sink %q; the only option is "stderr"`, c.auditSink)
}

func (a *app) cmdInit(args []string) error {
	fs, c := a.flags("init")
	profile := fs.String("kdf", string(vault.ProfileStrong), "KDF profile: interactive, standard, strong or max")
	acceptWeak := fs.Bool("accept-weak-passphrase", false, "skip the passphrase policy")
	generate := fs.Bool("generate-passphrase", false, "generate a passphrase and print it once")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	p, err := c.path()
	if err != nil {
		return err
	}
	prof := vault.Profile(*profile)
	var pass []byte
	switch {
	case *generate:
		s, err := password.Passphrase(password.MinWords+1, " ")
		if err != nil {
			return err
		}
		pass = s.Bytes()
		fmt.Fprintf(a.stdout, "Passphrase (shown once): %s\n", pass)
	case c.passphraseFD >= 0:
		if pass, err = readFD(c.passphraseFD); err != nil {
			return err
		}
	default:
		if pass, err = a.readHidden("New passphrase: "); err != nil {
			return err
		}
		again, err := a.readHidden("Repeat passphrase: ")
		if err != nil {
			return err
		}
		defer clear(again)
		if subtle.ConstantTimeCompare(pass, again) != 1 {
			return errors.New("the passphrases don't match")
		}
		clear(again)
	}
	kf, err := readKeyfile(c.keyfile)
	if err != nil {
		return err
	}
	v, code, err := vault.Create(p, vault.CreateOptions{
		Passphrase: pass, Keyfile: kf, Profile: prof, AcceptWeakPassphrase: *acceptWeak,
		Options: vault.Options{Warn: a.warn, Now: a.now},
	})
	if err != nil {
		if !code.IsZero() {
			// The file exists, so this code is still the way back in.
			fmt.Fprintf(a.stdout, "Recovery code (shown once):\n%s\n", code.Bytes())
		}
		return err
	}
	defer v.Close()
	if *acceptWeak && password.CheckMaster(pass) != nil {
		a.warn("this passphrase doesn't meet the policy, so a stolen copy of the vault may be guessed offline")
	}
	fmt.Fprintf(a.stdout, "Created %s\n", p)
	fmt.Fprintf(a.stdout, "Recovery code (shown once, store it apart from this vault):\n%s\n", code.Bytes())
	fmt.Fprintln(a.stdout, "If the passphrase and this code are both lost, the data can't be recovered.")
	return nil
}

func (a *app) readValue(prompt string) ([]byte, error) {
	if f := a.stdinFile(); f == nil || !isTTY(f) {
		b, err := io.ReadAll(io.LimitReader(a.stdin, format.MaxValueSize+2))
		if err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(b, []byte("\n")), nil
	}
	return a.readHidden(prompt)
}

func (a *app) cmdPut(args []string) error {
	fs, c := a.flags("put")
	typ := fs.String("type", "secret", "item type: secret, login, token or totp")
	user := fs.String("username", "", "username")
	url := fs.String("url", "", "URL")
	notes := fs.String("notes", "", "notes (not for secrets: arguments are visible to other processes)")
	expires := fs.Duration("expires-in", 0, "record when this value expires")
	gen := fs.Int("generate", 0, "generate a password of this length instead of reading one")
	otp := fs.Bool("otp", false, "the value is an otpauth:// URI")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: goraz put NAME")
	}
	if err := names.Validate(pos[0]); err != nil {
		return err
	}
	it := &vault.Item{Name: pos[0], Type: vault.ItemType(*typ), Username: *user, Notes: *notes}
	if *url != "" {
		it.URLs = []string{*url}
	}
	if *expires > 0 {
		t := a.now().Add(*expires).UTC()
		it.Expires = &t
	}
	switch {
	case *gen > 0:
		s, err := password.Generate(*gen, password.DefaultAlphabet)
		if err != nil {
			return err
		}
		it.Value = s
	default:
		b, err := a.readValue("Value: ")
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return errors.New("an empty value isn't stored")
		}
		if *otp {
			if _, err := password.ParseOTPAuth(string(b)); err != nil {
				return err
			}
			it.OTP = secret.Adopt(b)
			it.Type = vault.TypeTOTP
			a.warn("a one-time code seed in the same vault as a password removes the separation between the two factors")
		} else {
			it.Value = secret.Adopt(b)
		}
	}
	defer it.Wipe()
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	return v.Put(it)
}

func (a *app) cmdGet(args []string) error {
	fs, c := a.flags("get")
	ver := fs.Uint("version", 0, "version (default: latest)")
	force := fs.Bool("force", false, "print to a terminal")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: goraz get NAME")
	}
	if err := names.Validate(pos[0]); err != nil {
		return err
	}
	if a.stdoutIsTTY() && !*force {
		return errors.New("refusing to print a secret to a terminal; use --force or a pipe")
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	it, err := v.GetVersion(pos[0], uint32(*ver)) // #nosec G115 -- an out-of-range value simply isn't found.
	if err != nil {
		return err
	}
	defer it.Wipe()
	_, err = a.stdout.Write(it.Value.Bytes())
	return err
}

// parseRef splits goraz://NAME[#FIELD]. It accepts no other form.
func parseRef(ref string) (name, field string, err error) {
	rest, ok := strings.CutPrefix(ref, "goraz://")
	if !ok {
		return "", "", errors.New("a reference must look like goraz://NAME or goraz://NAME#FIELD")
	}
	name, field, _ = strings.Cut(rest, "#")
	if err := names.Validate(name); err != nil {
		return "", "", err
	}
	if !validField(field) {
		return "", "", errors.New("unknown field in reference")
	}
	return name, field, nil
}

func validField(field string) bool {
	switch field {
	case "", "value", "username", "url", "notes", "otp":
		return true
	}
	return false
}

func fieldOf(it *vault.Item, field string) []byte {
	switch field {
	case "username":
		return []byte(it.Username)
	case "url":
		if len(it.URLs) > 0 {
			return []byte(it.URLs[0])
		}
		return nil
	case "notes":
		return []byte(it.Notes)
	case "otp":
		return it.OTP.Bytes()
	}
	return it.Value.Bytes()
}

func (a *app) cmdRead(args []string) error {
	fs, c := a.flags("read")
	force := fs.Bool("force", false, "print to a terminal")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: goraz read goraz://NAME[#FIELD]")
	}
	name, field, err := parseRef(pos[0])
	if err != nil {
		return err
	}
	if a.stdoutIsTTY() && !*force {
		return errors.New("refusing to print a secret to a terminal; use --force or a pipe")
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	it, err := v.Get(name)
	if err != nil {
		return err
	}
	defer it.Wipe()
	_, err = a.stdout.Write(fieldOf(it, field))
	return err
}

func (a *app) cmdList(args []string) error {
	fs, c := a.flags("ls")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	list, err := v.List()
	if err != nil {
		return err
	}
	for _, m := range list {
		fmt.Fprintf(a.stdout, "%s\t%s\tv%d\n", m.Name, m.Type, m.Versions[len(m.Versions)-1])
	}
	return nil
}

func (a *app) oneName(name string, args []string, f func(*vault.Vault, string) error) error {
	fs, c := a.flags(name)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: goraz %s NAME", name)
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	return f(v, pos[0])
}

func (a *app) cmdDelete(args []string) error {
	return a.oneName("rm", args, func(v *vault.Vault, n string) error { return v.Delete(n) })
}

func (a *app) cmdDestroy(args []string) error {
	return a.oneName("destroy", args, func(v *vault.Vault, n string) error {
		if err := v.Destroy(n); err != nil {
			return err
		}
		a.warn("removed from this file; backups and filesystem snapshots may still hold old copies")
		return nil
	})
}

func (a *app) cmdHistory(args []string) error {
	return a.oneName("history", args, func(v *vault.Vault, n string) error {
		m, err := v.History(n)
		if err != nil {
			return err
		}
		for _, x := range m.Versions {
			fmt.Fprintf(a.stdout, "v%d\n", x)
		}
		if m.Deleted {
			fmt.Fprintln(a.stdout, "(deleted)")
		}
		return nil
	})
}

func (a *app) cmdRestore(args []string) error {
	fs, c := a.flags("restore")
	ver := fs.Uint("version", 0, "version (default: latest existing)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: goraz restore NAME [--version N]")
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	return v.Restore(pos[0], uint32(*ver)) // #nosec G115 -- an out-of-range value simply isn't found.
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type envMap []string

func (e *envMap) String() string { return strings.Join(*e, ",") }

// Set implements flag.Value.
func (e *envMap) Set(s string) error {
	*e = append(*e, s)
	return nil
}

func parseMapping(s string) (key, name, field string, err error) {
	k, ref, ok := strings.Cut(s, "=")
	if !ok || !envName.MatchString(k) {
		return "", "", "", errors.New("an environment mapping must look like KEY=goraz://NAME")
	}
	name, field, err = parseRef(ref)
	return k, name, field, err
}

// parseEnvFile reads references only. It holds no secrets, so it can be committed.
func parseEnvFile(data []byte) ([]string, error) {
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func (a *app) cmdRun(args []string) error {
	fs, c := a.flags("run")
	var env envMap
	fs.Var(&env, "env", "KEY=goraz://NAME[#FIELD]; repeatable")
	envFile := fs.String("env-file", "", "a file of KEY=goraz://NAME lines, holding no secrets")
	noWarn := fs.Bool("no-warn", false, "don't print the environment warning")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return usagef("usage: goraz run --env KEY=goraz://NAME -- COMMAND [ARGS]")
	}
	if *envFile != "" {
		b, err := fsutil.ReadFile(*envFile, 1<<20, fsutil.Policy{FollowSymlinks: true, AllowRootOwner: true})
		if err != nil {
			return err
		}
		lines, err := parseEnvFile(b)
		if err != nil {
			return err
		}
		env = append(env, lines...)
	}
	type mapped struct{ key, name, field string }
	maps := make([]mapped, 0, len(env))
	for _, e := range env {
		k, n, f, err := parseMapping(e)
		if err != nil {
			return err
		}
		maps = append(maps, mapped{k, n, f})
	}
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	// A mapped key must replace any inherited value: with both present, many programs
	// would read the first and never see the secret.
	mappedKeys := make(map[string]bool, len(maps))
	for _, m := range maps {
		mappedKeys[m.key] = true
	}
	envv := filterEnv(os.Environ(), mappedKeys)
	for _, m := range maps {
		it, err := v.Get(m.name)
		if err != nil {
			v.Close()
			return err
		}
		envv = append(envv, m.key+"="+string(fieldOf(it, m.field)))
		it.Wipe()
	}
	v.Close()
	if !*noWarn {
		a.warn("secrets in an environment can be read by other processes of this user, and programs may log them")
	}
	harden.RestoreBeforeExec()
	// Replacing this process means no parent stays behind holding keys, and signals
	// reach the program directly.
	return syscall.Exec(bin, argv, envv) // #nosec G204 -- running a named program is this command's purpose.
}

func filterEnv(env []string, drop map[string]bool) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if !drop[k] {
			out = append(out, e)
		}
	}
	return out
}

func (a *app) cmdImport(args []string) error {
	fs, c := a.flags("import")
	prefix := fs.String("prefix", "", "name prefix for imported items")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: goraz import FILE --prefix NAME")
	}
	data, err := fsutil.ReadFile(pos[0], format.MaxManifestSize, fsutil.Policy{FollowSymlinks: true})
	if err != nil {
		return err
	}
	defer clear(data)
	entries, err := parseDotEnv(data)
	if err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	for _, e := range entries {
		name := e.Key
		if *prefix != "" {
			name = *prefix + "/" + e.Key
		}
		if err := v.Put(&vault.Item{Name: name, Value: secret.Adopt(e.Value)}); err != nil {
			return err
		}
		clear(e.Value)
	}
	fmt.Fprintf(a.stdout, "Imported %d items.\n", len(entries))
	return nil
}

type dotEnvEntry struct {
	Key   string
	Value []byte
}

// parseDotEnv is a deliberately small parser: no expansion, no command substitution
// and no multi-line values. Its errors give only a line number, never content.
func parseDotEnv(data []byte) ([]dotEnvEntry, error) {
	var out []dotEnvEntry
	seen := map[string]bool{}
	for i, raw := range bytes.Split(data, []byte("\n")) {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		line = bytes.TrimPrefix(line, []byte("export "))
		k, val, ok := bytes.Cut(line, []byte("="))
		if !ok {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", i+1)
		}
		key := string(bytes.TrimSpace(k))
		if !envName.MatchString(key) {
			return nil, fmt.Errorf("line %d: invalid key", i+1)
		}
		if seen[key] {
			return nil, fmt.Errorf("line %d: repeated key", i+1)
		}
		seen[key] = true
		val = bytes.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') {
			if val[len(val)-1] != val[0] {
				return nil, fmt.Errorf("line %d: unterminated quote", i+1)
			}
			val = val[1 : len(val)-1]
		} else if len(val) > 0 && (val[0] == '"' || val[0] == '\'') {
			return nil, fmt.Errorf("line %d: unterminated quote", i+1)
		}
		if len(val) == 0 {
			return nil, fmt.Errorf("line %d: empty value", i+1)
		}
		out = append(out, dotEnvEntry{Key: key, Value: bytes.Clone(val)})
	}
	return out, nil
}

type exportItem struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Value    []byte   `json:"value,omitempty"`
	OTP      []byte   `json:"otp,omitempty"`
	Username string   `json:"username,omitempty"`
	URLs     []string `json:"urls,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

func (a *app) cmdExport(args []string) error {
	fs, c := a.flags("export")
	out := fs.String("out", "", "output file, created with mode 0600")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usagef("usage: goraz export --out FILE (the file holds every secret in plain text)")
	}
	if _, err := os.Lstat(*out); err == nil {
		return errors.New("the output file already exists")
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	list, err := v.List()
	if err != nil {
		return err
	}
	items := make([]exportItem, 0, len(list))
	defer func() {
		for _, it := range items {
			clear(it.Value)
			clear(it.OTP)
		}
	}()
	for _, m := range list {
		it, err := v.Get(m.Name)
		if err != nil {
			return err
		}
		items = append(items, exportItem{
			Name: it.Name, Type: string(it.Type), Value: it.Value.Bytes(), OTP: it.OTP.Bytes(),
			Username: it.Username, URLs: it.URLs, Notes: it.Notes,
		})
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	defer clear(b)
	// Created with O_EXCL, so a file made since the check above is never replaced.
	if err := fsutil.WriteNew(*out, b); err != nil {
		return err
	}
	a.warn("the export file holds every secret in plain text; delete it as soon as possible")
	return nil
}

func (a *app) newPassphrase(fd int) ([]byte, error) {
	if fd >= 0 {
		return readFD(fd)
	}
	p, err := a.readHidden("New passphrase: ")
	if err != nil {
		return nil, err
	}
	q, err := a.readHidden("Repeat passphrase: ")
	if err != nil {
		return nil, err
	}
	defer clear(q)
	if subtle.ConstantTimeCompare(p, q) != 1 {
		clear(p)
		return nil, errors.New("the passphrases don't match")
	}
	return p, nil
}

func (a *app) cmdPasswd(args []string) error {
	fs, c := a.flags("passwd")
	newFD := fs.Int("new-passphrase-fd", -1, "read the new passphrase from this file descriptor")
	profile := fs.String("kdf", string(vault.ProfileStrong), "KDF profile")
	acceptWeak := fs.Bool("accept-weak-passphrase", false, "skip the passphrase policy")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	prof := vault.Profile(*profile)
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	next, err := a.newPassphrase(*newFD)
	if err != nil {
		return err
	}
	defer clear(next)
	kf, err := readKeyfile(c.keyfile)
	if err != nil {
		return err
	}
	if err := v.ChangePassphrase(next, kf, prof, *acceptWeak); err != nil {
		return err
	}
	a.warn("this does not revoke the old passphrase: with an old copy of the file it still works. After a suspected exposure, run goraz rekey")
	return nil
}

func (a *app) cmdSlot(args []string) error {
	if len(args) == 0 {
		return usagef("usage: goraz slot list|add-machine|add-recovery|remove")
	}
	sub, rest := args[0], args[1:]
	fs, c := a.flags("slot " + sub)
	pos, err := parse(fs, rest)
	if err != nil {
		return err
	}
	if err := checkArgs("slot", sub, pos, "remove"); err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	switch sub {
	case "list":
		for _, s := range v.Slots() {
			fmt.Fprintf(a.stdout, "%s\t%s\n", s.ID, s.Type)
		}
		return nil
	case "add-machine":
		a.warn("a machine key opens the whole vault; for a service, use goraz service create instead")
		k, err := v.AddMachineKey()
		if err != nil {
			return err
		}
		defer k.Wipe()
		fmt.Fprintf(a.stdout, "%s\n", k.Bytes())
		return nil
	case "add-recovery":
		k, err := v.AddRecoveryCode()
		if err != nil {
			return err
		}
		defer k.Wipe()
		fmt.Fprintf(a.stdout, "%s\n", k.Bytes())
		return nil
	case "remove":
		if len(pos) != 1 {
			return usagef("usage: goraz slot remove ID")
		}
		if err := v.RemoveSlot(pos[0]); err != nil {
			return err
		}
		a.warn("this does not revoke the credential: with an old copy of the file it still works. After a suspected exposure, run goraz rekey")
		return nil
	}
	return fmt.Errorf("unknown slot command %q", sub)
}

func (a *app) cmdRekey(args []string) error {
	fs, c := a.flags("rekey")
	newFD := fs.Int("new-passphrase-fd", -1, "read the new passphrase from this file descriptor")
	profile := fs.String("kdf", string(vault.ProfileStrong), "KDF profile")
	keep := fs.Bool("keep-tokens", false, "keep verifier keys, for a routine rekey with no suspected compromise")
	reissue := fs.Int("reissue-machine", 0, "how many new machine keys to create")
	yes := fs.Bool("confirm-saved", false, "don't ask: the caller has arranged to save the new credentials from stdout")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	prof := vault.Profile(*profile)
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	next, err := a.newPassphrase(*newFD)
	if err != nil {
		return err
	}
	defer clear(next)
	kf, err := readKeyfile(c.keyfile)
	if err != nil {
		return err
	}
	err = v.Rekey(vault.RekeyOptions{
		Passphrase: next, Keyfile: kf, Profile: prof, KeepTokens: *keep, ReissueMachine: *reissue,
		Confirm: func(r vault.RekeyResult) error {
			// If these can't be written, the rekey must not go ahead.
			if _, err := fmt.Fprintf(a.stdout, "New recovery code (shown once):\n%s\n", r.RecoveryCode.Bytes()); err != nil {
				return fmt.Errorf("the new recovery code couldn't be written, so the vault wasn't changed: %w", err)
			}
			for _, k := range r.MachineKeys {
				if _, err := fmt.Fprintf(a.stdout, "New machine key (shown once):\n%s\n", k.Bytes()); err != nil {
					return fmt.Errorf("a new machine key couldn't be written, so the vault wasn't changed: %w", err)
				}
			}
			if *yes {
				return nil
			}
			fmt.Fprint(a.stderr, "Type SAVED once these are stored safely. The vault won't change until then: ")
			line, err := bufio.NewReader(a.stdin).ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "SAVED" {
				return errors.New("not confirmed; the vault wasn't changed")
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	for _, s := range v.Services() {
		a.warn("service " + s.Name + " must now run: goraz service rotate")
	}
	a.warn("old copies of the file still open with old credentials. Rotate real credentials that may have been exposed")
	return nil
}

func (a *app) cmdState(args []string) error {
	if len(args) == 0 || args[0] != "reset" {
		return usagef("usage: goraz state reset")
	}
	fs, c := a.flags("state reset")
	if err := parseNoArgs(fs, args[1:]); err != nil {
		return err
	}
	p, err := c.path()
	if err != nil {
		return err
	}
	id, err := vault.IDFromFile(p)
	if err != nil {
		return err
	}
	dir, err := vault.DefaultStateDir()
	if err != nil {
		return err
	}
	if err := vault.ResetLocalState(dir, id); err != nil {
		return err
	}
	a.warn("this device will now trust whichever file it sees next")
	return nil
}

func (a *app) cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	length := fs.Int("length", password.DefaultLength, "length")
	symbols := fs.Bool("symbols", false, "include symbols")
	words := fs.Int("words", 0, "generate a passphrase with this many words")
	sep := fs.String("separator", "-", "passphrase separator")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usagef("goraz generate takes no arguments")
	}
	var s secret.Secret
	var err error
	if *words > 0 {
		s, err = password.Passphrase(*words, *sep)
	} else {
		alpha := password.DefaultAlphabet
		if *symbols {
			alpha = password.Lower + password.Upper + password.Digits + password.Symbols
		}
		s, err = password.Generate(*length, alpha)
	}
	if err != nil {
		return err
	}
	defer s.Wipe()
	fmt.Fprintf(a.stdout, "%s\n", s.Bytes())
	return nil
}

func (a *app) cmdTOTP(args []string) error {
	return a.oneName("totp", args, func(v *vault.Vault, n string) error {
		it, err := v.Get(n)
		if err != nil {
			return err
		}
		defer it.Wipe()
		if it.OTP.IsZero() {
			return errors.New("this item has no one-time code seed")
		}
		o, err := password.ParseOTPAuth(string(it.OTP.Bytes()))
		if err != nil {
			return err
		}
		defer o.Key.Wipe()
		code, err := o.Code(a.now())
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, code)
		return nil
	})
}

func (a *app) cmdReport(args []string) error {
	fs, c := a.flags("report")
	checkHIBP := fs.Bool("hibp", false, "check passwords against Have I Been Pwned (the only network use in goraz)")
	maxAge := fs.Duration("max-age", 365*24*time.Hour, "report values older than this")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	list, err := v.List()
	if err != nil {
		return err
	}
	seen := map[[32]byte][]string{}
	client := hibp.New()
	for _, m := range list {
		if m.Type != vault.TypeLogin && m.Type != vault.TypeSecret {
			continue
		}
		it, err := v.Get(m.Name)
		if err != nil {
			return err
		}
		val := it.Value.Bytes()
		if len(val) > 0 {
			sum := sha256.Sum256(val)
			seen[sum] = append(seen[sum], m.Name)
			if m.Type == vault.TypeLogin && len(val) < 12 {
				fmt.Fprintf(a.stdout, "short\t%s\n", m.Name)
			}
			if *checkHIBP && m.Type == vault.TypeLogin {
				n, err := client.Count(context.Background(), val)
				if err != nil {
					it.Wipe()
					return err
				}
				if n > 0 {
					fmt.Fprintf(a.stdout, "breached\t%s\t%d\n", m.Name, n)
				}
			}
		}
		if a.now().Sub(it.Updated) > *maxAge {
			fmt.Fprintf(a.stdout, "old\t%s\n", m.Name)
		}
		it.Wipe()
	}
	for _, group := range seen {
		if len(group) > 1 {
			fmt.Fprintf(a.stdout, "reused\t%s\n", strings.Join(group, ","))
		}
	}
	return nil
}

func parseID(s string) (token.ID, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return token.ID{}, errors.New("a token ID must be hexadecimal")
	}
	id, ok := token.ParseID(b)
	if !ok {
		return token.ID{}, errors.New("a token ID must be 16 bytes")
	}
	return id, nil
}

type scopeList []string

func (s *scopeList) String() string { return strings.Join(*s, ",") }

// Set implements flag.Value.
func (s *scopeList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func (a *app) cmdToken(args []string) error {
	if len(args) == 0 {
		return usagef("usage: goraz token issue|list|revoke|rotate|verify|expiring|rotate-verifier")
	}
	sub, rest := args[0], args[1:]
	fs, c := a.flags("token " + sub)
	svc := fs.String("service", "", "use this service's tokens")
	name := fs.String("name", "", "token name")
	ttl := fs.Duration("ttl", token.DefaultTTL, "lifetime; every token expires")
	overlap := fs.Duration("overlap", 0, "how long the old token or key keeps working")
	within := fs.Duration("within", 30*24*time.Hour, "report stored tokens expiring within this period")
	var scopes scopeList
	fs.Var(&scopes, "scope", "scope, repeatable; matched exactly")
	pos, err := parse(fs, rest)
	if err != nil {
		return err
	}
	if err := checkArgs("token", sub, pos, "revoke", "rotate"); err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx := context.Background()

	if *svc != "" && (sub == "expiring" || sub == "rotate-verifier") {
		return fmt.Errorf("token %s doesn't apply to one service; goraz service rotate replaces a service's verifier key", sub)
	}
	if sub == "expiring" {
		list, err := v.ExpiringTokens(*within)
		if err != nil {
			return err
		}
		for _, m := range list {
			fmt.Fprintf(a.stdout, "%s\t%s\n", m.Name, m.Expires.Format(time.RFC3339))
		}
		return nil
	}
	if sub == "rotate-verifier" {
		if err := v.RotateVerifierKey(*overlap); err != nil {
			return err
		}
		if *overlap == 0 {
			a.warn("tokens under the old key stopped working now")
		}
		return nil
	}

	var m *token.Manager
	if *svc != "" {
		m, err = v.ServiceTokens(*svc, nil)
	} else {
		m, err = v.Tokens(nil)
	}
	if err != nil {
		return err
	}
	switch sub {
	case "issue":
		tok, rec, err := m.Issue(ctx, token.IssueRequest{Name: *name, Scopes: scopes, TTL: *ttl})
		if err != nil {
			return err
		}
		defer tok.Wipe()
		fmt.Fprintf(a.stdout, "%s\n", tok.Bytes())
		fmt.Fprintf(a.stderr, "ID %s, expires %s. The token is shown once.\n", hex.EncodeToString(rec.ID), rec.Expires.Format(time.RFC3339))
		return nil
	case "list":
		store := v.TokenStore()
		if *svc != "" {
			store = serviceStore{v, *svc}
		}
		recs, err := store.List(ctx)
		if err != nil {
			return err
		}
		for _, r := range recs {
			st := "active"
			switch {
			case r.Revoked:
				st = "revoked"
			case !a.now().Before(r.Expires):
				st = "expired"
			case r.RevokeAt != nil && !a.now().Before(*r.RevokeAt):
				st = "revoked"
			case r.RevokeAt != nil:
				st = "rotating"
			}
			fmt.Fprintf(a.stdout, "%s\t%s\t%s\t%s\t%s\n", hex.EncodeToString(r.ID), r.Name, st, r.Expires.Format(time.RFC3339), strings.Join(r.Scopes, ","))
		}
		return nil
	case "revoke", "rotate":
		if len(pos) != 1 {
			return usagef("usage: goraz token %s ID", sub)
		}
		id, err := parseID(pos[0])
		if err != nil {
			return err
		}
		if sub == "revoke" {
			if err := m.Revoke(ctx, id); err != nil {
				return err
			}
			if *svc != "" {
				a.warn("this reaches the service only after goraz service sync, deployment and a reload")
			}
			return nil
		}
		tok, _, err := m.Rotate(ctx, id, *overlap)
		if err != nil {
			return err
		}
		defer tok.Wipe()
		fmt.Fprintf(a.stdout, "%s\n", tok.Bytes())
		return nil
	case "verify":
		b, err := a.readValue("Token: ")
		if err != nil {
			return err
		}
		defer clear(b)
		rec, err := m.Verify(ctx, bytes.TrimSpace(b), scopes...)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "valid\t%s\t%s\n", rec.Name, rec.Expires.Format(time.RFC3339))
		return nil
	}
	return fmt.Errorf("unknown token command %q", sub)
}

// serviceStore lists one service's records.
type serviceStore struct {
	v    *vault.Vault
	name string
}

func (s serviceStore) List(ctx context.Context) ([]token.Record, error) {
	return s.v.ServiceTokenRecords(s.name)
}
func (s serviceStore) Get(context.Context, token.ID) (token.Record, error) {
	return token.Record{}, token.ErrNotFound
}
func (s serviceStore) Put(context.Context, token.Record) error { return token.ErrReadOnly }

// writeKey adds a key to a key file, keeping existing lines so that a rotation can
// run with both keys. The operator removes the old line afterwards.
func writeKey(path string, key []byte) error {
	var data []byte
	if old, err := fsutil.ReadFile(path, 4096, fsutil.Policy{DenyOtherRead: true}); err == nil {
		data = append(data, old...)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			data = append(data, '\n')
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data = append(data, key...)
	data = append(data, '\n')
	defer clear(data)
	return fsutil.AtomicWrite(path, data, nil)
}

func (a *app) cmdService(args []string) error {
	if len(args) == 0 {
		return usagef("usage: goraz service create|sync|rotate|remove|list")
	}
	sub, rest := args[0], args[1:]
	fs, c := a.flags("service " + sub)
	out := fs.String("out", "", "where to write the service file; never stored")
	keyOut := fs.String("key-out", "", "where to write the machine key; never stored")
	validFor := fs.Duration("valid-for", 0, "authenticated validity window; needs a scheduled sync")
	var prefixes scopeList
	fs.Var(&prefixes, "prefix", "name prefix, repeatable; matches whole segments")
	pos, err := parse(fs, rest)
	if err != nil {
		return err
	}
	if err := checkArgs("service", sub, pos, "create", "sync", "rotate", "remove"); err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	if sub == "list" {
		for _, s := range v.Services() {
			flagText := ""
			if s.NeedsRotation {
				flagText = "\tNEEDS ROTATION"
			}
			fmt.Fprintf(a.stdout, "%s\tgeneration %d\t%d tokens\t%s%s\n", s.Name, s.Generation, s.Tokens, strings.Join(s.Prefixes, ","), flagText)
		}
		return nil
	}
	if len(pos) != 1 {
		return usagef("usage: goraz service %s NAME", sub)
	}
	name := pos[0]
	if *validFor != 0 && sub != "create" {
		return errors.New("--valid-for is set when a service is created")
	}
	if len(prefixes) > 0 && sub != "create" {
		return errors.New("--prefix is set when a service is created")
	}
	switch sub {
	case "create", "rotate":
		if *out == "" || *keyOut == "" {
			return usagef("usage: goraz service %s NAME --out FILE --key-out FILE", sub)
		}
		// The key is saved before anything is committed. A failure changes nothing, so
		// no file can exist whose key nobody holds.
		save := func(k []byte) error {
			if err := writeKey(*keyOut, k); err != nil {
				return fmt.Errorf("the key couldn't be saved, so nothing was changed: %w", err)
			}
			return nil
		}
		var key secret.Secret
		if sub == "create" {
			key, err = v.CreateService(name, *out, vault.ServiceOptions{Prefixes: prefixes, ValidFor: *validFor, SaveKey: save})
		} else {
			key, err = v.RotateService(name, *out, save)
		}
		defer key.Wipe()
		if err != nil {
			if !key.IsZero() {
				return fmt.Errorf("the key was saved, but the service file wasn't written; run goraz service sync: %w", err)
			}
			return err
		}
		if sub == "rotate" {
			fmt.Fprintln(a.stderr, "Deploy the key file first, then the service file, then remove the old key's line.")
		}
		return nil
	case "sync":
		if *out == "" {
			return usagef("usage: goraz service sync NAME --out FILE")
		}
		if err := v.SyncService(name, *out); err != nil {
			return err
		}
		for _, s := range v.Services() {
			if s.Name == name && s.Tokens > 0 && s.ValidFor == 0 {
				a.warn("this service has tokens and no --valid-for window: if someone holds back the file, only each token's TTL limits a revoked token")
			}
		}
		return nil
	case "remove":
		return v.RemoveService(name)
	}
	return fmt.Errorf("unknown service command %q", sub)
}

func (a *app) cmdAudit(args []string) error {
	if len(args) == 0 {
		return usagef("usage: goraz audit verify|hash|tail|rotate-key")
	}
	sub, rest := args[0], args[1:]
	fs, c := a.flags("audit " + sub)
	pos, err := parse(fs, rest)
	if err != nil {
		return err
	}
	if err := checkArgs("audit", sub, pos, "hash"); err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	switch sub {
	case "verify":
		r, err := v.VerifyAudit()
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "valid: %d entries, head %d", r.Entries, r.Head.Seq)
		if r.Gap {
			fmt.Fprint(a.stdout, ", with a recorded gap")
		}
		fmt.Fprintln(a.stdout)
		return nil
	case "hash":
		if len(pos) != 1 {
			return usagef("usage: goraz audit hash NAME")
		}
		h, err := v.AuditHash(pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, h)
		return nil
	case "tail":
		es, err := v.ReadAudit()
		if err != nil {
			return err
		}
		for _, e := range es {
			fmt.Fprintf(a.stdout, "%d\t%s\t%s\t%s\t%s\t%s\n", e.Seq, e.Time.Format(time.RFC3339), e.Type, e.Outcome, e.Actor, e.Object)
		}
		return nil
	case "rotate-key":
		return v.RotateAuditKey()
	}
	return fmt.Errorf("unknown audit command %q", sub)
}

func (a *app) cmdVersion([]string) error {
	v := "(unknown)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		v = info.Main.Version
	}
	fmt.Fprintf(a.stdout, "goraz %s\n", v)
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (a *app) cmdDoctor(args []string) error {
	fs, c := a.flags("doctor")
	noVault := fs.Bool("no-vault", false, "report process protections only")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	s := harden.Status()
	fmt.Fprintf(a.stdout, "platform: %s\n", s.Platform)
	fmt.Fprintf(a.stdout, "core dumps disabled: %s\n", yesNo(s.CoreDumpsDisabled))
	if s.Platform == "linux" {
		fmt.Fprintf(a.stdout, "not dumpable: %s\n", yesNo(s.NotDumpable))
	}
	fmt.Fprintf(a.stdout, "Go secret mode: %s\n", yesNo(s.SecretMode))
	fmt.Fprintln(a.stdout, "memory protection is best effort; use full-disk encryption")
	fmt.Fprintln(a.stdout, "independent security audit: none")
	if *noVault {
		return nil
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	s = harden.Status()
	fmt.Fprintf(a.stdout, "master key memory locked: %s\n", yesNo(s.MemoryLocked))
	fmt.Fprintf(a.stdout, "generation: %d\n", v.Generation())
	fmt.Fprintf(a.stdout, "audit required: %s\n", yesNo(v.AuditRequired()))
	bad, err := v.FullCheck()
	if err != nil {
		return err
	}
	if len(bad) > 0 {
		fmt.Fprintf(a.stdout, "damaged items: %s\n", strings.Join(bad, ", "))
		return exitCodeError(1)
	}
	fmt.Fprintln(a.stdout, "all items verified")
	if _, err := v.VerifyAudit(); err != nil {
		fmt.Fprintf(a.stdout, "audit log: %v\n", err)
		return exitCodeError(1)
	}
	fmt.Fprintln(a.stdout, "audit log verified")
	return nil
}
