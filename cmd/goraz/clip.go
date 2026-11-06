package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/mtnaskari/goraz/internal/names"
)

var errClipTimer = errors.New("couldn't start the clipboard timer; clear the clipboard yourself")

type clipTool struct {
	copyArgs, pasteArgs []string
}

// Only fixed absolute paths are used, so a directory on PATH can't supply a fake
// clipboard program that would receive the secret.
func findClip() (*clipTool, error) {
	candidates := []clipTool{
		{[]string{"/usr/bin/pbcopy"}, []string{"/usr/bin/pbpaste"}},
		{[]string{"/usr/bin/wl-copy"}, []string{"/usr/bin/wl-paste", "--no-newline"}},
		{[]string{"/usr/bin/xclip", "-selection", "clipboard"}, []string{"/usr/bin/xclip", "-selection", "clipboard", "-o"}},
	}
	for i := range candidates {
		if st, err := os.Stat(candidates[i].copyArgs[0]); err == nil && !st.IsDir() {
			return &candidates[i], nil
		}
	}
	return nil, errors.New("no clipboard program found (pbcopy, wl-copy or xclip)")
}

func (t *clipTool) copyValue(val []byte) error {
	c := exec.Command(t.copyArgs[0], t.copyArgs[1:]...) // #nosec G204 -- fixed paths from findClip.
	c.Stdin = bytes.NewReader(val)
	return c.Run()
}

func (t *clipTool) paste() ([]byte, error) {
	return exec.Command(t.pasteArgs[0], t.pasteArgs[1:]...).Output() // #nosec G204 -- fixed paths from findClip.
}

func (a *app) cmdClip(args []string) error {
	fs, c := a.flags("clip")
	after := fs.Duration("clear-after", 20*time.Second, "clear the clipboard after this long, at most 5 minutes")
	field := fs.String("field", "value", "field to copy")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: goraz clip NAME")
	}
	if err := names.Validate(pos[0]); err != nil {
		return err
	}
	if !validField(*field) {
		return errors.New("unknown field")
	}
	if *after <= 0 || *after > 5*time.Minute {
		return errors.New("--clear-after must be between 1 second and 5 minutes; it can't be disabled")
	}
	tool, err := findClip()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	v, err := a.open(c)
	if err != nil {
		return err
	}
	defer v.Close()
	it, err := v.Get(pos[0])
	if err != nil {
		return err
	}
	defer it.Wipe()
	val := fieldOf(it, *field)
	if len(val) == 0 {
		return errors.New("this item has no value in that field")
	}
	if err := tool.copyValue(val); err != nil {
		return errors.New("the clipboard program failed")
	}
	// The clearing process holds only a hash, sent on stdin rather than in its
	// arguments, because a hash of a weak password could be guessed.
	sum := sha256.Sum256(val)
	cl := exec.Command(self, "__clipclear", "--after", after.String()) // #nosec G204 -- this program itself.
	cl.SysProcAttr = &syscall.SysProcAttr{Setsid: true}                // It outlives this command and its terminal.
	in, err := cl.StdinPipe()
	if err != nil {
		return errClipTimer
	}
	if err := cl.Start(); err != nil {
		return errClipTimer
	}
	// The hash is written and the pipe closed before returning. A background copy
	// could be cut off when this process exits, and then nothing would ever clear.
	_, werr := io.WriteString(in, hex.EncodeToString(sum[:]))
	if cerr := in.Close(); werr != nil || cerr != nil {
		return errClipTimer
	}
	_ = cl.Process.Release()
	fmt.Fprintf(a.stderr, "Copied. It will be cleared in %s if unchanged. Clipboard history tools may keep their own copy.\n", after)
	return nil
}

func (a *app) cmdClipClear(args []string) error {
	fs := flag.NewFlagSet("__clipclear", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	after := fs.Duration("after", 20*time.Second, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(a.stdin, 128))
	if err != nil {
		return err
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	if len(want) != sha256.Size {
		return errors.New("invalid clipboard hash")
	}
	time.Sleep(*after)
	tool, err := findClip()
	if err != nil {
		return err
	}
	cur, err := tool.paste()
	if err != nil {
		return err
	}
	defer clear(cur)
	sum := sha256.Sum256(cur)
	if subtle.ConstantTimeCompare(sum[:], want) == 1 {
		return tool.copyValue(nil)
	}
	return nil
}
