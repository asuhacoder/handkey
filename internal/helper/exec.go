// Package helper runs only in the caller's user session, never in the broker.
package helper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/asuhacoder/handkey/internal/broker"
)

// Redactor retains enough trailing bytes to redact matches split across writes.
type Redactor struct {
	mu      sync.Mutex
	writer  io.Writer
	secrets [][]byte
	pending []byte
	max     int
}

func NewRedactor(w io.Writer, values map[string]string) *Redactor {
	r := &Redactor{writer: w}
	for _, v := range values {
		if v != "" {
			r.secrets = append(r.secrets, []byte(v))
			if len(v) > r.max {
				r.max = len(v)
			}
		}
	}
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	return r
}
func (r *Redactor) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = append(r.pending, p...)
	return len(p), r.flush(false)
}
func (r *Redactor) Close() error { r.mu.Lock(); defer r.mu.Unlock(); return r.flush(true) }
func (r *Redactor) flush(final bool) error {
	for len(r.pending) > 0 {
		if !final && len(r.pending) < r.max {
			break
		}
		matched := 0
		for _, s := range r.secrets {
			if bytes.HasPrefix(r.pending, s) {
				matched = len(s)
				break
			}
		}
		if matched > 0 {
			if _, e := io.WriteString(r.writer, "[REDACTED]"); e != nil {
				return e
			}
			r.pending = r.pending[matched:]
		} else {
			if _, e := r.writer.Write(r.pending[:1]); e != nil {
				return e
			}
			r.pending = r.pending[1:]
		}
	}
	return nil
}
func Environment(base []string, bindings map[string]string, values map[string]string) []string {
	out := []string{}
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "OP_") || strings.HasPrefix(name, "HANDKEY_") {
			continue
		}
		if _, replaced := bindings[name]; !replaced {
			out = append(out, entry)
		}
	}
	for name, ref := range bindings {
		out = append(out, name+"="+values[ref])
	}
	return out
}
func Run(ctx context.Context, spec broker.Spec, values map[string]string, base []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(spec.Command) == 0 {
		return 2
	}
	cmd := exec.CommandContext(ctx, spec.Command[0], spec.Command[1:]...)
	cmd.Dir = spec.Directory
	cmd.Env = Environment(base, spec.Bindings, values)
	cmd.Stdin = stdin
	out, errout := NewRedactor(stdout, values), NewRedactor(stderr, values)
	if spec.Unredacted {
		cmd.Stdout = stdout
		cmd.Stderr = stderr
	} else {
		cmd.Stdout = out
		cmd.Stderr = errout
	}
	e := cmd.Run()
	oe, ee := out.Close(), errout.Close()
	if oe != nil || ee != nil {
		return 1
	}
	if e == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(e, &exit) {
		return exit.ExitCode()
	}
	_, _ = io.WriteString(stderr, "handkey: command could not be started\n")
	return 1
}
func CurrentEnvironment() []string { return os.Environ() }
