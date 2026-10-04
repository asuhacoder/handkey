package helper

import (
	"bytes"
	"context"
	"github.com/asuhacoder/handkey/internal/broker"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestRedactionAcrossAllChunkBoundaries(t *testing.T) {
	for width := 1; width < 30; width++ {
		var out bytes.Buffer
		r := NewRedactor(&out, map[string]string{"a": "supersecret", "b": "secret", "c": ""})
		input := "start supersecret secret finish"
		for i := 0; i < len(input); i += width {
			end := i + width
			if end > len(input) {
				end = len(input)
			}
			if _, e := r.Write([]byte(input[i:end])); e != nil {
				t.Fatal(e)
			}
		}
		if e := r.Close(); e != nil {
			t.Fatal(e)
		}
		if out.String() != "start [REDACTED] [REDACTED] finish" {
			t.Fatalf("chunk=%d: %s", width, out.String())
		}
	}
}
func TestChildDoesNotInheritBrokerCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	var out, errout bytes.Buffer
	dir := t.TempDir()
	s := broker.Spec{Command: []string{"/bin/sh", "-c", `printf '%s' "$SECRET"; printf '%s' "$SECRET" >&2; test -z "$OP_SERVICE_ACCOUNT_TOKEN" && test -z "$HANDKEY_ENDPOINT"; exit 7`}, Directory: dir, Bindings: map[string]string{"SECRET": "ref"}}
	code := Run(context.Background(), s, map[string]string{"ref": "sensitive-value"}, []string{"PATH=/usr/bin:/bin", "OP_SERVICE_ACCOUNT_TOKEN=vault-token", "HANDKEY_ENDPOINT=endpoint"}, strings.NewReader(""), &out, &errout)
	if code != 7 || strings.Contains(out.String()+errout.String(), "sensitive-value") || !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatal(code, out.String(), errout.String())
	}
	if _, e := os.Stat(dir); e != nil {
		t.Fatal(e)
	}
}
func TestEnvironmentReplacement(t *testing.T) {
	env := Environment([]string{"A=old", "OP_SESSION_x=bad", "HANDKEY_KEY=bad", "B=keep"}, map[string]string{"A": "ref"}, map[string]string{"ref": "new"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "old") || strings.Contains(joined, "bad") || !strings.Contains(joined, "A=new") || !strings.Contains(joined, "B=keep") {
		t.Fatal(env)
	}
}
