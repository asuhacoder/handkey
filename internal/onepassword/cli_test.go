package onepassword

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/asuhacoder/handkey/internal/broker"
)

func fakeOP(t *testing.T, fail bool) (*CLI, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX op process fixture")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "op")
	script := `#!/bin/sh
test "$OP_SERVICE_ACCOUNT_TOKEN" = "fixture-token" || exit 10
test -z "$POISONED_ENV" || exit 11
test -z "$OP_SESSION_fixture" || exit 12
test "$1" = "--cache=false" || exit 13
printf '%s\n' "$@" > '` + dir + `/args'
cat > '` + dir + `/stdin'
`
	if fail {
		script += `echo 'fixture-secret and fixture-token must not leak' >&2; exit 1`
	} else {
		script += `printf '%s' '{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","vault":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaa","name":"Main"},"title":"Example","fields":[{"id":"password","type":"CONCEALED","label":"password","value":"fixture-secret"},{"id":"unapproved","type":"STRING","value":"do-not-return"}]}'`
	}
	if e := os.WriteFile(path, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("POISONED_ENV", "poison")
	t.Setenv("OP_SESSION_fixture", "poison")
	return &CLI{Path: path, TempDir: dir}, dir
}
func TestProcessIsolationAndFieldSelection(t *testing.T) {
	c, dir := fakeOP(t, false)
	ref := broker.Ref{Vault: "aaaaaaaaaaaaaaaaaaaaaaaaaa", Item: "bbbbbbbbbbbbbbbbbbbbbbbbbb", Field: "password"}
	values, items, e := c.Read(context.Background(), []byte("fixture-token"), []broker.Ref{ref})
	if e != nil || len(values) != 1 || values[ref.Key()] != "fixture-secret" || len(items) != 1 {
		t.Fatal(values, e)
	}
	raw, _ := json.Marshal(items)
	if strings.Contains(string(raw), "fixture-secret") || strings.Contains(string(raw), "do-not-return") {
		t.Fatal("metadata leak")
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if strings.Contains(string(args), "fixture-token") {
		t.Fatal("token in argv")
	}
}
func TestCreateUsesStdinAndRequestTag(t *testing.T) {
	c, dir := fakeOP(t, false)
	_, e := c.Create(context.Background(), []byte("fixture-token"), broker.Create{Vault: "aaaaaaaaaaaaaaaaaaaaaaaaaa", Title: "new", Category: "LOGIN", GeneratePassword: "letters,digits,32", Fields: []broker.CreateField{{ID: "username", Label: "username", Type: "STRING", Value: "input-secret"}}}, "request-id")
	if e != nil {
		t.Fatal(e)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	input, _ := os.ReadFile(filepath.Join(dir, "stdin"))
	if strings.Contains(string(args), "input-secret") || !strings.Contains(string(input), "input-secret") || !strings.Contains(string(input), "handkey-request:request-id") {
		t.Fatal("unsafe create")
	}
	if !strings.Contains(string(args), "--generate-password=letters,digits,32") {
		t.Fatal("generation recipe lost")
	}
	if !strings.Contains(string(args), "\n--vault\naaaaaaaaaaaaaaaaaaaaaaaaaa\n") {
		t.Fatalf("create argv missing --vault followed by literal vault ID: %q", strings.Split(strings.TrimSpace(string(args)), "\n"))
	}
}
func TestProcessErrorsAreSanitized(t *testing.T) {
	c, _ := fakeOP(t, true)
	_, e := c.run(context.Background(), []byte("fixture-token"), nil, "item", "list")
	if e == nil || strings.Contains(e.Error(), "fixture-secret") || strings.Contains(e.Error(), "fixture-token") {
		t.Fatal(e)
	}
}
