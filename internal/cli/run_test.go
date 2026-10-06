package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/asuhacoder/handkey/internal/broker"
	"github.com/asuhacoder/handkey/internal/cryptobox"
)

const fixtureURI = "op://aaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbb/password"

type fixtureProvider struct{}

func (fixtureProvider) Read(_ context.Context, _ []byte, refs []broker.Ref) (map[string]string, []broker.Item, error) {
	v := map[string]string{}
	for _, r := range refs {
		v[r.Key()] = "private-fixture"
	}
	return v, nil, nil
}
func (fixtureProvider) List(context.Context, []byte) ([]broker.Item, error) { return nil, nil }
func (fixtureProvider) Create(context.Context, []byte, broker.Create, string) (broker.Item, error) {
	return broker.Item{ID: "created", Vault: "aaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
}
func cliFixture(t *testing.T) (*broker.Broker, string, broker.Credentials, []byte) {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	b, e := broker.Open(dir, fixtureProvider{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(b.Close)
	key := cryptobox.Random(32)
	c, e := b.Bootstrap("phone", key, []byte("test-token"))
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewServer(b.Handler(broker.HTTPOptions{Surfaces: broker.AgentSurface}))
	t.Cleanup(s.Close)
	return b, s.URL, c, key
}
func autoApprove(ctx context.Context, b *broker.Broker, c broker.Credentials, key []byte) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, r := range b.Requests() {
				_ = b.Approve(ctx, r.ID, c.ID, key)
			}
		}
	}
}
func TestCLIRevealEndToEnd(t *testing.T) {
	b, endpoint, c, key := cliFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go autoApprove(ctx, b, c, key)
	var out, errout bytes.Buffer
	path := filepath.Join(t.TempDir(), "receipt.json")
	r := Runner{In: strings.NewReader(""), Out: &out, Err: &errout, Cwd: t.TempDir()}
	code := r.Run(ctx, []string{"read", fixtureURI, "--endpoint", endpoint, "--dev", "--receipt", path})
	if code != 0 || out.String() != "private-fixture\n" {
		t.Fatal(code, out.String(), errout.String())
	}
	saved, e := LoadReceipt(path)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(errout.String(), saved.Receipt.Token) || strings.Contains(errout.String(), "private-fixture") {
		t.Fatal("receipt or secret logged")
	}
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("receipt permissions")
	}
}
func TestCLIExecEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command")
	}
	b, endpoint, c, key := cliFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go autoApprove(ctx, b, c, key)
	var out, errout bytes.Buffer
	r := Runner{In: strings.NewReader(""), Out: &out, Err: &errout, Env: []string{"SECRET=" + fixtureURI, "OP_SERVICE_ACCOUNT_TOKEN=forbidden"}, Cwd: t.TempDir()}
	code := r.Run(ctx, []string{"run", "--endpoint", endpoint, "--dev", "--receipt", filepath.Join(t.TempDir(), "receipt.json"), "--", "/bin/sh", "-c", `test -z "$OP_SERVICE_ACCOUNT_TOKEN" || exit 2; printf '%s' "$SECRET"; exit 6`})
	if code != 6 || out.String() != "[REDACTED]" {
		t.Fatal(code, out.String(), errout.String())
	}
}
func TestInjectWritesPrivateFile(t *testing.T) {
	b, endpoint, c, key := cliFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go autoApprove(ctx, b, c, key)
	var out, errout bytes.Buffer
	file := filepath.Join(t.TempDir(), "config")
	r := Runner{In: strings.NewReader("password={{ " + fixtureURI + " }}"), Out: &out, Err: &errout}
	code := r.Run(ctx, []string{"inject", "--endpoint", endpoint, "--dev", "--receipt", filepath.Join(t.TempDir(), "receipt.json"), "--out-file", file})
	raw, e := os.ReadFile(file)
	if code != 0 || e != nil || !strings.Contains(string(raw), "private-fixture") || out.Len() != 0 {
		t.Fatal(code, e, out.String(), errout.String())
	}
}
func TestCLINoWaitReceiptAndCancellation(t *testing.T) {
	_, endpoint, _, _ := cliFixture(t)
	var out, errout bytes.Buffer
	path := filepath.Join(t.TempDir(), "receipt.json")
	r := Runner{In: strings.NewReader(""), Out: &out, Err: &errout}
	code := r.Run(context.Background(), []string{"read", fixtureURI, "--endpoint", endpoint, "--dev", "--no-wait", "--receipt", path})
	if code != 0 {
		t.Fatal(errout.String())
	}
	saved, _ := LoadReceipt(path)
	if strings.Contains(out.String(), saved.Receipt.Token) {
		t.Fatal("printed receipt token")
	}
	out.Reset()
	code = r.Run(context.Background(), []string{"cancel", path, "--endpoint", endpoint, "--dev"})
	if code != 0 {
		t.Fatal(errout.String())
	}
	code = r.Run(context.Background(), []string{"status", path, "--endpoint", endpoint, "--dev"})
	if code != 0 || !strings.Contains(out.String(), "cancelled") {
		t.Fatal(out.String(), errout.String())
	}
}
func TestUnsupportedFlagsFailBeforeSubmitting(t *testing.T) {
	_, endpoint, _, _ := cliFixture(t)
	for _, args := range [][]string{{"read", fixtureURI, "--unknown"}, {"read", fixtureURI, "--no-masking"}, {"item", "edit", "id"}, {"run", "--env-file", "missing", "--", "echo"}, {"item", "list", "--format", "csv"}} {
		var out, errout bytes.Buffer
		r := Runner{In: strings.NewReader(""), Out: &out, Err: &errout}
		args = append([]string{"--endpoint", endpoint, "--dev"}, args...)
		if r.Run(context.Background(), args) == 0 {
			t.Fatalf("accepted %v", args)
		}
	}
}
func TestEndpointAndReferenceValidation(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "http://127.0.0.1:123", "https://user:pass@example.com", "https://example.com/path", "unix://relative"} {
		if _, e := NewClient(endpoint, false); e == nil {
			t.Fatal("insecure endpoint accepted")
		}
	}
	for _, endpoint := range []string{"http://example.com", "http://localhost:123"} {
		if _, e := NewClient(endpoint, true); e == nil {
			t.Fatal("nonliteral loopback accepted")
		}
	}
	if _, e := NewClient("http://127.0.0.1:123", true); e != nil {
		t.Fatal(e)
	}
	for _, uri := range []string{"op://Main/Item", "https://example.com/x/y", "op://Main/Item/password?attribute=type"} {
		if _, e := ParseRef(uri); e == nil {
			t.Fatal("invalid reference")
		}
	}
	ref, e := ParseRef("op://Main%20Vault/Example%20Login/section/password")
	if e != nil || ref.Vault != "Main Vault" || ref.Item != "Example Login" || ref.Field != "section.password" {
		t.Fatal(ref, e)
	}
}
func TestReceiptNeverOverwrites(t *testing.T) {
	file := filepath.Join(t.TempDir(), "receipt")
	_ = os.WriteFile(file, []byte("original"), 0600)
	if _, e := SaveReceipt(file, "https://example.com", broker.Receipt{ID: "id", Token: "token"}); e == nil {
		t.Fatal("overwrote receipt")
	}
	raw, _ := os.ReadFile(file)
	if string(raw) != "original" {
		t.Fatal("changed file")
	}
}
func TestJSONItemGetIsReveal(t *testing.T) {
	b, endpoint, c, key := cliFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go autoApprove(ctx, b, c, key)
	var out, errout bytes.Buffer
	r := Runner{In: strings.NewReader(""), Out: &out, Err: &errout}
	code := r.Run(ctx, []string{"item", "get", "bbbbbbbbbbbbbbbbbbbbbbbbbb", "--vault", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "--fields", "password", "--format", "json", "--endpoint", endpoint, "--dev", "--receipt", filepath.Join(t.TempDir(), "receipt")})
	if code != 0 {
		t.Fatal(errout.String())
	}
	var values map[string]string
	if json.Unmarshal(out.Bytes(), &values) != nil || len(values) != 1 {
		t.Fatal(out.String())
	}
}
func TestHelpHasNoServerDependency(t *testing.T) {
	var out bytes.Buffer
	r := Runner{Out: &out, Err: io.Discard}
	if r.Run(context.Background(), []string{"--help"}) != 0 || !strings.Contains(out.String(), "Receipt") {
		t.Fatal("help")
	}
}
