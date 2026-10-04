package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asuhacoder/handkey/internal/cryptobox"
)

const vaultID = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
const itemID = "bbbbbbbbbbbbbbbbbbbbbbbbbb"
const sentinel = "fixture-secret-never-in-state-or-audit"

var testRef = Ref{Vault: vaultID, Item: itemID, Field: "password"}

type fakeProvider struct {
	reads   atomic.Int32
	writes  atomic.Int32
	fail    bool
	token   []byte
	entered chan struct{}
	release chan struct{}
}

func (p *fakeProvider) Read(ctx context.Context, token []byte, refs []Ref) (map[string]string, []Item, error) {
	p.reads.Add(1)
	p.token = token
	if p.entered != nil {
		p.entered <- struct{}{}
		<-p.release
	}
	if p.fail {
		return nil, nil, errors.New(sentinel)
	}
	v := map[string]string{}
	for _, r := range refs {
		v[r.Key()] = sentinel
	}
	return v, []Item{fixtureItem()}, nil
}
func (p *fakeProvider) List(context.Context, []byte) ([]Item, error) {
	return []Item{fixtureItem()}, nil
}
func (p *fakeProvider) Create(ctx context.Context, token []byte, c Create, id string) (Item, error) {
	p.writes.Add(1)
	p.token = token
	if p.fail {
		return Item{}, errors.New(sentinel)
	}
	return fixtureItem(), nil
}
func fixtureItem() Item {
	return Item{ID: itemID, Vault: vaultID, VaultName: "Main", Title: "Example", URLs: []string{"https://name:password@example.com/private?token=secret#fragment"}, FieldsKnown: true, Fields: []Field{{ID: "password", Label: "password", Type: "CONCEALED"}, {ID: "username", Label: "username", Type: "STRING"}}}
}
func setup(t *testing.T) (*Broker, *fakeProvider, Credentials, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	p := &fakeProvider{}
	b, e := Open(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if !b.closed {
			b.Close()
		}
	})
	key := cryptobox.Random(32)
	c, e := b.Bootstrap("phone", key, []byte("service-token-fixture"))
	if e != nil {
		t.Fatal(e)
	}
	return b, p, c, key, dir
}
func submit(t *testing.T, b *Broker, s Spec) Receipt {
	t.Helper()
	r, e := b.Submit(s, "unix-peer")
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func approve(t *testing.T, b *Broker, r Receipt, c Credentials, key []byte) {
	t.Helper()
	if e := b.Approve(context.Background(), r.ID, c.ID, key); e != nil {
		t.Fatal(e)
	}
}
func TestApprovalReceiptAndLeastData(t *testing.T) {
	b, p, c, key, dir := setup(t)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	if p.reads.Load() != 0 {
		t.Fatal("read before approval")
	}
	if _, e := b.Consume(r.ID, r.Token); e == nil {
		t.Fatal("unapproved consume")
	}
	if e := b.Approve(context.Background(), r.ID, c.ID, cryptobox.Random(32)); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	approve(t, b, r, c, key)
	if _, e := b.Consume(r.ID, c.ViewToken); e == nil {
		t.Fatal("view token consumed result")
	}
	if _, e := b.Consume(r.ID, cryptobox.Token()); e == nil {
		t.Fatal("foreign receipt")
	}
	result, e := b.Consume(r.ID, r.Token)
	if e != nil || result.Values[testRef.Key()] != sentinel {
		t.Fatal(e)
	}
	if len(result.Values) != 1 {
		t.Fatal("extra fields")
	}
	if _, e = b.Consume(r.ID, r.Token); e == nil {
		t.Fatal("second use")
	}
	if !bytes.Equal(p.token, make([]byte, len(p.token))) {
		t.Fatal("service token retained")
	}
	for _, file := range []string{"state.enc", "audit.jsonl"} {
		raw, e := os.ReadFile(filepath.Join(dir, file))
		if e != nil {
			t.Fatal(e)
		}
		for _, secret := range []string{sentinel, "service-token-fixture", r.Token, c.ViewToken} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatalf("secret in %s", file)
			}
		}
	}
	cached, _, e := b.Metadata("", false)
	if e != nil || cached[0].URLs[0] != "https://example.com" {
		t.Fatal(cached, e)
	}
}
func TestConcurrentDecisionsExecuteOnce(t *testing.T) {
	b, p, c, key, _ := setup(t)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.Approve(context.Background(), r.ID, c.ID, key) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || p.reads.Load() != 1 {
		t.Fatalf("success=%d reads=%d", successes.Load(), p.reads.Load())
	}
}
func TestCancelDenyExpireWin(t *testing.T) {
	for _, action := range []string{"cancel", "deny", "expire"} {
		t.Run(action, func(t *testing.T) {
			b, p, c, key, _ := setup(t)
			r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}, WaitSeconds: 1})
			switch action {
			case "cancel":
				if e := b.Cancel(r.ID, r.Token); e != nil {
					t.Fatal(e)
				}
			case "deny":
				if e := b.Reject(r.ID, c.ID); e != nil {
					t.Fatal(e)
				}
			case "expire":
				future := time.Now().Add(2 * time.Second)
				b.now = func() time.Time { return future }
			}
			if e := b.Approve(context.Background(), r.ID, c.ID, key); !errors.Is(e, ErrConflict) {
				t.Fatal(e)
			}
			if p.reads.Load() != 0 {
				t.Fatal("executed")
			}
		})
	}
}
func TestLeaseLifetimeAndRestart(t *testing.T) {
	b, p, c, key, dir := setup(t)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}, TTLSeconds: 60, Uses: 2})
	approve(t, b, r, c, key)
	if _, e := b.Consume(r.ID, r.Token); e != nil {
		t.Fatal(e)
	}
	if p.reads.Load() != 1 {
		t.Fatal("unexpected provider read")
	}
	b.Close()
	next, e := Open(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	status, e := next.Status(r.ID, r.Token)
	if e != nil || status.Execution != "expired" {
		t.Fatal(status, e)
	}
	if _, e = next.Consume(r.ID, r.Token); e == nil {
		t.Fatal("restarted lease")
	}
}
func TestLeaseExpiryAndCountAreAtomic(t *testing.T) {
	b, _, c, key, _ := setup(t)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}, TTLSeconds: 60, Uses: 3})
	approve(t, b, r, c, key)
	var wg sync.WaitGroup
	var got atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := b.Consume(r.ID, r.Token); e == nil {
				got.Add(1)
			}
		}()
	}
	wg.Wait()
	if got.Load() != 3 {
		t.Fatal(got.Load())
	}
	r = submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}, TTLSeconds: 1})
	approve(t, b, r, c, key)
	future := time.Now().Add(2 * time.Second)
	b.now = func() time.Time { return future }
	if _, e := b.Consume(r.ID, r.Token); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
}
func TestPendingAndUnknownWriteRecovery(t *testing.T) {
	b, p, _, _, dir := setup(t)
	pending := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	write := submit(t, b, Spec{Method: "write", Create: &Create{Vault: vaultID, Title: "new", Category: "LOGIN"}})
	b.st.Requests[write.ID].Approval = "approved"
	b.st.Requests[write.ID].Execution = "running"
	if e := b.disk.save(&b.st); e != nil {
		t.Fatal(e)
	}
	b.Close()
	next, e := Open(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	s, e := next.Status(write.ID, write.Token)
	if e != nil || s.Execution != "unknown" {
		t.Fatal(s, e)
	}
	s, e = next.Status(pending.ID, pending.Token)
	if e != nil || s.Approval != "pending" {
		t.Fatal(s, e)
	}
	if p.writes.Load() != 0 {
		t.Fatal("write retried")
	}
}
func TestDeviceRevocationAndRotation(t *testing.T) {
	b, _, c, key, _ := setup(t)
	k2 := cryptobox.Random(32)
	c2, e := b.AddDevice(c.ID, key, "ring", k2)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Revoke(c.ID, key, c2.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = b.View(c2.ViewToken); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	if e = b.Approve(context.Background(), r.ID, c2.ID, k2); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	if e = b.Rotate(c.ID, key, []byte("rotated-token")); e != nil {
		t.Fatal(e)
	}
	approve(t, b, r, c, key)
	renewed, e := b.Renew(c.ID, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.View(c.ViewToken); e == nil {
		t.Fatal("old view token")
	}
	if _, e = b.View(renewed.ViewToken); e != nil {
		t.Fatal(e)
	}
}
func TestRequestValidationAndFreezing(t *testing.T) {
	b, _, _, _, _ := setup(t)
	for _, s := range []Spec{{Method: "unknown"}, {Method: "reveal", Refs: []Ref{testRef}, Uses: 2}, {Method: "write", TTLSeconds: 10}, {Method: "proxy", Refs: []Ref{testRef}, Origin: "https://example.com/path", Command: []string{"true"}, Directory: "/"}, {Method: "exec", Refs: []Ref{testRef}, Bindings: map[string]string{"OP_SERVICE_ACCOUNT_TOKEN": testRef.Key()}, Command: []string{"true"}, Directory: "/"}} {
		if _, e := b.Submit(s, ""); e == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
	s := Spec{Method: "exec", Refs: []Ref{testRef}, Bindings: map[string]string{"SECRET": testRef.Key()}, Command: []string{"true"}, Directory: "/"}
	r := submit(t, b, s)
	s.Command[0] = "changed"
	s.Bindings["SECRET"] = "changed"
	got, e := b.Status(r.ID, r.Token)
	if e != nil || got.Spec.Command[0] != "true" || got.Spec.Bindings["SECRET"] != testRef.Key() {
		t.Fatal("mutable request")
	}
}
func TestFailureDoesNotDiscloseProviderError(t *testing.T) {
	b, p, c, key, dir := setup(t)
	p.fail = true
	r := submit(t, b, Spec{Method: "write", Create: &Create{Vault: vaultID, Title: "new", Category: "LOGIN", Fields: []CreateField{{ID: "password", Type: "CONCEALED", Value: sentinel}}}})
	approve(t, b, r, c, key)
	status, _ := b.Status(r.ID, r.Token)
	raw, _ := json.Marshal(status)
	if strings.Contains(string(raw), sentinel) || status.Execution != "unknown" {
		t.Fatal("unsafe write result")
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if strings.Contains(string(raw), sentinel) {
		t.Fatal("audit leak")
	}
}
func TestStateLockAndEncryptedIntegrity(t *testing.T) {
	b, p, _, _, dir := setup(t)
	if other, e := Open(dir, p); e == nil {
		other.Close()
		t.Fatal("second broker")
	}
	b.Close()
	raw, e := os.ReadFile(filepath.Join(dir, "state.enc"))
	if e != nil {
		t.Fatal(e)
	}
	raw[len(raw)-1] ^= 1
	_ = os.WriteFile(filepath.Join(dir, "state.enc"), raw, 0600)
	if other, e := Open(dir, p); e == nil {
		other.Close()
		t.Fatal("corruption accepted")
	}
}
func TestNamesNormalizeAtSubmission(t *testing.T) {
	b, _, c, key, _ := setup(t)
	refresh := submit(t, b, Spec{Method: "refresh"})
	approve(t, b, refresh, c, key)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{{Vault: "Main", Item: "Example", Field: "password"}}})
	b.st.Cache[vaultID+"/"+itemID] = Item{Title: "Changed"}
	s, _ := b.Status(r.ID, r.Token)
	if s.Spec.Refs[0] != testRef {
		t.Fatal(s.Spec.Refs)
	}
}
func TestMetadataApproval(t *testing.T) {
	b, _, _, _, _ := setup(t)
	b.RequireMetadataApproval = true
	if _, _, e := b.Metadata("", false); e == nil {
		t.Fatal("unapproved metadata")
	}
	if _, _, e := b.Metadata("", true); e != nil {
		t.Fatal(e)
	}
}
func TestFailedPersistenceStopsExecution(t *testing.T) {
	b, p, c, key, dir := setup(t)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	if e := os.Remove(filepath.Join(dir, "state.enc")); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(dir, "state.enc"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := b.Approve(context.Background(), r.ID, c.ID, key); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if p.reads.Load() != 0 {
		t.Fatal("execution after failed durable commit")
	}
}
