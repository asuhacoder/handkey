package broker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/asuhacoder/handkey/internal/cryptobox"
)

func TestRequestDisplayCached(t *testing.T) {
	b, _, c, key, _ := setup(t)
	refresh := submit(t, b, Spec{Method: "refresh"})
	approve(t, b, refresh, c, key)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{{Vault: "Main", Item: "Example", Field: "password"}}})
	want := &RequestDisplay{Refs: []RefDisplay{{Vault: vaultID, Item: itemID, Field: "password", VaultName: "Main", ItemTitle: "Example", FieldLabel: "password", FieldType: "CONCEALED", Origins: []string{"https://example.com"}, Known: true}}}
	s, e := b.Status(r.ID, r.Token)
	if e != nil || !reflect.DeepEqual(s.Display, want) || s.Spec.Refs[0] != testRef {
		t.Fatal(s, e)
	}
	requests := b.Requests()
	if len(requests) != 1 || !reflect.DeepEqual(requests[0].Display, want) {
		t.Fatal(requests)
	}
	h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	for _, path := range []string{"/v1/requests/" + r.ID, "/v1/requests"} {
		w := httpCall(t, h, "GET", path, c.ViewToken, nil, "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"display"`) {
			t.Fatal(w.Code, w.Body.String())
		}
		var got Request
		if path == "/v1/requests" {
			var list []Request
			if e := json.Unmarshal(w.Body.Bytes(), &list); e != nil || len(list) != 1 {
				t.Fatal(list, e)
			}
			got = list[0]
		} else if e := json.Unmarshal(w.Body.Bytes(), &got); e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(got.Display, want) {
			t.Fatal(got.Display)
		}
	}
	s.Display.Refs[0].Origins[0] = "https://changed.example"
	approve(t, b, r, c, key)
	result, e := b.Consume(r.ID, r.Token)
	if e != nil || !reflect.DeepEqual(result.Request.Display, want) {
		t.Fatal(result, e)
	}
}

func TestRequestDisplayUncached(t *testing.T) {
	b, _, _, _, _ := setup(t)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	s, e := b.Status(r.ID, r.Token)
	want := &RequestDisplay{Refs: []RefDisplay{{Vault: vaultID, Item: itemID, Field: "password", Origins: []string{}}}}
	if e != nil || !reflect.DeepEqual(s.Display, want) {
		t.Fatal(s, e)
	}
	r = submit(t, b, Spec{Method: "refresh"})
	s, e = b.Status(r.ID, r.Token)
	raw, err := json.Marshal(s)
	if e != nil || err != nil || !strings.Contains(string(raw), `"display":{"refs":[]}`) {
		t.Fatal(string(raw), e, err)
	}
}

func TestRequestDisplayUnknownField(t *testing.T) {
	b, _, _, _, _ := setup(t)
	item := fixtureItem()
	item.FieldsKnown, item.Fields = false, nil
	b.st.Cache[vaultID+"/"+itemID] = item
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	s, e := b.Status(r.ID, r.Token)
	want := &RequestDisplay{Refs: []RefDisplay{{Vault: vaultID, Item: itemID, Field: "password", VaultName: "Main", ItemTitle: "Example", Origins: []string{"https://example.com"}}}}
	if e != nil || !reflect.DeepEqual(s.Display, want) {
		t.Fatal(s, e)
	}
}

func TestHTTPRejectsRequestDisplay(t *testing.T) {
	b, _, _, _, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: AgentSurface})
	body := map[string]any{"method": "reveal", "refs": []Ref{testRef}, "display": map[string]any{"refs": []any{}}}
	if w := httpCall(t, h, "POST", "/v1/requests", "", body, ""); w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	delete(body, "display")
	if w := httpCall(t, h, "POST", "/v1/requests", "", body, ""); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
}

type displayProvider struct {
	fakeProvider
	item Item
}

func (p *displayProvider) List(context.Context, []byte) ([]Item, error) {
	return []Item{p.item}, nil
}

func TestRequestDisplayFrozenAndPersisted(t *testing.T) {
	b, p, c, key, dir := setup(t)
	approve(t, b, submit(t, b, Spec{Method: "refresh"}), c, key)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	item := fixtureItem()
	item.Title, item.VaultName = "Renamed item", "Renamed vault"
	item.Fields[0].Label = "Renamed field"
	item.URLs = []string{"https://renamed.example/private"}
	b.st.Cache[vaultID+"/"+itemID] = item
	b.provider = &displayProvider{item: item}
	approve(t, b, submit(t, b, Spec{Method: "refresh"}), c, key)
	want := &RequestDisplay{Refs: []RefDisplay{{Vault: vaultID, Item: itemID, Field: "password", VaultName: "Main", ItemTitle: "Example", FieldLabel: "password", FieldType: "CONCEALED", Origins: []string{"https://example.com"}, Known: true}}}
	s, e := b.Status(r.ID, r.Token)
	if e != nil || !reflect.DeepEqual(s.Display, want) {
		t.Fatal(s, e)
	}
	b.Close()
	next, e := Open(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	s, e = next.Status(r.ID, r.Token)
	if e != nil || !reflect.DeepEqual(s.Display, want) {
		t.Fatal(s, e)
	}
}

func TestRequestDisplayCreateVault(t *testing.T) {
	b, _, c, key, _ := setup(t)
	approve(t, b, submit(t, b, Spec{Method: "refresh"}), c, key)
	for _, v := range []struct{ vault, want string }{{vaultID, "Main"}, {"cccccccccccccccccccccccccc", ""}} {
		r := submit(t, b, Spec{Method: "write", Create: &Create{Vault: v.vault, Title: "new", Category: "LOGIN"}})
		s, e := b.Status(r.ID, r.Token)
		if e != nil || !reflect.DeepEqual(s.Display, &RequestDisplay{Refs: []RefDisplay{}, CreateVaultName: v.want}) {
			t.Fatal(s, e)
		}
	}
	for _, v := range []struct {
		key, name string
		at        time.Time
	}{{"z", "Old", time.Unix(1, 0)}, {"c", "Later", time.Unix(2, 0)}, {"a", "First", time.Unix(2, 0)}, {"b", "", time.Unix(3, 0)}} {
		b.st.Cache[v.key] = Item{Vault: vaultID, VaultName: v.name, SyncedAt: v.at}
	}
	delete(b.st.Cache, vaultID+"/"+itemID)
	r := submit(t, b, Spec{Method: "write", Create: &Create{Vault: vaultID, Title: "new", Category: "LOGIN"}})
	s, e := b.Status(r.ID, r.Token)
	if e != nil || s.Display.CreateVaultName != "First" {
		t.Fatal(s, e)
	}
}

func TestRequestDisplayRuneLimits(t *testing.T) {
	b, _, _, _, _ := setup(t)
	item := fixtureItem()
	item.Title = strings.Repeat("あ", 300)
	item.VaultName = strings.Repeat("é", 200)
	item.Fields[0].Label, item.Fields[0].Type = strings.Repeat("é", 200), strings.Repeat("é", 200)
	b.st.Cache[vaultID+"/"+itemID] = item
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	s, e := b.Status(r.ID, r.Token)
	if e != nil {
		t.Fatal(e)
	}
	d := s.Display.Refs[0]
	if d.ItemTitle != strings.Repeat("あ", 256) || !utf8.ValidString(d.ItemTitle) || utf8.RuneCountInString(d.ItemTitle) != 256 {
		t.Fatal(d.ItemTitle)
	}
	for _, name := range []string{d.VaultName, d.FieldLabel, d.FieldType} {
		if name != strings.Repeat("é", 128) || !utf8.ValidString(name) || utf8.RuneCountInString(name) != 128 {
			t.Fatal(name)
		}
	}
	r = submit(t, b, Spec{Method: "write", Create: &Create{Vault: vaultID, Title: "new", Category: "LOGIN"}})
	s, e = b.Status(r.ID, r.Token)
	if e != nil || s.Display.CreateVaultName != strings.Repeat("é", 128) {
		t.Fatal(s, e)
	}
}

func TestRequestDisplayNamesStayOutOfAudit(t *testing.T) {
	b, _, c, key, dir := setup(t)
	item := fixtureItem()
	item.Title, item.VaultName, item.Fields[0].Label = "distinctive-item-title", "distinctive-vault-name", "distinctive-field-label"
	b.st.Cache[vaultID+"/"+itemID] = item
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	approve(t, b, r, c, key)
	if _, e := b.Consume(r.ID, r.Token); e != nil {
		t.Fatal(e)
	}
	s, e := b.Status(r.ID, r.Token)
	if e != nil {
		t.Fatal(e)
	}
	response, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	audit, e := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"distinctive-item-title", "distinctive-vault-name", "distinctive-field-label"} {
		if !strings.Contains(string(response), name) || strings.Contains(string(audit), name) {
			t.Fatal(name, string(response), string(audit))
		}
	}
}

func TestRequestDisplayOldState(t *testing.T) {
	b, p, _, _, dir := setup(t)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	b.Close()
	key, e := os.ReadFile(filepath.Join(dir, "state.key"))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "state.enc"))
	if e != nil {
		t.Fatal(e)
	}
	data, e := cryptobox.Open(key, raw, "handkey-state-v1")
	if e != nil {
		t.Fatal(e)
	}
	var state map[string]any
	if e = json.Unmarshal(data, &state); e != nil {
		t.Fatal(e)
	}
	if state["version"] != float64(stateVersion) {
		t.Fatal(state["version"])
	}
	request := state["requests"].(map[string]any)[r.ID].(map[string]any)
	delete(request, "display")
	data, e = json.Marshal(state)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = cryptobox.Seal(key, data, "handkey-state-v1")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "state.enc"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	next, e := Open(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	s, e := next.Status(r.ID, r.Token)
	if e != nil || s.Display != nil || s.ID != r.ID || s.Spec.Refs[0] != testRef {
		t.Fatal(s, e)
	}
	data, e = json.Marshal(s)
	if e != nil || strings.Contains(string(data), `"display"`) {
		t.Fatal(string(data), e)
	}
	raw, e = os.ReadFile(filepath.Join(dir, "state.enc"))
	if e != nil {
		t.Fatal(e)
	}
	data, e = cryptobox.Open(key, raw, "handkey-state-v1")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &state); e != nil || state["version"] != float64(stateVersion) {
		t.Fatal(state["version"], e)
	}
}

func TestRequestDisplayOrigins(t *testing.T) {
	for _, v := range []struct {
		name       string
		urls, want []string
	}{
		{"path", []string{"https://example.com/a/b?q=1"}, []string{"https://example.com"}},
		{"port", []string{"https://example.com:8443/x"}, []string{"https://example.com:8443"}},
		{"invalid", []string{"ftp://example.com", "not a url", "", "https:///path"}, []string{}},
		{"duplicates", []string{"https://example.com/a", "https://example.com/b", "http://example.com/x"}, []string{"https://example.com", "http://example.com"}},
		{"limit", []string{"https://a.example", "https://b.example", "https://c.example", "https://d.example", "https://e.example", "https://f.example", "https://g.example", "https://h.example", "https://i.example", "https://j.example"}, []string{"https://a.example", "https://b.example", "https://c.example", "https://d.example", "https://e.example", "https://f.example", "https://g.example", "https://h.example"}},
		{"long", []string{"https://" + strings.Repeat("a", 249), "https://example.com"}, []string{"https://example.com"}},
		{"runes", []string{"https://" + strings.Repeat("é", 248)}, []string{"https://" + strings.Repeat("é", 248)}},
	} {
		t.Run(v.name, func(t *testing.T) {
			b, _, _, _, _ := setup(t)
			item := fixtureItem()
			item.URLs = v.urls
			b.st.Cache[vaultID+"/"+itemID] = item
			r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
			s, e := b.Status(r.ID, r.Token)
			if e != nil || !reflect.DeepEqual(s.Display.Refs[0].Origins, v.want) {
				t.Fatal(s, e)
			}
		})
	}
}

func TestRequestDisplayRefOrder(t *testing.T) {
	b, _, c, key, _ := setup(t)
	approve(t, b, submit(t, b, Spec{Method: "refresh"}), c, key)
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{{Vault: vaultID, Item: itemID, Field: "username"}, testRef}})
	s, e := b.Status(r.ID, r.Token)
	want := &RequestDisplay{Refs: []RefDisplay{
		{Vault: vaultID, Item: itemID, Field: "username", VaultName: "Main", ItemTitle: "Example", FieldLabel: "username", FieldType: "STRING", Origins: []string{"https://example.com"}, Known: true},
		{Vault: vaultID, Item: itemID, Field: "password", VaultName: "Main", ItemTitle: "Example", FieldLabel: "password", FieldType: "CONCEALED", Origins: []string{"https://example.com"}, Known: true},
	}}
	if e != nil || !reflect.DeepEqual(s.Display, want) {
		t.Fatal(s, e)
	}
}
