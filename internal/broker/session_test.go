package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asuhacoder/handkey/internal/cryptobox"
)

func encodeKey(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }

func newSession(t *testing.T, h http.Handler, device string, key []byte, name string) Credentials {
	t.Helper()
	w := httpCall(t, h, "POST", "/v1/devices/"+device+"/sessions", "", map[string]string{"key": encodeKey(key), "name": name}, "")
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var c Credentials
	if e := json.Unmarshal(w.Body.Bytes(), &c); e != nil {
		t.Fatal(e)
	}
	return c
}
func listSessions(t *testing.T, h http.Handler, c Credentials) []SessionInfo {
	t.Helper()
	w := httpCall(t, h, "GET", "/v1/devices/"+c.ID+"/sessions", c.ViewToken, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var list []SessionInfo
	if e := json.Unmarshal(w.Body.Bytes(), &list); e != nil {
		t.Fatal(e)
	}
	return list
}
func viewStatus(t *testing.T, h http.Handler, token string) int {
	t.Helper()
	return httpCall(t, h, "GET", "/v1/requests", token, nil, "").Code
}

func TestSessionsShareOneKey(t *testing.T) {
	b, _, c, key, dir := setup(t)
	h := b.Handler(HTTPOptions{})
	page := newSession(t, h, c.ID, key, "Phone page")
	plugin := newSession(t, h, c.ID, key, "dsh plugin")
	if page.ID != c.ID || plugin.ID != c.ID || page.SessionID == plugin.SessionID || page.SessionID == c.SessionID {
		t.Fatal("sessions must be distinct and belong to the same device", page, plugin)
	}
	for _, token := range []string{c.ViewToken, page.ViewToken, plugin.ViewToken} {
		if code := viewStatus(t, h, token); code != 200 {
			t.Fatal("view token invalidated by a sibling session", code)
		}
	}
	w := httpCall(t, h, "GET", "/v1/devices/"+c.ID+"/sessions", plugin.ViewToken, nil, "")
	list := listSessions(t, h, plugin)
	names := map[string]bool{}
	for _, s := range list {
		names[s.Name] = true
		if s.Current != (s.SessionID == plugin.SessionID) {
			t.Fatal("current flag", s)
		}
	}
	if len(list) != 3 || !names["phone"] || !names["Phone page"] || !names["dsh plugin"] {
		t.Fatal(list)
	}
	audit, e := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	created := map[string]string{}
	for _, line := range bytes.Split(bytes.TrimSpace(audit), []byte("\n")) {
		var entry Audit
		if e = json.Unmarshal(line, &entry); e != nil {
			t.Fatal(e)
		}
		if entry.Kind == "session_created" {
			created[entry.Session] = entry.Device
		}
	}
	if len(created) != 2 || created[page.SessionID] != c.ID || created[plugin.SessionID] != c.ID {
		t.Fatal("audit must name each created session", created)
	}
	for _, token := range []string{c.ViewToken, page.ViewToken, plugin.ViewToken} {
		for _, secret := range []string{token, cryptobox.Hash(token)} {
			if bytes.Contains(audit, []byte(secret)) || strings.Contains(w.Body.String(), secret) {
				t.Fatal("view token or hash disclosed")
			}
		}
	}
	if w = httpCall(t, h, "POST", "/v1/devices/"+c.ID+"/sessions", "", map[string]string{"key": encodeKey(key), "name": strings.Repeat("鍵", 129)}, ""); w.Code != 400 {
		t.Fatal("overlong session name accepted", w.Code)
	}
	if long := newSession(t, h, c.ID, key, strings.Repeat("鍵", 128)); viewStatus(t, h, long.ViewToken) != 200 {
		t.Fatal("128-character session name rejected")
	}
	if w = httpCall(t, h, "GET", "/v1/devices/"+cryptobox.Token()+"/sessions", c.ViewToken, nil, ""); w.Code != 404 {
		t.Fatal("listed another device", w.Code)
	}
}

func TestSessionCreationNeedsTheDeviceKey(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{})
	wrongKey := httpCall(t, h, "POST", "/v1/devices/"+c.ID+"/sessions", c.ViewToken, map[string]string{"key": encodeKey(cryptobox.Random(32)), "name": "x"}, "")
	noDevice := httpCall(t, h, "POST", "/v1/devices/"+cryptobox.Token()+"/sessions", "", map[string]string{"key": encodeKey(key), "name": "x"}, "")
	if wrongKey.Code != 401 || noDevice.Code != 401 || wrongKey.Body.String() != noDevice.Body.String() {
		t.Fatal(wrongKey.Code, wrongKey.Body.String(), noDevice.Code, noDevice.Body.String())
	}
	if n := len(listSessions(t, h, c)); n != 1 {
		t.Fatal("session created without the key", n)
	}
}

func TestDecisionRecordsTheSession(t *testing.T) {
	b, _, c, key, dir := setup(t)
	h := b.Handler(HTTPOptions{})
	a := newSession(t, h, c.ID, key, "A")
	other := newSession(t, h, c.ID, key, "B")
	approved := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	denied := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	if w := httpCall(t, h, "POST", "/v1/requests/"+approved.ID+"/approve", a.ViewToken, map[string]string{"key": encodeKey(key)}, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := httpCall(t, h, "POST", "/v1/requests/"+denied.ID+"/deny", other.ViewToken, nil, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	want := map[string]string{approved.ID: a.SessionID, denied.ID: other.SessionID}
	for _, r := range []Receipt{approved, denied} {
		got, e := b.Status(r.ID, r.Token)
		if e != nil || got.ApprovedBy != c.ID || got.ApprovedSession != want[r.ID] {
			t.Fatal(got, e)
		}
	}
	raw, e := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]string{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var entry Audit
		if e = json.Unmarshal(line, &entry); e != nil {
			t.Fatal(e)
		}
		if entry.Kind == "approved" || entry.Kind == "denied" {
			seen[entry.Kind] = entry.Device + "/" + entry.Session
		}
	}
	if seen["approved"] != c.ID+"/"+a.SessionID || seen["denied"] != c.ID+"/"+other.SessionID {
		t.Fatal(seen)
	}
}

func TestApprovalNeedsTheKeyOfTheSessionsDevice(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{})
	secondKey := cryptobox.Random(32)
	second, e := b.AddDevice(c.ID, key, "Even app", secondKey)
	if e != nil {
		t.Fatal(e)
	}
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	approveWith := func(token string, k []byte) int {
		return httpCall(t, h, "POST", "/v1/requests/"+r.ID+"/approve", token, map[string]string{"key": encodeKey(k)}, "").Code
	}
	if code := approveWith(c.ViewToken, secondKey); code != 401 {
		t.Fatal("first device's session approved with the second device's key", code)
	}
	if code := approveWith(second.ViewToken, key); code != 401 {
		t.Fatal("second device's session approved with the first device's key", code)
	}
	if got, e := b.Status(r.ID, r.Token); e != nil || got.Approval != "pending" {
		t.Fatal(got, e)
	}
	if code := approveWith(second.ViewToken, secondKey); code != 200 {
		t.Fatal(code)
	}
	if got, e := b.Status(r.ID, r.Token); e != nil || got.ApprovedBy != second.ID || got.ApprovedSession != second.SessionID {
		t.Fatal(got, e)
	}
}

func TestSessionRevocation(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{})
	a := newSession(t, h, c.ID, key, "A")
	other := newSession(t, h, c.ID, key, "B")
	secondKey := cryptobox.Random(32)
	foreign, e := b.AddDevice(c.ID, key, "Even app", secondKey)
	if e != nil {
		t.Fatal(e)
	}
	revoke := func(token, target string, body any) int {
		return httpCall(t, h, "POST", "/v1/sessions/"+target+"/revoke", token, body, "").Code
	}
	if code := revoke(a.ViewToken, a.SessionID, map[string]string{}); code != 200 {
		t.Fatal("logout with an empty JSON body", code)
	}
	if viewStatus(t, h, a.ViewToken) != 401 || viewStatus(t, h, other.ViewToken) != 200 || viewStatus(t, h, c.ViewToken) != 200 {
		t.Fatal("logout must end exactly one session")
	}
	if code := revoke(other.ViewToken, c.SessionID, nil); code != 401 {
		t.Fatal("sibling revoked without the key", code)
	}
	if code := revoke(other.ViewToken, c.SessionID, map[string]string{"key": encodeKey(secondKey)}); code != 401 {
		t.Fatal("sibling revoked with another device's key", code)
	}
	if code := revoke(other.ViewToken, foreign.SessionID, map[string]string{"key": encodeKey(key)}); code != 404 {
		t.Fatal("revoked a session of another device", code)
	}
	if viewStatus(t, h, c.ViewToken) != 200 || viewStatus(t, h, foreign.ViewToken) != 200 {
		t.Fatal("rejected revocation had an effect")
	}
	if code := revoke(other.ViewToken, c.SessionID, map[string]string{"key": encodeKey(key)}); code != 200 {
		t.Fatal("sibling revocation with the key", code)
	}
	if viewStatus(t, h, c.ViewToken) != 401 || viewStatus(t, h, other.ViewToken) != 200 {
		t.Fatal("sibling revocation")
	}
}

func TestDeviceRevocationEndsEverySession(t *testing.T) {
	b, _, c, key, _ := setup(t)
	server := httptest.NewServer(b.Handler(HTTPOptions{}))
	defer server.Close()
	h := server.Config.Handler
	secondKey := cryptobox.Random(32)
	first, e := b.AddDevice(c.ID, key, "Even app", secondKey)
	if e != nil {
		t.Fatal(e)
	}
	second := newSession(t, h, first.ID, secondKey, "Even tablet")
	req, _ := http.NewRequest("GET", server.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+second.ViewToken)
	res, e := server.Client().Do(req)
	if e != nil || res.StatusCode != 200 {
		t.Fatal(res, e)
	}
	defer res.Body.Close()
	if w := httpCall(t, h, "POST", "/v1/devices/"+first.ID+"/revoke", c.ViewToken, map[string]string{"key": encodeKey(key)}, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if viewStatus(t, h, first.ViewToken) != 401 || viewStatus(t, h, second.ViewToken) != 401 || viewStatus(t, h, c.ViewToken) != 200 {
		t.Fatal("device revocation must end its own sessions only")
	}
	b.mu.Lock()
	revoked := b.st.Devices[first.ID]
	cleared := revoked.Revoked && revoked.WrappedKey == nil && len(revoked.Sessions) == 0
	b.mu.Unlock()
	if !cleared {
		t.Fatal("revoked device kept its wrapped key or session hashes")
	}
	if w := httpCall(t, h, "POST", "/v1/devices/"+first.ID+"/sessions", "", map[string]string{"key": encodeKey(secondKey), "name": "again"}, ""); w.Code != 401 {
		t.Fatal("revoked device issued a session", w.Code)
	}
	closed := make(chan string, 1)
	go func() {
		stream, _ := io.ReadAll(res.Body)
		closed <- string(stream)
	}()
	select {
	case stream := <-closed:
		if strings.Contains(stream, "device_revoked") {
			t.Fatal("revoked session received the event after revocation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event stream stayed open after device revocation")
	}
}

func TestSessionLimit(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{})
	tokens := []string{c.ViewToken}
	for i := 2; i <= 16; i++ {
		tokens = append(tokens, newSession(t, h, c.ID, key, fmt.Sprint("client ", i)).ViewToken)
	}
	w := httpCall(t, h, "POST", "/v1/devices/"+c.ID+"/sessions", "", map[string]string{"key": encodeKey(key), "name": "client 17"}, "")
	if w.Code != 409 || !strings.Contains(w.Body.String(), "session limit") {
		t.Fatal(w.Code, w.Body.String())
	}
	for i, token := range tokens {
		if viewStatus(t, h, token) != 200 {
			t.Fatal("existing session evicted", i)
		}
	}
	list := listSessions(t, h, c)
	if len(list) != 16 {
		t.Fatal(len(list))
	}
	for _, s := range list {
		if !s.Current {
			if w = httpCall(t, h, "POST", "/v1/sessions/"+s.SessionID+"/revoke", c.ViewToken, map[string]string{"key": encodeKey(key)}, ""); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			break
		}
	}
	newSession(t, h, c.ID, key, "replaces the revoked session")
	late := time.Now().Add(91 * 24 * time.Hour)
	b.now = func() time.Time { return late }
	fresh := newSession(t, h, c.ID, key, "after every session expired, before the sweep")
	if viewStatus(t, h, fresh.ViewToken) != 200 {
		t.Fatal("expired sessions counted against the limit")
	}
}

func TestSessionExpiry(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{})
	late := time.Now().Add(91 * 24 * time.Hour)
	b.now = func() time.Time { return late }
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	if viewStatus(t, h, c.ViewToken) != 401 {
		t.Fatal("expired session accepted")
	}
	if e := b.Reject(r.ID, c.ID, c.SessionID); !errors.Is(e, ErrDenied) {
		t.Fatal("expired session denied a request", e)
	}
	if e := b.Approve(t.Context(), r.ID, c.ID, c.SessionID, key); !errors.Is(e, ErrDenied) {
		t.Fatal("expired session approved", e)
	}
	if len(b.st.Devices[c.ID].Sessions) != 1 {
		t.Fatal("expired session removed before the sweep")
	}
	b.Sweep()
	if len(b.st.Devices[c.ID].Sessions) != 0 {
		t.Fatal("sweep kept an expired session")
	}
	renewed := newSession(t, h, c.ID, key, "phone")
	if viewStatus(t, h, renewed.ViewToken) != 200 || viewStatus(t, h, c.ViewToken) != 401 {
		t.Fatal("the key must be able to replace an expired session")
	}
}

func TestVersion1StateMigration(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	stateKey, deviceKey, master := cryptobox.Random(32), cryptobox.Random(32), cryptobox.Random(32)
	token, revokedToken := cryptobox.Token(), cryptobox.Token()
	until := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	wrapped, _ := cryptobox.Seal(deviceKey, master, "device:phone-id")
	service, _ := cryptobox.Seal(master, []byte("service-token-fixture"), "service-account-v1")
	old, _ := json.Marshal(map[string]any{
		"version":         1,
		"encrypted_token": service,
		"devices": map[string]any{
			"phone-id": map[string]any{"id": "phone-id", "name": "Phone", "wrapped_key": wrapped, "view_hash": cryptobox.Hash(token), "view_until": until, "revoked": false},
			"lost-id":  map[string]any{"id": "lost-id", "name": "Lost", "wrapped_key": nil, "view_hash": cryptobox.Hash(revokedToken), "view_until": until, "revoked": true},
		},
		"requests": map[string]any{},
		"cache":    map[string]any{},
	})
	sealed, _ := cryptobox.Seal(stateKey, old, "handkey-state-v1")
	if e := os.WriteFile(filepath.Join(dir, "state.key"), stateKey, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "state.enc"), sealed, 0600); e != nil {
		t.Fatal(e)
	}
	saved := func() map[string]any {
		raw, e := os.ReadFile(filepath.Join(dir, "state.enc"))
		if e != nil {
			t.Fatal(e)
		}
		plain, e := cryptobox.Open(stateKey, raw, "handkey-state-v1")
		if e != nil {
			t.Fatal(e)
		}
		var state map[string]any
		if e = json.Unmarshal(plain, &state); e != nil {
			t.Fatal(e)
		}
		return state
	}
	var sessionID string
	for pass := 1; pass <= 2; pass++ {
		b, e := Open(dir, &fakeProvider{})
		if e != nil {
			t.Fatal(pass, e)
		}
		h := b.Handler(HTTPOptions{})
		if viewStatus(t, h, token) != 200 || viewStatus(t, h, revokedToken) != 401 {
			t.Fatal("pass", pass, "existing view token must survive, revoked one must not")
		}
		list := listSessions(t, h, Credentials{ID: "phone-id", ViewToken: token})
		if len(list) != 1 || list[0].Name != "Phone" || !list[0].ViewUntil.Equal(until) || !list[0].Current {
			t.Fatal(pass, list)
		}
		if pass == 2 && list[0].SessionID != sessionID {
			t.Fatal("second open migrated again")
		}
		sessionID = list[0].SessionID
		r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
		if e = b.Approve(t.Context(), r.ID, "phone-id", sessionID, deviceKey); e != nil {
			t.Fatal(pass, e)
		}
		b.Close()
		state := saved()
		devices := state["devices"].(map[string]any)
		phone, lost := devices["phone-id"].(map[string]any), devices["lost-id"].(map[string]any)
		_, hasHash := phone["view_hash"]
		_, hasUntil := phone["view_until"]
		if state["version"] != float64(2) || hasHash || hasUntil || len(phone["sessions"].(map[string]any)) != 1 || len(lost["sessions"].(map[string]any)) != 0 {
			t.Fatal(pass, state["version"], phone, lost)
		}
	}
}

func TestRenewRouteIsGone(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{})
	w := httpCall(t, h, "POST", "/v1/devices/"+c.ID+"/renew", c.ViewToken, map[string]string{"key": encodeKey(key)}, "")
	if w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
	if viewStatus(t, h, c.ViewToken) != 200 {
		t.Fatal("renew attempt changed the session")
	}
}
