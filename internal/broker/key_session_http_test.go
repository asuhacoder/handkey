package broker

import (
	"bytes"
	"context"
	"encoding/json"
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

func keySessionListPath(device string) string {
	return "/v1/devices/" + device + "/sessions/list"
}

func keySessionRevokePath(device, session string) string {
	return "/v1/devices/" + device + "/sessions/" + session + "/revoke"
}

func assertKeySessionResponse(t *testing.T, w *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if w.Code != status || w.Body.String() != body {
		t.Fatalf("got %d %q, want %d %q", w.Code, w.Body.String(), status, body)
	}
}

func keySessionJSON(c Credentials, name string, created time.Time) string {
	return fmt.Sprintf(`{"session_id":%q,"name":%q,"created_at":%q,"view_until":%q,"current":false}`, c.SessionID, name, created.Format(time.RFC3339Nano), c.ViewUntil.Format(time.RFC3339Nano))
}

func TestHTTPKeySessionList(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	first := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	second := first.Add(time.Hour)
	b.mu.Lock()
	b.st.Devices[c.ID].Sessions[c.SessionID].CreatedAt = first
	b.now = func() time.Time { return second }
	b.mu.Unlock()
	a := newSession(t, h, c.ID, key, "A")
	other := newSession(t, h, c.ID, key, "B")
	foreign, e := b.AddDevice(c.ID, key, "foreign", cryptobox.Random(32))
	if e != nil {
		t.Fatal(e)
	}
	expired := newSession(t, h, c.ID, key, "expired")
	b.mu.Lock()
	b.st.Devices[c.ID].Sessions[expired.SessionID].ViewUntil = second
	b.mu.Unlock()
	tied := []string{keySessionJSON(a, "A", second), keySessionJSON(other, "B", second)}
	if a.SessionID > other.SessionID {
		tied[0], tied[1] = tied[1], tied[0]
	}
	want := "[" + keySessionJSON(c, "phone", first) + "," + strings.Join(tied, ",") + "]\n"
	for _, authorization := range []string{"", "invalid", "Bearer " + foreign.ViewToken, "Bearer " + a.ViewToken} {
		r := httptest.NewRequest("POST", keySessionListPath(c.ID), strings.NewReader(`{"key":"`+encodeKey(key)+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assertKeySessionResponse(t, w, 200, want)
	}
	b.mu.Lock()
	late := c.ViewUntil.Add(91 * 24 * time.Hour)
	b.now = func() time.Time { return late }
	b.mu.Unlock()
	assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionListPath(c.ID), "", map[string]string{"key": encodeKey(key)}, ""), 200, "[]\n")
}

func TestHTTPKeySessionAuthentication(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	wrong := encodeKey(cryptobox.Random(32))
	revokedKey := cryptobox.Random(32)
	revoked, e := b.AddDevice(c.ID, key, "revoked", revokedKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Revoke(c.ID, key, revoked.ID); e != nil {
		t.Fatal(e)
	}
	for _, route := range []string{"list", "revoke"} {
		for _, v := range []struct{ name, device, key string }{
			{"wrong", c.ID, wrong},
			{"unknown", "unknown-device", encodeKey(key)},
			{"malformed", c.ID, "not-a-key"},
			{"missing", c.ID, ""},
			{"revoked", revoked.ID, encodeKey(revokedKey)},
		} {
			t.Run(route+"/"+v.name, func(t *testing.T) {
				path := keySessionListPath(v.device)
				if route == "revoke" {
					path = keySessionRevokePath(v.device, c.SessionID)
				}
				assertKeySessionResponse(t, httpCall(t, h, "POST", path, c.ViewToken, map[string]string{"key": v.key}, ""), 401, "{\"error\":\"authentication failed\"}\n")
			})
		}
	}
	for _, target := range []string{c.SessionID, "unknown-session"} {
		assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionRevokePath(c.ID, target), "", map[string]string{"key": wrong}, ""), 401, "{\"error\":\"authentication failed\"}\n")
	}
	if got := viewStatus(t, h, c.ViewToken); got != 200 {
		t.Fatalf("wrong key invalidated session: %d", got)
	}
}

func TestHTTPKeySessionBodyValidation(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	for _, path := range []string{keySessionListPath(c.ID), keySessionRevokePath(c.ID, c.SessionID)} {
		for _, v := range []struct {
			name, body, contentType, query string
			status                         int
			want                           string
		}{
			{"unknown field", `{"key":"` + encodeKey(key) + `","name":"x"}`, "application/json", "", 400, "{\"error\":\"invalid request body\"}\n"},
			{"wrong content type", `{"key":"` + encodeKey(key) + `"}`, "text/plain", "", 415, "{\"error\":\"Content-Type must be application/json\"}\n"},
			{"content type parameters", `{}`, "application/json; charset=utf-8", "", 415, "{\"error\":\"Content-Type must be application/json\"}\n"},
			{"query without body", "", "application/json", "?key=" + encodeKey(key), 400, "{\"error\":\"invalid request body\"}\n"},
			{"query without content type", "", "", "?key=" + encodeKey(key), 415, "{\"error\":\"Content-Type must be application/json\"}\n"},
			{"oversized", `{"key":"` + strings.Repeat("a", 1<<20) + `"}`, "application/json", "", 400, "{\"error\":\"invalid request body\"}\n"},
			{"trailing body", `{} {}`, "application/json", "", 400, "{\"error\":\"invalid request body\"}\n"},
		} {
			t.Run(path+"/"+v.name, func(t *testing.T) {
				r := httptest.NewRequest("POST", path+v.query, strings.NewReader(v.body))
				r.Header.Set("Content-Type", v.contentType)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				assertKeySessionResponse(t, w, v.status, v.want)
			})
		}
	}
}

func TestHTTPKeySessionRevoke(t *testing.T) {
	b, _, c, key, dir := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	foreign, e := b.AddDevice(c.ID, key, "foreign", cryptobox.Random(32))
	if e != nil {
		t.Fatal(e)
	}
	body := map[string]string{"key": encodeKey(key)}
	for _, target := range []string{"unknown-session", foreign.SessionID} {
		assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionRevokePath(c.ID, target), "", body, ""), 404, "{\"error\":\"not found or not authorized\"}\n")
	}
	if got := viewStatus(t, h, foreign.ViewToken); got != 200 {
		t.Fatalf("foreign session invalidated: %d", got)
	}
	var targets []Credentials
	for _, authorization := range []string{"", "invalid", "Bearer " + foreign.ViewToken} {
		target := newSession(t, h, c.ID, key, "private-session-name")
		targets = append(targets, target)
		r := httptest.NewRequest("POST", keySessionRevokePath(c.ID, target.SessionID), strings.NewReader(`{"key":"`+encodeKey(key)+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assertKeySessionResponse(t, w, 200, "{\"status\":\"revoked\"}\n")
		assertKeySessionResponse(t, httpCall(t, h, "GET", "/v1/requests", target.ViewToken, nil, ""), 401, "{\"error\":\"authentication failed\"}\n")
		if got := viewStatus(t, h, c.ViewToken); got != 200 {
			t.Fatalf("sibling invalidated: %d", got)
		}
	}
	b.mu.Lock()
	created := b.st.Devices[c.ID].Sessions[c.SessionID].CreatedAt
	b.mu.Unlock()
	assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionListPath(c.ID), "", body, ""), 200, "["+keySessionJSON(c, "phone", created)+"]\n")
	raw, e := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	var revoked []string
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var entry Audit
		if e = json.Unmarshal(line, &entry); e != nil {
			t.Fatal(e)
		}
		if entry.Kind == "session_revoked" {
			if entry.Device != c.ID {
				t.Fatalf("audit device = %q, want %q", entry.Device, c.ID)
			}
			revoked = append(revoked, entry.Session)
		}
	}
	if len(revoked) != len(targets) {
		t.Fatalf("revocations = %v, want %v", revoked, targets)
	}
	for i, target := range targets {
		if revoked[i] != target.SessionID {
			t.Fatalf("audit session = %q, want %q", revoked[i], target.SessionID)
		}
	}
	if bytes.Contains(raw, []byte("private-session-name")) {
		t.Fatal("audit disclosed session name")
	}
}

func TestHTTPKeySessionLimitRecovery(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	for i := 2; i <= 16; i++ {
		newSession(t, h, c.ID, key, fmt.Sprint("client ", i))
	}
	assertKeySessionResponse(t, httpCall(t, h, "POST", "/v1/devices/"+c.ID+"/sessions", "", map[string]string{"key": encodeKey(key), "name": "17"}, ""), 409, "{\"error\":\"session limit reached; revoke a session first\"}\n")
	w := httpCall(t, h, "POST", keySessionListPath(c.ID), "", map[string]string{"key": encodeKey(key)}, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var list []SessionInfo
	if e := json.Unmarshal(w.Body.Bytes(), &list); e != nil {
		t.Fatal(e)
	}
	if len(list) != 16 {
		t.Fatalf("listed %d sessions, want 16", len(list))
	}
	assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionRevokePath(c.ID, c.SessionID), "", map[string]string{"key": encodeKey(key)}, ""), 200, "{\"status\":\"revoked\"}\n")
	newSession(t, h, c.ID, key, "replacement")
}

func TestHTTPKeySessionExpiredUnsweptRevoke(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	b.mu.Lock()
	b.now = func() time.Time { return c.ViewUntil }
	b.mu.Unlock()
	body := map[string]string{"key": encodeKey(key)}
	assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionListPath(c.ID), "", body, ""), 200, "[]\n")
	assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionRevokePath(c.ID, c.SessionID), "", body, ""), 200, "{\"status\":\"revoked\"}\n")
	assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionRevokePath(c.ID, c.SessionID), "", body, ""), 404, "{\"error\":\"not found or not authorized\"}\n")
}

func TestHTTPKeySessionApproverOnly(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: AgentSurface})
	for _, path := range []string{keySessionListPath(c.ID), keySessionRevokePath(c.ID, c.SessionID)} {
		assertKeySessionResponse(t, httpCall(t, h, "POST", path, c.ViewToken, map[string]string{"key": encodeKey(key)}, ""), 404, "404 page not found\n")
	}
}

func TestHTTPKeySessionUnavailable(t *testing.T) {
	for _, state := range []string{"broken", "closed"} {
		t.Run(state, func(t *testing.T) {
			b, _, c, key, _ := setup(t)
			h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
			if state == "closed" {
				b.Close()
			} else {
				b.mu.Lock()
				b.broken = true
				b.mu.Unlock()
			}
			for _, path := range []string{keySessionListPath(c.ID), keySessionListPath("unknown-device"), keySessionRevokePath(c.ID, c.SessionID), keySessionRevokePath("unknown-device", "unknown-session")} {
				assertKeySessionResponse(t, httpCall(t, h, "POST", path, "", map[string]string{"key": encodeKey(key)}, ""), 503, "{\"error\":\"operation unavailable; inspect request status\"}\n")
			}
		})
	}
}

func TestHTTPKeySessionRevokeClosesSSE(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	sibling := newSession(t, h, c.ID, key, "sibling")
	server := httptest.NewServer(h)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r, e := http.NewRequestWithContext(ctx, "GET", server.URL+"/v1/events", nil)
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Authorization", "Bearer "+c.ViewToken)
	res, e := server.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	initial := make([]byte, len("event: sync\ndata: {}\n\n"))
	if _, e = io.ReadFull(res.Body, initial); e != nil || string(initial) != "event: sync\ndata: {}\n\n" {
		t.Fatal(string(initial), e)
	}
	assertKeySessionResponse(t, httpCall(t, h, "POST", keySessionRevokePath(c.ID, c.SessionID), "", map[string]string{"key": encodeKey(key)}, ""), 200, "{\"status\":\"revoked\"}\n")
	rest, e := io.ReadAll(res.Body)
	if e != nil || len(rest) != 0 {
		t.Fatalf("revoked SSE = %q, %v, want clean EOF", rest, e)
	}
	if got := viewStatus(t, h, sibling.ViewToken); got != 200 {
		t.Fatalf("sibling invalidated: %d", got)
	}
}
