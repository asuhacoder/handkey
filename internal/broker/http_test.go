package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asuhacoder/handkey/internal/cryptobox"
)

func httpCall(t *testing.T, h http.Handler, method, path, token string, body any, origin string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestHTTPAuthorizationAndCORS(t *testing.T) {
	b, _, c, key, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: AgentSurface | ApproverSurface, AllowedOrigins: []string{"https://approve.example.com"}})
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	for _, v := range []struct {
		path, token string
		want        int
	}{{"/v1/requests", "", 401}, {"/v1/requests?token=" + c.ViewToken, "", 401}, {"/v1/requests", c.ViewToken, 200}, {"/v1/requests/" + r.ID, "", 404}, {"/v1/requests/" + r.ID, r.Token, 200}} {
		w := httpCall(t, h, "GET", v.path, v.token, nil, "")
		if w.Code != v.want {
			t.Fatal(v, w.Code, w.Body.String())
		}
	}
	w := httpCall(t, h, "POST", "/v1/requests/"+r.ID+"/approve", c.ViewToken, map[string]string{"key": base64.RawURLEncoding.EncodeToString(key)}, "https://evil.example.com")
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	w = httpCall(t, h, "POST", "/v1/requests/"+r.ID+"/approve", c.ViewToken, map[string]string{"key": base64.RawURLEncoding.EncodeToString(key)}, "https://approve.example.com")
	if w.Code != 200 || strings.Contains(w.Body.String(), sentinel) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httpCall(t, h, "POST", "/v1/requests/"+r.ID+"/consume", c.ViewToken, nil, "")
	if w.Code != 404 {
		t.Fatal("view token used as receipt")
	}
	w = httpCall(t, h, "POST", "/v1/requests/"+r.ID+"/consume", r.Token, nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), sentinel) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httpCall(t, h, "OPTIONS", "/v1/requests", c.ViewToken, nil, "https://approve.example.com")
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "https://approve.example.com" {
		t.Fatal("preflight")
	}
}
func TestMalformedHTTPAndNoFrontend(t *testing.T) {
	b, _, _, _, _ := setup(t)
	h := b.Handler(HTTPOptions{Surfaces: AgentSurface | ApproverSurface})
	for _, path := range []string{"/", "/register", "/index.html"} {
		w := httpCall(t, h, "GET", path, "", nil, "")
		if w.Code != 404 {
			t.Fatal("frontend exposed")
		}
	}
	w := httpCall(t, h, "POST", "/v1/requests", "", map[string]any{"method": "reveal", "unexpected": sentinel}, "")
	if w.Code != 400 || strings.Contains(w.Body.String(), sentinel) {
		t.Fatal(w.Body.String())
	}
	w = httpCall(t, h, "POST", "/v1/bootstrap", "", map[string]string{}, "")
	if w.Code != 404 {
		t.Fatal("bootstrap enabled implicitly")
	}
}
func TestProxyDestinationAndLifetime(t *testing.T) {
	b, _, c, key, _ := setup(t)
	var receivedHost, receivedAuth, receivedCookie string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		receivedAuth = r.Header.Get("Authorization")
		receivedCookie = r.Header.Get("Cookie")
		w.Header().Set("Location", "https://other.example.com/")
		w.WriteHeader(302)
	}))
	defer upstream.Close()
	old := proxyClient
	proxyClient = upstream.Client()
	proxyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { proxyClient = old }()
	receipt := submit(t, b, Spec{Method: "proxy", Refs: []Ref{testRef}, Origin: upstream.URL, Header: "Authorization", Prefix: "Bearer ", Command: []string{"curl"}, Directory: "/", TTLSeconds: 1})
	approve(t, b, receipt, c, key)
	result, e := b.Consume(receipt.ID, receipt.Token)
	if e != nil || result.Values != nil || result.ExecutionToken == "" {
		t.Fatal(result, e)
	}
	future := time.Now().Add(2 * time.Second)
	b.now = func() time.Time { return future }
	b.Sweep() // execution survives lease expiry
	h := b.Handler(HTTPOptions{Surfaces: AgentSurface | ApproverSurface})
	r := httptest.NewRequest("GET", "/v1/requests/"+receipt.ID+"/proxy/https:%2F%2Fevil.example/path", nil)
	r.Host = "evil.example"
	r.Header.Set("Cookie", "private")
	r.Header.Set("Authorization", "Bearer "+result.ExecutionToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 302 || receivedHost != strings.TrimPrefix(upstream.URL, "https://") || receivedAuth != "Bearer "+sentinel || receivedCookie != "" {
		t.Fatal(w.Code, receivedHost, receivedCookie)
	}
	if w = httpCall(t, h, "GET", "/v1/requests/"+receipt.ID+"/proxy/..%2F..", result.ExecutionToken, nil, ""); w.Code != 302 || receivedHost != strings.TrimPrefix(upstream.URL, "https://") {
		t.Fatal("escaped traversal changed upstream destination", w.Code, receivedHost)
	}
	if w = httpCall(t, h, "POST", "/v1/requests/"+receipt.ID+"/heartbeat", receipt.Token, nil, ""); w.Code != 410 {
		t.Fatal("receipt cannot act as execution token")
	}
	if w = httpCall(t, h, "DELETE", "/v1/requests/"+receipt.ID+"/execution", result.ExecutionToken, nil, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = httpCall(t, h, "GET", "/v1/requests/"+receipt.ID+"/proxy/", result.ExecutionToken, nil, ""); w.Code != 410 {
		t.Fatal("closed execution alive")
	}
}
func TestProxyEscapedPath(t *testing.T) {
	b, _, c, key, _ := setup(t)
	receivedPath := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath <- r.URL.EscapedPath()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	old := proxyClient
	proxyClient = upstream.Client()
	defer func() { proxyClient = old }()
	receipt := submit(t, b, Spec{Method: "proxy", Refs: []Ref{testRef}, Origin: upstream.URL, Header: "Authorization", Prefix: "Bearer ", Command: []string{"curl"}, Directory: "/"})
	approve(t, b, receipt, c, key)
	result, e := b.Consume(receipt.ID, receipt.Token)
	if e != nil {
		t.Fatal(e)
	}
	h := b.Handler(HTTPOptions{Surfaces: AgentSurface})
	w := httpCall(t, h, "GET", "/v1/requests/"+receipt.ID+"/proxy/api/v4/projects/group%2Fproject", result.ExecutionToken, nil, "")
	if w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := <-receivedPath; got != "/api/v4/projects/group%2Fproject" {
		t.Fatalf("upstream escaped path = %q, want %q", got, "/api/v4/projects/group%2Fproject")
	}
}
func TestSSEFanout(t *testing.T) {
	b, _, c, _, _ := setup(t)
	server := httptest.NewServer(b.Handler(HTTPOptions{Surfaces: AgentSurface | ApproverSurface}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streams := []io.ReadCloser{}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/v1/events", nil)
		req.Header.Set("Authorization", "Bearer "+c.ViewToken)
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode)
		}
		streams = append(streams, res.Body)
		defer res.Body.Close()
		buffer := make([]byte, len("event: sync\ndata: {}\n\n"))
		if _, e = io.ReadFull(res.Body, buffer); e != nil {
			t.Fatal(e)
		}
	}
	receipt := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	for _, stream := range streams {
		buffer := make([]byte, 1024)
		n, e := stream.Read(buffer)
		if e != nil || !strings.Contains(string(buffer[:n]), receipt.ID) {
			t.Fatal("missing event", e)
		}
	}
}
func TestListenerSurfacesAreSeparate(t *testing.T) {
	b, _, c, key, _ := setup(t)
	agent := b.Handler(HTTPOptions{Surfaces: AgentSurface})
	approver := b.Handler(HTTPOptions{Surfaces: ApproverSurface})
	spec := map[string]any{"method": "reveal", "refs": []Ref{testRef}}
	approval := map[string]string{"key": base64.RawURLEncoding.EncodeToString(key)}
	r := submit(t, b, Spec{Method: "reveal", Refs: []Ref{testRef}})
	for _, v := range []struct {
		name         string
		h            http.Handler
		method, path string
		token        string
		body         any
		want         int
	}{
		{"approver submit", approver, "POST", "/v1/requests", "", spec, 405},
		{"approver items", approver, "GET", "/v1/items", "", nil, 404},
		{"approver status by receipt", approver, "GET", "/v1/requests/" + r.ID, r.Token, nil, 401},
		{"approver consume", approver, "POST", "/v1/requests/" + r.ID + "/consume", r.Token, nil, 404},
		{"approver cancel", approver, "POST", "/v1/requests/" + r.ID + "/cancel", r.Token, nil, 404},
		{"agent list", agent, "GET", "/v1/requests", c.ViewToken, nil, 405},
		{"agent status by view token", agent, "GET", "/v1/requests/" + r.ID, c.ViewToken, nil, 404},
		{"agent approve", agent, "POST", "/v1/requests/" + r.ID + "/approve", c.ViewToken, approval, 404},
		{"agent deny", agent, "POST", "/v1/requests/" + r.ID + "/deny", c.ViewToken, nil, 404},
		{"agent create session", agent, "POST", "/v1/devices/" + c.ID + "/sessions", "", map[string]string{"key": approval["key"], "name": "x"}, 404},
		{"agent list sessions", agent, "GET", "/v1/devices/" + c.ID + "/sessions", c.ViewToken, nil, 404},
		{"agent revoke session", agent, "POST", "/v1/sessions/" + c.SessionID + "/revoke", c.ViewToken, nil, 404},
		{"agent submit", agent, "POST", "/v1/requests", "", spec, 202},
		{"agent items", agent, "GET", "/v1/items", "", nil, 200},
		{"agent status by receipt", agent, "GET", "/v1/requests/" + r.ID, r.Token, nil, 200},
		{"approver list", approver, "GET", "/v1/requests", c.ViewToken, nil, 200},
		{"approver status by view token", approver, "GET", "/v1/requests/" + r.ID, c.ViewToken, nil, 200},
		{"approver approve", approver, "POST", "/v1/requests/" + r.ID + "/approve", c.ViewToken, approval, 200},
		{"agent consume", agent, "POST", "/v1/requests/" + r.ID + "/consume", r.Token, nil, 200},
		{"agent health", agent, "GET", "/healthz", "", nil, 200},
		{"approver health", approver, "GET", "/healthz", "", nil, 200},
	} {
		if w := httpCall(t, v.h, v.method, v.path, v.token, v.body, ""); w.Code != v.want {
			t.Errorf("%s: got %d, want %d", v.name, w.Code, v.want)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	events := httptest.NewRequest("GET", "/v1/events", nil).WithContext(ctx)
	events.Header.Set("Authorization", "Bearer "+c.ViewToken)
	w := httptest.NewRecorder()
	agent.ServeHTTP(w, events)
	if w.Code != 404 {
		t.Errorf("agent events: got %d, want 404", w.Code)
	}
}
func TestBootstrapOnlyOnApproverSurface(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	b, e := Open(dir, &fakeProvider{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(b.Close)
	body := map[string]string{"name": "phone", "key": base64.RawURLEncoding.EncodeToString(cryptobox.Random(32)), "service_account_token": "service-token-fixture"}
	agent := b.Handler(HTTPOptions{Surfaces: AgentSurface, Bootstrap: true})
	if w := httpCall(t, agent, "POST", "/v1/bootstrap", "", body, ""); w.Code != 404 {
		t.Fatalf("agent surface bootstrap: got %d, want 404", w.Code)
	}
	if b.Initialized() {
		t.Fatal("agent surface initialized the broker")
	}
	approver := b.Handler(HTTPOptions{Surfaces: ApproverSurface, Bootstrap: true})
	if w := httpCall(t, approver, "POST", "/v1/bootstrap", "", body, ""); w.Code != 201 {
		t.Fatalf("approver surface bootstrap: got %d, want 201", w.Code)
	}
}
