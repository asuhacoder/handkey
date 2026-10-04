package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	h := b.Handler(HTTPOptions{AllowedOrigins: []string{"https://approve.example.com"}})
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
	h := b.Handler(HTTPOptions{})
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
	h := b.Handler(HTTPOptions{})
	r := httptest.NewRequest("GET", "/v1/requests/"+receipt.ID+"/proxy/https:%2F%2Fevil.example/path", nil)
	r.Host = "evil.example"
	r.Header.Set("Cookie", "private")
	r.Header.Set("Authorization", "Bearer "+result.ExecutionToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 302 || receivedHost != strings.TrimPrefix(upstream.URL, "https://") || receivedAuth != "Bearer "+sentinel || receivedCookie != "" {
		t.Fatal(w.Code, receivedHost, receivedCookie)
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
	h := b.Handler(HTTPOptions{})
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
	server := httptest.NewServer(b.Handler(HTTPOptions{}))
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
