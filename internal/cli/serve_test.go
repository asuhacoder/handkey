package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedOutput struct {
	mu   sync.Mutex
	text strings.Builder
}

func (o *lockedOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.text.Write(p)
}

func (o *lockedOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.text.String()
}

var developmentEndpoint = regexp.MustCompile(`http://127\.0\.0\.1:\d+`)

const socketBase = "http://handkey.local"

func serveOnSocket(t *testing.T, extra ...string) (*http.Client, string) {
	t.Helper()
	dir, e := os.MkdirTemp("", "hk")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	state, op, socket := filepath.Join(dir, "state"), filepath.Join(dir, "op"), filepath.Join(dir, "s")
	if e = os.Mkdir(state, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(op, []byte("#!/bin/sh\nexit 1\n"), 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	args := append([]string{"--state-dir", state, "--op", op, "--socket", socket, "--dev", "--bootstrap"}, extra...)
	out := &lockedOutput{}
	go func() { done <- Serve(ctx, args, out, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.Dial("unix", socket)
		if e == nil {
			c.Close()
			break
		}
		select {
		case e := <-done:
			done <- e
			t.Fatalf("serve stopped before the socket accepted connections: %v", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never accepted connections")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tcp := ""
	for strings.Contains(strings.Join(extra, " "), "--listen") && tcp == "" {
		if time.Now().After(deadline) {
			t.Fatal("serve never printed the TCP endpoint")
		}
		time.Sleep(10 * time.Millisecond)
		tcp = developmentEndpoint.FindString(out.String())
	}
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}, tcp
}

func status(t *testing.T, c *http.Client, method, url, body string) int {
	t.Helper()
	req, e := http.NewRequest(method, url, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, e := c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	return res.StatusCode
}

const bootstrapBody = `{"name":"phone","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","service_account_token":"fixture"}`
const submitBody = `{"method":"reveal","refs":[{"vault":"aaaaaaaaaaaaaaaaaaaaaaaaaa","item":"bbbbbbbbbbbbbbbbbbbbbbbbbb","field":"password"}],"reason":"r","agent":"a"}`

func TestServeSocketOnlyCarriesApprovalRoutes(t *testing.T) {
	c, _ := serveOnSocket(t)
	if got := status(t, c, "POST", socketBase+"/v1/bootstrap", bootstrapBody); got != 201 {
		t.Fatalf("socket-only bootstrap: got %d, want 201", got)
	}
}

func TestServeSocketIsAgentOnlyBesideListen(t *testing.T) {
	c, _ := serveOnSocket(t, "--listen", "127.0.0.1:0")
	if got := status(t, c, "POST", socketBase+"/v1/bootstrap", bootstrapBody); got != 404 {
		t.Fatalf("bootstrap on the socket beside --listen: got %d, want 404", got)
	}
}

func TestServeListenCarriesApprovalRoutesOnly(t *testing.T) {
	_, tcp := serveOnSocket(t, "--listen", "127.0.0.1:0")
	for _, v := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"submit", "POST", "/v1/requests", submitBody, 405},
		{"items", "GET", "/v1/items", "", 404},
		{"bootstrap", "POST", "/v1/bootstrap", bootstrapBody, 201},
	} {
		if got := status(t, http.DefaultClient, v.method, tcp+v.path, v.body); got != v.want {
			t.Errorf("%s on --listen: got %d, want %d", v.name, got, v.want)
		}
	}
}

func TestServeRemoteAgentsAddsAgentRoutesToListen(t *testing.T) {
	_, tcp := serveOnSocket(t, "--listen", "127.0.0.1:0", "--remote-agents")
	for _, v := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"bootstrap", "POST", "/v1/bootstrap", bootstrapBody, 201},
		{"submit", "POST", "/v1/requests", submitBody, 202},
		{"items", "GET", "/v1/items", "", 200},
	} {
		if got := status(t, http.DefaultClient, v.method, tcp+v.path, v.body); got != v.want {
			t.Errorf("%s on --listen with --remote-agents: got %d, want %d", v.name, got, v.want)
		}
	}
}

func TestServeSocketOnlyHonoursOrigins(t *testing.T) {
	c, _ := serveOnSocket(t, "--origins", "https://approve.example.com")
	req, e := http.NewRequest("GET", socketBase+"/healthz", nil)
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Origin", "https://approve.example.com")
	res, e := c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Access-Control-Allow-Origin") != "https://approve.example.com" {
		t.Fatalf("allowed origin on the socket: got %d with Access-Control-Allow-Origin %q, want 200 with the origin", res.StatusCode, res.Header.Get("Access-Control-Allow-Origin"))
	}
}
