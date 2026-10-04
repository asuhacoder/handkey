package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func serveOnSocket(t *testing.T, extra ...string) *http.Client {
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
	go func() { done <- Serve(ctx, args, io.Discard, io.Discard) }()
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
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
}

func socketBootstrap(t *testing.T, c *http.Client) int {
	t.Helper()
	body := `{"name":"phone","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","service_account_token":"fixture"}`
	res, e := c.Post("http://handkey.local/v1/bootstrap", "application/json", strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestServeSocketOnlyCarriesApprovalRoutes(t *testing.T) {
	if got := socketBootstrap(t, serveOnSocket(t)); got != 201 {
		t.Fatalf("socket-only bootstrap: got %d, want 201", got)
	}
}

func TestServeSocketIsAgentOnlyBesideListen(t *testing.T) {
	if got := socketBootstrap(t, serveOnSocket(t, "--listen", "127.0.0.1:0")); got != 404 {
		t.Fatalf("bootstrap on the socket beside --listen: got %d, want 404", got)
	}
}
