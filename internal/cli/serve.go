package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asuhacoder/handkey/internal/broker"
	"github.com/asuhacoder/handkey/internal/onepassword"
)

func developmentHostCheck(next http.Handler, address string) http.Handler {
	_, port, _ := net.SplitHostPort(address)
	localhost := net.JoinHostPort("localhost", port)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != address && r.Host != localhost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMisdirectedRequest)
			_, _ = io.WriteString(w, "{\"error\":\"unexpected Host header\"}\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func Serve(ctx context.Context, args []string, out, errout io.Writer) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	f.SetOutput(errout)
	state := f.String("state-dir", "", "Private broker data directory (required)")
	op := f.String("op", "", "Absolute path to a dedicated real op binary (required)")
	listen := f.String("listen", "", "TCP address for approval clients; requires TLS unless --dev with loopback")
	remoteAgents := f.Bool("remote-agents", false, "Also serve the unauthenticated agent API on --listen; restrict that address with network ACLs")
	socketMode := f.String("socket-mode", "0600", "Unix socket permissions: 0600 or 0660 for the dedicated broker group")
	socket := f.String("socket", "", "Absolute Unix socket path for the agent API (0600); pre-create an appropriate shared group directory if needed")
	cert := f.String("tls-cert", "", "TLS certificate PEM")
	key := f.String("tls-key", "", "TLS private key PEM")
	origins := f.String("origins", "", "Comma-separated exact HTTPS origins of separately hosted approval clients")
	dev := f.Bool("dev", false, "Local development: allow HTTP loopback and user-owned binaries")
	bootstrap := f.Bool("bootstrap", false, "Enable first-device registration on --listen until initialized")
	webhook := f.String("webhook", "", "Optional HTTPS event webhook; delivers request IDs and event kinds only")
	metadataApproval := f.Bool("require-metadata-approval", false, "Require an approved refresh receipt for metadata access")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected serve arguments")
	}
	if !filepath.IsAbs(*state) || !filepath.IsAbs(*op) {
		return errors.New("state-dir and op must be absolute paths")
	}
	if *listen == "" {
		return errors.New("configure --listen for approval clients; --socket serves the agent API only")
	}
	if e := disableCoreDumps(); e != nil {
		return e
	}
	if !*dev {
		for _, path := range []string{*op} {
			if e := protectedPath(path); e != nil {
				return e
			}
		}
	}
	info, e := os.Stat(*op)
	if e != nil || !info.Mode().IsRegular() {
		return errors.New("real op binary is unavailable")
	}
	if *cert == "" || *key == "" {
		host, _, e := net.SplitHostPort(*listen)
		ip := net.ParseIP(host)
		if !*dev || e != nil || ip == nil || !ip.IsLoopback() {
			return errors.New("TCP listener requires TLS; development HTTP is limited to numeric loopback")
		}
	}
	allowed := []string{}
	if *origins != "" {
		for _, origin := range strings.Split(*origins, ",") {
			origin = strings.TrimSpace(origin)
			if origin == "*" || origin == "null" || (!strings.HasPrefix(origin, "https://") && !*dev) {
				return errors.New("CORS requires exact HTTPS origins")
			}
			allowed = append(allowed, origin)
		}
	}
	b, e := broker.Open(*state, &onepassword.CLI{Path: *op, TempDir: *state})
	if e != nil {
		return e
	}
	defer b.Close()
	b.RequireMetadataApproval = *metadataApproval
	approverSurfaces := broker.ApproverSurface
	if *remoteAgents {
		approverSurfaces |= broker.AgentSurface
	}
	agentHandler := b.Handler(broker.HTTPOptions{Surfaces: broker.AgentSurface})
	approverHandler := b.Handler(broker.HTTPOptions{Surfaces: approverSurfaces, Bootstrap: *bootstrap, AllowedOrigins: allowed})
	webhookCtx, stopWebhook := context.WithCancel(ctx)
	defer stopWebhook()
	failures := make(chan error, 3)
	if *webhook != "" {
		go func() {
			if e := b.Webhook(webhookCtx, *webhook); e != nil {
				failures <- e
			}
		}()
	}
	servers := []*http.Server{}
	defer func() {
		for _, s := range servers {
			_ = s.Close()
		}
	}()
	if *socket != "" {
		if *socketMode != "0600" && *socketMode != "0660" {
			return errors.New("socket-mode must be 0600 or 0660")
		}
		if !filepath.IsAbs(*socket) {
			return errors.New("socket path must be absolute")
		}
		// Never remove an existing path; avoids clobbering files or a live broker socket.
		l, e := net.Listen("unix", *socket)
		if e != nil {
			return errors.New("cannot bind Unix socket; remove a stale socket only after verifying the broker is stopped")
		}
		mode := os.FileMode(0600)
		if *socketMode == "0660" {
			mode = 0660
		}
		if e = os.Chmod(*socket, mode); e != nil {
			l.Close()
			return e
		}
		s := &http.Server{Handler: agentHandler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
		servers = append(servers, s)
		go func() { failures <- s.Serve(l) }()
		fmt.Fprintln(out, "Agent endpoint: unix://"+*socket)
	}
	l, e := net.Listen("tcp", *listen)
	if e != nil {
		return errors.New("cannot bind TCP listener")
	}
	s := &http.Server{Handler: approverHandler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	servers = append(servers, s)
	label := "Approval endpoint: "
	if *remoteAgents {
		label = "Approval and agent endpoint: "
	}
	if *cert != "" && *key != "" {
		go func() { failures <- s.ServeTLS(l, *cert, *key) }()
		fmt.Fprintln(out, label+"https://"+l.Addr().String())
	} else {
		s.Handler = developmentHostCheck(approverHandler, l.Addr().String())
		go func() { failures <- s.Serve(l) }()
		fmt.Fprintln(out, label+"http://"+l.Addr().String()+" (development)")
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return errors.New("broker listener stopped")
		case <-ticker.C:
			b.Sweep()
		}
	}
}
