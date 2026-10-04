package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/asuhacoder/handkey/internal/broker"
	"github.com/asuhacoder/handkey/internal/cryptobox"
	"github.com/asuhacoder/handkey/internal/helper"
)

func (r Runner) runProxy(ctx context.Context, c *Client, id, token string, spec broker.Spec) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 1, e
	}
	defer listener.Close()
	pathToken := cryptobox.Token()
	basePath := "/" + pathToken + "/"
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.URL.Path, basePath) || req.Header.Get("Origin") != "" {
			http.Error(w, "not found", 404)
			return
		}
		path := strings.TrimPrefix(req.URL.EscapedPath(), basePath)
		target := c.Base + "/v1/requests/" + id + "/proxy/" + path
		if req.URL.RawQuery != "" {
			target += "?" + req.URL.RawQuery
		}
		upstream, e := http.NewRequestWithContext(req.Context(), req.Method, target, req.Body)
		if e != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		upstream.Header = req.Header.Clone()
		upstream.Header.Set("Authorization", "Bearer "+token)
		response, e := c.HTTP.Do(upstream)
		if e != nil {
			http.Error(w, "proxy unavailable", 502)
			return
		}
		defer response.Body.Close()
		for k, v := range response.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if e := c.Do(ctx, "POST", "/v1/requests/"+id+"/heartbeat", token, nil, nil); e != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		closeCtx, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = c.Do(closeCtx, "DELETE", "/v1/requests/"+id+"/execution", token, nil, nil)
	}()
	// This variable is helper-generated, not an agent-supplied credential binding.
	spec.Bindings = map[string]string{"HANDKEY_PROXY_URL": "proxy-url"}
	values := map[string]string{"proxy-url": "http://" + listener.Addr().String() + basePath}
	return helper.Run(ctx, spec, values, r.Env, r.In, r.Out, r.Err), nil
}
