package broker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/asuhacoder/handkey/internal/cryptobox"
)

var proxyTransport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConns: 32, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
var proxyClient = &http.Client{Transport: proxyTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
var forbiddenHeaders = map[string]bool{"Host": true, "Connection": true, "Proxy-Authorization": true, "Proxy-Authenticate": true, "Keep-Alive": true, "Transfer-Encoding": true, "Te": true, "Trailer": true, "Upgrade": true, "Content-Length": true}

func validHeader(s string) bool {
	if s == "" || forbiddenHeaders[http.CanonicalHeaderKey(s)] {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, s := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(s))
		}
	}
	for k := range forbiddenHeaders {
		h.Del(k)
	}
}
func (b *Broker) execution(id, token string, renew bool) (Spec, map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return Spec{}, nil, ErrUnavailable
	}
	e := b.executions[id+":"+cryptobox.Hash(token)]
	if e == nil || !b.now().Before(e.Until) {
		return Spec{}, nil, ErrExpired
	}
	r := b.st.Requests[id]
	if r == nil {
		return Spec{}, nil, ErrMissing
	}
	if renew {
		e.Until = b.now().Add(20 * time.Second)
	}
	return r.Spec, e.Values, nil
}
func (a *api) heartbeat(w http.ResponseWriter, r *http.Request) {
	if _, _, e := a.b.execution(r.PathValue("id"), bearer(r), true); e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, map[string]string{"status": "active"})
}
func (a *api) endExecution(w http.ResponseWriter, r *http.Request) {
	a.b.mu.Lock()
	defer a.b.mu.Unlock()
	delete(a.b.executions, r.PathValue("id")+":"+cryptobox.Hash(bearer(r)))
	reply(w, 200, map[string]string{"status": "closed"})
}
func (a *api) proxy(w http.ResponseWriter, r *http.Request) {
	spec, values, e := a.b.execution(r.PathValue("id"), bearer(r), false)
	if e != nil {
		failure(w, e)
		return
	}
	origin, e := url.Parse(spec.Origin)
	if e != nil {
		failure(w, ErrUnavailable)
		return
	}
	// Construct the URL from the fixed origin; never resolve a caller URL against it.
	origin.Path = "/" + r.PathValue("path")
	origin.RawPath = ""
	origin.RawQuery = r.URL.RawQuery
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	// Stop an in-flight upstream request if the helper disappears.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, _, e := a.b.execution(r.PathValue("id"), bearer(r), false); e != nil {
					cancel()
					return
				}
			}
		}
	}()
	upstream, e := http.NewRequestWithContext(ctx, r.Method, origin.String(), http.MaxBytesReader(w, r.Body, 16<<20))
	if e != nil {
		failure(w, errors.New("invalid proxy request"))
		return
	}
	upstream.Header = r.Header.Clone()
	stripHop(upstream.Header)
	upstream.Header.Del("Authorization")
	upstream.Header.Del("Cookie")
	upstream.Header.Del("Origin")
	upstream.Header.Del("Referer")
	upstream.Header.Set(spec.Header, spec.Prefix+values[spec.Refs[0].Key()])
	upstream.Host = origin.Host
	response, e := proxyClient.Do(upstream)
	if e != nil {
		reply(w, 502, map[string]string{"error": "upstream request failed"})
		return
	}
	defer response.Body.Close()
	stripHop(response.Header)
	for k, vs := range response.Header {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") || strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		w.Header()[k] = vs
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}
