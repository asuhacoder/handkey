package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Webhook sends notification hints, not authoritative state. Receivers reconcile
// via the authenticated API. Slow/offline receivers cannot block approvals.
func (b *Broker) Webhook(ctx context.Context, destination string) error {
	u, e := url.Parse(destination)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("webhook requires an HTTPS URL without user information")
	}
	events, unsubscribe := b.events.subscribe()
	defer unsubscribe()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-events:
			payload, _ := json.Marshal(event)
			req, e := http.NewRequestWithContext(ctx, "POST", destination, bytes.NewReader(payload))
			if e != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			response, e := client.Do(req)
			if e == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				response.Body.Close()
			}
		}
	}
}
