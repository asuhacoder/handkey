package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asuhacoder/handkey/internal/broker"
)

type Client struct {
	Base string
	HTTP *http.Client
}

func NewClient(endpoint string, dev bool) (*Client, error) {
	t := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 3 * time.Minute, TLSHandshakeTimeout: 10 * time.Second}
	base := endpoint
	if strings.HasPrefix(endpoint, "unix://") {
		path := strings.TrimPrefix(endpoint, "unix://")
		if !filepath.IsAbs(path) {
			return nil, errors.New("socket path must be absolute")
		}
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}
		base = "http://handkey.local"
	} else {
		u, e := url.Parse(endpoint)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return nil, errors.New("endpoint must be an HTTPS origin or unix:///absolute/socket")
		}
		if u.Scheme != "https" {
			ip := net.ParseIP(u.Hostname())
			if !dev || u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
				return nil, errors.New("HTTPS required (development HTTP permits only numeric loopback addresses)")
			}
		}
	}
	return &Client{Base: base, HTTP: &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Do(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = bytes.NewReader(raw)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if e != nil {
		return errors.New("invalid API request")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, e := c.HTTP.Do(req)
	if e != nil {
		return errors.New("broker unavailable; check endpoint and TLS configuration")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var msg struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 8192)).Decode(&msg)
		if msg.Error == "" {
			msg.Error = http.StatusText(res.StatusCode)
		}
		return fmt.Errorf("broker: %s", msg.Error)
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(output)
}

type SavedReceipt struct {
	Endpoint string         `json:"endpoint"`
	Receipt  broker.Receipt `json:"receipt"`
}

func SaveReceipt(path, endpoint string, r broker.Receipt) (string, error) {
	if path == "" {
		dir, e := os.UserCacheDir()
		if e != nil {
			return "", e
		}
		dir = filepath.Join(dir, "handkey", "receipts")
		if e = os.MkdirAll(dir, 0700); e != nil {
			return "", e
		}
		path = filepath.Join(dir, r.ID+".receipt.json")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", errors.New("cannot create receipt file (must not already exist)")
	}
	defer f.Close()
	if e = json.NewEncoder(f).Encode(SavedReceipt{Endpoint: endpoint, Receipt: r}); e != nil {
		return "", e
	}
	if e = f.Sync(); e != nil {
		return "", e
	}
	return path, nil
}
func LoadReceipt(path string) (SavedReceipt, error) {
	var saved SavedReceipt
	raw, e := os.ReadFile(path)
	if e != nil {
		return saved, errors.New("cannot read receipt")
	}
	if json.Unmarshal(raw, &saved) != nil || saved.Receipt.ID == "" || saved.Receipt.Token == "" {
		return saved, errors.New("invalid receipt")
	}
	return saved, nil
}
func (c *Client) Wait(ctx context.Context, r broker.Receipt) (*broker.Request, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var req broker.Request
		e := c.Do(ctx, "GET", "/v1/requests/"+r.ID, r.Token, nil, &req)
		if e != nil {
			return nil, e
		}
		if req.Execution == "ready" || req.Execution == "succeeded" {
			return &req, nil
		}
		if req.Approval == "denied" || req.Approval == "expired" || req.Approval == "cancelled" || req.Execution == "failed" || req.Execution == "unknown" || req.Execution == "expired" || req.Execution == "consumed" {
			return nil, fmt.Errorf("request %s: approval=%s execution=%s", r.ID, req.Approval, req.Execution)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
