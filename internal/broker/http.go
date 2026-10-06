package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/asuhacoder/handkey/internal/cryptobox"
)

type HTTPOptions struct {
	Bootstrap      bool
	AllowedOrigins []string
}
type api struct {
	b       *Broker
	options HTTPOptions
}

func (b *Broker) Handler(options HTTPOptions) http.Handler {
	a := &api{b: b, options: options}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{"status": "ok", "initialized": b.Initialized()})
	})
	mux.HandleFunc("POST /v1/bootstrap", a.bootstrap)
	mux.HandleFunc("POST /v1/devices", a.addDevice)
	mux.HandleFunc("POST /v1/devices/{id}/revoke", a.revoke)
	mux.HandleFunc("POST /v1/devices/{id}/sessions", a.createSession)
	mux.HandleFunc("GET /v1/devices/{id}/sessions", a.sessions)
	mux.HandleFunc("POST /v1/sessions/{sid}/revoke", a.revokeSession)
	mux.HandleFunc("POST /v1/token/rotate", a.rotate)
	mux.HandleFunc("POST /v1/requests", a.submit)
	mux.HandleFunc("GET /v1/requests", a.requests)
	mux.HandleFunc("GET /v1/requests/{id}", a.status)
	mux.HandleFunc("POST /v1/requests/{id}/approve", a.approve)
	mux.HandleFunc("POST /v1/requests/{id}/deny", a.deny)
	mux.HandleFunc("POST /v1/requests/{id}/cancel", a.cancel)
	mux.HandleFunc("POST /v1/requests/{id}/consume", a.consume)
	mux.HandleFunc("POST /v1/requests/{id}/heartbeat", a.heartbeat)
	mux.HandleFunc("DELETE /v1/requests/{id}/execution", a.endExecution)
	mux.HandleFunc("/v1/requests/{id}/proxy/{path...}", a.proxy)
	mux.HandleFunc("GET /v1/items", a.items)
	mux.HandleFunc("GET /v1/events", a.events)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if origin := r.Header.Get("Origin"); origin != "" {
			allowed := false
			for _, o := range options.AllowedOrigins {
				if o == origin && o != "null" && o != "*" {
					allowed = true
				}
			}
			if !allowed {
				failure(w, ErrDenied)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			if r.Method == "OPTIONS" {
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.WriteHeader(204)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		reply(w, 415, map[string]string{"error": "Content-Type must be application/json"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil {
		reply(w, 400, map[string]string{"error": "invalid request body"})
		return false
	}
	if decoder.Decode(new(any)) != io.EOF {
		reply(w, 400, map[string]string{"error": "invalid request body"})
		return false
	}
	return true
}
func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func failure(w http.ResponseWriter, e error) {
	status := 400
	switch {
	case errors.Is(e, ErrDenied):
		status = 401
	case errors.Is(e, ErrMissing):
		status = 404
	case errors.Is(e, ErrConflict), errors.Is(e, ErrSessionLimit):
		status = 409
	case errors.Is(e, ErrExpired):
		status = 410
	case errors.Is(e, ErrUnavailable):
		status = 503
	}
	reply(w, status, map[string]string{"error": e.Error()})
}

// viewer authenticates the view token and returns its device and session IDs.
func (a *api) viewer(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	device, session, e := a.b.View(bearer(r))
	if e != nil {
		failure(w, e)
		return "", "", false
	}
	return device, session, true
}

type keyBody struct {
	Key string `json:"key"`
}

func readKey(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	var input keyBody
	if !decode(w, r, &input) {
		return nil, false
	}
	key, e := cryptobox.DecodeKey(input.Key)
	input.Key = ""
	if e != nil {
		failure(w, ErrDenied)
		return nil, false
	}
	return key, true
}
func (a *api) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !a.options.Bootstrap {
		failure(w, ErrMissing)
		return
	}
	var in struct {
		Name        string `json:"name"`
		SessionName string `json:"session_name"`
		Key         string `json:"key"`
		Token       string `json:"service_account_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	key, e := cryptobox.DecodeKey(in.Key)
	if e != nil {
		failure(w, ErrDenied)
		return
	}
	defer cryptobox.Wipe(key)
	token := []byte(in.Token)
	in.Token = ""
	defer cryptobox.Wipe(token)
	c, e := a.b.Bootstrap(in.Name, in.SessionName, key, token)
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 201, c)
}
func (a *api) addDevice(w http.ResponseWriter, r *http.Request) {
	id, _, ok := a.viewer(w, r)
	if !ok {
		return
	}
	var in struct {
		Name   string `json:"name"`
		Key    string `json:"key"`
		NewKey string `json:"new_key"`
	}
	if !decode(w, r, &in) {
		return
	}
	key, e := cryptobox.DecodeKey(in.Key)
	if e != nil {
		failure(w, ErrDenied)
		return
	}
	defer cryptobox.Wipe(key)
	newKey, e := cryptobox.DecodeKey(in.NewKey)
	if e != nil {
		failure(w, ErrDenied)
		return
	}
	defer cryptobox.Wipe(newKey)
	c, e := a.b.AddDevice(id, key, in.Name, newKey)
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 201, c)
}
func (a *api) revoke(w http.ResponseWriter, r *http.Request) {
	id, _, ok := a.viewer(w, r)
	if !ok {
		return
	}
	key, ok := readKey(w, r)
	if !ok {
		return
	}
	defer cryptobox.Wipe(key)
	if e := a.b.Revoke(id, key, r.PathValue("id")); e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, map[string]string{"status": "revoked"})
}
func (a *api) createSession(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	key, e := cryptobox.DecodeKey(in.Key)
	in.Key = ""
	if e != nil {
		failure(w, ErrDenied)
		return
	}
	defer cryptobox.Wipe(key)
	c, e := a.b.CreateSession(r.PathValue("id"), key, in.Name)
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 201, c)
}
func (a *api) sessions(w http.ResponseWriter, r *http.Request) {
	device, session, ok := a.viewer(w, r)
	if !ok {
		return
	}
	list, e := a.b.Sessions(device, session, r.PathValue("id"))
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, list)
}
func (a *api) revokeSession(w http.ResponseWriter, r *http.Request) {
	device, session, ok := a.viewer(w, r)
	if !ok {
		return
	}
	// A session ends itself with no body. Ending a sibling carries the device key.
	var key []byte
	if r.ContentLength != 0 {
		if key, ok = readKey(w, r); !ok {
			return
		}
		defer cryptobox.Wipe(key)
	}
	if e := a.b.RevokeSession(device, session, r.PathValue("sid"), key); e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, map[string]string{"status": "revoked"})
}
func (a *api) rotate(w http.ResponseWriter, r *http.Request) {
	id, _, ok := a.viewer(w, r)
	if !ok {
		return
	}
	var in struct {
		Key   string `json:"key"`
		Token string `json:"service_account_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	key, e := cryptobox.DecodeKey(in.Key)
	if e != nil {
		failure(w, ErrDenied)
		return
	}
	defer cryptobox.Wipe(key)
	token := []byte(in.Token)
	defer cryptobox.Wipe(token)
	if e = a.b.Rotate(id, key, token); e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, map[string]string{"status": "rotated"})
}
func (a *api) submit(w http.ResponseWriter, r *http.Request) {
	var spec Spec
	if !decode(w, r, &spec) {
		return
	}
	receipt, e := a.b.Submit(spec, r.RemoteAddr)
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 202, receipt)
}
func (a *api) requests(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.viewer(w, r); !ok {
		return
	}
	reply(w, 200, a.b.Requests())
}
func (a *api) status(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, _, e := a.b.View(bearer(r)); e == nil {
		a.b.mu.Lock()
		defer a.b.mu.Unlock()
		req := a.b.st.Requests[id]
		if req == nil {
			failure(w, ErrMissing)
			return
		}
		reply(w, 200, cloneRequest(req))
		return
	}
	req, e := a.b.Status(id, bearer(r))
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, req)
}
func (a *api) approve(w http.ResponseWriter, r *http.Request) {
	device, session, ok := a.viewer(w, r)
	if !ok {
		return
	}
	key, ok := readKey(w, r)
	if !ok {
		return
	}
	defer cryptobox.Wipe(key)
	if e := a.b.Approve(r.Context(), r.PathValue("id"), device, session, key); e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, map[string]string{"status": "processed"})
}
func (a *api) deny(w http.ResponseWriter, r *http.Request) {
	device, session, ok := a.viewer(w, r)
	if !ok {
		return
	}
	if e := a.b.Reject(r.PathValue("id"), device, session); e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, map[string]string{"status": "denied"})
}
func (a *api) cancel(w http.ResponseWriter, r *http.Request) {
	if e := a.b.Cancel(r.PathValue("id"), bearer(r)); e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, map[string]string{"status": "cancelled"})
}
func (a *api) consume(w http.ResponseWriter, r *http.Request) {
	v, e := a.b.Consume(r.PathValue("id"), bearer(r))
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, v)
}
func (a *api) items(w http.ResponseWriter, r *http.Request) {
	authorized := false
	if id := r.URL.Query().Get("receipt_id"); id != "" {
		if req, e := a.b.Status(id, bearer(r)); e == nil && req.Spec.Method == "refresh" && req.Execution == "succeeded" && a.b.now().Before(req.ApprovedAt.Add(15*time.Minute)) {
			authorized = true
		}
	}
	items, sync, e := a.b.Metadata(r.URL.Query().Get("q"), authorized)
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, map[string]any{"items": items, "last_sync": sync, "synced": !sync.IsZero()})
}
func (a *api) events(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.viewer(w, r); !ok {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	c, unsubscribe := a.b.events.subscribe()
	defer unsubscribe()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, _ = fmt.Fprint(w, "event: sync\ndata: {}\n\n")
	if rc.Flush() != nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-c:
			if _, _, e := a.b.View(bearer(r)); e != nil {
				return
			}
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			data, _ := json.Marshal(event)
			if _, e := fmt.Fprintf(w, "event: change\ndata: %s\n\n", data); e != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		case <-ticker.C:
			if _, _, e := a.b.View(bearer(r)); e != nil {
				return
			}
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, e := fmt.Fprint(w, ": heartbeat\n\n"); e != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
	}
}
