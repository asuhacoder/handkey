package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/asuhacoder/handkey/internal/cryptobox"
)

var (
	ErrDenied       = errors.New("authentication failed")
	ErrConflict     = errors.New("request is no longer pending")
	ErrSessionLimit = errors.New("session limit reached; revoke a session first")
	ErrUnavailable  = errors.New("operation unavailable; inspect request status")
	ErrMissing      = errors.New("not found or not authorized")
	ErrExpired      = errors.New("result or lease expired; submit a new request")
)

// Provider is only called while an approval key has unlocked the token.
type Provider interface {
	Read(context.Context, []byte, []Ref) (map[string]string, []Item, error)
	List(context.Context, []byte) ([]Item, error)
	Create(context.Context, []byte, Create, string) (Item, error)
}
type Broker struct {
	mu                      sync.Mutex
	st                      State
	disk                    *store
	provider                Provider
	values                  map[string]map[string]string
	executions              map[string]*execution
	events                  events
	now                     func() time.Time
	broken                  bool
	closed                  bool
	wg                      sync.WaitGroup
	RequireMetadataApproval bool
}
type execution struct {
	Request string
	Hash    string
	Values  map[string]string
	Until   time.Time
}

func Open(dir string, p Provider) (*Broker, error) {
	disk, state, e := openStore(dir)
	if e != nil {
		return nil, e
	}
	b := &Broker{st: state, disk: disk, provider: p, values: map[string]map[string]string{}, executions: map[string]*execution{}, now: time.Now}
	for _, r := range b.st.Requests {
		if r.Execution == "running" {
			if r.Spec.Method == "write" {
				r.Execution = "unknown"
			} else {
				r.Execution = "failed"
			}
			r.Error = "broker restarted during execution"
		}
		if r.Execution == "ready" && r.Spec.Method != "write" && r.Spec.Method != "refresh" {
			r.Execution = "expired"
			r.Error = "in-memory values were lost on restart"
		}
	}
	if e = b.disk.save(&b.st); e != nil {
		disk.close()
		return nil, e
	}
	return b, nil
}
func (b *Broker) Close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.wg.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values = map[string]map[string]string{}
	b.executions = map[string]*execution{}
	b.disk.close()
}
func (b *Broker) changed(r *Request, kind string) error {
	if b.broken {
		return ErrUnavailable
	}
	if e := b.disk.save(&b.st); e != nil {
		b.broken = true
		return ErrUnavailable
	}
	a := Audit{At: b.now(), Kind: kind}
	if r != nil {
		a.Request = r.ID
		a.Method = r.Spec.Method
		a.Refs = r.Spec.Refs
		a.Origin = r.Spec.Origin
		a.Device = r.ApprovedBy
		a.Session = r.ApprovedSession
		a.TTL = r.Spec.TTLSeconds
		a.Uses = r.Spec.Uses
	}
	if e := b.disk.audit(a); e != nil {
		b.broken = true
		return ErrUnavailable
	}
	b.events.send(Event{ID: a.Request, Kind: kind, At: a.At})
	return nil
}
func (b *Broker) Initialized() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.st.EncryptedToken) > 0
}
func (b *Broker) Bootstrap(name, sessionName string, key, token []byte) (Credentials, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.broken {
		return Credentials{}, ErrUnavailable
	}
	if len(b.st.EncryptedToken) > 0 {
		return Credentials{}, ErrConflict
	}
	if sessionName == "" {
		sessionName = name
	}
	if len(key) != 32 || len(token) == 0 || len(token) > 16384 || len(name) > maxNameLength || len(sessionName) > maxNameLength {
		return Credentials{}, errors.New("invalid registration")
	}
	master := cryptobox.Random(32)
	defer cryptobox.Wipe(master)
	encrypted, e := cryptobox.Seal(master, token, "service-account-v1")
	if e != nil {
		return Credentials{}, e
	}
	d, c, e := b.newDevice(name, sessionName, key, master)
	if e != nil {
		return Credentials{}, e
	}
	b.st.EncryptedToken = encrypted
	b.st.Devices[d.ID] = d
	return c, b.changed(nil, "bootstrap")
}

const (
	sessionLifetime = 90 * 24 * time.Hour
	maxSessions     = 16
	maxNameLength   = 128
)

func (b *Broker) newDevice(name, sessionName string, key, master []byte) (*Device, Credentials, error) {
	id := cryptobox.Token()
	wrapped, e := cryptobox.Seal(key, master, "device:"+id)
	d := &Device{ID: id, Name: name, WrappedKey: wrapped, Sessions: map[string]*Session{}}
	return d, b.newSession(d, sessionName), e
}
func (b *Broker) newSession(d *Device, name string) Credentials {
	view := cryptobox.Token()
	s := &Session{ID: cryptobox.Token(), Name: name, ViewHash: cryptobox.Hash(view), CreatedAt: b.now(), ViewUntil: b.now().Add(sessionLifetime)}
	d.Sessions[s.ID] = s
	return Credentials{ID: d.ID, SessionID: s.ID, ViewToken: view, ViewUntil: s.ViewUntil}
}

// live returns the session only while its device is active and it is unexpired.
func (b *Broker) live(device, session string) *Session {
	d := b.st.Devices[device]
	if d == nil || d.Revoked {
		return nil
	}
	s := d.Sessions[session]
	if s == nil || !b.now().Before(s.ViewUntil) {
		return nil
	}
	return s
}
func (b *Broker) unlock(id string, key []byte) ([]byte, []byte, error) {
	d := b.st.Devices[id]
	if d == nil || d.Revoked {
		return nil, nil, ErrDenied
	}
	master, e := cryptobox.Open(key, d.WrappedKey, "device:"+id)
	if e != nil {
		return nil, nil, ErrDenied
	}
	token, e := cryptobox.Open(master, b.st.EncryptedToken, "service-account-v1")
	if e != nil {
		cryptobox.Wipe(master)
		return nil, nil, ErrDenied
	}
	return master, token, nil
}

// verify proves possession of the device key without keeping what it unlocks.
func (b *Broker) verify(id string, key []byte) error {
	master, token, e := b.unlock(id, key)
	cryptobox.Wipe(master)
	cryptobox.Wipe(token)
	return e
}

// View resolves a view token to the device and session it belongs to.
func (b *Broker) View(token string) (string, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return "", "", ErrUnavailable
	}
	for _, d := range b.st.Devices {
		for _, s := range d.Sessions {
			if cryptobox.Matches(s.ViewHash, token) && b.live(d.ID, s.ID) != nil {
				return d.ID, s.ID, nil
			}
		}
	}
	return "", "", ErrDenied
}

// AddDevice registers a second key. Clients that share an existing key call
// CreateSession instead.
func (b *Broker) AddDevice(id string, key []byte, name string, newKey []byte) (Credentials, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return Credentials{}, ErrUnavailable
	}
	if len(name) > maxNameLength || len(newKey) != 32 {
		return Credentials{}, errors.New("invalid registration")
	}
	master, token, e := b.unlock(id, key)
	if e != nil {
		return Credentials{}, e
	}
	defer cryptobox.Wipe(master)
	defer cryptobox.Wipe(token)
	d, c, e := b.newDevice(name, name, newKey, master)
	if e != nil {
		return Credentials{}, e
	}
	b.st.Devices[d.ID] = d
	return c, b.changed(nil, "device_added")
}

// CreateSession issues another view token for a device. The device key is the
// only credential, so an unknown device and a wrong key are indistinguishable.
func (b *Broker) CreateSession(device string, key []byte, name string) (Credentials, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return Credentials{}, ErrUnavailable
	}
	if len(name) > maxNameLength {
		return Credentials{}, errors.New("invalid session name")
	}
	if e := b.verify(device, key); e != nil {
		return Credentials{}, e
	}
	d := b.st.Devices[device]
	active := 0
	for id := range d.Sessions {
		if b.live(device, id) != nil {
			active++
		}
	}
	if active >= maxSessions {
		return Credentials{}, ErrSessionLimit
	}
	return b.newSession(d, name), b.changed(nil, "session_created")
}

// Sessions lists the active sessions of the caller's own device.
func (b *Broker) Sessions(device, session, target string) ([]SessionInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return nil, ErrUnavailable
	}
	if b.live(device, session) == nil {
		return nil, ErrDenied
	}
	if target != device {
		return nil, ErrMissing
	}
	out := []SessionInfo{}
	for id, s := range b.st.Devices[device].Sessions {
		if b.live(device, id) != nil {
			out = append(out, SessionInfo{SessionID: id, Name: s.Name, CreatedAt: s.CreatedAt, ViewUntil: s.ViewUntil, Current: id == session})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out, nil
}

// RevokeSession ends one session of the caller's device. A session may end
// itself with its view token alone; ending a sibling also needs the device key.
func (b *Broker) RevokeSession(device, session, target string, key []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return ErrUnavailable
	}
	if b.live(device, session) == nil {
		return ErrDenied
	}
	d := b.st.Devices[device]
	if d.Sessions[target] == nil {
		return ErrMissing
	}
	if target != session {
		if e := b.verify(device, key); e != nil {
			return e
		}
	}
	delete(d.Sessions, target)
	return b.changed(nil, "session_revoked")
}
func (b *Broker) Revoke(id string, key []byte, target string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return ErrUnavailable
	}
	if e := b.verify(id, key); e != nil {
		return e
	}
	d := b.st.Devices[target]
	if d == nil {
		return ErrMissing
	}
	d.Revoked = true
	d.WrappedKey = nil
	d.Sessions = map[string]*Session{}
	return b.changed(nil, "device_revoked")
}
func (b *Broker) Rotate(id string, key, token []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return ErrUnavailable
	}
	if len(token) == 0 || len(token) > 16384 {
		return errors.New("invalid token")
	}
	master, old, e := b.unlock(id, key)
	if e != nil {
		return e
	}
	defer cryptobox.Wipe(master)
	defer cryptobox.Wipe(old)
	encrypted, e := cryptobox.Seal(master, token, "service-account-v1")
	if e != nil {
		return e
	}
	b.st.EncryptedToken = encrypted
	return b.changed(nil, "token_rotated")
}

var idPattern = regexp.MustCompile(`^[a-z0-9]{26}$`)
var fieldPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (b *Broker) normalize(r Ref) (Ref, error) {
	var matches []Ref
	for _, item := range b.st.Cache {
		if (item.Vault == r.Vault || item.VaultName == r.Vault) && (item.ID == r.Item || item.Title == r.Item) {
			for _, f := range item.Fields {
				if f.ID == r.Field || f.Label == r.Field {
					matches = append(matches, Ref{item.Vault, item.ID, f.ID})
				}
			}
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return Ref{}, errors.New("ambiguous reference; use vault, item and field IDs")
	}
	// Explicit IDs are usable before a metadata sync. Names never resolve during execution.
	if idPattern.MatchString(r.Vault) && idPattern.MatchString(r.Item) && fieldPattern.MatchString(r.Field) {
		return r, nil
	}
	return Ref{}, errors.New("reference not cached; request an approved refresh, or use canonical IDs")
}
func cloneRequest(r *Request) *Request {
	data, _ := json.Marshal(r)
	var copy Request
	_ = json.Unmarshal(data, &copy)
	copy.ReceiptHash = ""
	if copy.Spec.Create != nil {
		for i := range copy.Spec.Create.Fields {
			copy.Spec.Create.Fields[i].Value = ""
		}
	}
	return &copy
}
func (b *Broker) Submit(spec Spec, source string) (Receipt, error) {
	// Freeze all nested slices/maps before retaining an in-process caller's request.
	encoded, err := json.Marshal(spec)
	if err != nil {
		return Receipt{}, errors.New("invalid request")
	}
	var frozen Spec
	if json.Unmarshal(encoded, &frozen) != nil {
		return Receipt{}, errors.New("invalid request")
	}
	cryptobox.Wipe(encoded)
	spec = frozen
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed || len(b.st.EncryptedToken) == 0 {
		return Receipt{}, ErrUnavailable
	}
	if spec.OutputFormat != "" && spec.OutputFormat != "json" {
		return Receipt{}, errors.New("unsupported output format")
	}
	if len(spec.Reason) > 4096 || len(spec.Agent) > 128 || len(spec.Refs) > 64 || len(spec.Command) > 256 {
		return Receipt{}, errors.New("request exceeds limits")
	}
	if spec.Uses == 0 {
		spec.Uses = 1
	}
	if spec.WaitSeconds == 0 {
		spec.WaitSeconds = 900
	}
	if spec.Uses < 1 || spec.Uses > 10000 || spec.TTLSeconds < 0 || spec.TTLSeconds > 86400 || spec.WaitSeconds < 1 || spec.WaitSeconds > 900 {
		return Receipt{}, errors.New("invalid lease or approval deadline")
	}
	if spec.Uses > 1 && spec.TTLSeconds == 0 {
		return Receipt{}, errors.New("multiple uses require an explicit ttl")
	}
	switch spec.Method {
	case "reveal", "otp", "exec", "proxy", "type", "clipboard":
		if len(spec.Refs) == 0 {
			return Receipt{}, errors.New("references required")
		}
	case "write", "refresh":
		if spec.Uses != 1 || spec.TTLSeconds != 0 {
			return Receipt{}, errors.New("write and refresh cannot be leased")
		}
	default:
		return Receipt{}, errors.New("unsupported method")
	}
	oldKeys := map[string]string{}
	seen := map[string]bool{}
	for i, r := range spec.Refs {
		normalized, e := b.normalize(r)
		if e != nil {
			return Receipt{}, e
		}
		if seen[normalized.Key()] {
			return Receipt{}, errors.New("duplicate reference")
		}
		seen[normalized.Key()] = true
		oldKeys[r.Key()] = normalized.Key()
		spec.Refs[i] = normalized
	}
	for name, key := range spec.Bindings {
		if !envPattern.MatchString(name) || strings.HasPrefix(name, "OP_") || strings.HasPrefix(name, "HANDKEY_") {
			return Receipt{}, errors.New("invalid or reserved environment variable")
		}
		normalized, ok := oldKeys[key]
		if !ok {
			return Receipt{}, errors.New("binding is outside approved fields")
		}
		spec.Bindings[name] = normalized
	}
	if spec.Method == "exec" || spec.Method == "proxy" {
		if len(spec.Command) == 0 || spec.Directory == "" {
			return Receipt{}, errors.New("command and working directory required")
		}
	}
	if spec.Method == "proxy" {
		u, e := url.Parse(spec.Origin)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return Receipt{}, errors.New("proxy requires a fixed HTTPS origin")
		}
		if len(spec.Refs) != 1 || !validHeader(spec.Header) || strings.ContainsAny(spec.Prefix, "\r\n") {
			return Receipt{}, errors.New("invalid proxy header or references")
		}
	}
	if (spec.Method == "type" || spec.Method == "clipboard") && len(spec.Refs) != 1 {
		return Receipt{}, errors.New("one reference required")
	}
	if spec.Method == "type" && spec.Target == "" {
		return Receipt{}, errors.New("foreground target required")
	}
	if spec.Method == "write" {
		if e := validateCreate(spec.Create); e != nil {
			return Receipt{}, e
		}
	} else if spec.Create != nil {
		return Receipt{}, errors.New("create payload requires write method")
	}
	// Bound uncollected requests to keep a network peer from exhausting memory/disk indefinitely.
	if len(b.st.Requests) >= 10000 {
		return Receipt{}, errors.New("request limit reached; prune expired requests")
	}
	id, token := cryptobox.Token(), cryptobox.Token()
	now := b.now()
	r := &Request{ID: id, Spec: spec, Approval: "pending", Execution: "not_started", CreatedAt: now, Deadline: now.Add(time.Duration(spec.WaitSeconds) * time.Second), ReceiptHash: cryptobox.Hash(token), ReceiptUntil: now.Add(24 * time.Hour), Source: source}
	b.st.Requests[id] = r
	return Receipt{ID: id, Token: token}, b.changed(r, "requested")
}
func validateCreate(c *Create) error {
	if c == nil || !idPattern.MatchString(c.Vault) || c.Title == "" || len(c.Title) > 256 || len(c.Fields) > 64 {
		return errors.New("create requires vault ID, title and at most 64 fields")
	}
	switch c.Category {
	case "LOGIN", "PASSWORD", "API_CREDENTIAL", "SECURE_NOTE", "CREDIT_CARD", "IDENTITY":
	default:
		return errors.New("unsupported item category")
	}
	if c.GeneratePassword != "" {
		for _, part := range strings.Split(c.GeneratePassword, ",") {
			if part == "letters" || part == "digits" || part == "symbols" {
				continue
			}
			var n int
			if _, e := fmt.Sscanf(part, "%d", &n); e != nil || n < 1 || n > 64 || fmt.Sprint(n) != part {
				return errors.New("invalid password recipe")
			}
		}
	}
	seen := map[string]bool{}
	for _, f := range c.Fields {
		if !fieldPattern.MatchString(f.ID) || seen[f.ID] || len(f.Value) > 65536 {
			return errors.New("invalid create field")
		}
		seen[f.ID] = true
		switch f.Type {
		case "STRING", "CONCEALED", "EMAIL", "URL", "PHONE", "DATE", "MONTH_YEAR", "OTP":
		default:
			return errors.New("unsupported field type")
		}
	}
	return nil
}
func (b *Broker) expireLocked(r *Request) bool {
	if r.Approval == "pending" && !b.now().Before(r.Deadline) {
		r.Approval = "expired"
		return true
	}
	if r.Execution == "ready" && r.Spec.Method != "write" && r.Spec.Method != "refresh" && (!b.now().Before(r.LeaseUntil) || r.Used >= r.Spec.Uses) {
		delete(b.values, r.ID)
		r.Execution = "expired"
		return true
	}
	return false
}
func (b *Broker) Sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.broken {
		return
	}
	changed := false
	for id, r := range b.st.Requests {
		if b.expireLocked(r) {
			changed = true
		}
		if b.now().After(r.ReceiptUntil.Add(7*24*time.Hour)) && r.Execution != "running" {
			delete(b.st.Requests, id)
			delete(b.values, id)
			changed = true
		}
	}
	for id, e := range b.executions {
		if !b.now().Before(e.Until) {
			delete(b.executions, id)
		}
	}
	for _, d := range b.st.Devices {
		for id, s := range d.Sessions {
			if !b.now().Before(s.ViewUntil) {
				delete(d.Sessions, id)
				changed = true
			}
		}
	}
	if changed {
		_ = b.changed(nil, "expired")
	}
}
func (b *Broker) Requests() []*Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []*Request{}
	for _, r := range b.st.Requests {
		if r.Approval == "pending" && b.now().Before(r.Deadline) {
			out = append(out, cloneRequest(r))
		}
	}
	return out
}
func (b *Broker) Status(id, token string) (*Request, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.st.Requests[id]
	if b.broken || b.closed {
		return nil, ErrUnavailable
	}
	if r == nil || !cryptobox.Matches(r.ReceiptHash, token) || !b.now().Before(r.ReceiptUntil) {
		return nil, ErrMissing
	}
	if b.expireLocked(r) {
		if e := b.changed(r, "expired"); e != nil {
			return nil, e
		}
	}
	return cloneRequest(r), nil
}
func (b *Broker) Cancel(id, token string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return ErrUnavailable
	}
	r := b.st.Requests[id]
	if r == nil || !cryptobox.Matches(r.ReceiptHash, token) || !b.now().Before(r.ReceiptUntil) {
		return ErrMissing
	}
	if r.Approval != "pending" {
		return ErrConflict
	}
	r.Approval = "cancelled"
	return b.changed(r, "cancelled")
}
func (b *Broker) Reject(id, device, session string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return ErrUnavailable
	}
	r := b.st.Requests[id]
	if r == nil {
		return ErrMissing
	}
	if b.live(device, session) == nil {
		return ErrDenied
	}
	if b.expireLocked(r) {
		if e := b.changed(r, "expired"); e != nil {
			return e
		}
	}
	if r.Approval != "pending" {
		return ErrConflict
	}
	r.Approval = "denied"
	r.ApprovedBy = device
	r.ApprovedSession = session
	return b.changed(r, "denied")
}

// Approve takes the caller's device and session as resolved by View. The key
// must unlock that same device, so a session cannot approve with another
// device's key.
func (b *Broker) Approve(ctx context.Context, id, device, session string, key []byte) error {
	b.mu.Lock()
	if b.closed || b.broken {
		b.mu.Unlock()
		return ErrUnavailable
	}
	r := b.st.Requests[id]
	if r == nil {
		b.mu.Unlock()
		return ErrMissing
	}
	if b.expireLocked(r) {
		if e := b.changed(r, "expired"); e != nil {
			b.mu.Unlock()
			return e
		}
	}
	if r.Approval != "pending" {
		b.mu.Unlock()
		return ErrConflict
	}
	if b.live(device, session) == nil {
		b.mu.Unlock()
		return ErrDenied
	}
	master, token, e := b.unlock(device, key)
	if e != nil {
		b.mu.Unlock()
		return e
	}
	cryptobox.Wipe(master)
	r.Approval = "approved"
	r.ApprovedBy = device
	r.ApprovedSession = session
	r.ApprovedAt = b.now()
	r.Execution = "running"
	if e = b.changed(r, "approved"); e != nil {
		cryptobox.Wipe(token)
		b.mu.Unlock()
		return e
	}
	b.wg.Add(1)
	b.mu.Unlock()
	defer b.wg.Done()
	// Once committed, an approver disconnect cannot cancel a write whose outcome may be unknown.
	opctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	values, items, created, err := b.perform(opctx, token, r)
	// An occasional list refresh shares this short unlock window; it never keeps
	// the service account token alive between approvals.
	b.mu.Lock()
	syncDue := b.now().Sub(b.st.LastSync) >= 15*time.Minute
	b.mu.Unlock()
	synced := r.Spec.Method == "refresh" && err == nil
	if err == nil && r.Spec.Method != "refresh" && syncDue {
		if listed, listErr := b.provider.List(opctx, token); listErr == nil {
			items = append(listed, items...)
			synced = true
		}
	}
	cryptobox.Wipe(token) // before result delivery or any user command starts
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Spec.Create != nil {
		for i := range r.Spec.Create.Fields {
			r.Spec.Create.Fields[i].Value = ""
		}
	}
	if err != nil {
		r.Execution = "failed"
		r.Error = "1Password operation failed"
		if r.Spec.Method == "write" {
			r.Execution = "unknown"
			r.Error = "write outcome unknown; reconcile using the request tag before retrying"
		}
		return b.changed(r, "execution_"+r.Execution)
	}
	if synced {
		retained := map[string]bool{}
		for _, item := range items {
			retained[item.Vault+"/"+item.ID] = true
		}
		for key := range b.st.Cache {
			if !retained[key] {
				delete(b.st.Cache, key)
			}
		}
	}
	for _, item := range items {
		b.cache(item)
	}
	if synced {
		b.st.LastSync = b.now()
	}
	if created != nil {
		b.cache(*created)
		safe := b.st.Cache[created.Vault+"/"+created.ID]
		r.CreatedItem = &safe
	}
	if r.Spec.Method == "write" || r.Spec.Method == "refresh" {
		r.Execution = "succeeded"
	} else {
		r.Execution = "ready"
		ttl := r.Spec.TTLSeconds
		if ttl == 0 {
			ttl = 900
		}
		r.LeaseUntil = b.now().Add(time.Duration(ttl) * time.Second)
		approved := map[string]string{}
		for _, ref := range r.Spec.Refs {
			approved[ref.Key()] = values[ref.Key()]
		}
		b.values[r.ID] = approved
	}
	// Caller-supplied write values are needed only until the operation completes.
	if r.Spec.Create != nil {
		for i := range r.Spec.Create.Fields {
			r.Spec.Create.Fields[i].Value = ""
		}
	}
	return b.changed(r, "execution_"+r.Execution)
}
func (b *Broker) perform(ctx context.Context, token []byte, r *Request) (map[string]string, []Item, *Item, error) {
	switch r.Spec.Method {
	case "refresh":
		items, e := b.provider.List(ctx, token)
		if e == nil && len(r.Spec.Refs) > 0 {
			_, details, err := b.provider.Read(ctx, token, r.Spec.Refs)
			if err != nil {
				return nil, nil, nil, err
			}
			items = append(items, details...)
		}
		return nil, items, nil, e
	case "write":
		item, e := b.provider.Create(ctx, token, *r.Spec.Create, r.ID)
		return nil, nil, &item, e
	default:
		values, items, e := b.provider.Read(ctx, token, r.Spec.Refs)
		if e == nil {
			for _, ref := range r.Spec.Refs {
				if _, ok := values[ref.Key()]; !ok {
					return nil, nil, nil, errors.New("provider did not return the approved field")
				}
			}
		}
		return values, items, nil, e
	}
}
func (b *Broker) cache(item Item) {
	item.SyncedAt = b.now()
	urls := []string{}
	for _, s := range item.URLs {
		u, e := url.Parse(s)
		if e == nil && u.Hostname() != "" && (u.Scheme == "https" || u.Scheme == "http") {
			urls = append(urls, u.Scheme+"://"+u.Host)
		}
	}
	item.URLs = urls
	key := item.Vault + "/" + item.ID
	if prev, ok := b.st.Cache[key]; ok && !item.FieldsKnown {
		item.Fields = prev.Fields
		item.FieldsKnown = prev.FieldsKnown
	}
	b.st.Cache[key] = item
}
func (b *Broker) Metadata(query string, authorized bool) ([]Item, time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return nil, time.Time{}, ErrUnavailable
	}
	if b.RequireMetadataApproval && !authorized {
		return nil, time.Time{}, errors.New("metadata requires approved refresh; use that receipt to read the cache")
	}
	out := []Item{}
	for _, item := range b.st.Cache {
		hay := strings.ToLower(item.Title + " " + item.ID + " " + strings.Join(item.URLs, " "))
		if strings.Contains(hay, strings.ToLower(query)) {
			out = append(out, item)
		}
	}
	return out, b.st.LastSync, nil
}

func (b *Broker) Consume(id, token string) (Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.broken || b.closed {
		return Result{}, ErrUnavailable
	}
	r := b.st.Requests[id]
	if r == nil || !cryptobox.Matches(r.ReceiptHash, token) || !b.now().Before(r.ReceiptUntil) {
		return Result{}, ErrMissing
	}
	if b.expireLocked(r) {
		if e := b.changed(r, "expired"); e != nil {
			return Result{}, e
		}
	}
	if r.Execution != "ready" || r.Approval != "approved" {
		return Result{}, ErrExpired
	}
	values, ok := b.values[id]
	if !ok {
		return Result{}, ErrExpired
	}
	result := Result{Request: cloneRequest(r), Values: map[string]string{}}
	for _, ref := range r.Spec.Refs {
		value := values[ref.Key()]
		if r.Spec.Method == "otp" {
			code, e := TOTP(value, b.now())
			if e != nil {
				return Result{}, e
			}
			value = code
		}
		result.Values[ref.Key()] = value
	}
	if r.Spec.Method == "proxy" {
		session := cryptobox.Token()
		b.executions[id+":"+cryptobox.Hash(session)] = &execution{Request: id, Hash: cryptobox.Hash(session), Values: result.Values, Until: b.now().Add(20 * time.Second)}
		result.Values = nil
		result.ExecutionToken = session
	}
	r.Used++
	result.Request.Used = r.Used
	if r.Used >= r.Spec.Uses {
		delete(b.values, id)
		r.Execution = "consumed"
		result.Request.Execution = "consumed"
	}
	if e := b.changed(r, "consumed"); e != nil {
		return Result{}, e
	}
	return result, nil
}
