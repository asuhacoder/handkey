package broker

import "time"

type Ref struct {
	Vault string `json:"vault"`
	Item  string `json:"item"`
	Field string `json:"field"`
}

func (r Ref) Key() string { return r.Vault + "/" + r.Item + "/" + r.Field }

type Field struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
}
type Item struct {
	ID          string    `json:"id"`
	Vault       string    `json:"vault"`
	VaultName   string    `json:"vault_name,omitempty"`
	Title       string    `json:"title"`
	URLs        []string  `json:"urls,omitempty"`
	Fields      []Field   `json:"fields,omitempty"`
	FieldsKnown bool      `json:"fields_known"`
	SyncedAt    time.Time `json:"synced_at"`
}
type Create struct {
	Vault            string        `json:"vault"`
	Title            string        `json:"title"`
	Category         string        `json:"category"`
	GeneratePassword string        `json:"generate_password,omitempty"`
	Fields           []CreateField `json:"fields,omitempty"`
}
type CreateField struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}
type Spec struct {
	Method       string            `json:"method"`
	Refs         []Ref             `json:"refs,omitempty"`
	Reason       string            `json:"reason"`
	Agent        string            `json:"agent,omitempty"`
	TTLSeconds   int               `json:"ttl_seconds,omitempty"`
	Uses         int               `json:"uses,omitempty"`
	WaitSeconds  int               `json:"wait_seconds,omitempty"`
	Command      []string          `json:"command,omitempty"`
	Directory    string            `json:"directory,omitempty"`
	Bindings     map[string]string `json:"bindings,omitempty"` // environment/header name -> canonical reference key
	Origin       string            `json:"origin,omitempty"`
	Header       string            `json:"header,omitempty"`
	Prefix       string            `json:"prefix,omitempty"`
	Unredacted   bool              `json:"unredacted,omitempty"`
	OutputFormat string            `json:"output_format,omitempty"`
	Target       string            `json:"target,omitempty"`
	Create       *Create           `json:"create,omitempty"`
}

// RefDisplay is what the cache knew about one reference when the request was
// submitted. The names are untrusted text and are never updated afterwards.
type RefDisplay struct {
	Vault      string   `json:"vault"`
	Item       string   `json:"item"`
	Field      string   `json:"field"`
	VaultName  string   `json:"vault_name"`
	ItemTitle  string   `json:"item_title"`
	FieldLabel string   `json:"field_label"`
	FieldType  string   `json:"field_type"`
	Origins    []string `json:"origins"`
	Known      bool     `json:"known"`
}
type RequestDisplay struct {
	Refs            []RefDisplay `json:"refs"`
	CreateVaultName string       `json:"create_vault_name,omitempty"`
}
type Request struct {
	ID              string          `json:"id"`
	Spec            Spec            `json:"spec"`
	Display         *RequestDisplay `json:"display,omitempty"`
	Approval        string          `json:"approval"`
	Execution       string          `json:"execution"`
	CreatedAt       time.Time       `json:"created_at"`
	Deadline        time.Time       `json:"deadline"`
	ApprovedAt      time.Time       `json:"approved_at,omitempty"`
	ApprovedBy      string          `json:"approved_by,omitempty"`
	ApprovedSession string          `json:"approved_session,omitempty"`
	LeaseUntil      time.Time       `json:"lease_until,omitempty"`
	Used            int             `json:"used"`
	ReceiptHash     string          `json:"receipt_hash,omitempty"`
	ReceiptUntil    time.Time       `json:"receipt_until"`
	Source          string          `json:"source"`
	Error           string          `json:"error,omitempty"`
	CreatedItem     *Item           `json:"created_item,omitempty"`
}

// Device is one key registration, not a physical device. Its key may be synced
// to many machines, and every client that holds it gets its own Session.
type Device struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	WrappedKey []byte              `json:"wrapped_key"`
	Sessions   map[string]*Session `json:"sessions"`
	Revoked    bool                `json:"revoked"`
}

// Session is one client installation. Name is caller-supplied and untrusted.
type Session struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	ViewHash  string    `json:"view_hash"`
	CreatedAt time.Time `json:"created_at"`
	ViewUntil time.Time `json:"view_until"`
}
type SessionInfo struct {
	SessionID string    `json:"session_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	ViewUntil time.Time `json:"view_until"`
	Current   bool      `json:"current"`
}
type Credentials struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	ViewToken string    `json:"view_token"`
	ViewUntil time.Time `json:"view_until"`
}
type Receipt struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}
type Result struct {
	Request        *Request          `json:"request"`
	Values         map[string]string `json:"values,omitempty"`
	ExecutionToken string            `json:"execution_token,omitempty"`
}
type Event struct {
	ID   string    `json:"id"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}
type State struct {
	Version        int                 `json:"version"`
	EncryptedToken []byte              `json:"encrypted_token,omitempty"`
	Devices        map[string]*Device  `json:"devices"`
	Requests       map[string]*Request `json:"requests"`
	Cache          map[string]Item     `json:"cache"`
	LastSync       time.Time           `json:"last_sync"`
}
