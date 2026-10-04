// Package onepassword is the only code that launches the real 1Password CLI.
package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/asuhacoder/handkey/internal/broker"
)

type CLI struct {
	Path    string
	TempDir string
}
type opItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Vault struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	URLs []struct {
		Href string `json:"href"`
	} `json:"urls"`
	Fields []struct {
		ID      string `json:"id"`
		Label   string `json:"label"`
		Type    string `json:"type"`
		Value   string `json:"value"`
		Section *struct {
			ID string `json:"id"`
		} `json:"section"`
	} `json:"fields"`
}

func metadata(item opItem, known bool) broker.Item {
	m := broker.Item{ID: item.ID, Vault: item.Vault.ID, VaultName: item.Vault.Name, Title: item.Title, FieldsKnown: known}
	for _, u := range item.URLs {
		m.URLs = append(m.URLs, u.Href)
	}
	for _, f := range item.Fields {
		id := f.ID
		if f.Section != nil && f.Section.ID != "" {
			id = f.Section.ID + "." + id
		}
		m.Fields = append(m.Fields, broker.Field{ID: id, Label: f.Label, Type: f.Type})
	}
	return m
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("1Password response exceeded limit")
	}
	return b.Buffer.Write(p)
}
func (c *CLI) run(ctx context.Context, token []byte, input []byte, args ...string) ([]byte, error) {
	if !filepath.IsAbs(c.Path) {
		return nil, errors.New("real op path must be absolute")
	}
	dir, e := os.MkdirTemp(c.TempDir, "handkey-op-")
	if e != nil {
		return nil, errors.New("cannot create isolated op configuration")
	}
	defer os.RemoveAll(dir)
	command := exec.CommandContext(ctx, c.Path, append([]string{"--cache=false"}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "OP_CONFIG_DIR=" + dir, "OP_SERVICE_ACCOUNT_TOKEN=" + string(token), "OP_BIOMETRIC_UNLOCK_ENABLED=false"}
	if root := os.Getenv("SystemRoot"); root != "" {
		command.Env = append(command.Env, "SystemRoot="+root)
	}
	command.Dir = dir
	command.Stdin = bytes.NewReader(input)
	command.Stderr = io.Discard
	out := &limitedBuffer{limit: 8 << 20}
	command.Stdout = out
	if e = command.Run(); e != nil {
		clear(out.Bytes())
		return nil, errors.New("1Password operation failed")
	}
	return out.Bytes(), nil
}
func (c *CLI) Read(ctx context.Context, token []byte, refs []broker.Ref) (map[string]string, []broker.Item, error) {
	values := map[string]string{}
	items := []broker.Item{}
	group := map[string][]broker.Ref{}
	for _, r := range refs {
		group[r.Vault+"/"+r.Item] = append(group[r.Vault+"/"+r.Item], r)
	}
	for _, rs := range group {
		raw, e := c.run(ctx, token, nil, "item", "get", rs[0].Item, "--vault", rs[0].Vault, "--format=json")
		if e != nil {
			return nil, nil, e
		}
		var item opItem
		e = json.Unmarshal(raw, &item)
		clear(raw)
		if e != nil || item.ID != rs[0].Item || item.Vault.ID != rs[0].Vault {
			return nil, nil, errors.New("1Password returned an unexpected item")
		}
		items = append(items, metadata(item, true))
		for _, r := range rs {
			found := false
			for _, f := range item.Fields {
				id := f.ID
				if f.Section != nil && f.Section.ID != "" {
					id = f.Section.ID + "." + id
				}
				if id == r.Field {
					if f.Type == "SSHKEY" || f.Type == "FILE" {
						return nil, nil, errors.New("binary and SSH key fields require a future adapter")
					}
					values[r.Key()] = f.Value
					found = true
					break
				}
			}
			if !found {
				return nil, nil, errors.New("approved field was not found")
			}
		}
	}
	return values, items, nil
}
func (c *CLI) List(ctx context.Context, token []byte) ([]broker.Item, error) {
	raw, e := c.run(ctx, token, nil, "item", "list", "--format=json")
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	var items []opItem
	if json.Unmarshal(raw, &items) != nil {
		return nil, errors.New("invalid 1Password list response")
	}
	result := make([]broker.Item, 0, len(items))
	for _, item := range items {
		result = append(result, metadata(item, false))
	}
	return result, nil
}
func (c *CLI) Create(ctx context.Context, token []byte, create broker.Create, request string) (broker.Item, error) {
	// Values travel exclusively on stdin, never in process arguments.
	fields := make([]map[string]string, 0, len(create.Fields))
	for _, f := range create.Fields {
		fields = append(fields, map[string]string{"id": f.ID, "label": f.Label, "type": f.Type, "value": f.Value})
	}
	payload := map[string]any{"title": create.Title, "category": create.Category, "vault": map[string]string{"id": create.Vault}, "fields": fields, "tags": []string{"handkey-request:" + request}}
	input, e := json.Marshal(payload)
	if e != nil {
		return broker.Item{}, errors.New("invalid create payload")
	}
	defer clear(input)
	args := []string{"item", "create", "--format=json"}
	if create.GeneratePassword != "" {
		args = append(args, "--generate-password="+create.GeneratePassword)
	}
	raw, e := c.run(ctx, token, input, args...)
	if e != nil {
		return broker.Item{}, e
	}
	defer clear(raw)
	var item opItem
	if json.Unmarshal(raw, &item) != nil || item.ID == "" || !strings.EqualFold(item.Vault.ID, create.Vault) {
		return broker.Item{}, errors.New("invalid create response")
	}
	return metadata(item, true), nil
}
