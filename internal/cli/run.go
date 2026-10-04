package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/asuhacoder/handkey/internal/broker"
	"github.com/asuhacoder/handkey/internal/helper"
)

const Help = `handkey — approval-gated 1Password CLI

Usage:
  handkey serve --state-dir DIR --op ABSOLUTE_PATH [server options]
  handkey read op://VAULT/ITEM/FIELD [--reason TEXT] [--ttl 5m --uses 3]
  handkey item list [--vault ID] [--format json] [--query TEXT]
  handkey item get ITEM --vault VAULT [--fields FIELD,...] [--reveal | --otp | --format json]
  handkey item create --vault ID --title TITLE --category LOGIN [--generate-password letters,digits,32]
  handkey run [--env-file FILE] [--no-masking] -- COMMAND [ARG...]
  handkey inject [--in-file FILE] [--out-file FILE]
  handkey type op://VAULT/ITEM/FIELD
  handkey clipboard op://VAULT/ITEM/FIELD
  handkey proxy op://VAULT/ITEM/FIELD --origin https://api.example.com --header Authorization --prefix 'Bearer ' -- COMMAND
  handkey refresh [op://VAULT/ITEM/FIELD ...]
  handkey request --in-file REQUEST.json [--no-wait]
  handkey status RECEIPT_FILE | cancel RECEIPT_FILE | use RECEIPT_FILE

Common options (before --):
  --endpoint unix:///absolute/handkey.sock  Or an HTTPS origin; HANDKEY_ENDPOINT also works.
  --reason TEXT   --agent NAME   --ttl DURATION   --uses N   --wait DURATION (max 15m)
  --receipt FILE  Save the automatic receiver token to a new private file.
  --no-wait      Return the request ID and receipt path; use the receipt later.
  --dev         Permit plain HTTP only on numeric loopback addresses, for testing.

Copy/symlink the binary as op to use the same supported command syntax. Unsupported
commands and flags fail; they are never passed through to the real op executable.
Secrets use standard op:// references. Uncached names require an approved refresh;
explicit vault/item IDs and field IDs work without cache. 'refresh REF' also loads
field names. item get without a reveal/JSON/OTP flag returns metadata only.

read, inject (including --out-file), and JSON item get request reveal approval.
run injects op:// environment references into a child under your own user and cwd.
Each approval defaults to one use. A lease needs --ttl and --uses; 'use RECEIPT_FILE'
reuses only that request's approved fields and method. Command runs already started
may outlive the lease. Receipt files are bearer capabilities: do not share or log them.
Result tokens and approval keys are separate. No approval key belongs in CLI arguments.

proxy provides HANDKEY_PROXY_URL to one command, uses a fixed HTTPS origin, never
follows redirects, and is not an HTTPS_PROXY/CONNECT proxy. type and clipboard currently
require macOS; type checks the foreground window, clipboard clears it after 10 seconds
only if unchanged. run masks exact secret values in stdout/stderr unless --no-masking
was approved. Transformed/split disclosures by an untrusted command are not prevented.

item create reads optional JSON fields from --in-file (or stdin with '-'); generated
passwords are never returned. Existing-item edits, password promotion, documents,
attachments, passkeys, account management and unknown flags are not supported yet.
Write outcomes marked unknown must be reconciled by the handkey-request:<ID> tag
before submitting another create. No writes are retried automatically.

Approval clients live in separate repositories. See docs/api.md for registration,
request inspection, key submission, device revocation and event subscriptions.
`

type options struct {
	values   map[string]string
	flags    map[string]bool
	position []string
	command  []string
}

var boolFlags = map[string]bool{"reveal": true, "otp": true, "no-masking": true, "no-wait": true, "dev": true}
var valueFlags = map[string]bool{"endpoint": true, "reason": true, "agent": true, "ttl": true, "uses": true, "wait": true, "receipt": true, "vault": true, "format": true, "fields": true, "query": true, "env-file": true, "in-file": true, "out-file": true, "title": true, "category": true, "generate-password": true, "origin": true, "header": true, "prefix": true}

func parse(args []string) (options, error) {
	o := options{values: map[string]string{}, flags: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		s := args[i]
		if s == "--" {
			o.command = args[i+1:]
			break
		}
		if !strings.HasPrefix(s, "-") {
			o.position = append(o.position, s)
			continue
		}
		if !strings.HasPrefix(s, "--") {
			return o, errors.New("short flags are not supported")
		}
		k, v, eq := strings.Cut(s[2:], "=")
		if boolFlags[k] {
			if eq {
				return o, errors.New("boolean flags take no value")
			}
			if o.flags[k] {
				return o, errors.New("duplicate flag")
			}
			o.flags[k] = true
			continue
		}
		if !valueFlags[k] {
			return o, errors.New("unsupported flag; see --help")
		}
		if _, seen := o.values[k]; seen {
			return o, errors.New("duplicate flag")
		}
		if !eq {
			i++
			if i >= len(args) {
				return o, errors.New("missing flag value")
			}
			v = args[i]
		}
		o.values[k] = v
	}
	return o, nil
}
func allow(o options, flags ...string) error {
	common := map[string]bool{"endpoint": true, "reason": true, "agent": true, "ttl": true, "uses": true, "wait": true, "receipt": true, "no-wait": true, "dev": true}
	for _, f := range flags {
		common[f] = true
	}
	for k := range o.values {
		if !common[k] {
			return errors.New("flag not supported by this command")
		}
	}
	for k := range o.flags {
		if !common[k] {
			return errors.New("flag not supported by this command")
		}
	}
	return nil
}
func ParseRef(s string) (broker.Ref, error) {
	var ref broker.Ref
	if !strings.HasPrefix(s, "op://") || strings.ContainsAny(s, "?#") {
		return ref, errors.New("expected op://VAULT/ITEM/FIELD")
	}
	parts := strings.Split(strings.TrimPrefix(s, "op://"), "/")
	if len(parts) != 3 && len(parts) != 4 {
		return ref, errors.New("reference requires vault, item and field (optionally section)")
	}
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" || strings.ContainsAny(decoded, "\r\n") {
			return ref, errors.New("invalid reference encoding")
		}
		parts[i] = decoded
	}
	return broker.Ref{Vault: parts[0], Item: parts[1], Field: strings.Join(parts[2:], ".")}, nil
}

func (o options) spec(method string) (broker.Spec, error) {
	s := broker.Spec{Method: method, Reason: o.values["reason"], Agent: o.values["agent"]}
	if s.Agent == "" {
		s.Agent = "handkey-cli"
	}
	if v := o.values["uses"]; v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 {
			return s, errors.New("uses must be positive")
		}
		s.Uses = n
	}
	for _, p := range []struct {
		name string
		dst  *int
	}{{"ttl", &s.TTLSeconds}, {"wait", &s.WaitSeconds}} {
		if v := o.values[p.name]; v != "" {
			d, e := time.ParseDuration(v)
			if e != nil || d < time.Second || d%time.Second != 0 {
				return s, errors.New("duration must be a positive whole number of seconds")
			}
			*p.dst = int(d / time.Second)
		}
	}
	return s, nil
}

type Runner struct {
	In       io.Reader
	Out, Err io.Writer
	Env      []string
	Cwd      string
}

func (r Runner) Run(ctx context.Context, args []string) int {
	code, e := r.run(ctx, args)
	if e != nil {
		fmt.Fprintln(r.Err, "handkey:", e)
		return 1
	}
	return code
}
func (r Runner) run(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		_, e := io.WriteString(r.Out, Help)
		return 0, e
	}
	o, e := parse(args)
	if e != nil {
		return 1, e
	}
	if len(o.position) == 0 {
		return 1, errors.New("command required")
	}
	endpoint := o.values["endpoint"]
	if endpoint == "" {
		endpoint = os.Getenv("HANDKEY_ENDPOINT")
	}
	if endpoint == "" {
		return 1, errors.New("set HANDKEY_ENDPOINT or --endpoint to the broker's Unix socket or HTTPS origin")
	}
	if o.position[0] == "status" || o.position[0] == "cancel" || o.position[0] == "use" {
		if len(o.position) != 2 {
			return 1, errors.New("receipt file required")
		}
		if e = allow(o); e != nil {
			return 1, e
		}
		saved, e := LoadReceipt(o.position[1])
		if e != nil {
			return 1, e
		}
		if saved.Endpoint != endpoint {
			return 1, errors.New("receipt belongs to a different endpoint")
		}
		client, e := NewClient(endpoint, o.flags["dev"])
		if e != nil {
			return 1, e
		}
		switch o.position[0] {
		case "status":
			var req broker.Request
			e = client.Do(ctx, "GET", "/v1/requests/"+saved.Receipt.ID, saved.Receipt.Token, nil, &req)
			if e == nil {
				e = json.NewEncoder(r.Out).Encode(req)
			}
			return 0, e
		case "cancel":
			return 0, client.Do(ctx, "POST", "/v1/requests/"+saved.Receipt.ID+"/cancel", saved.Receipt.Token, nil, nil)
		default:
			return r.deliver(ctx, client, saved.Receipt, "", "")
		}
	}
	client, e := NewClient(endpoint, o.flags["dev"])
	if e != nil {
		return 1, e
	}
	method := o.position[0]
	var spec broker.Spec
	template, outfile := "", ""
	switch method {
	case "read", "type", "clipboard":
		if len(o.position) != 2 {
			return 1, errors.New("one reference required")
		}
		if e = allow(o); e != nil {
			return 1, e
		}
		if method == "read" {
			method = "reveal"
		}
		spec, e = o.spec(method)
		if e != nil {
			return 1, e
		}
		ref, e := ParseRef(o.position[1])
		if e != nil {
			return 1, e
		}
		spec.Refs = []broker.Ref{ref}
		if method == "type" {
			spec.Target, e = helper.Foreground(ctx)
			if e != nil {
				return 1, e
			}
		}
	case "refresh":
		if e = allow(o); e != nil {
			return 1, e
		}
		spec, e = o.spec("refresh")
		if e != nil {
			return 1, e
		}
		for _, s := range o.position[1:] {
			ref, e := ParseRef(s)
			if e != nil {
				return 1, e
			}
			spec.Refs = append(spec.Refs, ref)
		}
	case "run":
		if len(o.position) != 1 || len(o.command) == 0 {
			return 1, errors.New("run requires -- COMMAND")
		}
		if e = allow(o, "env-file", "no-masking"); e != nil {
			return 1, e
		}
		spec, e = o.spec("exec")
		if e != nil {
			return 1, e
		}
		spec.Command = o.command
		spec.Directory = r.Cwd
		spec.Unredacted = o.flags["no-masking"]
		env := append([]string{}, r.Env...)
		if path := o.values["env-file"]; path != "" {
			raw, e := os.ReadFile(path)
			if e != nil {
				return 1, errors.New("cannot read env file")
			}
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				name, value, ok := strings.Cut(line, "=")
				if !ok || name == "" {
					return 1, errors.New("env file accepts only NAME=value lines")
				}
				env = replaceEnv(env, name, strings.Trim(value, "\"'"))
			}
		}
		r.Env = env
		spec.Bindings = map[string]string{}
		seen := map[string]bool{}
		for _, entry := range env {
			name, value, _ := strings.Cut(entry, "=")
			if strings.HasPrefix(value, "op://") {
				ref, e := ParseRef(value)
				if e != nil {
					return 1, e
				}
				spec.Bindings[name] = ref.Key()
				if !seen[ref.Key()] {
					spec.Refs = append(spec.Refs, ref)
					seen[ref.Key()] = true
				}
			}
		}
		if len(spec.Refs) == 0 {
			return 1, errors.New("run needs at least one environment variable containing an op:// reference")
		}
	case "proxy":
		if len(o.position) != 2 || len(o.command) == 0 {
			return 1, errors.New("proxy requires one reference and -- COMMAND")
		}
		if e = allow(o, "origin", "header", "prefix"); e != nil {
			return 1, e
		}
		spec, e = o.spec("proxy")
		if e != nil {
			return 1, e
		}
		ref, e := ParseRef(o.position[1])
		if e != nil {
			return 1, e
		}
		spec.Refs = []broker.Ref{ref}
		spec.Command = o.command
		spec.Directory = r.Cwd
		spec.Origin = o.values["origin"]
		spec.Header = o.values["header"]
		spec.Prefix = o.values["prefix"]
	case "inject":
		if len(o.position) != 1 {
			return 1, errors.New("inject takes no positional arguments")
		}
		if e = allow(o, "in-file", "out-file"); e != nil {
			return 1, e
		}
		spec, e = o.spec("reveal")
		if e != nil {
			return 1, e
		}
		raw, e := r.input(o.values["in-file"])
		if e != nil {
			return 1, e
		}
		template = string(raw)
		outfile = o.values["out-file"]
		seen := map[string]bool{}
		for _, s := range refPattern.FindAllString(template, -1) {
			ref, e := ParseRef(s)
			if e != nil {
				return 1, e
			}
			if !seen[ref.Key()] {
				spec.Refs = append(spec.Refs, ref)
				seen[ref.Key()] = true
			}
		}
		if len(spec.Refs) == 0 {
			return 1, errors.New("template contains no op:// references")
		}
		if o.flags["no-wait"] {
			return 1, errors.New("inject requires inline waiting; its template stays in this process")
		}
	case "item":
		if len(o.position) < 2 {
			return 1, errors.New("item subcommand required")
		}
		switch o.position[1] {
		case "list":
			if len(o.position) != 2 {
				return 1, errors.New("unexpected item list argument")
			}
			if e = allow(o, "vault", "format", "query"); e != nil {
				return 1, e
			}
			if f := o.values["format"]; f != "" && f != "json" {
				return 1, errors.New("only JSON output is currently supported")
			}
			var result struct {
				Items    []broker.Item `json:"items"`
				Synced   bool          `json:"synced"`
				LastSync time.Time     `json:"last_sync"`
			}
			e = client.Do(ctx, "GET", "/v1/items?q="+url.QueryEscape(o.values["query"]), "", nil, &result)
			if e != nil {
				return 1, e
			}
			if v := o.values["vault"]; v != "" {
				filtered := []broker.Item{}
				for _, item := range result.Items {
					if item.Vault == v || item.VaultName == v {
						filtered = append(filtered, item)
					}
				}
				result.Items = filtered
			}
			return 0, json.NewEncoder(r.Out).Encode(result)
		case "get":
			if len(o.position) != 3 || o.values["vault"] == "" {
				return 1, errors.New("item get requires ITEM --vault VAULT")
			}
			if e = allow(o, "vault", "fields", "format", "reveal", "otp"); e != nil {
				return 1, e
			}
			if f := o.values["format"]; f != "" && f != "json" {
				return 1, errors.New("only JSON format is supported")
			}
			var result struct {
				Items []broker.Item `json:"items"`
			}
			e = client.Do(ctx, "GET", "/v1/items", "", nil, &result)
			if e != nil {
				return 1, e
			}
			var found *broker.Item
			for _, item := range result.Items {
				if (item.ID == o.position[2] || item.Title == o.position[2]) && (item.Vault == o.values["vault"] || item.VaultName == o.values["vault"]) {
					if found != nil {
						return 1, errors.New("ambiguous item; use IDs")
					}
					copy := item
					found = &copy
				}
			}
			reveal := o.flags["reveal"] || o.values["format"] == "json" || o.flags["otp"]
			if !reveal {
				if found == nil {
					return 1, errors.New("item not cached; use an approved refresh")
				}
				return 0, json.NewEncoder(r.Out).Encode(found)
			}
			method = "reveal"
			if o.flags["otp"] {
				method = "otp"
			}
			spec, e = o.spec(method)
			spec.OutputFormat = o.values["format"]
			if e != nil {
				return 1, e
			}
			fields := []string{}
			if v := o.values["fields"]; v != "" {
				fields = strings.Split(v, ",")
			} else if found != nil {
				for _, f := range found.Fields {
					if method != "otp" || f.Type == "OTP" {
						fields = append(fields, f.ID)
					}
				}
			}
			if len(fields) == 0 {
				return 1, errors.New("field IDs required; use --fields or refresh field metadata first")
			}
			for _, f := range fields {
				spec.Refs = append(spec.Refs, broker.Ref{Vault: o.values["vault"], Item: o.position[2], Field: f})
			}
		case "create":
			if len(o.position) != 2 {
				return 1, errors.New("unexpected item create argument")
			}
			if e = allow(o, "vault", "title", "category", "generate-password", "in-file"); e != nil {
				return 1, e
			}
			spec, e = o.spec("write")
			if e != nil {
				return 1, e
			}
			create := broker.Create{Vault: o.values["vault"], Title: o.values["title"], Category: o.values["category"], GeneratePassword: o.values["generate-password"]}
			if create.Category == "" {
				create.Category = "LOGIN"
			}
			if path := o.values["in-file"]; path != "" {
				raw, e := r.input(path)
				if e != nil {
					return 1, e
				}
				if json.Unmarshal(raw, &create.Fields) != nil {
					return 1, errors.New("in-file must contain a JSON array of create fields")
				}
			}
			spec.Create = &create
		default:
			return 1, errors.New("unsupported item command; existing-item edits are intentionally unavailable until lossless field updates are verified")
		}
	case "request":
		if len(o.position) != 1 {
			return 1, errors.New("request takes no positional arguments")
		}
		if e = allow(o, "in-file"); e != nil {
			return 1, e
		}
		raw, e := r.input(o.values["in-file"])
		if e != nil {
			return 1, e
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&spec) != nil {
			return 1, errors.New("invalid request JSON")
		}
	default:
		return 1, errors.New("unsupported command; see --help")
	}
	if len(o.command) > 0 && method != "run" && method != "proxy" && spec.Method != "exec" {
		return 1, errors.New("unexpected command arguments")
	}
	var receipt broker.Receipt
	if e = client.Do(ctx, "POST", "/v1/requests", "", spec, &receipt); e != nil {
		return 1, e
	}
	path, e := SaveReceipt(o.values["receipt"], endpoint, receipt)
	if e != nil {
		_ = client.Do(ctx, "POST", "/v1/requests/"+receipt.ID+"/cancel", receipt.Token, nil, nil)
		return 1, e
	}
	fmt.Fprintln(r.Err, "Approval requested:", receipt.ID)
	fmt.Fprintln(r.Err, "Receipt:", path)
	if o.flags["no-wait"] {
		return 0, json.NewEncoder(r.Out).Encode(map[string]string{"id": receipt.ID, "receipt_file": path})
	}
	return r.deliver(ctx, client, receipt, template, outfile)
}

var refPattern = regexp.MustCompile("op://[^\\s\"'`<>}{,;]+")

func (r Runner) input(path string) ([]byte, error) {
	if path == "" || path == "-" {
		data, e := io.ReadAll(io.LimitReader(r.In, (1<<20)+1))
		if e != nil || len(data) > 1<<20 {
			return nil, errors.New("input exceeds 1 MiB")
		}
		return data, nil
	}
	data, e := os.ReadFile(path)
	if e != nil || len(data) > 1<<20 {
		return nil, errors.New("cannot read input or input exceeds 1 MiB")
	}
	return data, nil
}
func replaceEnv(env []string, name, value string) []string {
	out := []string{}
	for _, v := range env {
		if !strings.HasPrefix(v, name+"=") {
			out = append(out, v)
		}
	}
	return append(out, name+"="+value)
}
func (r Runner) deliver(ctx context.Context, c *Client, receipt broker.Receipt, template, outfile string) (int, error) {
	req, e := c.Wait(ctx, receipt)
	if e != nil {
		return 1, e
	}
	if req.Execution == "succeeded" {
		return 0, json.NewEncoder(r.Out).Encode(req)
	}
	var result broker.Result
	if e = c.Do(ctx, "POST", "/v1/requests/"+receipt.ID+"/consume", receipt.Token, nil, &result); e != nil {
		return 1, e
	}
	spec := result.Request.Spec
	switch spec.Method {
	case "exec":
		return helper.Run(ctx, spec, result.Values, r.Env, r.In, r.Out, r.Err), nil
	case "proxy":
		return r.runProxy(ctx, c, receipt.ID, result.ExecutionToken, spec)
	case "type", "clipboard":
		value := result.Values[spec.Refs[0].Key()]
		if spec.Method == "type" {
			e = helper.Type(ctx, spec.Target, value)
		} else {
			e = helper.Clipboard(ctx, value)
		}
		return 0, e
	case "reveal", "otp":
		if template != "" {
			// Broker returns canonical refs in the original order. Resolve original template tokens locally.
			replacements := map[string]string{}
			seen := map[string]bool{}
			i := 0
			for _, s := range refPattern.FindAllString(template, -1) {
				ref, _ := ParseRef(s)
				if !seen[ref.Key()] {
					replacements[ref.Key()] = result.Values[spec.Refs[i].Key()]
					seen[ref.Key()] = true
					i++
				}
			}
			rendered := refPattern.ReplaceAllStringFunc(template, func(s string) string { ref, _ := ParseRef(s); return replacements[ref.Key()] })
			if outfile != "" {
				f, e := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if e != nil {
					return 1, errors.New("output file must not already exist")
				}
				_, e = io.WriteString(f, rendered)
				ce := f.Close()
				if e == nil {
					e = ce
				}
				return 0, e
			}
			_, e = io.WriteString(r.Out, rendered)
			return 0, e
		}
		if len(spec.Refs) == 1 && spec.OutputFormat != "json" {
			_, e = fmt.Fprintln(r.Out, result.Values[spec.Refs[0].Key()])
			return 0, e
		}
		return 0, json.NewEncoder(r.Out).Encode(result.Values)
	default:
		return 1, errors.New("unsupported delivery method")
	}
}
