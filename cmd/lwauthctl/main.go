// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Command lwauthctl is a small operator CLI for inspecting config,
// listing registered modules, and dry-running an authorization request
// against a local config file.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "modules":
		listModules()
	case "validate":
		validate(os.Args[2:])
	case "diff":
		diff(os.Args[2:])
	case "explain":
		explain(os.Args[2:])
	case "audit":
		auditTail(os.Args[2:])
	case "promote":
		promote(os.Args[2:])
	case "rollback":
		rollback(os.Args[2:])
	case "drift":
		drift(os.Args[2:])
	case "replay":
		replay()
	case "backup":
		backup(os.Args[2:])
	case "restore":
		restore(os.Args[2:])
	case "revoke":
		revoke(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lwauthctl <command> [args]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  modules                                  list registered identifier/authorizer/mutator types")
	fmt.Fprintln(os.Stderr, "  validate --config FILE                   compile an AuthConfig YAML offline")
	fmt.Fprintln(os.Stderr, "  diff --from A.yaml --to B.yaml           show what would change between two AuthConfigs")
	fmt.Fprintln(os.Stderr, "  explain --config FILE --request req.json dry-run a request through the pipeline")
	fmt.Fprintln(os.Stderr, "  audit [--file F] [--tenant T] ...        tail / filter audit JSONL")
	fmt.Fprintln(os.Stderr, "  promote --config FILE [--version V]      validate, tag version, and emit GitOps-ready YAML")
	fmt.Fprintln(os.Stderr, "  rollback --config FILE --to-version V    rewrite spec.version to a previous value")
	fmt.Fprintln(os.Stderr, "  drift --config FILE --namespace NS       compare local config to live AuthConfig status")
	fmt.Fprintln(os.Stderr, "  backup --config FILE [--out FILE] [--signing-key KEY] [--redact-secrets]")
	fmt.Fprintln(os.Stderr, "                                           export HMAC-signed config snapshot")
	fmt.Fprintln(os.Stderr, "  restore --from FILE --out FILE [--signing-key KEY] [--force] [--allow-stale]")
	fmt.Fprintln(os.Stderr, "                                           restore config from backup (verifies HMAC)")
	fmt.Fprintln(os.Stderr, "  revoke --admin-url URL --token TOKEN [--jti JTI] [--token-hash HASH] [--subject SUB] [--tenant T] [--reason R] [--ttl D]")
	fmt.Fprintln(os.Stderr, "                                           revoke a credential via the admin endpoint (E2)")
	os.Exit(2)
}

func listModules() {
	for _, k := range []module.Kind{module.KindIdentifier, module.KindAuthorizer, module.KindMutator} {
		names := module.RegisteredTypes(k)
		sort.Strings(names)
		fmt.Printf("%s:\n", k)
		for _, n := range names {
			fmt.Printf("  - %s\n", n)
		}
	}
}

func validate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "--config required")
		os.Exit(2)
	}
	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	if _, err := config.Compile(ac); err != nil {
		fmt.Fprintln(os.Stderr, "compile:", err)
		os.Exit(1)
	}
	// Surface a brief summary so operators can sanity-check at a glance.
	fmt.Printf("OK  hosts=%v identifiers=%d authorizers=%d mutators=%d cache=%v rateLimit=%v\n",
		ac.Hosts, len(ac.Identifiers), len(ac.Authorizers), len(ac.Response),
		ac.Cache != nil, ac.RateLimit != nil)
}

// --- diff -----------------------------------------------------------------

// diff loads two AuthConfig YAML files and prints a stable, human-readable
// summary of what would change if --to replaced --from. We diff at the
// module-spec level (name+type+config), at the cache/rate-limit blocks,
// and at top-level scalars (hosts, withBody, identifierMode).
//
// Both files are validated (Compile) before the diff so we don't print a
// "what would change" against a config that wouldn't even start.
func diff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	from := fs.String("from", "", "path to baseline AuthConfig YAML")
	to := fs.String("to", "", "path to candidate AuthConfig YAML")
	_ = fs.Parse(args)
	if *from == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "--from and --to required")
		os.Exit(2)
	}
	a, err := config.LoadFile(*from)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load --from:", err)
		os.Exit(1)
	}
	b, err := config.LoadFile(*to)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load --to:", err)
		os.Exit(1)
	}
	if _, err := config.Compile(a); err != nil {
		fmt.Fprintln(os.Stderr, "compile --from:", err)
		os.Exit(1)
	}
	if _, err := config.Compile(b); err != nil {
		fmt.Fprintln(os.Stderr, "compile --to:", err)
		os.Exit(1)
	}

	any := false
	any = printScalarDiff("hosts", strings.Join(a.Hosts, ","), strings.Join(b.Hosts, ",")) || any
	any = printScalarDiff("tenantId", a.TenantID, b.TenantID) || any
	any = printScalarDiff("withBody", fmt.Sprint(a.WithBody), fmt.Sprint(b.WithBody)) || any
	any = printScalarDiff("identifierMode", string(a.Identifier), string(b.Identifier)) || any
	any = printModuleDiff("identifiers", a.Identifiers, b.Identifiers) || any
	any = printModuleDiff("authorizers", a.Authorizers, b.Authorizers) || any
	any = printModuleDiff("response", a.Response, b.Response) || any
	any = printBlockDiff("cache", a.Cache, b.Cache) || any
	any = printBlockDiff("rateLimit", a.RateLimit, b.RateLimit) || any

	if !any {
		fmt.Println("(no changes)")
	}
}

func printScalarDiff(label, a, b string) bool {
	if a == b {
		return false
	}
	fmt.Printf("~ %s: %q -> %q\n", label, a, b)
	return true
}

func printBlockDiff(label string, a, b any) bool {
	// Use reflect.DeepEqual so nil pointer vs zero pointer difference is
	// surfaced too.
	if reflect.DeepEqual(a, b) {
		return false
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	fmt.Printf("~ %s: %s -> %s\n", label, string(aj), string(bj))
	return true
}

func printModuleDiff(label string, a, b []config.ModuleSpec) bool {
	idx := func(specs []config.ModuleSpec) map[string]config.ModuleSpec {
		m := map[string]config.ModuleSpec{}
		for _, s := range specs {
			m[s.Name] = s
		}
		return m
	}
	ai, bi := idx(a), idx(b)
	any := false
	// Removed.
	for _, s := range a {
		if _, ok := bi[s.Name]; !ok {
			fmt.Printf("- %s/%s (type=%s)\n", label, s.Name, s.Type)
			any = true
		}
	}
	// Added.
	for _, s := range b {
		if _, ok := ai[s.Name]; !ok {
			fmt.Printf("+ %s/%s (type=%s)\n", label, s.Name, s.Type)
			any = true
		}
	}
	// Changed.
	for _, s := range b {
		old, ok := ai[s.Name]
		if !ok {
			continue
		}
		if old.Type != s.Type {
			fmt.Printf("~ %s/%s: type %q -> %q\n", label, s.Name, old.Type, s.Type)
			any = true
		}
		if !reflect.DeepEqual(old.Config, s.Config) {
			oj, _ := json.Marshal(old.Config)
			nj, _ := json.Marshal(s.Config)
			fmt.Printf("~ %s/%s config: %s -> %s\n", label, s.Name, string(oj), string(nj))
			any = true
		}
	}
	return any
}

// --- explain --------------------------------------------------------------

// explainRequest is the JSON shape lwauthctl explain --request reads.
// It mirrors the user-facing fields of module.Request (the rest are
// filled by the server layer in production).
type explainRequest struct {
	TenantID string              `json:"tenantId,omitempty"`
	Method   string              `json:"method,omitempty"`
	Host     string              `json:"host,omitempty"`
	Path     string              `json:"path,omitempty"`
	Headers  map[string][]string `json:"headers,omitempty"`
	Body     string              `json:"body,omitempty"`
	Context  map[string]any      `json:"context,omitempty"`
}

// explain dry-runs a request through the configured pipeline and prints a
// per-stage breakdown:
//
//   - which identifier matched (or which errors each one returned),
//   - which authorizer fired and what it decided,
//   - which response mutators ran on allow.
//
// We don't reach into pipeline.Engine for this — the Engine is a black
// box on purpose. Instead we re-build the same module graph from the
// AuthConfig and drive it stage-by-stage, which is straightforward
// because module.Build* gives us the same factories the pipeline uses.
func explain(args []string) {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML")
	reqPath := fs.String("request", "", "path to request JSON (- for stdin)")
	_ = fs.Parse(args)
	if *cfgPath == "" || *reqPath == "" {
		fmt.Fprintln(os.Stderr, "--config and --request required")
		os.Exit(2)
	}
	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	if _, err := config.Compile(ac); err != nil {
		fmt.Fprintln(os.Stderr, "compile:", err)
		os.Exit(1)
	}
	req, err := loadExplainRequest(*reqPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request:", err)
		os.Exit(1)
	}

	mr := &module.Request{
		TenantID: req.TenantID,
		Method:   req.Method,
		Host:     req.Host,
		Path:     req.Path,
		Headers:  req.Headers,
		Body:     []byte(req.Body),
		Context:  req.Context,
	}
	if mr.Context == nil {
		mr.Context = map[string]any{}
	}

	ctx := context.Background()

	// Identifiers ----------------------------------------------------------
	fmt.Println("identify:")
	var matched *module.Identity
	var matchedName string
	for _, spec := range ac.Identifiers {
		iden, err := module.BuildIdentifier(spec.Type, spec.Name, spec.Config)
		if err != nil {
			fmt.Printf("  ! %s (%s) build error: %v\n", spec.Name, spec.Type, err)
			os.Exit(1)
		}
		id, err := iden.Identify(ctx, mr)
		switch {
		case err == nil && id != nil:
			fmt.Printf("  ✓ %s (%s) → subject=%q claims=%d\n", spec.Name, spec.Type, id.Subject, len(id.Claims))
			id.Source = spec.Name
			matched = id
			matchedName = spec.Name
		case errors.Is(err, module.ErrNoMatch):
			fmt.Printf("  · %s (%s) no_match\n", spec.Name, spec.Type)
			continue
		case errors.Is(err, module.ErrInvalidCredential):
			fmt.Printf("  ✗ %s (%s) invalid_credential: %v\n", spec.Name, spec.Type, err)
			fmt.Println("decision: deny status=401")
			return
		default:
			fmt.Printf("  ✗ %s (%s) error: %v\n", spec.Name, spec.Type, err)
			fmt.Println("decision: error")
			return
		}
		if matched != nil && ac.Identifier != config.IdentifierAllMust {
			break
		}
	}
	if matched == nil {
		fmt.Println("decision: deny status=401 reason=\"no identifier matched\"")
		return
	}
	mr.Context["identity"] = matched

	// Authorizer -----------------------------------------------------------
	if len(ac.Authorizers) == 0 {
		fmt.Println("authorize: (no authorizer configured)")
		return
	}
	azSpec := ac.Authorizers[0]
	az, err := module.BuildAuthorizer(azSpec.Type, azSpec.Name, azSpec.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "authorizer build:", err)
		os.Exit(1)
	}
	dec, err := az.Authorize(ctx, mr, matched)
	switch {
	case err != nil && errors.Is(err, module.ErrUpstream):
		fmt.Printf("authorize: ✗ %s (%s) upstream: %v\n", azSpec.Name, azSpec.Type, err)
		fmt.Println("decision: error status=503")
		return
	case err != nil:
		fmt.Printf("authorize: ✗ %s (%s) error: %v\n", azSpec.Name, azSpec.Type, err)
		fmt.Println("decision: error")
		return
	case dec == nil || !dec.Allow:
		reason := "denied"
		status := 403
		if dec != nil {
			if dec.Reason != "" {
				reason = dec.Reason
			}
			if dec.Status != 0 {
				status = dec.Status
			}
		}
		fmt.Printf("authorize: ✗ %s (%s) deny: %s\n", azSpec.Name, azSpec.Type, reason)
		fmt.Printf("decision: deny status=%d reason=%q\n", status, reason)
		return
	default:
		fmt.Printf("authorize: ✓ %s (%s) allow: %s\n", azSpec.Name, azSpec.Type, dec.Reason)
	}

	// Mutators -------------------------------------------------------------
	if len(ac.Response) > 0 {
		fmt.Println("mutate:")
	}
	for _, spec := range ac.Response {
		mut, err := module.BuildMutator(spec.Type, spec.Name, spec.Config)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mutator build:", err)
			os.Exit(1)
		}
		if err := mut.Mutate(ctx, mr, matched, dec); err != nil {
			fmt.Printf("  ✗ %s (%s) error: %v\n", spec.Name, spec.Type, err)
			fmt.Println("decision: error")
			return
		}
		fmt.Printf("  ✓ %s (%s)\n", spec.Name, spec.Type)
	}

	fmt.Printf("decision: allow identifier=%q authorizer=%q upstreamHeaders=%d responseHeaders=%d\n",
		matchedName, azSpec.Name, len(dec.UpstreamHeaders), len(dec.ResponseHeaders))
}

func loadExplainRequest(path string) (*explainRequest, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var er explainRequest
	if err := json.NewDecoder(r).Decode(&er); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &er, nil
}

// auditTail reads JSON-line audit records (the shape emitted by
// pkg/observability/audit's slog sink) from --file (default stdin) and
// pretty-prints filtered records.
//
// Filters compose with AND. Empty filters match everything.
//
//	lwauthctl audit --file /var/log/lwauth/audit.jsonl --tenant acme --decision deny
//	kubectl logs deploy/lwauth -f | lwauthctl audit --decision deny
//
// The reader is line-oriented and tolerates non-audit slog records
// (anything without `"msg":"audit"` is skipped) so it works against a
// shared stdout stream that mixes operational + audit logs.
func auditTail(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	file := fs.String("file", "", "path to audit JSONL (defaults to stdin)")
	tenant := fs.String("tenant", "", "filter on tenant (exact match)")
	decision := fs.String("decision", "", "filter on decision: allow | deny | error")
	subject := fs.String("subject", "", "filter on subject (exact match)")
	follow := fs.Bool("follow", false, "do not exit at EOF; keep reading appended lines")
	_ = fs.Parse(args)

	var src io.Reader = os.Stdin
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			os.Exit(1)
		}
		defer f.Close()
		src = f
	}

	rd := bufio.NewReader(src)
	enc := json.NewEncoder(os.Stdout)
	for {
		line, err := rd.ReadBytes('\n')
		if len(line) > 0 {
			matchAndPrint(line, *tenant, *decision, *subject, enc)
		}
		if err == io.EOF {
			if !*follow {
				return
			}
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
	}
}

func matchAndPrint(line []byte, tenant, decision, subject string, enc *json.Encoder) {
	var rec map[string]any
	if err := json.Unmarshal(line, &rec); err != nil {
		return // not JSON; skip
	}
	if msg, _ := rec["msg"].(string); msg != "" && msg != "audit" {
		return
	}
	if tenant != "" && asString(rec["tenant"]) != tenant {
		return
	}
	if subject != "" && asString(rec["subject"]) != subject {
		return
	}
	if decision != "" && asString(rec["decision"]) != decision {
		return
	}
	_ = enc.Encode(rec)
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
