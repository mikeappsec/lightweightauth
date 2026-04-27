// Command lwauthctl is a small operator CLI for inspecting config,
// listing registered modules, and dry-running an authorization request
// against a local config file.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

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
	case "audit":
		auditTail(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lwauthctl <modules|validate|audit> [args]")
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
	fmt.Println("OK")
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
