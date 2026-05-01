package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// replay loads two AuthConfig YAML files (A = baseline, B = candidate),
// compiles both into pipeline.Engines, replays audit events from a JSONL
// file against both engines, and reports verdict differences.
//
// Usage:
//
//	lwauthctl replay --baseline config-a.yaml --candidate config-b.yaml --audit audit.jsonl
//	lwauthctl replay --baseline config-a.yaml --candidate config-b.yaml --audit audit.jsonl --out diff.jsonl
func replay() {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	baselinePath := fs.String("baseline", "", "Path to baseline AuthConfig YAML (production)")
	candidatePath := fs.String("candidate", "", "Path to candidate AuthConfig YAML (new policy)")
	auditPath := fs.String("audit", "", "Path to audit JSONL file to replay")
	outPath := fs.String("out", "", "Optional output file for disagreements (default: stdout)")
	fs.Parse(os.Args[2:])

	if *baselinePath == "" || *candidatePath == "" || *auditPath == "" {
		fmt.Fprintln(os.Stderr, "usage: lwauthctl replay --baseline <file> --candidate <file> --audit <file>")
		os.Exit(1)
	}

	baselineEngine, err := compileFromFile(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline compile error: %v\n", err)
		os.Exit(1)
	}
	candidateEngine, err := compileFromFile(*candidatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "candidate compile error: %v\n", err)
		os.Exit(1)
	}

	events, err := loadAuditEvents(*auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit load error: %v\n", err)
		os.Exit(1)
	}

	out := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot create output: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	var total, agree, disagree int
	enc := json.NewEncoder(out)

	for _, ev := range events {
		r := requestFromAuditEvent(ev)
		ctx := context.Background()

		decA, _, _ := baselineEngine.Evaluate(ctx, r)
		decB, _, _ := candidateEngine.Evaluate(ctx, r)

		total++
		aAllow := decA != nil && decA.Allow
		bAllow := decB != nil && decB.Allow

		if aAllow == bAllow {
			agree++
			continue
		}
		disagree++
		_ = enc.Encode(map[string]any{
			"ts":                 ev.Timestamp,
			"method":             ev.Method,
			"host":               ev.Host,
			"path":               ev.Path,
			"subject":            ev.Subject,
			"tenant":             ev.Tenant,
			"baseline_decision":  decisionStr(aAllow),
			"candidate_decision": decisionStr(bAllow),
			"baseline_reason":    reasonStr(decA),
			"candidate_reason":   reasonStr(decB),
		})
	}

	fmt.Fprintf(os.Stderr, "\nReplay complete: %d events, %d agree, %d disagree (%.1f%% agreement)\n",
		total, agree, disagree, pct(agree, total))
	if disagree > 0 {
		os.Exit(2) // non-zero exit so CI can gate on disagreements
	}
}

func compileFromFile(path string) (interface {
	Evaluate(context.Context, *module.Request) (*module.Decision, *module.Identity, error)
}, error) {
	ac, err := config.LoadFile(path)
	if err != nil {
		return nil, err
	}
	return config.Compile(ac)
}

func loadAuditEvents(path string) ([]audit.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []audit.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1MB line buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue // skip malformed lines
		}
		events = append(events, ev)
	}
	return events, scanner.Err()
}

func requestFromAuditEvent(ev audit.Event) *module.Request {
	return &module.Request{
		Method:   ev.Method,
		Host:     ev.Host,
		Path:     ev.Path,
		TenantID: ev.Tenant,
		Headers:  map[string][]string{},
		Context:  map[string]any{},
	}
}

func decisionStr(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

func reasonStr(d *module.Decision) string {
	if d == nil {
		return ""
	}
	return d.Reason
}

func pct(num, denom int) float64 {
	if denom == 0 {
		return 100.0
	}
	return float64(num) / float64(denom) * 100.0
}

// ensure time is imported for audit.Event.Timestamp
