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
		if err := validateOutPath(*outPath); err != nil {
			fmt.Fprintf(os.Stderr, "invalid --out path: %v\n", err)
			os.Exit(1)
		}
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot create output: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	// PM4: Warn that replay is credential-less.
	fmt.Fprintln(os.Stderr, "⚠ Replaying without credentials — identity-dependent authorization differences may not be detected.")

	var total, agree, disagree int
	var baselineErrs, candidateErrs int
	enc := json.NewEncoder(out)

	for _, ev := range events {
		r := requestFromAuditEvent(ev)
		ctx := context.Background()

		decA, _, errA := baselineEngine.Evaluate(ctx, r)
		decB, _, errB := candidateEngine.Evaluate(ctx, r)

		if errA != nil {
			baselineErrs++
		}
		if errB != nil {
			candidateErrs++
		}

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
	if baselineErrs > 0 || candidateErrs > 0 {
		fmt.Fprintf(os.Stderr, "  Evaluation errors: baseline=%d, candidate=%d\n", baselineErrs, candidateErrs)
	}
	if disagree > 0 {
		os.Exit(2) // non-zero exit so CI can gate on disagreements
	}
	if candidateErrs > 0 {
		os.Exit(3) // candidate errors indicate a broken policy
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
	var totalLines, skipped int
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1MB line buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		totalLines++
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			skipped++
			continue
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// PM2: Report and fail on excessive malformed lines.
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "⚠ %d/%d audit lines skipped (malformed)\n", skipped, totalLines)
		if totalLines > 0 && float64(skipped)/float64(totalLines) > 0.05 {
			return nil, fmt.Errorf("too many malformed lines (%d/%d = %.0f%%), aborting — audit file may be corrupted",
				skipped, totalLines, float64(skipped)/float64(totalLines)*100)
		}
	}
	return events, nil
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
