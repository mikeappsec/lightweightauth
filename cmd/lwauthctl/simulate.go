// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// simulateCmd implements `lwauthctl simulate` — replay audit events against
// a candidate policy and report impact (G7 — POL-SIM-1).
func simulateCmd(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to candidate AuthConfig YAML")
	auditPath := fs.String("audit", "", "path to audit JSONL file (- for stdin)")
	limit := fs.Int("limit", 0, "max events to replay (0 = unlimited)")
	outputFmt := fs.String("output", "text", "output format: text | json")
	_ = fs.Parse(args)

	if *cfgPath == "" || *auditPath == "" {
		fmt.Fprintln(os.Stderr, "usage: lwauthctl simulate --config FILE --audit FILE")
		fmt.Fprintln(os.Stderr, "  --config   path to candidate AuthConfig YAML")
		fmt.Fprintln(os.Stderr, "  --audit    path to audit JSONL (- for stdin)")
		fmt.Fprintln(os.Stderr, "  --limit N  max events to replay (0 = all)")
		fmt.Fprintln(os.Stderr, "  --output   text | json")
		os.Exit(2)
	}

	// Load and compile the candidate policy.
	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	engine, err := config.Compile(ac)
	if err != nil {
		fmt.Fprintln(os.Stderr, "compile config:", err)
		os.Exit(1)
	}
	defer engine.Close()

	// Open audit source.
	var reader io.Reader = os.Stdin
	if *auditPath != "-" {
		f, err := os.Open(*auditPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open audit:", err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	}

	// Replay events.
	report := runSimulation(context.Background(), engine, reader, *limit)

	// Output.
	switch *outputFmt {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	default:
		printSimulationReport(report)
	}

	if report.Changed > 0 {
		os.Exit(1) // non-zero exit when decisions differ
	}
}

// auditEventInput is the minimal subset of an audit event we need for replay.
type auditEventInput struct {
	Tenant         string `json:"tenant"`
	Subject        string `json:"subject"`
	IdentitySource string `json:"identity_source"`
	Decision       string `json:"decision"`
	Method         string `json:"method"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	PolicyVersion  string `json:"policy_version"`
}

// SimulationReport is the aggregate output of a simulation run.
type SimulationReport struct {
	Timestamp       string              `json:"timestamp"`
	CandidateConfig string              `json:"candidate_config,omitempty"`
	Total           int                 `json:"total"`
	Replayed        int                 `json:"replayed"`
	Skipped         int                 `json:"skipped"`
	Changed         int                 `json:"changed"`
	ChangedPct      float64             `json:"changed_pct"`
	NewDenies       int                 `json:"new_denies"`
	NewAllows       int                 `json:"new_allows"`
	TopSubjects     []ImpactEntry       `json:"top_subjects"`
	TopPaths        []ImpactEntry       `json:"top_paths"`
	TopDenyReasons  []ImpactEntry       `json:"top_deny_reasons"`
	PerTenant       map[string]*TenantImpact `json:"per_tenant,omitempty"`
}

// ImpactEntry is a label + count pair for top-N lists.
type ImpactEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// TenantImpact holds per-tenant simulation stats.
type TenantImpact struct {
	Total      int     `json:"total"`
	Changed    int     `json:"changed"`
	ChangedPct float64 `json:"changed_pct"`
	NewDenies  int     `json:"new_denies"`
	NewAllows  int     `json:"new_allows"`
}

// simEngine is the interface we need for simulation (allows testing).
type simEngine interface {
	SimEvaluate(ctx context.Context, r *module.Request) (allow bool, reason string)
}

// runSimulation replays audit events through the candidate engine.
func runSimulation(ctx context.Context, engine simEngine, reader io.Reader, limit int) *SimulationReport {
	report := &SimulationReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		PerTenant: map[string]*TenantImpact{},
	}

	subjectCounts := map[string]int{}
	pathCounts := map[string]int{}
	reasonCounts := map[string]int{}

	scanner := bufio.NewScanner(reader)
	// Allow large lines (audit events can be big with embedded claims).
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var evt auditEventInput
		if err := json.Unmarshal(line, &evt); err != nil {
			report.Skipped++
			continue
		}
		// Skip non-decision events (e.g. cache_invalidate, revocation ops).
		if evt.Decision != "allow" && evt.Decision != "deny" && evt.Decision != "error" {
			report.Skipped++
			continue
		}
		report.Total++

		if limit > 0 && report.Replayed >= limit {
			break
		}

		// Reconstruct request.
		req := &module.Request{
			TenantID: evt.Tenant,
			Method:   evt.Method,
			Host:     evt.Host,
			Path:     evt.Path,
			Headers:  map[string][]string{},
			Context:  map[string]any{},
		}

		// Run candidate policy.
		candidateAllow, candidateReason := engine.SimEvaluate(ctx, req)
		report.Replayed++

		// Compare.
		origAllow := evt.Decision == "allow"
		if candidateAllow != origAllow {
			report.Changed++

			if candidateAllow {
				report.NewAllows++
			} else {
				report.NewDenies++
			}

			// Track affected subjects/paths.
			if evt.Subject != "" {
				subjectCounts[evt.Subject]++
			}
			if evt.Path != "" {
				pathCounts[evt.Path]++
			}
			if !candidateAllow && candidateReason != "" {
				reasonCounts[candidateReason]++
			}

			// Per-tenant.
			tenant := evt.Tenant
			if tenant == "" {
				tenant = "(none)"
			}
			ti := report.PerTenant[tenant]
			if ti == nil {
				ti = &TenantImpact{}
				report.PerTenant[tenant] = ti
			}
			ti.Changed++
			if candidateAllow {
				ti.NewAllows++
			} else {
				ti.NewDenies++
			}
		}

		// Per-tenant total.
		tenant := evt.Tenant
		if tenant == "" {
			tenant = "(none)"
		}
		ti := report.PerTenant[tenant]
		if ti == nil {
			ti = &TenantImpact{}
			report.PerTenant[tenant] = ti
		}
		ti.Total++
	}

	// Compute percentages.
	if report.Replayed > 0 {
		report.ChangedPct = float64(report.Changed) / float64(report.Replayed) * 100
	}
	for _, ti := range report.PerTenant {
		if ti.Total > 0 {
			ti.ChangedPct = float64(ti.Changed) / float64(ti.Total) * 100
		}
	}

	// Build top-N lists (max 10).
	report.TopSubjects = topN(subjectCounts, 10)
	report.TopPaths = topN(pathCounts, 10)
	report.TopDenyReasons = topN(reasonCounts, 10)

	return report
}

// topN returns the top N entries from counts, sorted descending by count.
func topN(counts map[string]int, n int) []ImpactEntry {
	entries := make([]ImpactEntry, 0, len(counts))
	for k, v := range counts {
		entries = append(entries, ImpactEntry{Key: k, Count: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// printSimulationReport outputs a human-readable text report.
func printSimulationReport(r *SimulationReport) {
	fmt.Printf("Policy Simulation Report — %s\n", r.Timestamp)
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Events replayed: %d  (skipped: %d)\n", r.Replayed, r.Skipped)
	fmt.Printf("Decisions changed: %d / %d (%.1f%%)\n", r.Changed, r.Replayed, r.ChangedPct)
	fmt.Printf("  New denies: %d   New allows: %d\n", r.NewDenies, r.NewAllows)
	fmt.Println()

	if len(r.TopSubjects) > 0 {
		fmt.Println("Top affected subjects:")
		for _, e := range r.TopSubjects {
			fmt.Printf("  %-40s %d\n", e.Key, e.Count)
		}
		fmt.Println()
	}

	if len(r.TopPaths) > 0 {
		fmt.Println("Top affected paths:")
		for _, e := range r.TopPaths {
			fmt.Printf("  %-40s %d\n", e.Key, e.Count)
		}
		fmt.Println()
	}

	if len(r.TopDenyReasons) > 0 {
		fmt.Println("Top new deny reasons:")
		for _, e := range r.TopDenyReasons {
			fmt.Printf("  %-40s %d\n", e.Key, e.Count)
		}
		fmt.Println()
	}

	if len(r.PerTenant) > 0 {
		fmt.Println("Per-tenant breakdown:")
		tenants := make([]string, 0, len(r.PerTenant))
		for t := range r.PerTenant {
			tenants = append(tenants, t)
		}
		sort.Strings(tenants)
		for _, t := range tenants {
			ti := r.PerTenant[t]
			fmt.Printf("  %-20s total=%-6d changed=%-4d (%.1f%%) denies=%-3d allows=%-3d\n",
				t, ti.Total, ti.Changed, ti.ChangedPct, ti.NewDenies, ti.NewAllows)
		}
	}
}
