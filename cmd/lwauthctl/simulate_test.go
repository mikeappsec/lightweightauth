// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// fakeSimEngine implements simEngine for testing.
type fakeSimEngine struct {
	// denyPaths is a set of paths that the candidate policy denies.
	denyPaths map[string]string // path -> reason
}

func (f *fakeSimEngine) SimEvaluate(_ context.Context, r *module.Request) (bool, string) {
	if reason, denied := f.denyPaths[r.Path]; denied {
		return false, reason
	}
	return true, ""
}

func TestRunSimulation_NoChanges(t *testing.T) {
	t.Parallel()
	engine := &fakeSimEngine{denyPaths: map[string]string{}}

	audit := strings.Join([]string{
		`{"decision":"allow","method":"GET","path":"/api/v1","tenant":"acme","subject":"alice"}`,
		`{"decision":"allow","method":"POST","path":"/api/v2","tenant":"acme","subject":"bob"}`,
	}, "\n")

	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 0)

	if report.Replayed != 2 {
		t.Fatalf("Replayed = %d, want 2", report.Replayed)
	}
	if report.Changed != 0 {
		t.Fatalf("Changed = %d, want 0", report.Changed)
	}
	if report.ChangedPct != 0 {
		t.Fatalf("ChangedPct = %f, want 0", report.ChangedPct)
	}
}

func TestRunSimulation_AllDenied(t *testing.T) {
	t.Parallel()
	engine := &fakeSimEngine{denyPaths: map[string]string{
		"/api/v1": "not in admin group",
		"/api/v2": "rate limited",
	}}

	audit := strings.Join([]string{
		`{"decision":"allow","method":"GET","path":"/api/v1","tenant":"acme","subject":"alice"}`,
		`{"decision":"allow","method":"POST","path":"/api/v2","tenant":"beta","subject":"bob"}`,
	}, "\n")

	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 0)

	if report.Replayed != 2 {
		t.Fatalf("Replayed = %d, want 2", report.Replayed)
	}
	if report.Changed != 2 {
		t.Fatalf("Changed = %d, want 2", report.Changed)
	}
	if report.NewDenies != 2 {
		t.Fatalf("NewDenies = %d, want 2", report.NewDenies)
	}
	if report.NewAllows != 0 {
		t.Fatalf("NewAllows = %d, want 0", report.NewAllows)
	}
	if report.ChangedPct != 100 {
		t.Fatalf("ChangedPct = %f, want 100", report.ChangedPct)
	}
}

func TestRunSimulation_MixedChanges(t *testing.T) {
	t.Parallel()
	engine := &fakeSimEngine{denyPaths: map[string]string{
		"/admin/delete": "forbidden",
	}}

	audit := strings.Join([]string{
		`{"decision":"allow","method":"GET","path":"/public","tenant":"acme","subject":"alice"}`,
		`{"decision":"allow","method":"DELETE","path":"/admin/delete","tenant":"acme","subject":"alice"}`,
		`{"decision":"deny","method":"POST","path":"/locked","tenant":"beta","subject":"bob"}`,
	}, "\n")

	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 0)

	if report.Replayed != 3 {
		t.Fatalf("Replayed = %d, want 3", report.Replayed)
	}
	// /public: allow→allow (no change), /admin/delete: allow→deny (change),
	// /locked: deny→allow (change, since fakeSimEngine doesn't deny /locked)
	if report.Changed != 2 {
		t.Fatalf("Changed = %d, want 2", report.Changed)
	}
	if report.NewDenies != 1 {
		t.Fatalf("NewDenies = %d, want 1", report.NewDenies)
	}
	if report.NewAllows != 1 {
		t.Fatalf("NewAllows = %d, want 1", report.NewAllows)
	}
}

func TestRunSimulation_TopSubjectsAndPaths(t *testing.T) {
	t.Parallel()
	engine := &fakeSimEngine{denyPaths: map[string]string{
		"/secret": "no access",
	}}

	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, `{"decision":"allow","method":"GET","path":"/secret","tenant":"acme","subject":"alice"}`)
	}
	for i := 0; i < 3; i++ {
		lines = append(lines, `{"decision":"allow","method":"GET","path":"/secret","tenant":"acme","subject":"bob"}`)
	}
	audit := strings.Join(lines, "\n")

	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 0)

	if report.Changed != 8 {
		t.Fatalf("Changed = %d, want 8", report.Changed)
	}
	if len(report.TopSubjects) != 2 {
		t.Fatalf("TopSubjects len = %d, want 2", len(report.TopSubjects))
	}
	if report.TopSubjects[0].Key != "alice" || report.TopSubjects[0].Count != 5 {
		t.Errorf("TopSubjects[0] = %+v, want alice/5", report.TopSubjects[0])
	}
	if report.TopSubjects[1].Key != "bob" || report.TopSubjects[1].Count != 3 {
		t.Errorf("TopSubjects[1] = %+v, want bob/3", report.TopSubjects[1])
	}
	if len(report.TopPaths) != 1 {
		t.Fatalf("TopPaths len = %d, want 1", len(report.TopPaths))
	}
	if report.TopPaths[0].Key != "/secret" {
		t.Errorf("TopPaths[0].Key = %q, want /secret", report.TopPaths[0].Key)
	}
	if len(report.TopDenyReasons) != 1 || report.TopDenyReasons[0].Key != "no access" {
		t.Errorf("TopDenyReasons = %+v, want [{no access, 8}]", report.TopDenyReasons)
	}
}

func TestRunSimulation_PerTenant(t *testing.T) {
	t.Parallel()
	engine := &fakeSimEngine{denyPaths: map[string]string{
		"/admin": "forbidden",
	}}

	audit := strings.Join([]string{
		`{"decision":"allow","method":"GET","path":"/admin","tenant":"acme","subject":"alice"}`,
		`{"decision":"allow","method":"GET","path":"/admin","tenant":"acme","subject":"bob"}`,
		`{"decision":"allow","method":"GET","path":"/admin","tenant":"beta","subject":"carol"}`,
		`{"decision":"allow","method":"GET","path":"/public","tenant":"beta","subject":"dave"}`,
	}, "\n")

	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 0)

	acme := report.PerTenant["acme"]
	if acme == nil {
		t.Fatal("missing acme tenant")
	}
	if acme.Total != 2 || acme.Changed != 2 {
		t.Errorf("acme: total=%d changed=%d, want 2/2", acme.Total, acme.Changed)
	}
	beta := report.PerTenant["beta"]
	if beta == nil {
		t.Fatal("missing beta tenant")
	}
	if beta.Total != 2 || beta.Changed != 1 {
		t.Errorf("beta: total=%d changed=%d, want 2/1", beta.Total, beta.Changed)
	}
}

func TestRunSimulation_Limit(t *testing.T) {
	t.Parallel()
	engine := &fakeSimEngine{denyPaths: map[string]string{}}

	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, `{"decision":"allow","method":"GET","path":"/api","tenant":"t","subject":"u"}`)
	}
	audit := strings.Join(lines, "\n")

	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 10)

	if report.Replayed != 10 {
		t.Fatalf("Replayed = %d, want 10", report.Replayed)
	}
}

func TestRunSimulation_SkipsNonDecisionEvents(t *testing.T) {
	t.Parallel()
	engine := &fakeSimEngine{denyPaths: map[string]string{}}

	audit := strings.Join([]string{
		`{"decision":"cache_invalidate","method":"POST","path":"/admin/cache"}`,
		`{"decision":"allow","method":"GET","path":"/api","tenant":"t","subject":"u"}`,
		`not json at all`,
		`{"decision":"revoke","method":"POST","path":"/admin/revoke"}`,
	}, "\n")

	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 0)

	if report.Replayed != 1 {
		t.Fatalf("Replayed = %d, want 1", report.Replayed)
	}
	if report.Skipped != 3 {
		t.Fatalf("Skipped = %d, want 3", report.Skipped)
	}
}

func TestRunSimulation_JSONOutput(t *testing.T) {
	t.Parallel()
	engine := &fakeSimEngine{denyPaths: map[string]string{"/x": "nope"}}

	audit := `{"decision":"allow","method":"GET","path":"/x","tenant":"t","subject":"u"}`
	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 0)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Verify it round-trips.
	var decoded SimulationReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Changed != 1 {
		t.Errorf("Changed = %d, want 1", decoded.Changed)
	}
	if decoded.NewDenies != 1 {
		t.Errorf("NewDenies = %d, want 1", decoded.NewDenies)
	}
}

func TestRunSimulation_DenyToAllow(t *testing.T) {
	t.Parallel()
	// Candidate policy allows everything — previously denied events become allows.
	engine := &fakeSimEngine{denyPaths: map[string]string{}}

	audit := strings.Join([]string{
		`{"decision":"deny","method":"GET","path":"/locked","tenant":"acme","subject":"alice"}`,
		`{"decision":"deny","method":"POST","path":"/restricted","tenant":"acme","subject":"bob"}`,
	}, "\n")

	report := runSimulation(context.Background(), engine, strings.NewReader(audit), 0)

	if report.Changed != 2 {
		t.Fatalf("Changed = %d, want 2", report.Changed)
	}
	if report.NewAllows != 2 {
		t.Fatalf("NewAllows = %d, want 2", report.NewAllows)
	}
	if report.NewDenies != 0 {
		t.Fatalf("NewDenies = %d, want 0", report.NewDenies)
	}
}
