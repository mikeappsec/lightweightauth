// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package lwauthd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

var (
	auditPolicyMu sync.Mutex
	auditBaseSink audit.Sink
	auditSeed     []byte
)

// applyAuditPolicy wires G3 controls (tenant redaction + data-residency routing)
// into the process-wide audit sink for the active AuthConfig.
func applyAuditPolicy(ac *config.AuthConfig, log *slog.Logger) error {
	if ac == nil {
		return nil
	}

	auditPolicyMu.Lock()
	defer auditPolicyMu.Unlock()

	if log == nil {
		log = slog.Default()
	}
	if auditBaseSink == nil {
		base := audit.Default()
		if base == audit.Discard {
			base = audit.NewSlogSink(log)
			audit.SetDefault(base)
		}
		auditBaseSink = base
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			sum := sha256.Sum256([]byte("lwauth-audit-seed-fallback"))
			seed = sum[:]
		}
		auditSeed = seed
	}

	sink := auditBaseSink
	tenant := strings.TrimSpace(ac.TenantID)

	// G3-03: If audit policy is configured, TenantID is required.
	// Empty TenantID with audit config is a misconfiguration.
	if ac.Audit != nil && (ac.Audit.Redaction != nil || ac.Audit.DataResidency != nil) {
		if tenant == "" {
			log.Error("audit policy configured but tenantId is empty",
				"error", "cannot apply PII redaction or data residency without tenant identity")
			return fmt.Errorf("tenantId required when audit policy (redaction/dataResidency) configured")
		}
	}

	if tenant == "" || ac.Audit == nil {
		audit.SetDefault(sink)
		return nil
	}

	// Apply per-tenant redaction first.
	if ac.Audit.Redaction != nil && len(ac.Audit.Redaction.Fields) > 0 {
		fields := make([]audit.RedactionField, 0, len(ac.Audit.Redaction.Fields))
		for _, f := range ac.Audit.Redaction.Fields {
			name := strings.TrimSpace(f.Name)
			if name == "" {
				continue
			}
			switch f.Action {
			case config.RedactHash:
				fields = append(fields, audit.RedactionField{Name: name, Action: audit.RedactHash})
			case config.RedactDrop:
				fields = append(fields, audit.RedactionField{Name: name, Action: audit.RedactDrop})
			default:
				log.Warn("audit: skipping unsupported redaction action",
					"tenant", tenant,
					"field", name,
					"action", string(f.Action),
				)
			}
		}
		if len(fields) > 0 {
			tas := audit.NewTenantAwareSink(sink)
			tas.SetTenantRedaction(tenant, fields, tenantAuditKey(tenant))
			sink = tas
		}
	}

	// Enforce region routing when configured. Unknown tenants/regions are dropped
	// because fallback is intentionally omitted.
	if ac.Audit.DataResidency != nil {
		region := strings.TrimSpace(ac.Audit.DataResidency.Region)
		if region != "" {
			router := audit.NewRegionRoutingSink(
				map[string]string{tenant: region},
				map[string]audit.Sink{region: sink},
			)
			sink = router
		}
	}

	audit.SetDefault(sink)
	return nil
}

func tenantAuditKey(tenant string) []byte {
	mac := hmac.New(sha256.New, auditSeed)
	_, _ = mac.Write([]byte(tenant))
	return mac.Sum(nil)
}
