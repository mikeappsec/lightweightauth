// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigMapName is the canonical name of the operator-editable alert
// rules ConfigMap. Operators commit overrides here and the loader
// merges them with DefaultRuleCatalog on the next polling cycle.
const ConfigMapName = "lwauth-alerting-rules"

// RulesKey is the JSON subkey inside the ConfigMap data block. Yaml
// support is intentionally omitted — JSON keeps the merge logic
// schema-tight and avoids yaml parsing dependencies.
const RulesKey = "rules.json"

// defaultLoadInterval bounds the loader's polling frequency. A poll
// every 30s keeps the edit-to-engine-apply latency low enough for
// operator workflows while avoiding switch-on-every-tick noise.
const defaultLoadInterval = 30 * time.Second

// ConfigMapLoader polls the lwauth-alerting-rules ConfigMap and
// applies merged rules to the engine via SetRules. The polling form
// (rather than an informer) keeps the loader dependency-free: no
// leader election, no event queue, no cache invalidation — just
// "every interval, get the latest document and recompile".
//
// In test/local mode, the loader can be constructed without a kube
// client (NilClient) — it will emit a one-time warning and skip the
// polling loop, leaving the engine running on the built-in defaults.
type ConfigMapLoader struct {
	Namespace string
	Client    client.Client
	Engine    *Engine
	Interval  time.Duration
	Scheme    *runtime.Scheme

	once sync.Once
}

// NewConfigMapLoader constructs the loader. Namespace defaults to
// "default" when empty (matches control-plane's deployment target).
func NewConfigMapLoader(kubeClient client.Client, namespace string, engine *Engine) *ConfigMapLoader {
	if namespace == "" {
		namespace = "default"
	}
	return &ConfigMapLoader{
		Namespace: namespace,
		Client:    kubeClient,
		Engine:    engine,
		Interval:  defaultLoadInterval,
	}
}

// Run blocks until ctx is cancelled, polling the ConfigMap every
// Interval and applying merged rules to the engine.
func (l *ConfigMapLoader) Run(ctx context.Context) {
	logger := slog.Default().With("service", "alerting-rules-loader", "namespace", l.Namespace)
	if l.Client == nil {
		l.once.Do(func() {
			logger.Warn("kubernetes client is nil — alerting-rules loader is disabled; engine continues with built-in defaults")
		})
		// Soft disable: park on ctx so the engine keeps running with
		// its seed rules without churn.
		<-ctx.Done()
		return
	}
	logger.Info("starting alerting-rules loader", "interval", l.Interval, "configmap", ConfigMapName)
	ticker := time.NewTicker(l.Interval)
	defer ticker.Stop()
	// Prime the engine immediately so the first tick after boot uses
	// any operator overrides committed while the CP was down.
	_ = l.applyOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := l.applyOnce(ctx); err != nil {
				logger.Warn("alerting-rules reload failed", "err", err)
			}
		}
	}
}

// applyOnce reads the ConfigMap, decodes its rules.json block, and
// applies MergeRules(DefaultRuleCatalog(), overrides) to the engine.
// Missing ConfigMap is treated as empty overrides — defaults stay.
func (l *ConfigMapLoader) applyOnce(ctx context.Context) error {
	var cm corev1.ConfigMap
	err := l.Client.Get(ctx, client.ObjectKey{
		Namespace: l.Namespace,
		Name:      ConfigMapName,
	}, &cm)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// The operator has not yet committed overrides — the
			// default catalog continues. This is the common path for
			// local-dev and bootstrap-before-overlays scenarios, so
			// emit nothing.
			l.Engine.SetRules(DefaultRuleCatalog())
			return nil
		}
		return fmt.Errorf("get configmap: %w", err)
	}

	raw, ok := cm.Data[RulesKey]
	if !ok || raw == "" {
		// ConfigMap exists but the rule block is empty/missing — same
		// behavior as not-found: defaults continue.
		l.Engine.SetRules(DefaultRuleCatalog())
		return nil
	}
	var overrides []Rule
	if err := json.Unmarshal([]byte(raw), &overrides); err != nil {
		// Don't clobber the engine with malformed overrides: keep
		// the active rule set so the engine continues its previous
		// behaviour until the operator pushes a parseable document.
		return fmt.Errorf("decode rules.json: %w", err)
	}
	merged := MergeRules(DefaultRuleCatalog(), overrides)
	l.Engine.SetRules(merged)
	return nil
}

// PutRules writes the supplied overrides back into the ConfigMap (a
// CRUD helper for the POST /v1/controlplane/alerts/rules endpoint).
// Namespace + name default to the loader's own bounds so the endpoint
// touches the same object the polling loop reads. Empty overrides
// removes the rules.json key entirely (engine reverts to defaults on
// the next poll).
func (l *ConfigMapLoader) PutRules(ctx context.Context, overrides []Rule) error {
	if l.Client == nil {
		return fmt.Errorf("alerting-rules loader: kubernetes client unavailable (running in dev mode)")
	}
	raw, err := json.MarshalIndent(overrides, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}
	// Read-then-write — controller-runtime has no native
	// Patch...Data(...) helper that wouldn't require an informer cache,
	// and the rules ConfigMap is operator-edit-rate (~minute scale),
	// so a read-then-update is safe under single-replica CP.
	for attempt := 0; attempt < 3; attempt++ {
		var cm corev1.ConfigMap
		err := l.Client.Get(ctx, client.ObjectKey{
			Namespace: l.Namespace,
			Name:      ConfigMapName,
		}, &cm)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("get configmap: %w", err)
		}
		if apierrors.IsNotFound(err) {
			cm = corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: l.Namespace,
					Name:      ConfigMapName,
				},
				Data: map[string]string{},
			}
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		if len(overrides) == 0 {
			delete(cm.Data, RulesKey)
		} else {
			cm.Data[RulesKey] = string(raw)
		}
		if cm.ResourceVersion == "" {
			if err := l.Client.Create(ctx, &cm); err != nil {
				if apierrors.IsAlreadyExists(err) && attempt < 2 {
					// Lost create race; retry the cycle.
					continue
				}
				return fmt.Errorf("create configmap: %w", err)
			}
		} else {
			if err := l.Client.Update(ctx, &cm); err != nil {
				if apierrors.IsConflict(err) && attempt < 2 {
					// Optimistic-lock retry — ConfigMap updated by
					// another writer (likely ArgoCD sync wave) between
					// our read and our update.
					continue
				}
				return fmt.Errorf("update configmap: %w", err)
			}
		}
		// Best-effort: apply immediately so the REST response
		// reflects the new state before the next poll.
		merged := MergeRules(DefaultRuleCatalog(), overrides)
		l.Engine.SetRules(merged)
		return nil
	}
	return fmt.Errorf("exhausted 3 optimistic-lock retries writing %s", ConfigMapName)
}