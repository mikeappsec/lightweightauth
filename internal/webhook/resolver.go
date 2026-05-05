// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"fmt"
	"sync"

	crdv1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// InformerResolver implements PolicyResolver using controller-runtime's
// cached client (backed by an informer). The controller manager
// automatically populates the cache for resources it watches.
type InformerResolver struct {
	client client.Reader
}

// NewInformerResolver creates a resolver backed by a controller-runtime
// cached client. The client must have PolicyBinding in its scheme.
func NewInformerResolver(c client.Reader) *InformerResolver {
	return &InformerResolver{client: c}
}

// ListBindings returns all PolicyBindings in the given namespace.
func (r *InformerResolver) ListBindings(ctx context.Context, namespace string) ([]crdv1alpha1.PolicyBinding, error) {
	var list crdv1alpha1.PolicyBindingList
	if err := r.client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list PolicyBindings in %q: %w", namespace, err)
	}
	return list.Items, nil
}

// StaticResolver is a test-friendly PolicyResolver that returns
// pre-configured bindings.
type StaticResolver struct {
	mu       sync.RWMutex
	bindings map[string][]crdv1alpha1.PolicyBinding // namespace -> bindings
}

// NewStaticResolver creates a resolver with the given bindings keyed by
// namespace.
func NewStaticResolver(bindings map[string][]crdv1alpha1.PolicyBinding) *StaticResolver {
	if bindings == nil {
		bindings = make(map[string][]crdv1alpha1.PolicyBinding)
	}
	return &StaticResolver{bindings: bindings}
}

// ListBindings returns the pre-configured bindings for the namespace.
func (r *StaticResolver) ListBindings(_ context.Context, namespace string) ([]crdv1alpha1.PolicyBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bindings[namespace], nil
}

// SetBindings replaces bindings for a namespace (for tests).
func (r *StaticResolver) SetBindings(namespace string, bindings []crdv1alpha1.PolicyBinding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindings[namespace] = bindings
}
