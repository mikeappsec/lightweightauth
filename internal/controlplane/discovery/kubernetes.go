// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// DefaultLabelSelector is the label lwauth Pods/Services are expected
// to carry for auto-discovery.
var DefaultLabelSelector = labels.SelectorFromSet(labels.Set{
	"app.kubernetes.io/name": "lwauth",
})

// KubernetesWatcher watches Kubernetes Services matching a label selector
// and registers them in the instance registry.
type KubernetesWatcher struct {
	Client   client.Client
	Registry *Registry
	Config   KubernetesDiscoveryConfig
	Interval time.Duration
}

// NewKubernetesWatcher creates a watcher with sensible defaults.
func NewKubernetesWatcher(c client.Client, registry *Registry, cfg KubernetesDiscoveryConfig) *KubernetesWatcher {
	if cfg.LabelSelector == nil {
		cfg.LabelSelector = DefaultLabelSelector
	}
	return &KubernetesWatcher{
		Client:   c,
		Registry: registry,
		Config:   cfg,
		Interval: 30 * time.Second,
	}
}

// Run starts the periodic discovery loop. Blocks until ctx is cancelled.
func (w *KubernetesWatcher) Run(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("k8s-discovery").WithValues("cluster", w.Config.Cluster)

	// Initial discovery.
	if err := w.discover(ctx); err != nil {
		logger.Error(err, "initial discovery failed")
	}

	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.discover(ctx); err != nil {
				logger.V(1).Info("discovery cycle failed", "error", err)
			}
		}
	}
}

func (w *KubernetesWatcher) discover(ctx context.Context) error {
	var services corev1.ServiceList
	listOpts := []client.ListOption{
		client.MatchingLabelsSelector{Selector: w.Config.LabelSelector},
	}

	// If namespaces are restricted, list per namespace.
	if len(w.Config.Namespaces) > 0 {
		for _, ns := range w.Config.Namespaces {
			opts := append(listOpts, client.InNamespace(ns))
			var nsList corev1.ServiceList
			if err := w.Client.List(ctx, &nsList, opts...); err != nil {
				return fmt.Errorf("list services in %s: %w", ns, err)
			}
			services.Items = append(services.Items, nsList.Items...)
		}
	} else {
		if err := w.Client.List(ctx, &services, listOpts...); err != nil {
			return fmt.Errorf("list services: %w", err)
		}
	}

	for i := range services.Items {
		svc := &services.Items[i]
		inst := w.serviceToInstance(svc)
		w.Registry.Register(inst)
	}

	return nil
}

func (w *KubernetesWatcher) serviceToInstance(svc *corev1.Service) *Instance {
	// Determine the admin URL from the Service.
	// Convention: port named "admin" or port 8081.
	adminPort := "8081"
	for _, p := range svc.Spec.Ports {
		if p.Name == "admin" {
			adminPort = fmt.Sprintf("%d", p.Port)
			break
		}
	}

	adminURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:%s", svc.Name, svc.Namespace, adminPort)

	// Instance name from label or Service name.
	name := svc.Labels["app.kubernetes.io/instance"]
	if name == "" {
		name = svc.Name
	}

	return &Instance{
		Name:      name,
		Cluster:   w.Config.Cluster,
		Namespace: svc.Namespace,
		AdminURL:  adminURL,
		Source:    SourceAutoDiscovery,
	}
}
