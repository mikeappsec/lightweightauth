// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"k8s.io/apimachinery/pkg/types"
)

// matchesNamePredicate filters reconcile events to a single (namespace,
// name) pair. controller-runtime provides predicate.Funcs and we just
// fill in one predicate that's reused by all four event kinds.
type matchesNamePredicate struct {
	Watched types.NamespacedName
}

var _ predicate.Predicate = matchesNamePredicate{}

func (p matchesNamePredicate) match(name, ns string) bool {
	return name == p.Watched.Name && ns == p.Watched.Namespace
}

func (p matchesNamePredicate) Create(e event.CreateEvent) bool {
	return p.match(e.Object.GetName(), e.Object.GetNamespace())
}

func (p matchesNamePredicate) Update(e event.UpdateEvent) bool {
	return p.match(e.ObjectNew.GetName(), e.ObjectNew.GetNamespace())
}

func (p matchesNamePredicate) Delete(e event.DeleteEvent) bool {
	return p.match(e.Object.GetName(), e.Object.GetNamespace())
}

func (p matchesNamePredicate) Generic(e event.GenericEvent) bool {
	return p.match(e.Object.GetName(), e.Object.GetNamespace())
}
