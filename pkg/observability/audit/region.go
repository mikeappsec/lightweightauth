// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"log/slog"
)

// RegionRoutingSink routes audit events to region-specific sinks based
// on the event's Tenant field and a tenant→region mapping. Events
// whose tenant has no region assignment are forwarded to the fallback
// sink (typically the operator's default). This enforces data-residency
// constraints: EU tenant events only reach the EU sink, US events only
// the US sink, etc.
type RegionRoutingSink struct {
	// tenantRegion maps tenant ID → region label.
	tenantRegion map[string]string
	// regionSinks maps region label → Sink.
	regionSinks map[string]Sink
	// fallback receives events for tenants with no region assignment.
	fallback Sink
}

// RegionRoutingOption configures a RegionRoutingSink.
type RegionRoutingOption func(*RegionRoutingSink)

// WithFallbackSink sets the sink for events that have no region match.
// If not set, unmatched events are logged and dropped.
func WithFallbackSink(s Sink) RegionRoutingOption {
	return func(r *RegionRoutingSink) { r.fallback = s }
}

// NewRegionRoutingSink creates a routing sink. tenantRegion maps tenant
// IDs to region labels. regionSinks maps region labels to their
// designated sink.
func NewRegionRoutingSink(
	tenantRegion map[string]string,
	regionSinks map[string]Sink,
	opts ...RegionRoutingOption,
) *RegionRoutingSink {
	r := &RegionRoutingSink{
		tenantRegion: tenantRegion,
		regionSinks:  regionSinks,
		fallback:     Discard,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Record routes the event to the region-appropriate sink.
func (r *RegionRoutingSink) Record(ctx context.Context, e *Event) {
	region, ok := r.tenantRegion[e.Tenant]
	if !ok {
		r.fallback.Record(ctx, e)
		return
	}
	sink, ok := r.regionSinks[region]
	if !ok {
		slog.Warn("audit: no sink for region",
			"tenant", e.Tenant, "region", region)
		r.fallback.Record(ctx, e)
		return
	}
	sink.Record(ctx, e)
}
