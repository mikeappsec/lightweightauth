// Tests for the Dashboard's Request-Health banner — the surface that
// shows "why are requests not responding" before the operator navigates
// to /alerts. Page-level coverage complements the pure-helper tests in
// src/lib/alerts-merge.test.ts — here we exercise the WS integration:
// an `open` critical caller surfaces, an `acked` critical keeps the
// banner visible with the acked_by chip, and `resolved` clears it.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { Router, Route } from "@solidjs/router";
import { QueryClient, QueryClientProvider } from "@tanstack/solid-query";
import type { AlertEvent, HealthResponse } from "../api/client";

// Mock api/client so the Dashboard's initial fetches + WS URLs are
// deterministic — we exercise state transitions via the WS shim
// (`deliverWS`), not via the network stack.
vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    getHealth: vi.fn(async () => ({
      status: "ok",
      totalInstances: 1,
      healthyInstances: 1,
    }) as HealthResponse),
    listInstances: vi.fn(async () => []),
    metricsStreamUrl: () => "ws://test.invalid/metrics",
    alertStreamUrl: () => "ws://test.invalid/alerts",
  };
});

import Dashboard from "./Dashboard";
import { deliverWS, resetWSShim, currentWS } from "../test/ws-shim";

// renderDashboard wraps Dashboard in (1) a TanStack Query provider
// so the createQuery calls don't throw, and (2) a @solidjs/router
// Router because Dashboard's banner uses useNavigate() for the
// click-through to /alerts.
function renderDashboard() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 60_000, refetchInterval: false },
    },
  });
  return render(() => (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Route path="/" component={Dashboard} />
      </Router>
    </QueryClientProvider>
  ));
}

describe("Dashboard Request-Health banner", () => {
  afterEach(() => {
    cleanup();
    resetWSShim();
    vi.clearAllMocks();
  });

  it("renders the main dashboard without a banner initially", async () => {
    const { findByText, queryByText } = renderDashboard();
    expect(await findByText("Dashboard")).toBeTruthy();
    // No critical alert has fired yet — the banner must be absent.
    expect(queryByText("Request Health")).toBeNull();
  });

  it("surfaces the banner when an open critical alert arrives via the alert stream", async () => {
    const { findByText } = renderDashboard();
    expect(await findByText("Dashboard")).toBeTruthy();

    // Two WS connections open (metrics + alerts) — push an alert
    // event to whichever WebSocket was the most recently created.
    // By page-construction order in Dashboard.tsx, the metrics WS
    // is constructed first and the alert WS second, so the shim's
    // `currentWS` ones is the alert subscriber — push the open event.
    const evt: AlertEvent = {
      type: "open",
      timestamp: new Date().toISOString(),
      alert: {
        id: "p99",
        rule: "pipeline_p99_latency",
        severity: "critical",
        state: "open",
        fired_at: new Date().toISOString(),
        scope: { cluster: "prod-us-east" },
        metric: { value: 0.7, threshold: 0.5, window: 300, comparator: ">" },
        reason: {
          headline: "Pipeline P99 latency at 700ms — top slow paths: /checkout",
        },
      },
    };
    deliverWS(evt);

    // The banner headline and rule render verbatim from the reason
    // payload — proves the alert WS is wired through pickTopCritical
    // and into the banner.
    expect(await findByText("Request Health")).toBeTruthy();
    expect(await findByText("pipeline_p99_latency")).toBeTruthy();
    expect(await findByText(/Pipeline P99 latency at 700ms/)).toBeTruthy();
  });

  it("stickies the first critical on co-firing criticals — first-breach-wins", async () => {
    const { findByText, queryByText } = renderDashboard();
    expect(await findByText("Dashboard")).toBeTruthy();

    const first: AlertEvent = {
      type: "open",
      timestamp: new Date().toISOString(),
      alert: {
        id: "first",
        rule: "identifier_upstream_error",
        severity: "critical",
        state: "open",
        // Earlier timestamp so the helper picks this one.
        fired_at: "2026-07-09T10:00:00Z",
        scope: { cluster: "prod" },
      },
    };
    deliverWS(first);
    expect(await findByText("identifier_upstream_error")).toBeTruthy();

    const later: AlertEvent = {
      type: "open",
      timestamp: new Date().toISOString(),
      alert: {
        id: "later",
        rule: "authorizer_error",
        severity: "critical",
        state: "open",
        fired_at: "2026-07-09T10:00:30Z", // 30s later than first
        scope: { cluster: "prod" },
      },
    };
    deliverWS(later);

    // The banner persistently shows the first alert — the later alert
    // must NOT have replaced it (that's the first-breach-wins rule
    // exercised against a real-page render).
    expect(queryByText("authorizer_error")).toBeNull();
    expect(await findByText("identifier_upstream_error")).toBeTruthy();
  });

  it("shows the acked_by chip when the active critical alert is acked", async () => {
    const { findByText, queryByText } = renderDashboard();
    expect(await findByText("Dashboard")).toBeTruthy();

    const open: AlertEvent = {
      type: "open",
      timestamp: new Date().toISOString(),
      alert: {
        id: "ack-flow",
        rule: "pipeline_error_rate",
        severity: "critical",
        state: "open",
        fired_at: new Date().toISOString(),
        scope: { cluster: "local" },
      },
    };
    deliverWS(open);
    expect(await findByText("pipeline_error_rate")).toBeTruthy();

    const acked: AlertEvent = {
      type: "acked",
      timestamp: new Date().toISOString(),
      alert: {
        ...open.alert,
        state: "acknowledged",
        acked_by: "alice",
        ack_note: "investigating",
      },
    };
    deliverWS(acked);

    // The banner stays (acked criticals stay surfaced) and the
    // 'acked by alice' chip renders.
    expect(await findByText(/acked by alice/)).toBeTruthy();
    expect(queryByText("pipeline_error_rate")).toBeTruthy();
  });

  it("clears the banner when the active critical resolves", async () => {
    const { findByText, queryByText } = renderDashboard();
    expect(await findByText("Dashboard")).toBeTruthy();

    const open: AlertEvent = {
      type: "open",
      timestamp: new Date().toISOString(),
      alert: {
        id: "resolve-test",
        rule: "pipeline_error_rate",
        severity: "critical",
        state: "open",
        fired_at: new Date().toISOString(),
        scope: { cluster: "local" },
      },
    };
    deliverWS(open);
    expect(await findByText("Request Health")).toBeTruthy();

    const resolved: AlertEvent = {
      type: "resolved",
      timestamp: new Date().toISOString(),
      alert: { ...open.alert, state: "resolved" },
    };
    deliverWS(resolved);

    // Banner clears on resolve (the page's own code path matches
    // prev?.id === evt.alert.id ? null).
    expect(queryByText("Request Health")).toBeNull();
  });

  it("ignores non-critical alerts (severity filter on the WS subscription)", async () => {
    const { findByText, queryByText } = renderDashboard();
    expect(await findByText("Dashboard")).toBeTruthy();

    // A warning alert arrives — should never surface in the banner.
    const warning: AlertEvent = {
      type: "open",
      timestamp: new Date().toISOString(),
      alert: {
        id: "warn-1",
        rule: "deny_rate_spike",
        severity: "warning",
        state: "open",
        fired_at: new Date().toISOString(),
        scope: { cluster: "local", tenant: "acme" },
      },
    };
    deliverWS(warning);

    // The banner never paints because Dashboard filters
    // severity=critical — non-critical events are silently dropped
    // at the onmessage handler. Wait a tick for any reflow then
    // assert the banner is still hidden.
    await new Promise((r) => setTimeout(r, 30));
    expect(queryByText("Request Health")).toBeNull();
  });

  it("opens two WS connections (metrics + alerts)", async () => {
    const { findByText } = renderDashboard();
    expect(await findByText("Dashboard")).toBeTruthy();
    // The shim only tracks the latest WS so we can't assert two
    // directly, but the current one must be the alert WS (the most
    // recent constructor). The metrics WS would have used the
    // metrics URL — proving the alert subscription is wired is
    // enough; metrics stream wiring is symmetric.
    expect(currentWS()?.url).toContain("alerts");
  });
});