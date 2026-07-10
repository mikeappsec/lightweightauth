// Smoke + WS-event tests for the Alerts page.
//
// Approach: mock `../api/client` so REST helpers and the WS URL
// builder are deterministic and offline; the shim WebSocket from
// `../test/ws-shim` lets the test push AlertEvent payloads. Because
// the meaty state-machine logic (merge/alert ack/resolve transitions
// and paused-buffer replay) is covered in
// src/lib/alerts-merge.test.ts, the component file's remaining
// concern is: does the page render the empty state when nothing
// fires, and does it actually paint an alert tile when an `open`
// event arrives on the WS?

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { Router, Route } from "@solidjs/router";
import type { Alert, AlertEvent, ListAlertsResponse } from "../api/client";

// Mock the api/client module BEFORE importing the page. Vitest hoists
// vi.mock to the top of the file transitively, but the explicit
// placement keeps the test readable.
vi.mock("../api/client", async () => {
  // Real module exports include the WS URL helper + REST helpers —
  // stubs of those are enough because the test never actually hits
  // the backend (the WS shim intercepts the constructor).
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    // listAlerts returns an empty panel so the page renders the
    // empty state on mount; the test then drives events via WS.
    listAlerts: vi.fn(async () => ({
      alerts: [],
      enabled: true,
      degraded: { prometheus: false, loki: false },
    }) as ListAlertsResponse),
    ackAlert: vi.fn(async () => ({ acked: true, id: "stub", by: "tester" })),
    // alertStreamUrl returns a banner-only URL so any captured URL
    // is visibly test-not-real.
    alertStreamUrl: () => "ws://test.invalid/alerts",
  };
});

import Alerts from "./Alerts";
import { deliverWS, resetWSShim, currentWS } from "../test/ws-shim";

// renderWithRouter wraps the Alerts component in a @solidjs/router
// Router provider because Alerts uses useNavigate() for the
// "View dashboard →" link — the router primitives can only be
// invoked inside an active Route context.
function renderWithRouter() {
  return render(() => (
    <Router>
      <Route path="/" component={Alerts} />
    </Router>
  ));
}

describe("Alerts page", () => {
  afterEach(() => {
    cleanup();
    resetWSShim();
    vi.clearAllMocks();
  });

  it("renders the empty state when no alerts arrive", async () => {
    const { findByText } = renderWithRouter();
    // The expected empty-state copy:
    expect(await findByText("No active alerts")).toBeTruthy();
  });

  it("renders an alert tile when an `open` AlertEvent arrives on the WS", async () => {
    const { findByText, queryByText } = renderWithRouter();
    // Wait for the empty state so we know mount + initial fetch settled.
    expect(await findByText("No active alerts")).toBeTruthy();

    const alert: Alert = {
      id: "a-1",
      rule: "pipeline_p99_latency",
      severity: "critical",
      state: "open",
      fired_at: new Date().toISOString(),
      scope: { cluster: "prod-us-east" },
      metric: { value: 0.7, threshold: 0.5, window: 300, comparator: ">" },
    };
    const evt: AlertEvent = { type: "open", alert, timestamp: new Date().toISOString() };
    deliverWS(evt);

    // The rule name renders as the tile's heading, so finding it by
    // text proves the WS event landed and the merge helper prepended
    // the alert to the page's signal array.
    expect(await findByText("pipeline_p99_latency")).toBeTruthy();
    // Empty-state should now be gone since the list has one row.
    expect(queryByText("No active alerts")).toBeNull();
  });

  it("connects to the alert stream with the expected URL scheme", async () => {
    const { findByText } = renderWithRouter();
    expect(await findByText("No active alerts")).toBeTruthy();
    // The shim captures the constructed URL — one assertion that the
    // page actually opened a WS subscription is enough; deeper
    // integration belongs with backend tests.
    expect(currentWS()?.url.startsWith("ws://test.invalid/alerts")).toBe(true);
  });

  it("ack button mutates the visible state to 'acknowledged' on click", async () => {
    const { findByText, getByText, queryByText } = renderWithRouter();
    expect(await findByText("No active alerts")).toBeTruthy();

    const openAlertEvent: AlertEvent = {
      type: "open",
      alert: {
        id: "ack-test",
        rule: "identifier_upstream_error",
        severity: "critical",
        state: "open",
        fired_at: new Date().toISOString(),
        scope: { cluster: "local", identifier: "jwt" },
        metric: { value: 0.1, threshold: 0.05, window: 300, comparator: ">" },
      },
      timestamp: new Date().toISOString(),
    };
    deliverWS(openAlertEvent);
    expect(await findByText("identifier_upstream_error")).toBeTruthy();

    // Click the Ack button. The api mock resolves synchronously so
    // the optimistic 'ackedIds' set adds the id right away.
    const ackBtn = getByText("Ack");
    ackBtn.click();

    // In real flow the engine acks and broadcasts EventAcked via the
    // WS — the page merges that to flip a.state → "acknowledged",
    // which then relabels the button. Deliver the EventAcked so the
    // state transition lands.
    deliverWS({
      type: "acked",
      timestamp: new Date().toISOString(),
      alert: {
        ...openAlertEvent.alert,
        state: "acknowledged",
        acked_by: "tester",
        ack_note: "",
      },
    });

    // The button now relabels to 'Snoozed' once the acked state
    // propagates; the optimistic button was disabled too.
    expect(await findByText("Snoozed")).toBeTruthy();
    // The alert row itself stays present (the design keeps acked
    // alerts visible through their snooze window).
    expect(queryByText("identifier_upstream_error")).toBeTruthy();
  });
});