// Unit tests for the pure alert-merge helpers used by the Alerts
// page and the Dashboard banner. Covers the meaty triage logic:
// first-breach-wins banner selection, ack/resolved transitions, and
// paused-buffer replay — without spinning up a fake WebSocket in
// jsdom.

import { describe, it, expect } from "vitest";
import { pickTopCritical, mergeAlert, replayBuffer } from "./alerts-merge";
import type { Alert } from "../api/client";

// Factories keep tests terse and visually-scannable.
function openAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: "a-1",
    rule: "identifier_upstream_error",
    severity: "critical",
    state: "open",
    fired_at: "2026-07-09T10:00:00Z",
    scope: { cluster: "local", identifier: "jwt" },
    metric: { value: 0.08, threshold: 0.05, window: 300, comparator: ">" },
    ...overrides,
  };
}

describe("pickTopCritical", () => {
  it("returns incoming when prev is null", () => {
    const incoming = openAlert();
    expect(pickTopCritical(null, incoming)).toBe(incoming);
  });

  it("keeps the earlier firing alert on co-firing criticals (first-breach-wins)", () => {
    const prev = openAlert({ id: "a-1", fired_at: "2026-07-09T10:00:00Z" });
    // Later firing alert arrives second — banner must stick with prev.
    const incoming = openAlert({
      id: "a-2",
      fired_at: "2026-07-09T10:00:30Z",
    });
    expect(pickTopCritical(prev, incoming)).toBe(prev);
  });

  it("replaces prev when incoming fires earlier", () => {
    const prev = openAlert({ id: "a-1", fired_at: "2026-07-09T10:00:30Z" });
    const incoming = openAlert({
      id: "a-2",
      fired_at: "2026-07-09T10:00:00Z",
    });
    expect(pickTopCritical(prev, incoming)).toBe(incoming);
  });

  it("ignores non-open, non-acknowledged alerts (e.g. resolved)", () => {
    const prev = openAlert();
    const resolved = openAlert({ state: "resolved" });
    expect(pickTopCritical(prev, resolved)).toBe(prev);
  });

  it("returns null-prev when incoming is resolved (no critical surfaces)", () => {
    expect(pickTopCritical(null, openAlert({ state: "resolved" }))).toBeNull();
  });

  it("acknowledged criticals stay banner-eligible", () => {
    const prev = openAlert({ state: "open" });
    const acked = openAlert({ state: "acknowledged", acked_by: "alice" });
    // Earlier-timestamp ack still wins over a later open.
    const laterAck = openAlert({
      id: "ack2",
      fired_at: "2026-07-09T10:00:30Z",
      state: "acknowledged",
    });
    expect(pickTopCritical(acked, laterAck)).toBe(acked);
    expect(pickTopCritical(prev, acked)).toBe(prev); // same fired_at → prev wins (tie-break)
  });

  it("acknowledged replaces a non-critical prev", () => {
    const prev = openAlert({ severity: "warning" });
    const critical = openAlert({ severity: "critical" });
    expect(pickTopCritical(prev, critical)).toBe(critical);
  });

  it("does not repeatedly replace a stable critical with a later one", () => {
    const stable = openAlert({ id: "a-stable", fired_at: "2026-07-09T09:59:00Z" });
    for (let i = 0; i < 5; i++) {
      const later = openAlert({
        id: `a-${i}`,
        fired_at: `2026-07-09T10:0${i}:00Z`,
      });
      expect(pickTopCritical(stable, later)).toBe(stable);
    }
  });
});

describe("mergeAlert", () => {
  it("prepends an unknown alert (fresh open)", () => {
    const incoming = openAlert();
    const result = mergeAlert([], incoming, "open");
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(incoming);
  });

  it("updates an existing alert in-place on ack", () => {
    const seed = openAlert({ state: "open" });
    const acked = openAlert({ state: "acknowledged", acked_by: "alice" });
    const result = mergeAlert([seed], acked, "acked");
    expect(result).toHaveLength(1);
    expect(result[0].state).toBe("acknowledged");
    expect(result[0].acked_by).toBe("alice");
  });

  it("preserves the alert's slot position on resolve (per the design)", () => {
    const a = openAlert({ id: "a-1" });
    const b = openAlert({ id: "a-2" });
    const c = openAlert({ id: "a-3" });
    const evolvedB = openAlert({ id: "a-2", state: "resolved" });
    const result = mergeAlert([a, b, c], evolvedB, "resolved");
    // b stays at index 1 (operator context preserved during triage).
    expect(result[1].id).toBe("a-2");
    expect(result[1].state).toBe("resolved");
  });

  it("handles reopen: same id, EventOpen from resolved", () => {
    const resolved = openAlert({ state: "resolved" });
    const reopened = openAlert({ state: "open" });
    const result = mergeAlert([resolved], reopened, "open");
    expect(result).toHaveLength(1);
    expect(result[0].state).toBe("open");
  });

  it("does not lose sibling alerts when one transition arrives", () => {
    const a = openAlert({ id: "a-1" });
    const b = openAlert({ id: "a-2" });
    const ackB = openAlert({ id: "a-2", state: "acknowledged" });
    const result = mergeAlert([a, b], ackB, "acked");
    expect(result).toHaveLength(2);
    expect(result[0].id).toBe("a-1");
    expect(result[1].id).toBe("a-2");
    expect(result[1].state).toBe("acknowledged");
  });

  it("returns a fresh array reference (immutable for SolidJS signals)", () => {
    const seed = [openAlert()];
    const result = mergeAlert(seed, openAlert({ id: "a-2" }), "open");
    expect(result).not.toBe(seed);
  });
});

describe("replayBuffer", () => {
  it("prepends paused-buffer entries oldest-first to the live array", () => {
    const older = openAlert({ id: "p1", fired_at: "2026-07-09T10:00:10Z" });
    const newer = openAlert({ id: "p2", fired_at: "2026-07-09T10:00:50Z" });
    const live = [openAlert({ id: "live1" })];
    const result = replayBuffer(live, [newer, older]); // buffer in arrival order
    expect(result[0].id).toBe("p1"); // oldest wins after sort
    expect(result[1].id).toBe("p2");
    expect(result[2].id).toBe("live1");
  });

  it("handles an empty buffer", () => {
    const live = [openAlert({ id: "live1" })];
    expect(replayBuffer(live, [])).toEqual(live);
  });

  it("handles an empty live", () => {
    const buffered = [openAlert({ id: "p1" })];
    const result = replayBuffer([], buffered);
    expect(result).toEqual(buffered);
  });

  it("merges interleaved buffer timestamps into chronological order", () => {
    const live = [openAlert({ id: "live1", fired_at: "2026-07-09T10:05:00Z" })];
    const buffer = [
      openAlert({ id: "p2", fired_at: "2026-07-09T10:01:00Z" }),
      openAlert({ id: "p1", fired_at: "2026-07-09T10:00:00Z" }),
      openAlert({ id: "p3", fired_at: "2026-07-09T10:02:00Z" }),
    ];
    const result = replayBuffer(live, buffer);
    expect(result.map((a) => a.id)).toEqual(["p1", "p2", "p3", "live1"]);
  });
});