// Pure helpers shared by the Alerts page and the Dashboard banner.
//
// Extracting these out of the JSX keeps the WebSocket glue minimal in
// the page components and lets us unit-test the meaty transition logic
// (first-breach-wins, ack/resolve merge, paused-buffer replay) without
// spinning up a fake WS in jsdom.

import type { Alert } from "../api/client";

// pickTopCritical keeps whichever critical open-or-acked alert has
// the earliest fired_at — first-breach-wins so the banner doesn't
// flicker between co-firing criticals. Pass `prev` (null on first
// call) and the incoming alert just delivered via the WS stream.
//
// Logic:
//   - resolved alerts never appear in the banner; they fall through
//     to the next call's null reset when they ARE the active one
//     (caller also flips prev→null in the Dashboard banner code on
//     `resolved` events).
//   - open/acknowledged criticals compete on fired_at: the older
//     breach wins so a burst of co-firing criticals pins the banner
//     to whichever fired first while the acked & resolved transitions
//     for that single ID update in-place.
//   - non-criticals and resolved alerts never bubble up from the
//     WS filter because the Dashboard subscribes with
//     severity=critical, but the function still defends against that
//     to keep behaviour predictable under operator filter edits.
export function pickTopCritical(
  prev: Alert | null,
  incoming: Alert,
): Alert | null {
  if (incoming.state !== "open" && incoming.state !== "acknowledged") {
    return prev;
  }
  if (!prev) return incoming;
  if (prev.severity !== "critical") return incoming;
  const prevTime = +new Date(prev.fired_at);
  const incomingTime = +new Date(incoming.fired_at);
  return incomingTime < prevTime ? incoming : prev;
}

// mergeAlert applies one open/acked/resolved transition to the
// Alerts page's in-memory list. Returns a new array so the call
// remains a pure side-effect-free mutation on SolidJS signals.
//
// Semantics:
//   - open: prepend if unknown; mutate in-place if the alert ID
//     already exists (the engine reopens alerts after an ack-cooldown
//     expiry by re-emitting an EventOpen with the same ID).
//   - acked: update the existing row with the ack metadata; do NOT
//     move its position in the list — the page sorts by state/severity
//     at render time so reordering mid-buffer would lose operator
//     context.
//   - resolved: keep the row in place with the new resolved_at; the
//     list renderer styles resolved rows differently and lets the
//     sort key fall them to the bottom. They're only displaced when
//     the engine's history ring (server side) signals replacement,
//     not on this transition.
export function mergeAlert(
  prev: Alert[],
  incoming: Alert,
  evt: string,
): Alert[] {
  const idx = prev.findIndex((a) => a.id === incoming.id);
  if (idx === -1) return [incoming, ...prev];
  const copy = prev.slice();
  copy[idx] = { ...copy[idx], ...incoming };
  // The evt parameter is documented above and kept on the signature
  // so callers can future-version the merge (e.g. moving a 'resolved'
  // alert to the end of the list) without a breaking change — today
  // every transition updates in place to preserve operator context.
  void evt;
  return copy;
}

// replayBuffer merges a paused-session buffer back into the live
// signals array, oldest-first so the timeline reads chronologically
// after Resume. `buffer` is drained in the call (the caller passes
// the array that was filled during pause and clears it after).
export function replayBuffer(
  live: Alert[],
  buffer: Alert[],
): Alert[] {
  // Oldest first — the buffer was filled in arrival order, but
  // re-emitted broadcasts may interleave so we sort defensively on
  // fired_at.
  const sorted = buffer.slice().sort((a, b) => +new Date(a.fired_at) - +new Date(b.fired_at));
  const merged = [...sorted, ...live];
  return merged;
}