// Test-time WebSocket shim for SolidJS pages that subscribe via
// `new WebSocket(url)`. The shim tracks every open socket in a
// URL-keyed map so tests that open multiple connections (e.g.
// Dashboard opens a metrics stream AND an alert stream) can target
// each socket independently via `wsForURL(url)`.
//
// `deliverWS` delivers to the most-recently-created socket for
// backward compatibility with single-socket tests. Multi-socket
// tests should use `deliverToURL(url, payload)` to be explicit.

export interface WSShim {
  url: string;
  onopen: ((ev: Event) => void) | null;
  onclose: ((ev: CloseEvent) => void) | null;
  onmessage: ((ev: MessageEvent) => void) | null;
  close: () => void;
}

// all tracks every open shim keyed by URL. When a URL is reused
// (e.g. a filter change triggers a new WS on the same path), the
// map entry is replaced with the newer socket.
const all = new Map<string, WSShim>();
let lastCreated: WSShim | null = null;

class WebSocketShim {
  public url: string;
  public onopen: ((ev: Event) => void) | null = null;
  public onclose: ((ev: CloseEvent) => void) | null = null;
  public onmessage: ((ev: MessageEvent) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    all.set(url, this);
    lastCreated = this;
    // Defer the open so callers that synchronously attach handlers
    // after construction still receive the event.
    queueMicrotask(() => {
      if (all.get(url) === this && this.onopen) {
        this.onopen(new Event("open"));
      }
    });
  }

  close() {
    if (all.get(this.url) === this) all.delete(this.url);
    if (lastCreated === this) lastCreated = null;
    if (this.onclose) this.onclose(new CloseEvent("close"));
  }
}

// Install the shim globally once per test process.
(globalThis as any).WebSocket = WebSocketShim;

// currentWS returns the most recently constructed shim. Backward-
// compatible with single-socket tests.
export function currentWS(): WSShim | null {
  return lastCreated;
}

// wsForURL returns the open shim for a given URL (or URL prefix), or
// null when no socket for that URL is currently open. Use this in
// multi-socket tests to target a specific stream.
export function wsForURL(urlOrPrefix: string): WSShim | null {
  for (const [key, shim] of all) {
    if (key === urlOrPrefix || key.startsWith(urlOrPrefix)) return shim;
  }
  return null;
}

// deliver synthesises a WS message on the most recently created shim.
export function deliverWS(payload: unknown): void {
  if (!lastCreated || !lastCreated.onmessage) return;
  lastCreated.onmessage({ data: JSON.stringify(payload) } as MessageEvent);
}

// deliverToURL synthesises a WS message on the shim matching the
// given URL prefix. Use in multi-socket tests where `deliverWS`
// would target the wrong socket.
export function deliverToURL(urlOrPrefix: string, payload: unknown): void {
  const shim = wsForURL(urlOrPrefix);
  if (!shim || !shim.onmessage) return;
  shim.onmessage({ data: JSON.stringify(payload) } as MessageEvent);
}

// resetWSShim closes and removes all tracked sockets. Call in
// afterEach to keep test isolation tight.
export function resetWSShim(): void {
  for (const shim of all.values()) {
    if (shim.onclose) shim.onclose(new CloseEvent("close"));
  }
  all.clear();
  lastCreated = null;
}