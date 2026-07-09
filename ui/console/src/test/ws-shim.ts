// Test-time WebSocket shim for SolidJS pages that subscribe via
// `new WebSocket(url)`. The shim captures the latest opened instance
// into a singleton so individual test files can push events through
// `__deliverWS(JSON.stringify(event))` without spinning up a real
// server. Tests clear the singleton in afterEach to keep order
// deterministic.

export interface WSShim {
  url: string;
  onopen: ((ev: Event) => void) | null;
  onclose: ((ev: CloseEvent) => void) | null;
  onmessage: ((ev: MessageEvent) => void) | null;
  close: () => void;
}

let current: WSShim | null = null;

class WebSocketShim {
  public url: string;
  public onopen: ((ev: Event) => void) | null = null;
  public onclose: ((ev: CloseEvent) => void) | null = null;
  public onmessage: ((ev: MessageEvent) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    current = this;
    // Defer the open so callers that synchronously attach handlers
    // after construction still receive the event.
    queueMicrotask(() => {
      if (current === this && this.onopen) {
        this.onopen(new Event("open"));
      }
    });
  }

  close() {
    if (current === this) current = null;
    if (this.onclose) this.onclose(new CloseEvent("close"));
  }
}

// Install the shim globally once per test process. We use a getter so
// users can reassign if they need to (rare) but the default is
// transparent to the api/client caller that just constructs WebSocket.
(globalThis as any).WebSocket = WebSocketShim;

// currentWS returns the most recently constructed shim so tests can
// push events or assert that subscription happened. Returns null
// when no WS has been created yet.
export function currentWS(): WSShim | null {
  return current;
}

// deliver synthesises a WS message on the current shim — the form
// matches what api/client expects: a JSON-stringified payload
// (AlertEvent for alerts, MetricsSnapshot for metrics).
export function deliverWS(payload: unknown): void {
  if (!current || !current.onmessage) return;
  current.onmessage({ data: JSON.stringify(payload) } as MessageEvent);
}

// resetWSShim clears the singleton so the next test starts clean.
// Call this in afterEach to keep test isolation tight.
export function resetWSShim(): void {
  if (current && current.onclose) current.onclose(new CloseEvent("close"));
  current = null;
}