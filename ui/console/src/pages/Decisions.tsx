import { createSignal, createEffect, onCleanup, For, Show } from "solid-js";
import { decisionStreamUrl, type Decision } from "../api/client";

const MAX_DECISIONS = 500;

export default function Decisions() {
  const [decisions, setDecisions] = createSignal<Decision[]>([]);
  const [paused, setPaused] = createSignal(false);
  const [filterCluster, setFilterCluster] = createSignal("");
  const [filterTenant, setFilterTenant] = createSignal("");
  const [filterVerdict, setFilterVerdict] = createSignal("");
  const [connected, setConnected] = createSignal(false);

  let buffer: Decision[] = [];

  createEffect(() => {
    const url = decisionStreamUrl({
      cluster: filterCluster() || undefined,
      tenant: filterTenant() || undefined,
      verdict: filterVerdict() || undefined,
    });

    const ws = new WebSocket(url);
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (e) => {
      try {
        const d: Decision = JSON.parse(e.data);
        if (paused()) {
          buffer.push(d);
          if (buffer.length > MAX_DECISIONS) buffer.shift();
        } else {
          setDecisions((prev) => {
            const next = [d, ...prev];
            return next.length > MAX_DECISIONS ? next.slice(0, MAX_DECISIONS) : next;
          });
        }
      } catch { /* ignore */ }
    };

    onCleanup(() => ws.close());
  });

  function resume() {
    setPaused(false);
    if (buffer.length > 0) {
      setDecisions((prev) => {
        const merged = [...buffer.reverse(), ...prev];
        buffer = [];
        return merged.slice(0, MAX_DECISIONS);
      });
    }
  }

  return (
    <div>
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-2xl font-bold">Decisions</h2>
        <div class="flex items-center gap-3">
          <span class={`inline-block w-2 h-2 rounded-full ${connected() ? "bg-green-500" : "bg-red-500"}`} />
          <span class="text-xs text-gray-500">{connected() ? "Live" : "Disconnected"}</span>
          <button
            class={`px-3 py-1 text-xs rounded ${paused() ? "bg-green-600 text-white" : "bg-yellow-500 text-white"}`}
            onClick={() => paused() ? resume() : setPaused(true)}
          >
            {paused() ? "Resume" : "Pause"}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div class="flex gap-3 mb-4">
        <input
          class="border rounded px-2 py-1 text-sm w-32"
          placeholder="Cluster"
          value={filterCluster()}
          onInput={(e) => setFilterCluster(e.currentTarget.value)}
        />
        <input
          class="border rounded px-2 py-1 text-sm w-32"
          placeholder="Tenant"
          value={filterTenant()}
          onInput={(e) => setFilterTenant(e.currentTarget.value)}
        />
        <select
          class="border rounded px-2 py-1 text-sm"
          value={filterVerdict()}
          onChange={(e) => setFilterVerdict(e.currentTarget.value)}
        >
          <option value="">All verdicts</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
        </select>
        <span class="text-xs text-gray-400 self-center">{decisions().length} shown</span>
      </div>

      {/* Decision table */}
      <div class="overflow-auto max-h-[calc(100vh-220px)] border rounded">
        <table class="w-full text-xs">
          <thead class="bg-gray-100 sticky top-0">
            <tr>
              <th class="px-2 py-1 text-left">Time</th>
              <th class="px-2 py-1 text-left">Verdict</th>
              <th class="px-2 py-1 text-left">Method</th>
              <th class="px-2 py-1 text-left">Path</th>
              <th class="px-2 py-1 text-left">Subject</th>
              <th class="px-2 py-1 text-left">Instance</th>
              <th class="px-2 py-1 text-left">Latency</th>
              <th class="px-2 py-1 text-left">Reason</th>
            </tr>
          </thead>
          <tbody>
            <For each={decisions()}>
              {(d) => (
                <tr class="border-t hover:bg-gray-50">
                  <td class="px-2 py-1 font-mono whitespace-nowrap">
                    {new Date(d.timestamp).toLocaleTimeString()}
                  </td>
                  <td class="px-2 py-1">
                    <span
                      class={`px-1.5 py-0.5 rounded text-white text-[10px] font-bold ${d.verdict === "allow" ? "bg-green-600" : "bg-red-600"}`}
                    >
                      {d.verdict.toUpperCase()}
                    </span>
                  </td>
                  <td class="px-2 py-1 font-mono">{d.method}</td>
                  <td class="px-2 py-1 font-mono max-w-xs truncate">{d.path}</td>
                  <td class="px-2 py-1 truncate max-w-[120px]">{d.subject}</td>
                  <td class="px-2 py-1 text-gray-600">{d.instance}@{d.cluster}</td>
                  <td class="px-2 py-1">{d.durationMs.toFixed(1)}ms</td>
                  <td class="px-2 py-1 text-gray-500 truncate max-w-[150px]">{d.reason || "—"}</td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
        <Show when={decisions().length === 0}>
          <p class="p-4 text-center text-gray-400 text-sm">Waiting for decisions...</p>
        </Show>
      </div>
    </div>
  );
}
