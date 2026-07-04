import { createSignal, createEffect, onCleanup, For, Show } from "solid-js";
import { decisionStreamUrl, type Decision } from "../api/client";
import { ShieldCheck, Pause, Play, Radio } from "lucide-solid";

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
    <div class="max-w-7xl">
      {/* Header */}
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Decisions</h1>
          <p class="text-sm text-gray-500 mt-1">Real-time authorization decision stream</p>
        </div>
        <div class="flex items-center gap-4">
          {/* Connection indicator */}
          <div class="flex items-center gap-2">
            <span class={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${
              connected()
                ? "bg-green-50 text-green-700"
                : "bg-red-50 text-red-700"
            }`}>
              <Radio size={12} class={connected() ? "text-green-500 animate-pulse" : "text-red-500"} />
              {connected() ? "Live" : "Disconnected"}
            </span>
          </div>
          {/* Pause/Resume */}
          <button
            class={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg transition-colors ${
              paused()
                ? "bg-green-600 text-white hover:bg-green-700"
                : "bg-amber-500 text-white hover:bg-amber-600"
            }`}
            onClick={() => paused() ? resume() : setPaused(true)}
          >
            {paused() ? <><Play size={13} /> Resume</> : <><Pause size={13} /> Pause</>}
          </button>
        </div>
      </div>

      {/* Filters bar */}
      <div class="bg-white rounded-xl border border-gray-200 shadow-sm px-4 py-3 mb-4 flex items-center gap-3">
        <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">Filters</span>
        <input
          class="border border-gray-200 rounded-lg px-3 py-2 text-sm w-36 focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
          placeholder="Cluster"
          value={filterCluster()}
          onInput={(e) => setFilterCluster(e.currentTarget.value)}
        />
        <input
          class="border border-gray-200 rounded-lg px-3 py-2 text-sm w-36 focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
          placeholder="Tenant"
          value={filterTenant()}
          onInput={(e) => setFilterTenant(e.currentTarget.value)}
        />
        <select
          class="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
          value={filterVerdict()}
          onChange={(e) => setFilterVerdict(e.currentTarget.value)}
        >
          <option value="">All verdicts</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
        </select>
        <span class="ml-auto text-xs text-gray-400">{decisions().length} events</span>
      </div>

      {/* Decision table */}
      <div class="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div class="overflow-auto max-h-[calc(100vh-320px)]">
          <table class="w-full text-xs">
            <thead class="bg-gray-50/80 sticky top-0 z-10">
              <tr class="text-left text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                <th class="px-4 py-3">Time</th>
                <th class="px-4 py-3">Verdict</th>
                <th class="px-4 py-3">Method</th>
                <th class="px-4 py-3">Path</th>
                <th class="px-4 py-3">Subject</th>
                <th class="px-4 py-3">Instance</th>
                <th class="px-4 py-3">Latency</th>
                <th class="px-4 py-3">Reason</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-50">
              <For each={decisions()}>
                {(d) => (
                  <tr class="hover:bg-gray-50/50 transition-colors">
                    <td class="px-4 py-2.5 font-mono text-gray-600 whitespace-nowrap">
                      {new Date(d.timestamp).toLocaleTimeString()}
                    </td>
                    <td class="px-4 py-2.5">
                      <span
                        class={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                          d.verdict === "allow"
                            ? "bg-green-50 text-green-700"
                            : "bg-red-50 text-red-700"
                        }`}
                      >
                        <span class={`w-1.5 h-1.5 rounded-full ${d.verdict === "allow" ? "bg-green-500" : "bg-red-500"}`} />
                        {d.verdict.toUpperCase()}
                      </span>
                    </td>
                    <td class="px-4 py-2.5 font-mono text-gray-700">{d.method}</td>
                    <td class="px-4 py-2.5 font-mono text-gray-600 max-w-xs truncate">{d.path}</td>
                    <td class="px-4 py-2.5 text-gray-600 truncate max-w-[120px]">{d.subject}</td>
                    <td class="px-4 py-2.5 text-gray-500">{d.instance}<span class="text-gray-300">@</span>{d.cluster}</td>
                    <td class="px-4 py-2.5 text-gray-600 font-mono">{d.durationMs.toFixed(1)}<span class="text-gray-400">ms</span></td>
                    <td class="px-4 py-2.5 text-gray-500 truncate max-w-[150px]">{d.reason || "—"}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
          <Show when={decisions().length === 0}>
            <div class="py-16 text-center">
              <ShieldCheck size={40} class="mx-auto text-gray-300 mb-3" />
              <p class="text-sm font-medium text-gray-600">Waiting for decisions…</p>
              <p class="text-xs text-gray-400 mt-1">Decisions will appear here as they stream in</p>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
}
