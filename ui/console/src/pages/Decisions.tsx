import { createSignal, createEffect, onCleanup, For, Show } from "solid-js";
import { decisionStreamUrl, type Decision } from "../api/client";
import { ShieldCheck, Pause, Play } from "lucide-solid";
import { WSDisconnectBanner, EmptyState } from "../components/ui";
import { GlowDot } from "../components/GlowDot";
import { Reveal } from "../components/Reveal";

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
      <WSDisconnectBanner show={!connected() && decisions().length === 0} />
      {/* Header */}
      <div class="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div>
          <h1 class="font-display text-2xl font-bold text-gray-900 dark:text-gray-100">Decisions</h1>
          <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Real-time authorization decision stream</p>
        </div>
        <div class="flex items-center gap-4">
          {/* Connection indicator */}
          <GlowDot tone={connected() ? "live" : "critical"} pulse={connected()} label={connected() ? "Live" : "Disconnected"} />
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
      <Reveal>
      <div class="bg-white dark:bg-white/[0.02] rounded-2xl border border-gray-200 dark:border-white/[0.08] shadow-sm dark:shadow-none px-4 py-3 mb-4 flex flex-wrap items-center gap-3">
        <span class="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide">Filters</span>
        <input
          class="border border-gray-200 dark:border-white/[0.12] bg-white dark:bg-white/[0.04] text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2 text-sm w-36 focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 outline-none transition-all"
          placeholder="Cluster"
          value={filterCluster()}
          onInput={(e) => setFilterCluster(e.currentTarget.value)}
        />
        <input
          class="border border-gray-200 dark:border-white/[0.12] bg-white dark:bg-white/[0.04] text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2 text-sm w-36 focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 outline-none transition-all"
          placeholder="Tenant"
          value={filterTenant()}
          onInput={(e) => setFilterTenant(e.currentTarget.value)}
        />
        <select
          class="border border-gray-200 dark:border-white/[0.12] bg-white dark:bg-white/[0.04] text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 outline-none transition-all"
          value={filterVerdict()}
          onChange={(e) => setFilterVerdict(e.currentTarget.value)}
        >
          <option value="">All verdicts</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
        </select>
        <span class="ml-auto text-xs text-gray-400 dark:text-gray-500">{decisions().length} events</span>
      </div>

      {/* Decision table */}
      <div class="bg-white dark:bg-white/[0.02] rounded-2xl border border-gray-200 dark:border-white/[0.08] shadow-sm dark:shadow-none overflow-hidden">
        <div class="overflow-auto max-h-[calc(100vh-320px)]">
          <table class="w-full text-xs">
            <thead class="bg-gray-50/80 dark:bg-white/[0.03] sticky top-0 z-10">
              <tr class="text-left text-[11px] font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
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
            <tbody class="divide-y divide-gray-50 dark:divide-white/[0.06]">
              <For each={decisions()}>
                {(d) => (
                  <tr class="hover:bg-gray-50/50 dark:hover:bg-white/[0.03] transition-colors">
                    <td class="px-4 py-2.5 font-mono text-gray-600 dark:text-gray-400 whitespace-nowrap">
                      {new Date(d.timestamp).toLocaleTimeString()}
                    </td>
                    <td class="px-4 py-2.5">
                      <span
                        class={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                          d.verdict === "allow"
                            ? "bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400"
                            : "bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400"
                        }`}
                      >
                        <span class={`w-1.5 h-1.5 rounded-full ${d.verdict === "allow" ? "bg-green-500" : "bg-red-500"}`} />
                        {d.verdict.toUpperCase()}
                      </span>
                    </td>
                    <td class="px-4 py-2.5 font-mono text-gray-700 dark:text-gray-300">{d.method}</td>
                    <td class="px-4 py-2.5 font-mono text-gray-600 dark:text-gray-400 max-w-xs truncate">{d.path}</td>
                    <td class="px-4 py-2.5 text-gray-600 dark:text-gray-400 truncate max-w-[120px]">{d.subject}</td>
                    <td class="px-4 py-2.5 text-gray-500 dark:text-gray-400">{d.instance}<span class="text-gray-300 dark:text-gray-700">@</span>{d.cluster}</td>
                    <td class="px-4 py-2.5 text-gray-600 dark:text-gray-400 font-mono">{d.durationMs.toFixed(1)}<span class="text-gray-400 dark:text-gray-500">ms</span></td>
                    <td class="px-4 py-2.5 text-gray-500 dark:text-gray-400 truncate max-w-[150px]">{d.reason || "—"}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
<Show when={decisions().length === 0}>
            <EmptyState
              icon={ShieldCheck}
              title="Waiting for decisions…"
              description="Decisions will appear here as they stream in"
            />
          </Show>
        </div>
      </div>
      </Reveal>
    </div>
  );
}
