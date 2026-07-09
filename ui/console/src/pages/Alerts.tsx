import { createSignal, createEffect, onCleanup, Show, For, createMemo } from "solid-js";
import { useNavigate } from "@solidjs/router";
import {
  alertStreamUrl,
  listAlerts,
  ackAlert,
  type Alert,
  type AlertEvent,
  type Severity,
} from "../api/client";
import {
  AlertTriangle,
  ShieldCheck,
  Pause,
  Play,
  Radio,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronRight,
  Activity,
} from "lucide-solid";

const MAX_ALERTS = 200;

export default function Alerts() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = createSignal<Alert[]>([]);
  const [paused, setPaused] = createSignal(false);
  const [filterSeverity, setFilterSeverity] = createSignal("");
  const [filterState, setFilterState] = createSignal("");
  const [filterRule, setFilterRule] = createSignal("");
  const [connected, setConnected] = createSignal(false);
  const [expanded, setExpanded] = createSignal<string | null>(null);
  const [ackedIds, setAckedIds] = createSignal<Set<string>>(new Set());
  const [degraded, setDegraded] = createSignal<{ prometheus: boolean; loki: boolean } | null>(null);

  // Initial fetch populates the historical view so operators arrive on
  // a populated panel rather than waiting for the next broadcast.
  (async () => {
    try {
      const resp = await listAlerts();
      setAlerts(resp.alerts.slice(0, MAX_ALERTS));
      setDegraded(resp.degraded);
    } catch { /* swallow — WS will refresh */ }
  })();

  let buffer: Alert[] = [];

  createEffect(() => {
    const url = alertStreamUrl({
      severity: filterSeverity() || undefined,
      state: filterState() || undefined,
      rule: filterRule() || undefined,
    });

    const ws = new WebSocket(url);
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (e) => {
      try {
        const evt: AlertEvent = JSON.parse(e.data);
        applyEvent(evt);
      } catch { /* ignore malformed */ }
    };

    onCleanup(() => ws.close());
  });

  function applyEvent(evt: AlertEvent) {
    if (paused()) {
      // While paused we still keep a small buffer so Resume lands the
      // missed transitions in chronological order (oldest front).
      buffer.push(evt.alert);
      if (buffer.length > MAX_ALERTS) buffer.shift();
      return;
    }
    setAlerts((prev) => {
      const next = mergeAlert(prev, evt.alert, evt.type);
      return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
    });
  }

  // mergeAlert applies an open/ack/resolve transition in-place or
  // prepends a fresh open alert (the engine may reopen an alert after
  // an ack-cooldown expires — that re-open is encoded by the engine as
  // an `EventOpen` for the same alert ID, so we mutate in-place).
  function mergeAlert(prev: Alert[], incoming: Alert, evt: string): Alert[] {
    const idx = prev.findIndex((a) => a.id === incoming.id);
    if (idx === -1) return [incoming, ...prev];
    const copy = prev.slice();
    copy[idx] = { ...copy[idx], ...incoming };
    // Resolved alerts remain in the list so the operator sees the
    // closure context — they're styled "resolved" via state. The
    // engine's history ring is the durable store; the UI keeps them
    // in-session until displaced.
    if (evt === "resolved") {
      // Keep at end of chronological list — resolved alerts fall to
      // the bottom via the sort below on render rather than here.
    }
    return copy;
  }

  function resume() {
    setPaused(false);
    if (buffer.length > 0) {
      setAlerts((prev) => {
        const merged = [...buffer, ...prev];
        buffer = [];
        return merged.slice(0, MAX_ALERTS);
      });
    }
  }

  async function handleAck(id: string) {
    try {
      await ackAlert(id);
      setAckedIds((prev) => new Set(prev).add(id));
    } catch { /* 404/409 surfaced via empty set — no optimistic mutate */ }
  }

  // Sorted view: open critical → open warning → acked → resolved.
  const sorted = createMemo(() => {
    const order: Record<string, number> = { open: 0, acknowledged: 1, resolved: 2 };
    const sev: Record<string, number> = { critical: 0, warning: 1, info: 2 };
    return alerts().slice().sort((a, b) => {
      if (a.state !== b.state) return order[a.state] - order[b.state];
      if (a.severity !== b.severity) return sev[a.severity] - sev[b.severity];
      return +new Date(b.fired_at) - +new Date(a.fired_at);
    });
  });

  return (
    <div class="max-w-7xl">
      {/* Header */}
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Alerts</h1>
          <p class="text-sm text-gray-500 mt-1">
            Policy-engine & request-health triage — see why requests aren't responding at a glance
          </p>
        </div>
        <div class="flex items-center gap-4">
          <Show when={degraded()}>
            <span
              class={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${
                (degraded()!.prometheus || degraded()!.loki)
                  ? "bg-amber-50 text-amber-700"
                  : "bg-green-50 text-green-700"
              }`}
              title="One or more alert backends are unconfigured — scoped rules no-op silently"
            >
              <Activity size={12} />
              {(degraded()!.prometheus || degraded()!.loki) ? "Degraded" : "Backends OK"}
            </span>
          </Show>
          <span
            class={`flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${
              connected() ? "bg-green-50 text-green-700" : "bg-red-50 text-red-700"
            }`}
          >
            <Radio size={12} class={connected() ? "text-green-500 animate-pulse" : "text-red-500"} />
            {connected() ? "Live" : "Disconnected"}
          </span>
          <button
            class={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg transition-colors ${
              paused()
                ? "bg-green-600 text-white hover:bg-green-700"
                : "bg-amber-500 text-white hover:bg-amber-600"
            }`}
            onClick={() => (paused() ? resume() : setPaused(true))}
          >
            {paused() ? <><Play size={13} /> Resume</> : <><Pause size={13} /> Pause</>}
          </button>
        </div>
      </div>

      {/* Filters bar */}
      <div class="bg-white rounded-xl border border-gray-200 shadow-sm px-4 py-3 mb-4 flex items-center gap-3">
        <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">Filters</span>
        <select
          class="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
          value={filterState()}
          onChange={(e) => setFilterState(e.currentTarget.value)}
        >
          <option value="">All states</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        <select
          class="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
          value={filterSeverity()}
          onChange={(e) => setFilterSeverity(e.currentTarget.value)}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </select>
        <input
          class="border border-gray-200 rounded-lg px-3 py-2 text-sm w-48 focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
          placeholder="Rule name"
          value={filterRule()}
          onInput={(e) => setFilterRule(e.currentTarget.value)}
        />
        <span
          class="ml-auto text-xs text-gray-400 cursor-pointer hover:text-blue-600"
          onClick={() => navigate("/")}
        >
          View dashboard →
        </span>
        <span class="text-xs text-gray-400">{alerts().length} alerts</span>
      </div>

      {/* Alerts list */}
      <div class="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div class="overflow-auto max-h-[calc(100vh-320px)]">
          <Show when={alerts().length > 0} fallback={
            <div class="py-16 text-center">
              <ShieldCheck size={40} class="mx-auto text-gray-300 mb-3" />
              <p class="text-sm font-medium text-gray-600">No active alerts</p>
              <p class="text-xs text-gray-400 mt-1">
                Open alerts will populate here as the policy-engine / request-health rules fire
              </p>
            </div>
          }>
            <ul class="divide-y divide-gray-100">
              <For each={sorted()}>
                {(a) => (
                  <li>
                    <button
                      class="w-full flex items-start gap-4 px-5 py-3.5 hover:bg-gray-50/50 transition-colors text-left"
                      onClick={() => setExpanded(expanded() === a.id ? null : a.id)}
                    >
                      <SeverityIcon severity={a.severity} state={a.state} />
                      <div class="min-w-0 flex-1">
                        <div class="flex items-center gap-2 flex-wrap">
                          <span class="text-sm font-semibold text-gray-900">{a.rule}</span>
                          <span class={`text-[10px] font-medium px-2 py-0.5 rounded-full uppercase tracking-wide ${severityBadge(a.severity)}`}>
                            {a.severity}
                          </span>
                          <span class={`text-[10px] font-medium px-2 py-0.5 rounded-full ${stateBadge(a.state)}`}>
                            {a.state}
                          </span>
                          <span class="text-xs text-gray-400 font-mono ml-auto whitespace-nowrap">
                            {new Date(a.fired_at).toLocaleTimeString()}
                          </span>
                        </div>
                        <div class="flex items-center gap-3 mt-1 text-xs text-gray-500">
                          <Show when={a.metric}>
                            <span class="font-mono">
                              value {a.metric!.value.toFixed(4)} {a.metric!.comparator} {a.metric!.threshold}
                            </span>
                          </Show>
                          <Show when={a.scope["cluster"]}>
                            <span>cluster: <code class="text-gray-700">{a.scope["cluster"]}</code></span>
                          </Show>
                          <For each={Object.entries(a.scope).filter(([k]) => k !== "cluster")}>
                            {([k, v]) => (
                              <span>{k}: <code class="text-gray-700">{v}</code></span>
                            )}
                          </For>
                        </div>
                      </div>
                      <Show when={a.state === "open" || a.state === "acknowledged"}>
                        <button
                          class="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium rounded-md bg-emerald-50 text-emerald-700 hover:bg-emerald-100 transition-colors shrink-0"
                          onClick={(e) => {
                            e.stopPropagation();
                            void handleAck(a.id);
                          }}
                          disabled={a.state === "acknowledged" && ackedIds().has(a.id)}
                        >
                          <CheckCircle2 size={13} />
                          {a.state === "acknowledged" ? "Snoozed" : "Ack"}
                        </button>
                      </Show>
                      {expanded() === a.id ? <ChevronDown size={16} class="text-gray-400 mt-1" /> : <ChevronRight size={16} class="text-gray-400 mt-1" />}
                    </button>

                    {/* ReasonPanel — expanded inline */}
                    <Show when={expanded() === a.id}>
                      <ReasonPanel alert={a} />
                    </Show>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </div>
      </div>
    </div>
  );
}

function SeverityIcon(props: { severity: Severity; state: string }) {
  if (props.state === "resolved") {
    return <CheckCircle2 size={18} class="text-emerald-500 mt-0.5 shrink-0" />;
  }
  if (props.severity === "critical") {
    return <XCircle size={18} class="text-red-500 mt-0.5 shrink-0" />;
  }
  return <AlertTriangle size={18} class="text-amber-500 mt-0.5 shrink-0" />;
}

function severityBadge(s: Severity): string {
  switch (s) {
    case "critical": return "bg-red-100 text-red-700";
    case "warning":  return "bg-amber-100 text-amber-700";
    default:         return "bg-blue-100 text-blue-700";
  }
}

function stateBadge(s: string): string {
  switch (s) {
    case "open":         return "bg-red-50 text-red-600";
    case "acknowledged": return "bg-amber-50 text-amber-700";
    case "resolved":     return "bg-emerald-50 text-emerald-700";
    default:             return "bg-gray-100 text-gray-600";
  }
}

function ReasonPanel(props: { alert: Alert }) {
  const r = () => props.alert.reason;
  return (
    <div class="bg-gray-50/60 border-t border-gray-100 px-5 py-4 text-sm">
      <Show when={r()} fallback={
        <p class="text-xs text-gray-500">
          Reason analysis unavailable — the alert fired before the recent-decisions ring populated.
        </p>
      }>
        <p class="text-sm text-gray-800 leading-relaxed font-medium mb-3">{r()!.headline}</p>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Top contributors */}
          <Show when={r()!.top_contributors && r()!.top_contributors!.length > 0}>
            <div>
              <p class="text-[10px] font-semibold uppercase tracking-wider text-gray-500 mb-2">
                Top contributors
              </p>
              <ul class="space-y-1">
                <For each={r()!.top_contributors!.slice(0, 3)}>
                  {(c) => (
                    <li class="flex items-center gap-2 text-xs text-gray-700">
                      <span class="text-[10px] uppercase tracking-wide text-gray-400 w-24 shrink-0">{c.dimension}</span>
                      <code class="text-gray-800 truncate">{c.value}</code>
                      <Show when={c.share !== undefined}>
                        <span class="ml-auto text-gray-400 font-mono">{(c.share! * 100).toFixed(0)}%</span>
                      </Show>
                    </li>
                  )}
                </For>
              </ul>
            </div>
          </Show>

          {/* Correlated alerts */}
          <Show when={r()!.correlated && r()!.correlated!.length > 0}>
            <div>
              <p class="text-[10px] font-semibold uppercase tracking-wider text-gray-500 mb-2">
                Correlated alerts
              </p>
              <ul class="space-y-1">
                <For each={r()!.correlated}>
                  {(c) => (
                    <li class="flex items-center gap-2 text-xs text-gray-700">
                      <AlertTriangle size={11} class="text-amber-500" />
                      <code class="text-gray-800">{c.rule}</code>
                      <Show when={c.value}>
                        <span class="text-gray-400 font-mono">{c.value}</span>
                      </Show>
                      <Show when={c.note}>
                        <span class="ml-auto text-[10px] text-amber-600 italic">{c.note}</span>
                      </Show>
                    </li>
                  )}
                </For>
              </ul>
            </div>
          </Show>
        </div>

        {/* Recent failures — metadata only, subject_hash already HMAC-hashed by data plane */}
        <Show when={r()!.recent_failures && r()!.recent_failures!.length > 0}>
          <div class="mt-4">
            <p class="text-[10px] font-semibold uppercase tracking-wider text-gray-500 mb-2">
              Recent failures (≤5 — subjects redacted to HMAC hash)
            </p>
            <div class="overflow-x-auto">
              <table class="w-full text-xs">
                <thead>
                  <tr class="text-left text-[10px] font-medium uppercase tracking-wide text-gray-400 border-b border-gray-200">
                    <th class="py-1.5 pr-3 font-medium">Time</th>
                    <th class="py-1.5 pr-3 font-medium">Method</th>
                    <th class="py-1.5 pr-3 font-medium">Path</th>
                    <th class="py-1.5 pr-3 font-medium">Subject (hash)</th>
                    <th class="py-1.5 pr-3 font-medium">Tenant</th>
                    <th class="py-1.5 font-medium">Reason</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-100">
                  <For each={r()!.recent_failures}>
                    {(f) => (
                      <tr>
                        <td class="py-1.5 pr-3 font-mono text-gray-500 whitespace-nowrap">
                          {new Date(f.timestamp).toLocaleTimeString()}
                        </td>
                        <td class="py-1.5 pr-3 font-mono text-gray-700">{f.method ?? "—"}</td>
                        <td class="py-1.5 pr-3 font-mono text-gray-600 truncate max-w-[200px]">{f.path ?? "—"}</td>
                        <td class="py-1.5 pr-3 font-mono text-gray-500 truncate max-w-[160px]" title={f.subject_hash}>
                          {f.subject_hash ?? "—"}
                        </td>
                        <td class="py-1.5 pr-3 text-gray-600">{f.tenant ?? "—"}</td>
                        <td class="py-1.5 text-gray-500 truncate max-w-[200px]">{f.reason ?? "—"}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </div>
        </Show>
      </Show>
    </div>
  );
}