import { createSignal, createEffect, onCleanup, Show, createMemo } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { A, useNavigate } from "@solidjs/router";
import {
  getHealth,
  listInstances,
  metricsStreamUrl,
  alertStreamUrl,
  type MetricsSnapshot,
  type Alert,
  type AlertEvent,
} from "../api/client";
import { pickTopCritical } from "../lib/alerts-merge";
import {
  Server,
  HeartPulse,
  AlertTriangle,
  Gauge,
  ShieldOff,
  Database,
  Zap,
  XCircle,
  ArrowRight,
} from "lucide-solid";

export default function Dashboard() {
  const navigate = useNavigate();
  const health = createQuery(() => ({
    queryKey: ["health"],
    queryFn: () => getHealth(),
    refetchInterval: 15_000,
  }));

  const instances = createQuery(() => ({
    queryKey: ["instances"],
    queryFn: () => listInstances(),
    refetchInterval: 15_000,
  }));

  // Real-time metrics via WebSocket.
  const [metrics, setMetrics] = createSignal<MetricsSnapshot | null>(null);

  createEffect(() => {
    const ws = new WebSocket(metricsStreamUrl());
    ws.onmessage = (e) => {
      try {
        setMetrics(JSON.parse(e.data));
      } catch { /* ignore parse errors */ }
    };
    onCleanup(() => ws.close());
  });

  // Request-Health banner — listens to the alert stream and surfaces
  // the single top critical open alert so the operator sees "why
  // requests aren't responding" before navigating to /alerts.
  const [topAlert, setTopAlert] = createSignal<Alert | null>(null);

  createEffect(() => {
    const ws = new WebSocket(alertStreamUrl({ severity: "critical" }));
    ws.onmessage = (e) => {
      try {
        const evt: AlertEvent = JSON.parse(e.data);
        if (evt.alert.severity !== "critical") return;
        if (evt.type === "open") {
          setTopAlert((prev) => pickTopCritical(prev, evt.alert));
        } else if (evt.type === "resolved") {
          setTopAlert((prev) => (prev?.id === evt.alert.id ? null : prev));
        } else if (evt.type === "acked") {
          // An acked critical alert stays surfaced — the banner reads
          // "acked by alice · investigating" so the operator at the
          // Dashboard knows someone is on it.
          setTopAlert((prev) => (prev?.id === evt.alert.id ? evt.alert : prev));
        }
      } catch { /* ignore */ }
    };
    onCleanup(() => ws.close());
  });

  const unhealthy = () =>
    health.data ? health.data.totalInstances - health.data.healthyInstances : 0;

  return (
    <div class="max-w-7xl">
      {/* Page header */}
      <div class="mb-8">
        <h1 class="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p class="text-sm text-gray-500 mt-1">Real-time overview of your LightweightAuth deployment</p>
      </div>

      {/* Request-Health banner — surfaces top critical open alert. */}
      <Show when={topAlert() && topAlert()!.state !== "resolved"}>
        <button
          class="group w-full mb-6 flex items-center gap-3 bg-red-50 border border-red-200 rounded-xl px-5 py-3.5 text-left hover:bg-red-100/70 transition-colors"
          onClick={() => navigate("/alerts")}
          title="Open the Alerts panel for the full triage reason"
        >
          <XCircle size={20} class="text-red-500 shrink-0" />
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-sm font-semibold text-red-700 uppercase tracking-wide">
                Request Health
              </span>
              <span class="text-xs text-red-500 font-mono">{topAlert()!.rule}</span>
            </div>
            <p class="text-sm text-red-800 mt-0.5 truncate">
              {topAlert()!.reason?.headline ?? `${topAlert()!.rule} firing in ${topAlert()!.scope["cluster"] ?? "cluster"}`}
            </p>
          </div>
          <Show when={topAlert()!.state === "acknowledged"}>
            <span class="text-xs text-amber-700 bg-amber-100 px-2 py-0.5 rounded-full shrink-0">
              acked by {topAlert()!.acked_by ?? "operator"}
            </span>
          </Show>
          <ArrowRight size={16} class="text-red-400 group-hover:text-red-600 transition-colors shrink-0" />
        </button>
      </Show>

      {/* Primary KPI row */}
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          icon={Server}
          label="Total Instances"
          value={health.data?.totalInstances ?? "—"}
          accent="blue"
        />
        <StatCard
          icon={HeartPulse}
          label="Healthy"
          value={health.data?.healthyInstances ?? "—"}
          accent="green"
        />
        <StatCard
          icon={AlertTriangle}
          label="Unhealthy"
          value={unhealthy() || "0"}
          accent={unhealthy() > 0 ? "red" : "gray"}
        />
        <StatCard
          icon={Gauge}
          label="Decision Rate"
          value={metrics() ? `${metrics()!.global.totalDecisionRate.toFixed(1)}/s` : "—"}
          accent="indigo"
        />
      </div>

      {/* Secondary metrics row */}
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
        <StatCard
          icon={ShieldOff}
          label="Deny Rate"
          value={metrics() ? `${metrics()!.global.totalDenyRate.toFixed(1)}/s` : "—"}
          accent="orange"
        />
        <StatCard
          icon={Database}
          label="Cache Hit Ratio"
          value={metrics() ? `${(metrics()!.global.avgCacheHitRatio * 100).toFixed(0)}%` : "—"}
          accent="purple"
        />
        <StatCard
          icon={Zap}
          label="Error Rate"
          value={metrics() ? `${metrics()!.global.totalErrorRate.toFixed(2)}/s` : "—"}
          accent="red"
        />
      </div>

      {/* Instance table */}
      <div class="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div class="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 class="text-sm font-semibold text-gray-900">Instance Overview</h2>
          <A href="/instances" class="text-xs text-blue-600 hover:text-blue-700 font-medium">
            View all →
          </A>
        </div>

        {instances.isLoading && (
          <div class="px-5 py-8 text-center text-sm text-gray-400">Loading instances…</div>
        )}
        {instances.isError && (
          <div class="px-5 py-8 text-center text-sm text-red-500">
            Failed to load: {(instances.error as Error).message}
          </div>
        )}
        {instances.data && instances.data.length === 0 && (
          <div class="px-5 py-8 text-center text-sm text-gray-400">
            No instances discovered. Deploy one to get started.
          </div>
        )}
        {instances.data && instances.data.length > 0 && (
          <table class="w-full text-sm">
            <thead>
              <tr class="bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <th class="px-5 py-3">Instance</th>
                <th class="px-5 py-3">Cluster</th>
                <th class="px-5 py-3">Status</th>
                <th class="px-5 py-3">Source</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
              {instances.data.map((inst) => (
                <tr class="hover:bg-gray-50/50 transition-colors">
                  <td class="px-5 py-3">
                    <A
                      href={`/instances/${inst.cluster}/${inst.name}`}
                      class="text-sm font-medium text-gray-900 hover:text-blue-600"
                    >
                      {inst.name}
                    </A>
                  </td>
                  <td class="px-5 py-3 text-gray-600">{inst.cluster}</td>
                  <td class="px-5 py-3">
                    <StatusPill healthy={inst.status.healthy} />
                  </td>
                  <td class="px-5 py-3">
                    <span class="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded-full">
                      {inst.source}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

const accentStyles: Record<string, { bg: string; icon: string; text: string }> = {
  blue:   { bg: "bg-blue-50", icon: "text-blue-600", text: "text-blue-700" },
  green:  { bg: "bg-green-50", icon: "text-green-600", text: "text-green-700" },
  red:    { bg: "bg-red-50", icon: "text-red-600", text: "text-red-700" },
  orange: { bg: "bg-orange-50", icon: "text-orange-600", text: "text-orange-700" },
  purple: { bg: "bg-purple-50", icon: "text-purple-600", text: "text-purple-700" },
  indigo: { bg: "bg-indigo-50", icon: "text-indigo-600", text: "text-indigo-700" },
  gray:   { bg: "bg-gray-50", icon: "text-gray-400", text: "text-gray-600" },
};

function StatCard(props: {
  icon: (p: any) => any;
  label: string;
  value: number | string;
  accent: string;
}) {
  const s = () => accentStyles[props.accent] ?? accentStyles.gray;

  return (
    <div class="bg-white rounded-xl border border-gray-200 shadow-sm p-5 flex items-start gap-4">
      <div class={`w-10 h-10 rounded-lg ${s().bg} flex items-center justify-center shrink-0`}>
        <props.icon size={20} class={s().icon} />
      </div>
      <div class="min-w-0">
        <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">{props.label}</p>
        <p class={`text-2xl font-bold mt-0.5 ${s().text}`}>{props.value}</p>
      </div>
    </div>
  );
}

function StatusPill(props: { healthy: boolean }) {
  return (
    <span
      class={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${
        props.healthy
          ? "bg-green-50 text-green-700"
          : "bg-red-50 text-red-700"
      }`}
    >
      <span
        class={`w-1.5 h-1.5 rounded-full ${
          props.healthy ? "bg-green-500" : "bg-red-500"
        }`}
      />
      {props.healthy ? "Healthy" : "Unhealthy"}
    </span>
  );
}
