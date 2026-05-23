import { createSignal, createEffect, onCleanup, Show } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { useParams, A } from "@solidjs/router";
import { getInstance, getInstanceMetrics, metricsStreamUrl, type InstanceMetrics, type MetricsSnapshot } from "../api/client";

export default function InstanceDetail() {
  const params = useParams<{ cluster: string; name: string }>();

  const instance = createQuery(() => ({
    queryKey: ["instance", params.cluster, params.name],
    queryFn: () => getInstance(params.cluster, params.name),
    refetchInterval: 10_000,
  }));

  // Sparkline history from WebSocket.
  const [history, setHistory] = createSignal<InstanceMetrics[]>([]);

  createEffect(() => {
    const ws = new WebSocket(metricsStreamUrl());
    ws.onmessage = (e) => {
      try {
        const snap: MetricsSnapshot = JSON.parse(e.data);
        const m = snap.instances.find(
          (i) => i.instance === params.name && i.cluster === params.cluster,
        );
        if (m) {
          setHistory((prev) => {
            const next = [...prev, m];
            return next.length > 60 ? next.slice(-60) : next; // ~2min at 2s intervals
          });
        }
      } catch { /* ignore */ }
    };
    onCleanup(() => ws.close());
  });

  return (
    <div>
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-semibold">
          Instance: <span class="font-mono">{params.name}</span>
        </h2>
        <A
          href={`/instances/${params.cluster}/${params.name}/config`}
          class="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700"
        >
          Edit Config
        </A>
      </div>

      {instance.isLoading && <p class="text-gray-500">Loading…</p>}
      {instance.isError && (
        <p class="text-red-600">Error: {(instance.error as Error).message}</p>
      )}
      {instance.data && (
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Info panel */}
          <div class="bg-white border border-gray-200 rounded-lg p-4">
            <h3 class="font-medium text-gray-700 mb-3">Instance Info</h3>
            <dl class="grid grid-cols-2 gap-y-2 text-sm">
              <dt class="text-gray-500">Name</dt>
              <dd class="font-mono">{instance.data.name}</dd>
              <dt class="text-gray-500">Cluster</dt>
              <dd>{instance.data.cluster}</dd>
              <dt class="text-gray-500">Namespace</dt>
              <dd>{instance.data.namespace ?? "—"}</dd>
              <dt class="text-gray-500">Admin URL</dt>
              <dd class="font-mono text-xs break-all">{instance.data.adminUrl}</dd>
              <dt class="text-gray-500">Source</dt>
              <dd>{instance.data.source}</dd>
              <dt class="text-gray-500">Last Seen</dt>
              <dd>{new Date(instance.data.lastSeen).toLocaleString()}</dd>
            </dl>
          </div>

          {/* Status panel */}
          <div class="bg-white border border-gray-200 rounded-lg p-4">
            <h3 class="font-medium text-gray-700 mb-3">Health Status</h3>
            <dl class="grid grid-cols-2 gap-y-2 text-sm">
              <dt class="text-gray-500">Healthy</dt>
              <dd>
                <span
                  class={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                    instance.data.status.healthy
                      ? "bg-green-100 text-green-800"
                      : "bg-red-100 text-red-800"
                  }`}
                >
                  {instance.data.status.healthy ? "Yes" : "No"}
                </span>
              </dd>
              <dt class="text-gray-500">Ready</dt>
              <dd>{instance.data.status.ready ? "Yes" : "No"}</dd>
              <dt class="text-gray-500">Config Version</dt>
              <dd class="font-mono text-xs">
                {instance.data.status.configVersion ?? "—"}
              </dd>
              <dt class="text-gray-500">Replicas</dt>
              <dd>{instance.data.status.replicas ?? "—"}</dd>
              <dt class="text-gray-500">Last Check</dt>
              <dd>
                {instance.data.status.lastCheck
                  ? new Date(instance.data.status.lastCheck).toLocaleString()
                  : "—"}
              </dd>
              {instance.data.status.error && (
                <>
                  <dt class="text-gray-500">Error</dt>
                  <dd class="text-red-600">{instance.data.status.error}</dd>
                </>
              )}
            </dl>
          </div>
        </div>
      )}

      {/* Metrics sparklines (Phase 4) */}
      <Show when={history().length > 1}>
        <div class="mt-6">
          <h3 class="text-lg font-medium mb-3">Live Metrics</h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <SparklineCard
              label="Decision Rate"
              unit="/s"
              data={history().map((m) => m.decisionRate)}
            />
            <SparklineCard
              label="Latency P50"
              unit="ms"
              data={history().map((m) => m.latencyP50Ms)}
            />
            <SparklineCard
              label="Latency P99"
              unit="ms"
              data={history().map((m) => m.latencyP99Ms)}
            />
            <SparklineCard
              label="Cache Hit Ratio"
              unit="%"
              data={history().map((m) => m.cacheHitRatio * 100)}
            />
          </div>
        </div>
      </Show>
    </div>
  );
}

function SparklineCard(props: { label: string; unit: string; data: number[] }) {
  const current = () => props.data[props.data.length - 1] ?? 0;
  const svgPath = () => {
    const d = props.data;
    if (d.length < 2) return "";
    const max = Math.max(...d, 1);
    const w = 120;
    const h = 30;
    return d
      .map((v, i) => {
        const x = (i / (d.length - 1)) * w;
        const y = h - (v / max) * h;
        return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(" ");
  };

  return (
    <div class="bg-white border border-gray-200 rounded-lg p-3">
      <div class="flex justify-between items-baseline mb-1">
        <span class="text-xs text-gray-500">{props.label}</span>
        <span class="text-sm font-bold">{current().toFixed(1)}{props.unit}</span>
      </div>
      <svg viewBox="0 0 120 30" class="w-full h-8" preserveAspectRatio="none">
        <path d={svgPath()} fill="none" stroke="#3b82f6" stroke-width="1.5" />
      </svg>
    </div>
  );
}
