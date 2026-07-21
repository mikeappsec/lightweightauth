import { createSignal, createEffect, onCleanup, Show, For } from "solid-js";
import { createStore, produce } from "solid-js/store";
import { createQuery, createMutation } from "@tanstack/solid-query";
import { useParams, A } from "@solidjs/router";
import {
  getInstance,
  getInstanceMetrics,
  getEndpoints,
  quickTest,
  metricsStreamUrl,
  type InstanceMetrics,
  type MetricsSnapshot,
  type QuickTestRequest,
  type QuickTestResponse,
} from "../api/client";
import { Copy, Send, Globe, Server as ServerIcon, Shield, ChevronDown, ChevronUp, ExternalLink } from "lucide-solid";
import { Reveal } from "../components/Reveal";

export default function InstanceDetail() {
  const params = useParams<{ cluster: string; name: string }>();

  const instance = createQuery(() => ({
    queryKey: ["instance", params.cluster, params.name],
    queryFn: () => getInstance(params.cluster, params.name),
    refetchInterval: 10_000,
  }));

  // Sparkline history from WebSocket.
  const [history, setHistory] = createSignal<InstanceMetrics[]>([]);
  const [updateTick, setUpdateTick] = createSignal(0);

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
          setUpdateTick((t) => t + 1);
        }
      } catch { /* ignore */ }
    };
    onCleanup(() => ws.close());
  });

  return (
    <div>
      <div class="flex items-center justify-between mb-6">
        <h2 class="font-display text-2xl font-semibold text-gray-900 dark:text-gray-100">
          Instance: <span class="font-mono">{params.name}</span>
        </h2>
        <A
          href={`/instances/${params.cluster}/${params.name}/config`}
          class="px-4 py-2 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm rounded-lg shadow-[0_0_20px_-6px_rgba(99,102,241,0.5)] transition-all"
        >
          Edit Config
        </A>
      </div>

      {instance.isLoading && <p class="text-gray-500 dark:text-gray-400">Loading…</p>}
      {instance.isError && (
        <p class="text-red-600 dark:text-red-400">Error: {(instance.error as Error).message}</p>
      )}
      {instance.data && (
        <Reveal>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Info panel */}
          <div class="bg-white dark:bg-white/[0.02] border border-gray-200 dark:border-white/[0.08] rounded-2xl p-4">
            <h3 class="font-medium text-gray-700 dark:text-gray-300 mb-3">Instance Info</h3>
            <dl class="grid grid-cols-2 gap-y-2 text-sm">
              <dt class="text-gray-500 dark:text-gray-400">Name</dt>
              <dd class="font-mono text-gray-900 dark:text-gray-100">{instance.data.name}</dd>
              <dt class="text-gray-500 dark:text-gray-400">Cluster</dt>
              <dd class="text-gray-900 dark:text-gray-100">{instance.data.cluster}</dd>
              <dt class="text-gray-500 dark:text-gray-400">Namespace</dt>
              <dd class="text-gray-900 dark:text-gray-100">{instance.data.namespace ?? "—"}</dd>
              <dt class="text-gray-500 dark:text-gray-400">Admin URL</dt>
              <dd class="font-mono text-xs break-all text-gray-900 dark:text-gray-100">{instance.data.adminUrl}</dd>
              <dt class="text-gray-500 dark:text-gray-400">Source</dt>
              <dd class="text-gray-900 dark:text-gray-100">{instance.data.source}</dd>
              <dt class="text-gray-500 dark:text-gray-400">Last Seen</dt>
              <dd class="text-gray-900 dark:text-gray-100">{new Date(instance.data.lastSeen).toLocaleString()}</dd>
            </dl>
          </div>

          {/* Status panel */}
          <div class="bg-white dark:bg-white/[0.02] border border-gray-200 dark:border-white/[0.08] rounded-2xl p-4">
            <h3 class="font-medium text-gray-700 dark:text-gray-300 mb-3">Health Status</h3>
            <dl class="grid grid-cols-2 gap-y-2 text-sm">
              <dt class="text-gray-500 dark:text-gray-400">Healthy</dt>
              <dd>
                <span
                  class={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                    instance.data.status.healthy
                      ? "bg-green-100 dark:bg-green-500/15 text-green-800 dark:text-green-400"
                      : "bg-red-100 dark:bg-red-500/15 text-red-800 dark:text-red-400"
                  }`}
                >
                  {instance.data.status.healthy ? "Yes" : "No"}
                </span>
              </dd>
              <dt class="text-gray-500 dark:text-gray-400">Ready</dt>
              <dd class="text-gray-900 dark:text-gray-100">{instance.data.status.ready ? "Yes" : "No"}</dd>
              <dt class="text-gray-500 dark:text-gray-400">Config Version</dt>
              <dd class="font-mono text-xs text-gray-900 dark:text-gray-100">
                {instance.data.status.configVersion ?? "—"}
              </dd>
              <dt class="text-gray-500 dark:text-gray-400">Replicas</dt>
              <dd class="text-gray-900 dark:text-gray-100">{instance.data.status.replicas ?? "—"}</dd>
              <dt class="text-gray-500 dark:text-gray-400">Last Check</dt>
              <dd class="text-gray-900 dark:text-gray-100">
                {instance.data.status.lastCheck
                  ? new Date(instance.data.status.lastCheck).toLocaleString()
                  : "—"}
              </dd>
              {instance.data.status.error && (
                <>
                  <dt class="text-gray-500 dark:text-gray-400">Error</dt>
                  <dd class="text-red-600 dark:text-red-400">{instance.data.status.error}</dd>
                </>
              )}
            </dl>
          </div>
        </div>
        </Reveal>
      )}

      {/* Metrics sparklines (Phase 4) */}
      <Show when={history().length > 1}>
        <div class="mt-6">
          <h3 class="text-lg font-medium mb-3 text-gray-900 dark:text-gray-100">Live Metrics</h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <SparklineCard
              label="Decision Rate"
              unit="/s"
              data={history().map((m) => m.decisionRate)}
              updateTick={updateTick()}
            />
            <SparklineCard
              label="Latency P50"
              unit="ms"
              data={history().map((m) => m.latencyP50Ms)}
              updateTick={updateTick()}
            />
            <SparklineCard
              label="Latency P99"
              unit="ms"
              data={history().map((m) => m.latencyP99Ms)}
              updateTick={updateTick()}
            />
            <SparklineCard
              label="Cache Hit Ratio"
              unit="%"
              data={history().map((m) => m.cacheHitRatio * 100)}
              updateTick={updateTick()}
            />
          </div>
        </div>
      </Show>

      {/* Endpoints panel (Phase B) */}
      <Show when={instance.data}>
        <EndpointsPanel cluster={params.cluster} name={params.name} />
      </Show>

      {/* Quick Test panel (Phase B) */}
      <Show when={instance.data}>
        <QuickTestPanel cluster={params.cluster} name={params.name} />
      </Show>
    </div>
  );
}

function EndpointsPanel(props: { cluster: string; name: string }) {
  const endpoints = createQuery(() => ({
    queryKey: ["endpoints", props.cluster, props.name],
    queryFn: () => getEndpoints(props.cluster, props.name),
    refetchInterval: 30_000,
  }));

  const [showEnvoy, setShowEnvoy] = createSignal(false);

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div class="mt-6">
      <h3 class="text-lg font-medium mb-3 flex items-center gap-2 text-gray-900 dark:text-gray-100">
        <Globe size={18} class="text-indigo-600 dark:text-indigo-400" />
        Endpoints
      </h3>

      <Show when={endpoints.isLoading}>
        <p class="text-sm text-gray-400 dark:text-gray-500">Loading endpoints…</p>
      </Show>

      <Show when={endpoints.data}>
        <Reveal>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* CP Proxy — primary external access path */}
          {(() => {
            const proxyBase = () => `${window.location.origin}${endpoints.data!.proxyPath}`;
            const authorizeUrl = () => `${proxyBase()}/v1/authorize`;
            return (
              <div class="lg:col-span-2 glass-panel bg-gradient-to-r from-indigo-50 to-violet-50 dark:from-indigo-500/10 dark:to-violet-500/10 border border-indigo-200 dark:border-indigo-500/30 rounded-2xl p-4">
                <div class="flex items-start justify-between mb-3">
                  <div>
                    <h4 class="text-sm font-semibold text-indigo-900 dark:text-indigo-300 flex items-center gap-1.5">
                      <ExternalLink size={14} class="text-indigo-600 dark:text-indigo-400" />
                      CP Proxy (recommended external endpoint)
                    </h4>
                    <p class="text-[11px] text-indigo-700 dark:text-indigo-400 mt-0.5">
                      This node is only reachable externally through the control plane proxy. The node's Service is cluster-internal only.
                    </p>
                  </div>
                  <button
                    onClick={() => copyText(proxyBase())}
                    class="shrink-0 p-1 hover:bg-indigo-100 dark:hover:bg-indigo-500/20 rounded text-indigo-500 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300"
                    title="Copy base URL"
                  >
                    <Copy size={14} />
                  </button>
                </div>
                <dl class="text-xs space-y-2">
                  <div>
                    <dt class="text-indigo-600 dark:text-indigo-400 font-medium">Base URL</dt>
                    <dd class="font-mono text-indigo-900 dark:text-indigo-200 break-all mt-0.5 bg-white/60 dark:bg-gray-900/40 px-2 py-1 rounded">
                      {proxyBase()}
                    </dd>
                  </div>
                </dl>
                <div class="mt-3 p-2.5 bg-white/70 dark:bg-gray-900/40 rounded-lg border border-indigo-100 dark:border-indigo-500/20">
                  <p class="text-[10px] text-indigo-600 dark:text-indigo-400 font-medium mb-1.5">Authorization request:</p>
                  <code class="text-[11px] text-gray-700 dark:text-gray-300 break-all leading-relaxed">
                    curl -s -X POST {authorizeUrl()}
                    {" "}-H 'Content-Type: application/json'
                    {" "}-d '{"{"}"method":"GET","path":"/","host":"example.com","headers":{"{"}"authorization":["Bearer &lt;token&gt;"]{"}"}{"}"}
                    {" "}'
                  </code>
                </div>
              </div>
            );
          })()}
          {/* HTTP */}
          <div class="bg-white dark:bg-white/[0.02] border border-gray-200 dark:border-white/[0.08] rounded-2xl p-4">
            <div class="flex items-center justify-between mb-2">
              <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300">HTTP</h4>
              <button
                onClick={() => copyText(endpoints.data!.http.external || endpoints.data!.http.internal)}
                class="p-1 hover:bg-gray-100 dark:hover:bg-white/[0.06] rounded text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300"
                title="Copy URL"
              >
                <Copy size={14} />
              </button>
            </div>
            <dl class="text-xs space-y-1.5">
              <div>
                <dt class="text-gray-500 dark:text-gray-400">Internal</dt>
                <dd class="font-mono text-gray-800 dark:text-gray-200 break-all">{endpoints.data!.http.internal}</dd>
              </div>
              <Show when={endpoints.data!.http.external}>
                <div>
                  <dt class="text-gray-500 dark:text-gray-400">External</dt>
                  <dd class="font-mono text-gray-800 dark:text-gray-200 break-all">{endpoints.data!.http.external}</dd>
                </div>
              </Show>
            </dl>
            <div class="mt-3 p-2 bg-gray-50 dark:bg-white/[0.04] rounded-lg">
              <p class="text-[10px] text-gray-500 dark:text-gray-400 mb-1">Sample curl:</p>
              <code class="text-[11px] text-gray-700 dark:text-gray-300 break-all">
                curl -H "Authorization: Bearer &lt;token&gt;" {endpoints.data!.http.external || endpoints.data!.http.internal}/v1/authorize
              </code>
            </div>
          </div>

          {/* gRPC */}
          <div class="bg-white dark:bg-white/[0.02] border border-gray-200 dark:border-white/[0.08] rounded-2xl p-4">
            <div class="flex items-center justify-between mb-2">
              <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300">gRPC (Native)</h4>
              <button
                onClick={() => copyText(endpoints.data!.grpc.external || endpoints.data!.grpc.internal)}
                class="p-1 hover:bg-gray-100 dark:hover:bg-white/[0.06] rounded text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300"
                title="Copy URL"
              >
                <Copy size={14} />
              </button>
            </div>
            <dl class="text-xs space-y-1.5">
              <div>
                <dt class="text-gray-500 dark:text-gray-400">Internal</dt>
                <dd class="font-mono text-gray-800 dark:text-gray-200 break-all">{endpoints.data!.grpc.internal}</dd>
              </div>
              <Show when={endpoints.data!.grpc.external}>
                <div>
                  <dt class="text-gray-500 dark:text-gray-400">External</dt>
                  <dd class="font-mono text-gray-800 dark:text-gray-200 break-all">{endpoints.data!.grpc.external}</dd>
                </div>
              </Show>
            </dl>
            <div class="mt-3 p-2 bg-gray-50 dark:bg-white/[0.04] rounded-lg">
              <p class="text-[10px] text-gray-500 dark:text-gray-400 mb-1">Sample grpcurl:</p>
              <code class="text-[11px] text-gray-700 dark:text-gray-300 break-all">
                grpcurl -d '{"{"}\"method\":\"GET\",\"resource\":\"/api/v1/...\"{"}"}'
                {" "}{endpoints.data!.grpc.external || endpoints.data!.grpc.internal}
                {" "}lightweightauth.v1.Auth/Authorize
              </code>
            </div>
          </div>

          {/* Envoy ext_authz */}
          <div class="bg-white dark:bg-white/[0.02] border border-gray-200 dark:border-white/[0.08] rounded-2xl p-4 lg:col-span-2">
            <div class="flex items-center justify-between mb-2">
              <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300 flex items-center gap-1.5">
                <Shield size={14} class="text-purple-500 dark:text-purple-400" />
                Envoy ext_authz
              </h4>
              <div class="flex items-center gap-2">
                <button
                  onClick={() => copyText(endpoints.data!.extAuthz.envoyClusterConfig)}
                  class="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-gray-600 dark:text-gray-300 border border-gray-200 dark:border-white/[0.12] rounded-md hover:bg-gray-50 dark:hover:bg-white/[0.04]"
                >
                  <Copy size={12} />
                  Copy Config
                </button>
                <button
                  onClick={() => setShowEnvoy(!showEnvoy())}
                  class="p-1 hover:bg-gray-100 dark:hover:bg-white/[0.06] rounded text-gray-400 dark:text-gray-500"
                >
                  {showEnvoy() ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>
            </div>
            <dl class="text-xs space-y-1">
              <div class="flex gap-4">
                <div>
                  <dt class="text-gray-500 dark:text-gray-400">Address</dt>
                  <dd class="font-mono text-gray-800 dark:text-gray-200">{endpoints.data!.extAuthz.address}</dd>
                </div>
                <div>
                  <dt class="text-gray-500 dark:text-gray-400">Port</dt>
                  <dd class="font-mono text-gray-800 dark:text-gray-200">{endpoints.data!.extAuthz.port}</dd>
                </div>
              </div>
            </dl>
            <Show when={showEnvoy()}>
              <pre class="mt-3 p-3 bg-gray-900 dark:bg-[#0b0d14] text-gray-100 text-[11px] rounded-lg overflow-x-auto leading-relaxed border dark:border-white/[0.08]">
                {endpoints.data!.extAuthz.envoyClusterConfig}
              </pre>
            </Show>
          </div>

          {/* Load Balancing */}
          <div class="bg-white dark:bg-white/[0.02] border border-gray-200 dark:border-white/[0.08] rounded-2xl p-4 lg:col-span-2">
            <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300 flex items-center gap-1.5 mb-2">
              <ServerIcon size={14} class="text-green-500 dark:text-green-400" />
              Load Balancing
            </h4>
            <div class="flex items-center gap-6 text-xs">
              <div>
                <span class="text-gray-500 dark:text-gray-400">Strategy:</span>{" "}
                <span class="font-medium text-gray-800 dark:text-gray-200">{endpoints.data!.loadBalancing.strategy}</span>
              </div>
              <div>
                <span class="text-gray-500 dark:text-gray-400">Replicas:</span>{" "}
                <span class="font-medium text-gray-800 dark:text-gray-200">
                  {endpoints.data!.loadBalancing.readyReplicas}/{endpoints.data!.loadBalancing.totalReplicas} ready
                </span>
              </div>
              <Show when={endpoints.data!.loadBalancing.podIPs && endpoints.data!.loadBalancing.podIPs!.length > 0}>
                <div>
                  <span class="text-gray-500 dark:text-gray-400">Pod IPs:</span>{" "}
                  <span class="font-mono text-gray-800 dark:text-gray-200">
                    {endpoints.data!.loadBalancing.podIPs!.join(", ")}
                  </span>
                </div>
              </Show>
            </div>
          </div>
        </div>
        </Reveal>
      </Show>
    </div>
  );
}

// ── Quick Test Panel ────────────────────────────────────────────────────

interface HeaderEntry {
  id: number;
  key: string;
  value: string;
}

function QuickTestPanel(props: { cluster: string; name: string }) {
  const [protocol, setProtocol] = createSignal<"http" | "grpc" | "ext_authz">("http");
  const [method, setMethod] = createSignal("GET");
  const [path, setPath] = createSignal("/api/v1/example");
  // A store-backed array (keyed by a stable id, not the header name) so
  // <For> can update a single row in place. A plain Record<string,string>
  // signal would key rows by content: every keystroke in the name field
  // produces a new object, <For> tears down and recreates that row's
  // <input>, and the field loses focus after each character. It also
  // silently collapsed same-named/empty-named headers into one entry.
  let nextHeaderId = 1;
  const [headers, setHeaders] = createStore<HeaderEntry[]>([
    { id: nextHeaderId++, key: "Authorization", value: "Bearer eyJhbGci..." },
  ]);
  const [body, setBody] = createSignal("");
  const [result, setResult] = createSignal<QuickTestResponse | null>(null);

  const testMut = createMutation(() => ({
    mutationFn: (req: QuickTestRequest) => quickTest(props.cluster, props.name, req),
    onSuccess: (data) => setResult(data),
  }));

  const addHeader = () => {
    setHeaders(produce((h) => { h.push({ id: nextHeaderId++, key: "", value: "" }); }));
  };

  const updateHeaderKey = (idx: number, newKey: string) => {
    setHeaders(idx, "key", newKey);
  };

  const updateHeaderValue = (idx: number, value: string) => {
    setHeaders(idx, "value", value);
  };

  const removeHeader = (idx: number) => {
    setHeaders(produce((h) => { h.splice(idx, 1); }));
  };

  const handleSubmit = () => {
    setResult(null);
    const headerMap: Record<string, string> = {};
    for (const h of headers) {
      if (h.key) headerMap[h.key] = h.value;
    }
    testMut.mutate({
      protocol: protocol(),
      method: method(),
      path: path(),
      headers: Object.keys(headerMap).length > 0 ? headerMap : undefined,
      body: body() || undefined,
    });
  };

  return (
    <div class="mt-6">
      <h3 class="text-lg font-medium mb-3 flex items-center gap-2 text-gray-900 dark:text-gray-100">
        <Send size={18} class="text-orange-500 dark:text-orange-400" />
        Quick Test
      </h3>

      <div class="bg-white dark:bg-white/[0.02] border border-gray-200 dark:border-white/[0.08] rounded-2xl p-5">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          {/* Protocol */}
          <div>
            <label class="text-xs font-medium text-gray-600 dark:text-gray-400 block mb-1">Protocol</label>
            <div class="flex gap-1">
              <For each={["http", "grpc", "ext_authz"] as const}>
                {(p) => (
                  <button
                    class={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-all ${
                      protocol() === p
                        ? "bg-indigo-600 text-white"
                        : "bg-gray-100 dark:bg-white/[0.06] text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-white/[0.1]"
                    }`}
                    onClick={() => setProtocol(p)}
                  >
                    {p.toUpperCase()}
                  </button>
                )}
              </For>
            </div>
          </div>

          {/* Method */}
          <div>
            <label class="text-xs font-medium text-gray-600 dark:text-gray-400 block mb-1">Method</label>
            <select
              value={method()}
              onChange={(e) => setMethod(e.currentTarget.value)}
              class="form-input text-sm"
            >
              <For each={["GET", "POST", "PUT", "DELETE", "PATCH"]}>
                {(m) => <option value={m}>{m}</option>}
              </For>
            </select>
          </div>

          {/* Path */}
          <div class="md:col-span-2">
            <label class="text-xs font-medium text-gray-600 dark:text-gray-400 block mb-1">Path</label>
            <input
              type="text"
              value={path()}
              onInput={(e) => setPath(e.currentTarget.value)}
              class="form-input text-sm"
              placeholder="/api/v1/resource"
            />
          </div>
        </div>

        {/* Headers */}
        <div class="mb-4">
          <div class="flex items-center justify-between mb-2">
            <label class="text-xs font-medium text-gray-600 dark:text-gray-400">Headers</label>
            <button
              onClick={addHeader}
              class="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 font-medium"
            >
              + Add Header
            </button>
          </div>
          <div class="space-y-1.5">
            <For each={headers}>
              {(h, idx) => (
                <div class="flex gap-2 items-center">
                  <input
                    type="text"
                    value={h.key}
                    onInput={(e) => updateHeaderKey(idx(), e.currentTarget.value)}
                    class="form-input text-xs flex-1"
                    placeholder="Header-Name"
                  />
                  <input
                    type="text"
                    value={h.value}
                    onInput={(e) => updateHeaderValue(idx(), e.currentTarget.value)}
                    class="form-input text-xs flex-[2]"
                    placeholder="value"
                  />
                  <button
                    onClick={() => removeHeader(idx())}
                    class="text-xs text-red-500 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 px-1"
                  >
                    ×
                  </button>
                </div>
              )}
            </For>
          </div>
        </div>

        {/* Submit */}
        <button
          onClick={handleSubmit}
          disabled={testMut.isPending}
          class="inline-flex items-center gap-2 px-5 py-2.5 bg-orange-500 text-white text-sm font-medium rounded-lg hover:bg-orange-600 disabled:opacity-50 shadow-sm transition-colors"
        >
          <Send size={14} />
          {testMut.isPending ? "Testing…" : "Send Request"}
        </button>

        {/* Result */}
        <Show when={result()}>
          <div class="mt-4 border border-gray-200 dark:border-white/[0.08] rounded-2xl overflow-hidden animate-scale-in">
            {/* Status bar */}
            <div
              class={`px-4 py-2.5 flex items-center justify-between ${
                result()!.error
                  ? "bg-yellow-50 dark:bg-yellow-500/10 border-b border-yellow-100 dark:border-yellow-500/20"
                  : result()!.status === "allow"
                  ? "bg-green-50 dark:bg-green-500/10 border-b border-green-100 dark:border-green-500/20"
                  : "bg-red-50 dark:bg-red-500/10 border-b border-red-100 dark:border-red-500/20"
              }`}
            >
              <div class="flex items-center gap-3">
                <span
                  class={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold ${
                    result()!.error
                      ? "bg-yellow-100 dark:bg-yellow-500/15 text-yellow-800 dark:text-yellow-400"
                      : result()!.status === "allow"
                      ? "bg-green-100 dark:bg-green-500/15 text-green-800 dark:text-green-400"
                      : "bg-red-100 dark:bg-red-500/15 text-red-800 dark:text-red-400"
                  }`}
                >
                  {result()!.error ? "ERROR" : result()!.status?.toUpperCase() ?? "UNKNOWN"}
                </span>
                <Show when={result()!.statusCode}>
                  <span class="text-xs text-gray-600 dark:text-gray-400">{result()!.statusCode}</span>
                </Show>
              </div>
              <Show when={result()!.latency}>
                <span class="text-xs font-mono text-gray-500 dark:text-gray-400">{result()!.latency}</span>
              </Show>
            </div>

            {/* Details */}
            <div class="p-4 space-y-3 text-xs">
              <Show when={result()!.error}>
                <div>
                  <p class="font-medium text-yellow-800 dark:text-yellow-400 mb-1">Error</p>
                  <p class="text-gray-700 dark:text-gray-300">{result()!.error}</p>
                </div>
              </Show>

              <Show when={result()!.denyReason}>
                <div>
                  <p class="font-medium text-red-700 dark:text-red-400 mb-1">Deny Reason</p>
                  <p class="text-gray-700 dark:text-gray-300">{result()!.denyReason}</p>
                </div>
              </Show>

              <Show when={result()!.identity && Object.keys(result()!.identity!).length > 0}>
                <div>
                  <p class="font-medium text-gray-700 dark:text-gray-300 mb-1">Identity</p>
                  <pre class="bg-gray-50 dark:bg-white/[0.04] text-gray-800 dark:text-gray-200 p-2 rounded text-[11px] overflow-x-auto">
                    {JSON.stringify(result()!.identity, null, 2)}
                  </pre>
                </div>
              </Show>

              <Show when={result()!.headers && Object.keys(result()!.headers!).length > 0}>
                <div>
                  <p class="font-medium text-gray-700 dark:text-gray-300 mb-1">Response Headers</p>
                  <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                    <For each={Object.entries(result()!.headers!)}>
                      {([k, v]) => (
                        <>
                          <dt class="font-mono text-gray-500 dark:text-gray-400">{k}</dt>
                          <dd class="font-mono text-gray-800 dark:text-gray-200">{v}</dd>
                        </>
                      )}
                    </For>
                  </dl>
                </div>
              </Show>

              <Show when={result()!.rawResponse}>
                <details class="group">
                  <summary class="font-medium text-gray-500 dark:text-gray-400 cursor-pointer hover:text-gray-700 dark:hover:text-gray-200">
                    Raw Response
                  </summary>
                  <pre class="mt-2 bg-gray-50 dark:bg-white/[0.04] text-gray-800 dark:text-gray-200 p-2 rounded text-[11px] overflow-x-auto">
                    {JSON.stringify(result()!.rawResponse, null, 2)}
                  </pre>
                </details>
              </Show>
            </div>
          </div>
        </Show>
      </div>
    </div>
  );
}

// ── Sparkline ───────────────────────────────────────────────────────────

function SparklineCard(props: { label: string; unit: string; data: number[]; updateTick: number }) {
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

  // Pulse briefly whenever fresh WS data lands, skipping the very first
  // render so the card doesn't flash on initial mount.
  const [pulsing, setPulsing] = createSignal(false);
  let firstTick = true;
  createEffect(() => {
    void props.updateTick;
    if (firstTick) {
      firstTick = false;
      return;
    }
    setPulsing(true);
    const timer = setTimeout(() => setPulsing(false), 600);
    onCleanup(() => clearTimeout(timer));
  });

  return (
    <div
      class={`bg-white dark:bg-white/[0.02] border border-gray-200 dark:border-white/[0.08] rounded-2xl p-3 transition-shadow ${
        pulsing() ? "animate-glow-pulse-once" : ""
      }`}
    >
      <div class="flex justify-between items-baseline mb-1">
        <span class="text-xs text-gray-500 dark:text-gray-400">{props.label}</span>
        <span class="text-sm font-bold text-gray-900 dark:text-gray-100">{current().toFixed(1)}{props.unit}</span>
      </div>
      <svg viewBox="0 0 120 30" class="w-full h-8" preserveAspectRatio="none">
        <path d={svgPath()} fill="none" stroke="#22d3ee" stroke-width="1.5" />
      </svg>
    </div>
  );
}
