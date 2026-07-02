import { createSignal, createEffect, onCleanup, Show, For } from "solid-js";
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
      <h3 class="text-lg font-medium mb-3 flex items-center gap-2">
        <Globe size={18} class="text-blue-600" />
        Endpoints
      </h3>

      <Show when={endpoints.isLoading}>
        <p class="text-sm text-gray-400">Loading endpoints…</p>
      </Show>

      <Show when={endpoints.data}>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* CP Proxy — primary external access path */}
          {(() => {
            const proxyBase = () => `${window.location.origin}${endpoints.data!.proxyPath}`;
            const authorizeUrl = () => `${proxyBase()}/v1/authorize`;
            return (
              <div class="lg:col-span-2 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-xl p-4">
                <div class="flex items-start justify-between mb-3">
                  <div>
                    <h4 class="text-sm font-semibold text-blue-900 flex items-center gap-1.5">
                      <ExternalLink size={14} class="text-blue-600" />
                      CP Proxy (recommended external endpoint)
                    </h4>
                    <p class="text-[11px] text-blue-700 mt-0.5">
                      This node is only reachable externally through the control plane proxy. The node's Service is cluster-internal only.
                    </p>
                  </div>
                  <button
                    onClick={() => copyText(proxyBase())}
                    class="shrink-0 p-1 hover:bg-blue-100 rounded text-blue-500 hover:text-blue-700"
                    title="Copy base URL"
                  >
                    <Copy size={14} />
                  </button>
                </div>
                <dl class="text-xs space-y-2">
                  <div>
                    <dt class="text-blue-600 font-medium">Base URL</dt>
                    <dd class="font-mono text-blue-900 break-all mt-0.5 bg-white/60 px-2 py-1 rounded">
                      {proxyBase()}
                    </dd>
                  </div>
                </dl>
                <div class="mt-3 p-2.5 bg-white/70 rounded-lg border border-blue-100">
                  <p class="text-[10px] text-blue-600 font-medium mb-1.5">Authorization request:</p>
                  <code class="text-[11px] text-gray-700 break-all leading-relaxed">
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
          <div class="bg-white border border-gray-200 rounded-xl p-4">
            <div class="flex items-center justify-between mb-2">
              <h4 class="text-sm font-semibold text-gray-700">HTTP</h4>
              <button
                onClick={() => copyText(endpoints.data!.http.external || endpoints.data!.http.internal)}
                class="p-1 hover:bg-gray-100 rounded text-gray-400 hover:text-gray-600"
                title="Copy URL"
              >
                <Copy size={14} />
              </button>
            </div>
            <dl class="text-xs space-y-1.5">
              <div>
                <dt class="text-gray-500">Internal</dt>
                <dd class="font-mono text-gray-800 break-all">{endpoints.data!.http.internal}</dd>
              </div>
              <Show when={endpoints.data!.http.external}>
                <div>
                  <dt class="text-gray-500">External</dt>
                  <dd class="font-mono text-gray-800 break-all">{endpoints.data!.http.external}</dd>
                </div>
              </Show>
            </dl>
            <div class="mt-3 p-2 bg-gray-50 rounded-lg">
              <p class="text-[10px] text-gray-500 mb-1">Sample curl:</p>
              <code class="text-[11px] text-gray-700 break-all">
                curl -H "Authorization: Bearer &lt;token&gt;" {endpoints.data!.http.external || endpoints.data!.http.internal}/v1/authorize
              </code>
            </div>
          </div>

          {/* gRPC */}
          <div class="bg-white border border-gray-200 rounded-xl p-4">
            <div class="flex items-center justify-between mb-2">
              <h4 class="text-sm font-semibold text-gray-700">gRPC (Native)</h4>
              <button
                onClick={() => copyText(endpoints.data!.grpc.external || endpoints.data!.grpc.internal)}
                class="p-1 hover:bg-gray-100 rounded text-gray-400 hover:text-gray-600"
                title="Copy URL"
              >
                <Copy size={14} />
              </button>
            </div>
            <dl class="text-xs space-y-1.5">
              <div>
                <dt class="text-gray-500">Internal</dt>
                <dd class="font-mono text-gray-800 break-all">{endpoints.data!.grpc.internal}</dd>
              </div>
              <Show when={endpoints.data!.grpc.external}>
                <div>
                  <dt class="text-gray-500">External</dt>
                  <dd class="font-mono text-gray-800 break-all">{endpoints.data!.grpc.external}</dd>
                </div>
              </Show>
            </dl>
            <div class="mt-3 p-2 bg-gray-50 rounded-lg">
              <p class="text-[10px] text-gray-500 mb-1">Sample grpcurl:</p>
              <code class="text-[11px] text-gray-700 break-all">
                grpcurl -d '{"{"}\"method\":\"GET\",\"resource\":\"/api/v1/...\"{"}"}'
                {" "}{endpoints.data!.grpc.external || endpoints.data!.grpc.internal}
                {" "}lightweightauth.v1.Auth/Authorize
              </code>
            </div>
          </div>

          {/* Envoy ext_authz */}
          <div class="bg-white border border-gray-200 rounded-xl p-4 lg:col-span-2">
            <div class="flex items-center justify-between mb-2">
              <h4 class="text-sm font-semibold text-gray-700 flex items-center gap-1.5">
                <Shield size={14} class="text-purple-500" />
                Envoy ext_authz
              </h4>
              <div class="flex items-center gap-2">
                <button
                  onClick={() => copyText(endpoints.data!.extAuthz.envoyClusterConfig)}
                  class="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-gray-600 border border-gray-200 rounded-md hover:bg-gray-50"
                >
                  <Copy size={12} />
                  Copy Config
                </button>
                <button
                  onClick={() => setShowEnvoy(!showEnvoy())}
                  class="p-1 hover:bg-gray-100 rounded text-gray-400"
                >
                  {showEnvoy() ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>
            </div>
            <dl class="text-xs space-y-1">
              <div class="flex gap-4">
                <div>
                  <dt class="text-gray-500">Address</dt>
                  <dd class="font-mono text-gray-800">{endpoints.data!.extAuthz.address}</dd>
                </div>
                <div>
                  <dt class="text-gray-500">Port</dt>
                  <dd class="font-mono text-gray-800">{endpoints.data!.extAuthz.port}</dd>
                </div>
              </div>
            </dl>
            <Show when={showEnvoy()}>
              <pre class="mt-3 p-3 bg-gray-900 text-gray-100 text-[11px] rounded-lg overflow-x-auto leading-relaxed">
                {endpoints.data!.extAuthz.envoyClusterConfig}
              </pre>
            </Show>
          </div>

          {/* Load Balancing */}
          <div class="bg-white border border-gray-200 rounded-xl p-4 lg:col-span-2">
            <h4 class="text-sm font-semibold text-gray-700 flex items-center gap-1.5 mb-2">
              <ServerIcon size={14} class="text-green-500" />
              Load Balancing
            </h4>
            <div class="flex items-center gap-6 text-xs">
              <div>
                <span class="text-gray-500">Strategy:</span>{" "}
                <span class="font-medium text-gray-800">{endpoints.data!.loadBalancing.strategy}</span>
              </div>
              <div>
                <span class="text-gray-500">Replicas:</span>{" "}
                <span class="font-medium text-gray-800">
                  {endpoints.data!.loadBalancing.readyReplicas}/{endpoints.data!.loadBalancing.totalReplicas} ready
                </span>
              </div>
              <Show when={endpoints.data!.loadBalancing.podIPs && endpoints.data!.loadBalancing.podIPs!.length > 0}>
                <div>
                  <span class="text-gray-500">Pod IPs:</span>{" "}
                  <span class="font-mono text-gray-800">
                    {endpoints.data!.loadBalancing.podIPs!.join(", ")}
                  </span>
                </div>
              </Show>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}

// ── Quick Test Panel ────────────────────────────────────────────────────

function QuickTestPanel(props: { cluster: string; name: string }) {
  const [protocol, setProtocol] = createSignal<"http" | "grpc" | "ext_authz">("http");
  const [method, setMethod] = createSignal("GET");
  const [path, setPath] = createSignal("/api/v1/example");
  const [headers, setHeaders] = createSignal<Record<string, string>>({
    Authorization: "Bearer eyJhbGci...",
  });
  const [body, setBody] = createSignal("");
  const [result, setResult] = createSignal<QuickTestResponse | null>(null);

  const testMut = createMutation(() => ({
    mutationFn: (req: QuickTestRequest) => quickTest(props.cluster, props.name, req),
    onSuccess: (data) => setResult(data),
  }));

  const addHeader = () => {
    setHeaders({ ...headers(), "": "" });
  };

  const updateHeaderKey = (oldKey: string, newKey: string) => {
    const h = { ...headers() };
    const val = h[oldKey];
    delete h[oldKey];
    h[newKey] = val;
    setHeaders(h);
  };

  const updateHeaderValue = (key: string, value: string) => {
    setHeaders({ ...headers(), [key]: value });
  };

  const removeHeader = (key: string) => {
    const h = { ...headers() };
    delete h[key];
    setHeaders(h);
  };

  const handleSubmit = () => {
    setResult(null);
    testMut.mutate({
      protocol: protocol(),
      method: method(),
      path: path(),
      headers: Object.keys(headers()).length > 0 ? headers() : undefined,
      body: body() || undefined,
    });
  };

  return (
    <div class="mt-6">
      <h3 class="text-lg font-medium mb-3 flex items-center gap-2">
        <Send size={18} class="text-orange-500" />
        Quick Test
      </h3>

      <div class="bg-white border border-gray-200 rounded-xl p-5">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          {/* Protocol */}
          <div>
            <label class="text-xs font-medium text-gray-600 block mb-1">Protocol</label>
            <div class="flex gap-1">
              <For each={["http", "grpc", "ext_authz"] as const}>
                {(p) => (
                  <button
                    class={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-all ${
                      protocol() === p
                        ? "bg-blue-600 text-white"
                        : "bg-gray-100 text-gray-600 hover:bg-gray-200"
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
            <label class="text-xs font-medium text-gray-600 block mb-1">Method</label>
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
            <label class="text-xs font-medium text-gray-600 block mb-1">Path</label>
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
            <label class="text-xs font-medium text-gray-600">Headers</label>
            <button
              onClick={addHeader}
              class="text-xs text-blue-600 hover:text-blue-700 font-medium"
            >
              + Add Header
            </button>
          </div>
          <div class="space-y-1.5">
            <For each={Object.entries(headers())}>
              {([key, value]) => (
                <div class="flex gap-2 items-center">
                  <input
                    type="text"
                    value={key}
                    onInput={(e) => updateHeaderKey(key, e.currentTarget.value)}
                    class="form-input text-xs flex-1"
                    placeholder="Header-Name"
                  />
                  <input
                    type="text"
                    value={value}
                    onInput={(e) => updateHeaderValue(key, e.currentTarget.value)}
                    class="form-input text-xs flex-[2]"
                    placeholder="value"
                  />
                  <button
                    onClick={() => removeHeader(key)}
                    class="text-xs text-red-500 hover:text-red-700 px-1"
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
          <div class="mt-4 border border-gray-200 rounded-xl overflow-hidden">
            {/* Status bar */}
            <div
              class={`px-4 py-2.5 flex items-center justify-between ${
                result()!.error
                  ? "bg-yellow-50 border-b border-yellow-100"
                  : result()!.status === "allow"
                  ? "bg-green-50 border-b border-green-100"
                  : "bg-red-50 border-b border-red-100"
              }`}
            >
              <div class="flex items-center gap-3">
                <span
                  class={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold ${
                    result()!.error
                      ? "bg-yellow-100 text-yellow-800"
                      : result()!.status === "allow"
                      ? "bg-green-100 text-green-800"
                      : "bg-red-100 text-red-800"
                  }`}
                >
                  {result()!.error ? "ERROR" : result()!.status?.toUpperCase() ?? "UNKNOWN"}
                </span>
                <Show when={result()!.statusCode}>
                  <span class="text-xs text-gray-600">{result()!.statusCode}</span>
                </Show>
              </div>
              <Show when={result()!.latency}>
                <span class="text-xs font-mono text-gray-500">{result()!.latency}</span>
              </Show>
            </div>

            {/* Details */}
            <div class="p-4 space-y-3 text-xs">
              <Show when={result()!.error}>
                <div>
                  <p class="font-medium text-yellow-800 mb-1">Error</p>
                  <p class="text-gray-700">{result()!.error}</p>
                </div>
              </Show>

              <Show when={result()!.denyReason}>
                <div>
                  <p class="font-medium text-red-700 mb-1">Deny Reason</p>
                  <p class="text-gray-700">{result()!.denyReason}</p>
                </div>
              </Show>

              <Show when={result()!.identity && Object.keys(result()!.identity!).length > 0}>
                <div>
                  <p class="font-medium text-gray-700 mb-1">Identity</p>
                  <pre class="bg-gray-50 p-2 rounded text-[11px] overflow-x-auto">
                    {JSON.stringify(result()!.identity, null, 2)}
                  </pre>
                </div>
              </Show>

              <Show when={result()!.headers && Object.keys(result()!.headers!).length > 0}>
                <div>
                  <p class="font-medium text-gray-700 mb-1">Response Headers</p>
                  <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                    <For each={Object.entries(result()!.headers!)}>
                      {([k, v]) => (
                        <>
                          <dt class="font-mono text-gray-500">{k}</dt>
                          <dd class="font-mono text-gray-800">{v}</dd>
                        </>
                      )}
                    </For>
                  </dl>
                </div>
              </Show>

              <Show when={result()!.rawResponse}>
                <details class="group">
                  <summary class="font-medium text-gray-500 cursor-pointer hover:text-gray-700">
                    Raw Response
                  </summary>
                  <pre class="mt-2 bg-gray-50 p-2 rounded text-[11px] overflow-x-auto">
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
