import { createSignal, Show, For } from "solid-js";
import { createQuery, createMutation } from "@tanstack/solid-query";
import { quickTest, type QuickTestResponse, type QuickTestRequest } from "../api/client";
import { EChart } from "../components/EChart";
import { waterfallOption, chartColors } from "../components/chart-options";
import { Card, EmptyState } from "../components/ui";
import { Play, ChevronDown, ChevronRight } from "lucide-solid";

interface ExplainStage {
  name: string;
  durationMs: number;
  color?: string;
}

export default function PolicyExplain() {
  const [method, setMethod] = createSignal("GET");
  const [path, setPath] = createSignal("/api/data");
  const [host, setHost] = createSignal("example.com");
  const [tenant, setTenant] = createSignal("");
  const [headersJson, setHeadersJson] = createSignal('{"Authorization": "Bearer <token>"}');
  const [expandedStage, setExpandedStage] = createSignal<string | null>(null);
  const [lastResult, setLastResult] = createSignal<QuickTestResponse | null>(null);
  const [stages, setStages] = createSignal<ExplainStage[]>([]);

  // The quickTest endpoint proxies to the data-plane /v1/admin/explain
  // which returns a stage-by-stage trace. We re-use it here because
  // the Explain Studio is fundamentally the same "submit a synthetic
  // request, get a trace" flow — the InstanceDetail's Quick Test panel
  // targets a specific instance, while the Explain Studio targets the
  // first available instance (or the operator can pick one).
  const testMutation = createMutation(() => ({
    mutationFn: async (req: QuickTestRequest) => {
      // In a real deployment the operator picks an instance; for the
      // standalone explain studio we use the first registered instance.
      // The quickTest API requires cluster + name, so we fetch the
      // instance list first.
      const { listInstances } = await import("../api/client");
      const instances = await listInstances();
      if (instances.length === 0) {
        throw new Error("no instances registered — register an instance first");
      }
      const inst = instances[0];
      return quickTest(inst.cluster, inst.name, req);
    },
    onSuccess: (resp) => {
      setLastResult(resp);
      // Extract stages from the explain response. The quickTest
      // response carries the raw explain trace in rawResponse.
      const raw = resp.rawResponse as any;
      if (raw?.stages) {
        const parsed: ExplainStage[] = raw.stages.map((s: any) => ({
          name: s.name ?? s.stage ?? "unknown",
          durationMs: (s.duration_ms ?? s.latency_ms ?? 0) as number,
          color: stageColor(s.name ?? s.stage),
        }));
        setStages(parsed);
      } else {
        setStages([]);
      }
    },
  }));

  function stageColor(name: string): string {
    const n = name.toLowerCase();
    if (n.includes("identif")) return chartColors.blue;
    if (n.includes("revoke") || n.includes("revocation")) return chartColors.orange;
    if (n.includes("authoriz")) return chartColors.indigo;
    if (n.includes("mutat")) return chartColors.purple;
    return chartColors.gray;
  }

  function handleSubmit(e: Event) {
    e.preventDefault();
    let headers: Record<string, string> = {};
    try {
      headers = JSON.parse(headersJson());
    } catch { /* invalid JSON — submit with empty headers */ }

    const req: QuickTestRequest = {
      protocol: "http",
      method: method(),
      path: path(),
      headers,
    };
    testMutation.mutate(req);
  }

  const waterfallChart = () => {
    const s = stages();
    if (s.length === 0) return null;
    return waterfallOption(s);
  };

  return (
    <div class="max-w-7xl">
      {/* Header */}
      <div class="mb-6">
        <h1 class="text-2xl font-bold text-gray-900">Policy Explain Studio</h1>
        <p class="text-sm text-gray-500 mt-1">
          Submit a synthetic request and inspect the stage-by-stage authorization trace
        </p>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Request form */}
        <Card title="Synthetic Request" subtitle="Construct a request to trace through the pipeline">
          <form onSubmit={handleSubmit} class="p-5 space-y-4">
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-medium text-gray-500 uppercase tracking-wide">Method</label>
                <select
                  class="mt-1 w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
                  value={method()}
                  onChange={(e) => setMethod(e.currentTarget.value)}
                >
                  <For each={["GET", "POST", "PUT", "DELETE", "PATCH"]}>
                    {(m) => <option value={m}>{m}</option>}
                  </For>
                </select>
              </div>
              <div>
                <label class="text-xs font-medium text-gray-500 uppercase tracking-wide">Host</label>
                <input
                  class="mt-1 w-full border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
                  value={host()}
                  onInput={(e) => setHost(e.currentTarget.value)}
                />
              </div>
            </div>
            <div>
              <label class="text-xs font-medium text-gray-500 uppercase tracking-wide">Path</label>
              <input
                class="mt-1 w-full border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
                value={path()}
                onInput={(e) => setPath(e.currentTarget.value)}
              />
            </div>
            <div>
              <label class="text-xs font-medium text-gray-500 uppercase tracking-wide">Tenant (optional)</label>
              <input
                class="mt-1 w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
                value={tenant()}
                onInput={(e) => setTenant(e.currentTarget.value)}
                placeholder="acme"
              />
            </div>
            <div>
              <label class="text-xs font-medium text-gray-500 uppercase tracking-wide">Headers (JSON)</label>
              <textarea
                class="mt-1 w-full border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none"
                rows={4}
                value={headersJson()}
                onInput={(e) => setHeadersJson(e.currentTarget.value)}
              />
            </div>
            <button
              type="submit"
              disabled={testMutation.isPending}
              class="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              <Play size={14} />
              {testMutation.isPending ? "Tracing…" : "Trace Request"}
            </button>
          </form>
        </Card>

        {/* Results — waterfall + outcome */}
        <div class="space-y-4">
          <Card title="Pipeline Waterfall" subtitle="Stage-by-stage latency breakdown">
            <Show when={waterfallChart()} fallback={
              <Show when={testMutation.isPending} fallback={
                <EmptyState title="No trace yet" description="Submit a request to see the waterfall" />
              }>
                <div class="p-8 animate-pulse">
                  <div class="h-4 bg-gray-100 rounded w-3/4 mb-3" />
                  <div class="h-4 bg-gray-100 rounded w-1/2 mb-3" />
                  <div class="h-4 bg-gray-100 rounded w-2/3" />
                </div>
              </Show>
            }>
              <div class="p-4">
                <EChart option={waterfallChart()!} height="300px" />
              </div>
            </Show>
          </Card>

          {/* Verdict summary */}
          <Show when={lastResult()}>
            <Card title="Verdict" subtitle="Pipeline outcome for the synthetic request">
              <div class="p-5 space-y-3">
                <div class="flex items-center gap-3">
                  <span class={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-semibold ${
                    lastResult()!.status === "allow"
                      ? "bg-green-50 text-green-700"
                      : "bg-red-50 text-red-700"
                  }`}>
                    <span class={`w-2 h-2 rounded-full ${
                      lastResult()!.status === "allow" ? "bg-green-500" : "bg-red-500"
                    }`} />
                    {lastResult()!.status.toUpperCase()}
                  </span>
                  <Show when={lastResult()!.latency}>
                    <span class="text-sm text-gray-500 font-mono">{lastResult()!.latency}</span>
                  </Show>
                </div>
                <Show when={lastResult()!.denyReason}>
                  <div class="bg-red-50 border border-red-200 rounded-lg px-4 py-3">
                    <p class="text-xs font-medium text-red-500 uppercase tracking-wide mb-1">Deny Reason</p>
                    <p class="text-sm text-red-800 font-mono">{lastResult()!.denyReason}</p>
                  </div>
                </Show>
                <Show when={lastResult()!.identity}>
                  <div class="bg-gray-50 rounded-lg px-4 py-3">
                    <p class="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Identity</p>
                    <pre class="text-xs text-gray-700 font-mono overflow-auto">
                      {JSON.stringify(lastResult()!.identity, null, 2)}
                    </pre>
                  </div>
                </Show>
                <Show when={lastResult()!.headers}>
                  <div class="bg-gray-50 rounded-lg px-4 py-3">
                    <p class="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1">Response Headers</p>
                    <pre class="text-xs text-gray-700 font-mono overflow-auto">
                      {JSON.stringify(lastResult()!.headers, null, 2)}
                    </pre>
                  </div>
                </Show>
                <Show when={lastResult()!.error}>
                  <div class="bg-red-50 border border-red-200 rounded-lg px-4 py-3">
                    <p class="text-xs font-medium text-red-500 uppercase tracking-wide mb-1">Error</p>
                    <p class="text-sm text-red-800">{lastResult()!.error}</p>
                  </div>
                </Show>
              </div>
            </Card>
          </Show>
        </div>
      </div>
    </div>
  );
}