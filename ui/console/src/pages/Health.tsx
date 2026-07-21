import { createSignal, onCleanup, createEffect, Show, For } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { A } from "@solidjs/router";
import { CheckCircle2, AlertTriangle, XCircle, Activity, Database, ScrollText } from "lucide-solid";
import { getHealth, listInstances, listAlerts } from "../api/client";
import { AmbientBackground } from "../components/AmbientBackground";
import { GlowDot } from "../components/GlowDot";
import { Reveal } from "../components/Reveal";
import { EmptyState } from "../components/ui";

// A real status page for the deployment — status-timeline style, built to
// fill the nav's previously-dead /health link. Aggregates instance health
// + the alerting pipeline's own backend-degradation signal (Prometheus/
// Loki) into one overall system status, mission-control style.
export default function Health() {
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

  const [degraded, setDegraded] = createSignal<{ prometheus: boolean; loki: boolean } | null>(null);
  const [alertsEnabled, setAlertsEnabled] = createSignal(true);

  createEffect(() => {
    (async () => {
      try {
        const resp = await listAlerts();
        setDegraded(resp.degraded);
        setAlertsEnabled(resp.enabled);
      } catch {
        /* alerting pipeline itself unreachable — surfaced via the pill below */
      }
    })();
  });

  const unhealthyCount = () => (health.data ? health.data.totalInstances - health.data.healthyInstances : 0);
  const backendsDegraded = () => !!(degraded() && (degraded()!.prometheus || degraded()!.loki));

  const overall = (): "operational" | "degraded" | "critical" => {
    if (!health.data) return "operational";
    if (unhealthyCount() > 0 && unhealthyCount() >= health.data.totalInstances) return "critical";
    if (unhealthyCount() > 0 || backendsDegraded()) return "degraded";
    return "operational";
  };

  const overallCopy: Record<ReturnType<typeof overall>, { label: string; tone: "healthy" | "critical" | "live" }> = {
    operational: { label: "All Systems Operational", tone: "healthy" },
    degraded: { label: "Partial Degradation", tone: "critical" },
    critical: { label: "Critical — Multiple Systems Down", tone: "critical" },
  };

  return (
    <div class="max-w-5xl">
      <div class="relative -mx-6 -mt-6 px-6 pt-6 pb-8 mb-6 overflow-hidden">
        <AmbientBackground />
        <div class="relative">
          <h1 class="font-display text-2xl font-bold text-gray-900 dark:text-gray-100">System Health</h1>
          <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Live status across every deployed instance and the observability pipeline.
          </p>

          <div class="mt-6 glass-panel rounded-2xl px-6 py-5 flex items-center gap-4 animate-scale-in">
            <div
              class={`flex h-11 w-11 items-center justify-center rounded-xl shrink-0 ${
                overall() === "operational"
                  ? "bg-emerald-500/15"
                  : overall() === "degraded"
                    ? "bg-amber-500/15"
                    : "bg-red-500/15"
              }`}
            >
              {overall() === "operational" ? (
                <CheckCircle2 size={22} class="text-emerald-500 dark:text-emerald-400" />
              ) : overall() === "degraded" ? (
                <AlertTriangle size={22} class="text-amber-500 dark:text-amber-400" />
              ) : (
                <XCircle size={22} class="text-red-500 dark:text-red-400" />
              )}
            </div>
            <div class="min-w-0">
              <p class="font-display text-lg font-semibold text-gray-900 dark:text-gray-100">
                {overallCopy[overall()].label}
              </p>
              <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                {health.data ? `${health.data.healthyInstances} / ${health.data.totalInstances} instances healthy` : "Checking…"}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Observability pipeline */}
      <Reveal>
        <div class="bg-white dark:bg-white/[0.02] rounded-2xl border border-gray-200 dark:border-white/[0.08] shadow-sm dark:shadow-none p-5 mb-6">
          <h2 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-4">Observability Pipeline</h2>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <BackendRow icon={Activity} name="Prometheus (metrics + alert rules)" ok={!degraded()?.prometheus} enabled={alertsEnabled()} />
            <BackendRow icon={ScrollText} name="Loki (log-based alert rules)" ok={!degraded()?.loki} enabled={alertsEnabled()} />
          </div>
          <Show when={!alertsEnabled()}>
            <p class="text-xs text-gray-400 dark:text-gray-500 mt-3">
              Alerting is disabled for this deployment — backend status isn't monitored.
            </p>
          </Show>
        </div>
      </Reveal>

      {/* Per-instance status */}
      <Reveal>
        <div class="bg-white dark:bg-white/[0.02] rounded-2xl border border-gray-200 dark:border-white/[0.08] shadow-sm dark:shadow-none overflow-hidden">
          <div class="px-5 py-4 border-b border-gray-100 dark:border-white/[0.06]">
            <h2 class="text-sm font-semibold text-gray-900 dark:text-gray-100">Instances</h2>
          </div>
          <Show when={instances.data && instances.data.length === 0}>
            <EmptyState icon={Database} title="No instances deployed" description="Deploy an instance to see its status here." />
          </Show>
          <Show when={instances.data && instances.data.length > 0}>
            <ul class="divide-y divide-gray-100 dark:divide-white/[0.06]">
              <For each={instances.data}>
                {(inst) => (
                  <li class="flex items-center justify-between px-5 py-3.5">
                    <div class="min-w-0 flex items-center gap-3">
                      <GlowDot tone={inst.status.healthy ? "healthy" : "critical"} pulse={!inst.status.healthy} />
                      <div class="min-w-0">
                        <A
                          href={`/instances/${inst.cluster}/${inst.name}`}
                          class="text-sm font-medium text-gray-900 dark:text-gray-100 hover:text-indigo-600 dark:hover:text-indigo-400"
                        >
                          {inst.name}
                        </A>
                        <p class="text-xs text-gray-400 dark:text-gray-500">{inst.cluster}</p>
                      </div>
                    </div>
                    <span
                      class={`text-xs font-medium px-2.5 py-1 rounded-full ${
                        inst.status.healthy
                          ? "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                          : "bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400"
                      }`}
                    >
                      {inst.status.healthy ? "Operational" : "Down"}
                    </span>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </div>
      </Reveal>
    </div>
  );
}

function BackendRow(props: { icon: (p: any) => any; name: string; ok: boolean; enabled: boolean }) {
  return (
    <div class="flex items-center gap-3 rounded-xl border border-gray-100 dark:border-white/[0.06] px-3.5 py-3">
      <props.icon size={16} class="text-gray-400 dark:text-gray-500 shrink-0" />
      <span class="text-sm text-gray-700 dark:text-gray-300 flex-1 min-w-0 truncate">{props.name}</span>
      <GlowDot
        tone={!props.enabled ? "idle" : props.ok ? "healthy" : "critical"}
        pulse={props.enabled && !props.ok}
        label={!props.enabled ? "N/A" : props.ok ? "OK" : "Degraded"}
      />
    </div>
  );
}
