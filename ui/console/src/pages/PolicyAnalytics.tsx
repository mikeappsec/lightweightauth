import { createQuery } from "@tanstack/solid-query";
import { For, Show, createMemo } from "solid-js";
import {
  getPolicyBreakdown,
  getDecisionTimeSeries,
  getLatencyQuantiles,
  getTopDimension,
  type PolicyVersionStats,
  type TimeSeriesResponse,
} from "../api/client";
import { EChart } from "../components/EChart";
import { timeSeriesOption, donutOption, chartColors } from "../components/chart-options";
import { DataTable } from "../components/DataTable";
import { Card, KPITile, EmptyState, SkeletonCard } from "../components/ui";
import { Reveal } from "../components/Reveal";
import { theme } from "../theme/store";
import type { ColumnDef } from "@tanstack/solid-table";
import { FileText, TrendingUp, Clock, ShieldOff } from "lucide-solid";

export default function PolicyAnalytics() {
  const window = "1h";

  const policyBreakdown = createQuery(() => ({
    queryKey: ["analytics", "policy", window],
    queryFn: () => getPolicyBreakdown(window),
    staleTime: 30_000,
  }));

  const decisionSeries = createQuery(() => ({
    queryKey: ["analytics", "decisions-ts", window],
    queryFn: () => getDecisionTimeSeries({ window, step: "1m", groupBy: "outcome" }),
    staleTime: 30_000,
  }));

  const latencyQuantiles = createQuery(() => ({
    queryKey: ["analytics", "latency-q", window],
    queryFn: () => getLatencyQuantiles({ window, step: "1m" }),
    staleTime: 30_000,
  }));

  const topDenyAuthors = createQuery(() => ({
    queryKey: ["analytics", "top", "authorizer", window],
    queryFn: () => getTopDimension("authorizer", { window, limit: 10 }),
    staleTime: 30_000,
  }));

  const totalDecisions = createMemo(() => {
    const data = policyBreakdown.data;
    if (!data) return 0;
    return data.versions.reduce((sum, v) => sum + v.total_count, 0);
  });

  const totalDenies = createMemo(() => {
    const data = policyBreakdown.data;
    if (!data) return 0;
    return data.versions.reduce((sum, v) => sum + v.deny_count, 0);
  });

  const topVersion = createMemo(() => {
    const data = policyBreakdown.data;
    if (!data || data.versions.length === 0) return null;
    return data.versions[0];
  });

  // Donut data for the latest policy version's outcome breakdown.
  const latestDonut = createMemo(() => {
    const v = topVersion();
    if (!v) return null;
    return donutOption(
      [
        { name: "Allow", value: v.allow_count, color: chartColors.allow },
        { name: "Deny", value: v.deny_count, color: chartColors.deny },
        { name: "Error", value: v.error_count, color: chartColors.error },
      ],
      { dark: theme() === "dark" },
    );
  });

  // Decision time-series chart option.
  const decisionChart = createMemo(() => {
    const resp = decisionSeries.data;
    if (!resp || resp.series.length === 0) return null;
    return timeSeriesOption(
      resp.series.map((s) => ({
        name: s.name,
        data: s.data.map((p) => [p.timestamp, p.value]),
        color: s.color,
        areaStyle: true,
      })),
      { yLabel: "decisions/s", yUnit: "/s", dark: theme() === "dark" },
    );
  });

  // Latency quantile chart option.
  const latencyChart = createMemo(() => {
    const resp = latencyQuantiles.data;
    if (!resp || resp.series.length === 0) return null;
    return timeSeriesOption(
      resp.series.map((s) => ({
        name: s.name,
        data: s.data.map((p) => [p.timestamp, p.value]),
        color: s.color,
      })),
      { yLabel: "latency", yUnit: "ms", dark: theme() === "dark" },
    );
  });

  // Table columns for the policy-version breakdown.
  const columns: ColumnDef<PolicyVersionStats, any>[] = [
    {
      accessorKey: "policy_version",
      header: "Version",
      cell: (info) => <code class="text-gray-800 dark:text-gray-200 text-xs">{info.getValue() || "—"}</code>,
    },
    {
      accessorKey: "total_count",
      header: "Total",
      cell: (info) => <span class="font-mono text-gray-600 dark:text-gray-400">{info.getValue().toFixed(0)}</span>,
    },
    {
      accessorKey: "allow_count",
      header: "Allow",
      cell: (info) => <span class="font-mono text-green-600 dark:text-green-400">{info.getValue().toFixed(0)}</span>,
    },
    {
      accessorKey: "deny_count",
      header: "Deny",
      cell: (info) => <span class="font-mono text-red-600 dark:text-red-400">{info.getValue().toFixed(0)}</span>,
    },
    {
      accessorKey: "error_count",
      header: "Error",
      cell: (info) => <span class="font-mono text-orange-600 dark:text-orange-400">{info.getValue().toFixed(0)}</span>,
    },
    {
      accessorKey: "deny_rate",
      header: "Deny %",
      cell: (info) => (
        <span class="font-mono text-gray-600 dark:text-gray-400">{(info.getValue() * 100).toFixed(1)}%</span>
      ),
    },
    {
      accessorKey: "shadow_disagreement",
      header: "Shadow Disagree",
      cell: (info) => (
        <Show when={info.getValue() > 0} fallback={<span class="text-gray-300 dark:text-gray-700">—</span>}>
          <span class="font-mono text-amber-600 dark:text-amber-400">{info.getValue().toFixed(0)}</span>
        </Show>
      ),
    },
    {
      accessorKey: "canary_disagreement",
      header: "Canary Disagree",
      cell: (info) => (
        <Show when={info.getValue() > 0} fallback={<span class="text-gray-300 dark:text-gray-700">—</span>}>
          <span class="font-mono text-amber-600 dark:text-amber-400">{info.getValue().toFixed(0)}</span>
        </Show>
      ),
    },
  ];

  return (
    <div class="max-w-7xl">
      {/* Header */}
      <div class="mb-6">
        <h1 class="font-display text-2xl font-bold text-gray-900 dark:text-gray-100">Policy Analytics</h1>
        <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Per-version decision breakdowns, latency trends, and authorizer leaderboards
        </p>
      </div>

      {/* KPI row */}
      <Reveal>
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <Show when={policyBreakdown.data} fallback={<SkeletonCard height="80px" />}>
          <KPITile
            label="Total Decisions (1h)"
            value={totalDecisions()}
            accent="indigo"
          />
        </Show>
        <Show when={policyBreakdown.data} fallback={<SkeletonCard height="80px" />}>
          <KPITile
            label="Total Denies"
            value={totalDenies().toFixed(0)}
            accent="red"
          />
        </Show>
        <Show when={topVersion()} fallback={<SkeletonCard height="80px" />}>
          <KPITile
            label="Active Version"
            value={topVersion()?.policy_version ?? "—"}
            accent="indigo"
          />
        </Show>
        <Show when={topVersion()} fallback={<SkeletonCard height="80px" />}>
          <KPITile
            label="Deny Rate"
            value={`${((topVersion()?.deny_rate ?? 0) * 100).toFixed(1)}%`}
            accent="orange"
          />
        </Show>
      </div>
      </Reveal>

      {/* Charts row */}
      <Reveal index={1}>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        <Card title="Decision Rate Over Time" subtitle="Allow / deny / error per minute">
          <Show when={decisionChart()} fallback={
            <div class="p-8"><SkeletonCard height="250px" /></div>
          }>
            <div class="p-4">
              <EChart option={decisionChart()!} height="280px" />
            </div>
          </Show>
        </Card>

        <Card title="Latency Quantiles" subtitle="P50 / P90 / P99 trend">
          <Show when={latencyChart()} fallback={
            <div class="p-8"><SkeletonCard height="250px" /></div>
          }>
            <div class="p-4">
              <EChart option={latencyChart()!} height="280px" />
            </div>
          </Show>
        </Card>
      </div>
      </Reveal>

      {/* Donut + Top Authorizers row */}
      <Reveal index={2}>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <Card title="Outcome Breakdown" subtitle="Latest policy version">
          <Show when={latestDonut()} fallback={
            <div class="p-8"><SkeletonCard height="200px" /></div>
          }>
            <div class="p-4">
              <EChart option={latestDonut()!} height="220px" />
            </div>
          </Show>
        </Card>

        <Card title="Top Authorizers" subtitle="By total decisions (1h)" class="lg:col-span-2">
          <Show when={topDenyAuthors.data} fallback={
            <div class="p-8"><SkeletonCard height="200px" /></div>
          }>
            <Show when={topDenyAuthors.data!.items.length > 0} fallback={
              <EmptyState icon={ShieldOff} title="No authorizer data" description="Prometheus may not be configured" />
            }>
              <div class="p-4 space-y-2">
                <For each={topDenyAuthors.data!.items.slice(0, 8)}>
                  {(item) => (
                    <div class="flex items-center gap-3">
                      <code class="text-xs text-gray-700 dark:text-gray-300 truncate w-40">{item.label}</code>
                      <div class="flex-1 h-6 bg-gray-100 dark:bg-white/[0.06] rounded overflow-hidden">
                        <div
                          class="h-full bg-indigo-500 rounded transition-all"
                          style={{ width: `${(item.share ?? 0) * 100}%` }}
                        />
                      </div>
                      <span class="text-xs font-mono text-gray-500 dark:text-gray-400 w-16 text-right">
                        {item.count.toFixed(0)}
                      </span>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </Show>
        </Card>
      </div>
      </Reveal>

      {/* Policy version table */}
      <Reveal index={3}>
      <Card title="Policy Version Breakdown" subtitle="Per-version decision counts and disagreement rates">
        <Show when={policyBreakdown.data} fallback={
          <div class="p-4"><SkeletonCard height="200px" /></div>
        }>
          <Show when={policyBreakdown.data!.versions.length > 0} fallback={
            <EmptyState icon={FileText} title="No policy-version data" description="No decisions recorded in the selected window" />
          }>
            <DataTable
              data={policyBreakdown.data!.versions}
              columns={columns}
              pageSize={15}
            />
          </Show>
        </Show>
      </Card>
      </Reveal>
    </div>
  );
}