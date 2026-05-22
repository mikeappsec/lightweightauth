import { createQuery } from "@tanstack/solid-query";
import { getHealth, listInstances } from "../api/client";

export default function Dashboard() {
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

  return (
    <div>
      <h2 class="text-2xl font-semibold mb-6">Dashboard</h2>

      {/* KPI cards */}
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <KPICard
          label="Total Instances"
          value={health.data?.totalInstances ?? "—"}
        />
        <KPICard
          label="Healthy"
          value={health.data?.healthyInstances ?? "—"}
          color="text-green-600"
        />
        <KPICard
          label="Unhealthy"
          value={
            health.data
              ? health.data.totalInstances - health.data.healthyInstances
              : "—"
          }
          color="text-red-600"
        />
      </div>

      {/* Instance summary table */}
      <h3 class="text-lg font-medium mb-3">Instances</h3>
      {instances.isLoading && <p class="text-gray-500">Loading…</p>}
      {instances.isError && (
        <p class="text-red-600">Error: {(instances.error as Error).message}</p>
      )}
      {instances.data && instances.data.length === 0 && (
        <p class="text-gray-500">No instances discovered yet.</p>
      )}
      {instances.data && instances.data.length > 0 && (
        <table class="w-full text-sm border border-gray-200 rounded">
          <thead class="bg-gray-100">
            <tr>
              <th class="text-left px-3 py-2">Name</th>
              <th class="text-left px-3 py-2">Cluster</th>
              <th class="text-left px-3 py-2">Status</th>
              <th class="text-left px-3 py-2">Source</th>
            </tr>
          </thead>
          <tbody>
            {instances.data.map((inst) => (
              <tr class="border-t border-gray-100 hover:bg-gray-50">
                <td class="px-3 py-2 font-mono">{inst.name}</td>
                <td class="px-3 py-2">{inst.cluster}</td>
                <td class="px-3 py-2">
                  <StatusBadge healthy={inst.status.healthy} />
                </td>
                <td class="px-3 py-2 text-gray-500">{inst.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function KPICard(props: { label: string; value: number | string; color?: string }) {
  return (
    <div class="bg-white rounded-lg border border-gray-200 p-4">
      <p class="text-sm text-gray-500">{props.label}</p>
      <p class={`text-3xl font-bold mt-1 ${props.color ?? "text-gray-900"}`}>
        {props.value}
      </p>
    </div>
  );
}

function StatusBadge(props: { healthy: boolean }) {
  return (
    <span
      class={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
        props.healthy
          ? "bg-green-100 text-green-800"
          : "bg-red-100 text-red-800"
      }`}
    >
      {props.healthy ? "Healthy" : "Unhealthy"}
    </span>
  );
}
