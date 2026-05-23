import { createQuery } from "@tanstack/solid-query";
import { useParams, A } from "@solidjs/router";
import { getInstance } from "../api/client";

export default function InstanceDetail() {
  const params = useParams<{ cluster: string; name: string }>();

  const instance = createQuery(() => ({
    queryKey: ["instance", params.cluster, params.name],
    queryFn: () => getInstance(params.cluster, params.name),
    refetchInterval: 10_000,
  }));

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
    </div>
  );
}
