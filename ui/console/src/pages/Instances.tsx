import { createSignal } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { listInstances, registerInstance, deleteInstance } from "../api/client";
import type { RegisterRequest } from "../api/client";
import { A } from "@solidjs/router";

export default function Instances() {
  const queryClient = useQueryClient();

  const instances = createQuery(() => ({
    queryKey: ["instances"],
    queryFn: () => listInstances(),
    refetchInterval: 10_000,
  }));

  const [showCreate, setShowCreate] = createSignal(false);

  const deleteMut = createMutation(() => ({
    mutationFn: ({ cluster, name }: { cluster: string; name: string }) =>
      deleteInstance(cluster, name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["instances"] });
    },
  }));

  return (
    <div>
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-semibold">Instances</h2>
        <button
          class="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700"
          onClick={() => setShowCreate(true)}
        >
          Register Instance
        </button>
      </div>

      {showCreate() && (
        <CreateInstanceDialog
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            queryClient.invalidateQueries({ queryKey: ["instances"] });
          }}
        />
      )}

      {instances.isLoading && <p class="text-gray-500">Loading…</p>}
      {instances.isError && (
        <p class="text-red-600">Error: {(instances.error as Error).message}</p>
      )}
      {instances.data && (
        <table class="w-full text-sm border border-gray-200 rounded">
          <thead class="bg-gray-100">
            <tr>
              <th class="text-left px-3 py-2">Name</th>
              <th class="text-left px-3 py-2">Cluster</th>
              <th class="text-left px-3 py-2">Namespace</th>
              <th class="text-left px-3 py-2">Status</th>
              <th class="text-left px-3 py-2">Config</th>
              <th class="text-left px-3 py-2">Replicas</th>
              <th class="text-left px-3 py-2">Source</th>
              <th class="text-left px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {instances.data.map((inst) => (
              <tr class="border-t border-gray-100 hover:bg-gray-50">
                <td class="px-3 py-2">
                  <A
                    href={`/instances/${inst.cluster}/${inst.name}`}
                    class="text-blue-600 hover:underline font-mono"
                  >
                    {inst.name}
                  </A>
                </td>
                <td class="px-3 py-2">{inst.cluster}</td>
                <td class="px-3 py-2 text-gray-500">{inst.namespace ?? "—"}</td>
                <td class="px-3 py-2">
                  <span
                    class={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                      inst.status.healthy
                        ? "bg-green-100 text-green-800"
                        : "bg-red-100 text-red-800"
                    }`}
                  >
                    {inst.status.healthy ? "Healthy" : "Unhealthy"}
                  </span>
                </td>
                <td class="px-3 py-2 font-mono text-xs">
                  {inst.status.configVersion
                    ? inst.status.configVersion.slice(0, 12)
                    : "—"}
                </td>
                <td class="px-3 py-2">{inst.status.replicas ?? "—"}</td>
                <td class="px-3 py-2 text-gray-500">{inst.source}</td>
                <td class="px-3 py-2">
                  <button
                    class="text-red-600 hover:text-red-800 text-xs"
                    onClick={() =>
                      deleteMut.mutate({ cluster: inst.cluster, name: inst.name })
                    }
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function CreateInstanceDialog(props: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = createSignal("");
  const [cluster, setCluster] = createSignal("local");
  const [adminUrl, setAdminUrl] = createSignal("");
  const [error, setError] = createSignal("");

  const mutation = createMutation(() => ({
    mutationFn: (req: RegisterRequest) => registerInstance(req),
    onSuccess: () => props.onCreated(),
    onError: (err: Error) => setError(err.message),
  }));

  const handleSubmit = (e: Event) => {
    e.preventDefault();
    setError("");
    mutation.mutate({
      name: name(),
      cluster: cluster(),
      adminUrl: adminUrl(),
    });
  };

  return (
    <div class="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-lg p-6 w-full max-w-md">
        <h3 class="text-lg font-semibold mb-4">Register Instance</h3>
        <form onSubmit={handleSubmit} class="flex flex-col gap-3">
          <label class="text-sm font-medium">
            Name
            <input
              type="text"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              class="mt-1 block w-full border border-gray-300 rounded px-3 py-2 text-sm"
              required
            />
          </label>
          <label class="text-sm font-medium">
            Cluster
            <input
              type="text"
              value={cluster()}
              onInput={(e) => setCluster(e.currentTarget.value)}
              class="mt-1 block w-full border border-gray-300 rounded px-3 py-2 text-sm"
              required
            />
          </label>
          <label class="text-sm font-medium">
            Admin URL
            <input
              type="url"
              value={adminUrl()}
              onInput={(e) => setAdminUrl(e.currentTarget.value)}
              placeholder="http://lwauth.ns.svc.cluster.local:8081"
              class="mt-1 block w-full border border-gray-300 rounded px-3 py-2 text-sm"
              required
            />
          </label>
          {error() && <p class="text-red-600 text-sm">{error()}</p>}
          <div class="flex justify-end gap-2 mt-2">
            <button
              type="button"
              onClick={props.onClose}
              class="px-4 py-2 text-sm text-gray-600 hover:text-gray-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              class="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
              disabled={mutation.isPending}
            >
              {mutation.isPending ? "Registering…" : "Register"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
