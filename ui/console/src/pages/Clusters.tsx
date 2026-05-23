import { createSignal } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { listClusters, addCluster, deleteCluster } from "../api/client";
import type { ClusterAddRequest } from "../api/client";

export default function Clusters() {
  const queryClient = useQueryClient();
  const [showAdd, setShowAdd] = createSignal(false);

  const clusters = createQuery(() => ({
    queryKey: ["clusters"],
    queryFn: () => listClusters(),
    refetchInterval: 15_000,
  }));

  const deleteMut = createMutation(() => ({
    mutationFn: (name: string) => deleteCluster(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["clusters"] });
      queryClient.invalidateQueries({ queryKey: ["instances"] });
    },
  }));

  return (
    <div>
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-semibold">Clusters</h2>
        <button
          class="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700"
          onClick={() => setShowAdd(true)}
        >
          Add Cluster
        </button>
      </div>

      {showAdd() && (
        <AddClusterDialog
          onClose={() => setShowAdd(false)}
          onAdded={() => {
            setShowAdd(false);
            queryClient.invalidateQueries({ queryKey: ["clusters"] });
          }}
        />
      )}

      {clusters.isLoading && <p class="text-gray-500">Loading…</p>}
      {clusters.isError && (
        <p class="text-red-600">Error: {(clusters.error as Error).message}</p>
      )}
      {clusters.data && clusters.data.length === 0 && (
        <p class="text-gray-500">No clusters registered yet.</p>
      )}
      {clusters.data && clusters.data.length > 0 && (
        <table class="w-full text-sm border border-gray-200 rounded">
          <thead class="bg-gray-100">
            <tr>
              <th class="text-left px-3 py-2">Name</th>
              <th class="text-left px-3 py-2">API Server</th>
              <th class="text-left px-3 py-2">Instances</th>
              <th class="text-left px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {clusters.data.map((c) => (
              <tr class="border-t border-gray-100 hover:bg-gray-50">
                <td class="px-3 py-2 font-mono">{c.name}</td>
                <td class="px-3 py-2 text-xs text-gray-600">
                  {c.apiServer || "local"}
                </td>
                <td class="px-3 py-2">{c.instanceCount}</td>
                <td class="px-3 py-2">
                  <button
                    class="text-red-600 hover:text-red-800 text-xs"
                    onClick={() => deleteMut.mutate(c.name)}
                    disabled={deleteMut.isPending}
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

function AddClusterDialog(props: { onClose: () => void; onAdded: () => void }) {
  const [name, setName] = createSignal("");
  const [apiServer, setApiServer] = createSignal("");
  const [token, setToken] = createSignal("");
  const [caBundle, setCaBundle] = createSignal("");
  const [kubeconfigPath, setKubeconfigPath] = createSignal("");
  const [error, setError] = createSignal("");

  const mutation = createMutation(() => ({
    mutationFn: (req: ClusterAddRequest) => addCluster(req),
    onSuccess: () => props.onAdded(),
    onError: (err: Error) => setError(err.message),
  }));

  const handleSubmit = (e: Event) => {
    e.preventDefault();
    setError("");
    const req: ClusterAddRequest = { name: name() };
    if (kubeconfigPath()) {
      req.kubeconfigPath = kubeconfigPath();
    } else {
      req.apiServer = apiServer();
      if (token()) req.token = token();
      if (caBundle()) req.caBundle = caBundle();
    }
    mutation.mutate(req);
  };

  return (
    <div class="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl p-6 w-full max-w-md">
        <h3 class="text-lg font-medium mb-4">Add Remote Cluster</h3>
        <form onSubmit={handleSubmit} class="space-y-3">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Name *</label>
            <input
              type="text"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              class="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
              required
            />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">API Server</label>
            <input
              type="text"
              value={apiServer()}
              onInput={(e) => setApiServer(e.currentTarget.value)}
              placeholder="https://api.cluster.example.com:6443"
              class="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
            />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Bearer Token</label>
            <input
              type="password"
              value={token()}
              onInput={(e) => setToken(e.currentTarget.value)}
              class="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
            />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">CA Bundle (PEM)</label>
            <textarea
              value={caBundle()}
              onInput={(e) => setCaBundle(e.currentTarget.value)}
              class="w-full border border-gray-300 rounded px-3 py-1.5 text-sm h-20 font-mono"
            />
          </div>
          <div class="border-t pt-3 mt-3">
            <label class="block text-sm text-gray-600 mb-1">
              Or: Kubeconfig Path (on control-plane host)
            </label>
            <input
              type="text"
              value={kubeconfigPath()}
              onInput={(e) => setKubeconfigPath(e.currentTarget.value)}
              placeholder="/etc/lwauth/kubeconfigs/cluster-b.yaml"
              class="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
            />
          </div>
          {error() && <p class="text-red-600 text-sm">{error()}</p>}
          <div class="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={props.onClose}
              class="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              class="px-4 py-1.5 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
            >
              {mutation.isPending ? "Adding…" : "Add Cluster"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
