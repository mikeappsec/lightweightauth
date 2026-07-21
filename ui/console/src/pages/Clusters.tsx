import { createSignal } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { listClusters, addCluster, deleteCluster } from "../api/client";
import type { ClusterAddRequest } from "../api/client";
import { Plus, Trash2, Globe } from "lucide-solid";
import { Reveal } from "../components/Reveal";

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

  function handleDelete(name: string) {
    if (!confirm(`Remove cluster "${name}"? Instances discovered from it will disappear from this console.`)) return;
    deleteMut.mutate(name);
  }

  return (
    <div class="max-w-7xl">
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="font-display text-2xl font-bold text-gray-900 dark:text-gray-100">Clusters</h1>
          <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Kubernetes clusters this control plane discovers instances from</p>
        </div>
        <button
          class="inline-flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm font-medium rounded-lg shadow-[0_0_20px_-6px_rgba(99,102,241,0.5)] transition-all"
          onClick={() => setShowAdd(true)}
        >
          <Plus size={16} />
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

      <Reveal>
      <div class="bg-white dark:bg-white/[0.02] rounded-2xl border border-gray-200 dark:border-white/[0.08] shadow-sm dark:shadow-none overflow-hidden">
        {clusters.isLoading && (
          <div class="px-5 py-12 text-center text-sm text-gray-400 dark:text-gray-500">Loading clusters…</div>
        )}
        {clusters.isError && (
          <div class="px-5 py-12 text-center text-sm text-red-500 dark:text-red-400">
            Failed to load: {(clusters.error as Error).message}
          </div>
        )}
        {clusters.data && clusters.data.length === 0 && (
          <div class="px-5 py-16 text-center">
            <Globe size={40} class="mx-auto text-gray-300 dark:text-gray-700 mb-3" />
            <p class="text-sm font-medium text-gray-700 dark:text-gray-300">No clusters registered yet</p>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Add a remote cluster to discover its instances</p>
          </div>
        )}
        {clusters.data && clusters.data.length > 0 && (
          <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="bg-gray-50/80 dark:bg-white/[0.03] text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider border-b border-gray-100 dark:border-white/[0.06]">
                <th class="px-5 py-3">Name</th>
                <th class="px-5 py-3">API Server</th>
                <th class="px-5 py-3">Instances</th>
                <th class="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-white/[0.06]">
              {clusters.data.map((c) => (
                <tr class="hover:bg-gray-50/50 dark:hover:bg-white/[0.03] transition-colors">
                  <td class="px-5 py-3.5 font-medium text-gray-900 dark:text-gray-100">{c.name}</td>
                  <td class="px-5 py-3.5 text-xs text-gray-500 dark:text-gray-400 font-mono">{c.apiServer || "local"}</td>
                  <td class="px-5 py-3.5 text-gray-600 dark:text-gray-400">{c.instanceCount}</td>
                  <td class="px-5 py-3.5 text-right">
                    <button
                      class="inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 font-medium disabled:opacity-40"
                      onClick={() => handleDelete(c.name)}
                      disabled={deleteMut.isPending}
                    >
                      <Trash2 size={13} />
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>
      </Reveal>
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
    <div class="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div class="bg-white dark:bg-[#12141f] rounded-2xl shadow-2xl p-6 w-full max-w-md border border-gray-100 dark:border-white/[0.08] animate-scale-in max-h-[90vh] overflow-y-auto">
        <h3 class="text-lg font-bold text-gray-900 dark:text-gray-100 mb-1">Add Remote Cluster</h3>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-5">
          Register a Kubernetes cluster for this control plane to discover instances from.
        </p>
        <form onSubmit={handleSubmit} class="flex flex-col gap-4">
          <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
            Name
            <input
              type="text"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              class="mt-1.5 block w-full border border-gray-200 dark:border-white/[0.12] bg-white dark:bg-white/[0.04] text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 outline-none transition-all"
              required
            />
          </label>
          <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
            API Server
            <input
              type="text"
              value={apiServer()}
              onInput={(e) => setApiServer(e.currentTarget.value)}
              placeholder="https://api.cluster.example.com:6443"
              class="mt-1.5 block w-full border border-gray-200 dark:border-white/[0.12] bg-white dark:bg-white/[0.04] text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 outline-none transition-all"
            />
          </label>
          <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
            Bearer Token
            <input
              type="password"
              value={token()}
              onInput={(e) => setToken(e.currentTarget.value)}
              class="mt-1.5 block w-full border border-gray-200 dark:border-white/[0.12] bg-white dark:bg-white/[0.04] text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 outline-none transition-all"
            />
          </label>
          <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
            CA Bundle (PEM)
            <textarea
              value={caBundle()}
              onInput={(e) => setCaBundle(e.currentTarget.value)}
              class="mt-1.5 block w-full border border-gray-200 dark:border-white/[0.12] bg-white dark:bg-white/[0.04] text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm h-20 font-mono focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 outline-none transition-all"
            />
          </label>
          <label class="text-xs font-medium text-gray-700 dark:text-gray-300 border-t border-gray-100 dark:border-white/[0.08] pt-4">
            Or: Kubeconfig Path (on control-plane host)
            <input
              type="text"
              value={kubeconfigPath()}
              onInput={(e) => setKubeconfigPath(e.currentTarget.value)}
              placeholder="/etc/lwauth/kubeconfigs/cluster-b.yaml"
              class="mt-1.5 block w-full border border-gray-200 dark:border-white/[0.12] bg-white dark:bg-white/[0.04] text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-500 outline-none transition-all"
            />
          </label>
          {error() && <p class="text-red-600 dark:text-red-400 text-xs font-medium">{error()}</p>}
          <div class="flex justify-end gap-3 mt-2 pt-4 border-t border-gray-100 dark:border-white/[0.08]">
            <button
              type="button"
              onClick={props.onClose}
              class="px-4 py-2.5 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-white/[0.06] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              class="px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm font-medium rounded-lg disabled:opacity-50 shadow-sm transition-all"
            >
              {mutation.isPending ? "Adding…" : "Add Cluster"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
