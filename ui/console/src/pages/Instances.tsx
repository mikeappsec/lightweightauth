import { createSignal } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { listInstances, registerInstance, deleteInstance } from "../api/client";
import type { RegisterRequest } from "../api/client";
import { A } from "@solidjs/router";
import { Plus, Link, Trash2, Server } from "lucide-solid";
import CreateInstanceWizard from "./CreateInstanceWizard";

export default function Instances() {
  const queryClient = useQueryClient();

  const instances = createQuery(() => ({
    queryKey: ["instances"],
    queryFn: () => listInstances(),
    refetchInterval: 10_000,
  }));

  const [showCreate, setShowCreate] = createSignal(false);
  const [showLink, setShowLink] = createSignal(false);

  const deleteMut = createMutation(() => ({
    mutationFn: ({ cluster, name }: { cluster: string; name: string }) =>
      deleteInstance(cluster, name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["instances"] });
    },
  }));

  return (
    <div class="max-w-7xl">
      {/* Page header */}
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-2xl font-bold text-gray-900 dark:text-gray-100">Instances</h1>
          <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Manage your LightweightAuth data-plane deployments</p>
        </div>
        <div class="flex gap-2">
          <button
            class="inline-flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 shadow-sm"
            onClick={() => setShowCreate(true)}
          >
            <Plus size={16} />
            Create Instance
          </button>
          <button
            class="inline-flex items-center gap-2 px-4 py-2.5 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800"
            onClick={() => setShowLink(true)}
          >
            <Link size={16} />
            Link External
          </button>
        </div>
      </div>

      {showCreate() && (
        <CreateInstanceWizard
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            queryClient.invalidateQueries({ queryKey: ["instances"] });
          }}
        />
      )}

      {showLink() && (
        <LinkExternalDialog
          onClose={() => setShowLink(false)}
          onCreated={() => {
            setShowLink(false);
            queryClient.invalidateQueries({ queryKey: ["instances"] });
          }}
        />
      )}

      {/* Table card */}
      <div class="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm overflow-hidden">
        {instances.isLoading && (
          <div class="px-5 py-12 text-center text-sm text-gray-400 dark:text-gray-500">Loading instances…</div>
        )}
        {instances.isError && (
          <div class="px-5 py-12 text-center text-sm text-red-500 dark:text-red-400">
            Failed to load: {(instances.error as Error).message}
          </div>
        )}
        {instances.data && instances.data.length === 0 && (
          <div class="px-5 py-16 text-center">
            <Server size={40} class="mx-auto text-gray-300 dark:text-gray-700 mb-3" />
            <p class="text-sm font-medium text-gray-700 dark:text-gray-300">No instances yet</p>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Create your first instance to get started</p>
          </div>
        )}
        {instances.data && instances.data.length > 0 && (
          <table class="w-full text-sm">
            <thead>
              <tr class="bg-gray-50/80 dark:bg-gray-800/50 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider border-b border-gray-100 dark:border-gray-800">
                <th class="px-5 py-3">Instance</th>
                <th class="px-5 py-3">Cluster</th>
                <th class="px-5 py-3">Namespace</th>
                <th class="px-5 py-3">Status</th>
                <th class="px-5 py-3">Config</th>
                <th class="px-5 py-3">Replicas</th>
                <th class="px-5 py-3">Source</th>
                <th class="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
              {instances.data.map((inst) => (
                <tr class="hover:bg-gray-50/50 dark:hover:bg-gray-800/40 transition-colors">
                  <td class="px-5 py-3.5">
                    <A
                      href={`/instances/${inst.cluster}/${inst.name}`}
                      class="text-sm font-medium text-gray-900 dark:text-gray-100 hover:text-blue-600 dark:hover:text-blue-400"
                    >
                      {inst.name}
                    </A>
                  </td>
                  <td class="px-5 py-3.5 text-gray-600 dark:text-gray-400">{inst.cluster}</td>
                  <td class="px-5 py-3.5 text-gray-500 dark:text-gray-400 text-xs">{inst.namespace ?? "—"}</td>
                  <td class="px-5 py-3.5">
                    <span
                      class={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${
                        inst.status.healthy
                          ? "bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400"
                          : "bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400"
                      }`}
                    >
                      <span
                        class={`w-1.5 h-1.5 rounded-full ${
                          inst.status.healthy ? "bg-green-500" : "bg-red-500"
                        }`}
                      />
                      {inst.status.healthy ? "Healthy" : "Unhealthy"}
                    </span>
                  </td>
                  <td class="px-5 py-3.5 font-mono text-xs text-gray-500 dark:text-gray-400">
                    {inst.status.configVersion
                      ? inst.status.configVersion.slice(0, 8)
                      : "—"}
                  </td>
                  <td class="px-5 py-3.5 text-gray-600 dark:text-gray-400">{inst.status.replicas ?? "—"}</td>
                  <td class="px-5 py-3.5">
                    <span class="text-xs text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded-full">
                      {inst.source}
                    </span>
                  </td>
                  <td class="px-5 py-3.5 text-right">
                    <button
                      class="inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 font-medium"
                      onClick={() => {
                        if (!confirm(`Remove instance "${inst.name}"? This tears down its Deployment, Service, and config in the cluster.`)) return;
                        deleteMut.mutate({ cluster: inst.cluster, name: inst.name });
                      }}
                    >
                      <Trash2 size={13} />
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function LinkExternalDialog(props: { onClose: () => void; onCreated: () => void }) {
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
    <div class="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50">
      <div class="bg-white dark:bg-gray-900 rounded-2xl shadow-2xl p-6 w-full max-w-md border border-gray-100 dark:border-gray-800">
        <h3 class="text-lg font-bold text-gray-900 dark:text-gray-100 mb-1">Link External Instance</h3>
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-5">
          Register a pre-existing lwauth instance not managed by this control plane.
        </p>
        <form onSubmit={handleSubmit} class="flex flex-col gap-4">
          <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
            Name
            <input
              type="text"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
              required
            />
          </label>
          <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
            Cluster
            <input
              type="text"
              value={cluster()}
              onInput={(e) => setCluster(e.currentTarget.value)}
              class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
              required
            />
          </label>
          <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
            Admin URL
            <input
              type="url"
              value={adminUrl()}
              onInput={(e) => setAdminUrl(e.currentTarget.value)}
              placeholder="http://lwauth.ns.svc.cluster.local:8080"
              class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
              required
            />
          </label>
          {error() && <p class="text-red-600 dark:text-red-400 text-xs font-medium">{error()}</p>}
          <div class="flex justify-end gap-3 mt-2 pt-4 border-t border-gray-100 dark:border-gray-800">
            <button
              type="button"
              onClick={props.onClose}
              class="px-4 py-2.5 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              class="px-5 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 shadow-sm"
              disabled={mutation.isPending}
            >
              {mutation.isPending ? "Linking…" : "Link Instance"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
