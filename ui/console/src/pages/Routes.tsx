import { createSignal, For, Show } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { listRoutes, createRoute, deleteRoute, type Route, type CreateRouteRequest } from "../api/client";
import { Plus, Trash2, Route as RouteIcon } from "lucide-solid";

export default function Routes() {
  const queryClient = useQueryClient();

  const routesQuery = createQuery(() => ({
    queryKey: ["routes"],
    queryFn: listRoutes,
    refetchInterval: 5000,
  }));

  const createMut = createMutation(() => ({
    mutationFn: (req: CreateRouteRequest) => createRoute(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["routes"] });
      resetForm();
    },
    onError: (err: Error) => setFormError(err.message),
  }));

  const deleteMut = createMutation(() => ({
    mutationFn: (name: string) => deleteRoute(name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["routes"] }),
  }));

  const [showForm, setShowForm] = createSignal(false);
  const [name, setName] = createSignal("");
  const [srcInstance, setSrcInstance] = createSignal("");
  const [srcCluster, setSrcCluster] = createSignal("");
  const [tgtInstance, setTgtInstance] = createSignal("");
  const [tgtCluster, setTgtCluster] = createSignal("");
  const [pathPrefix, setPathPrefix] = createSignal("");
  const [formError, setFormError] = createSignal("");

  function resetForm() {
    setShowForm(false);
    setName("");
    setSrcInstance("");
    setSrcCluster("");
    setTgtInstance("");
    setTgtCluster("");
    setPathPrefix("");
    setFormError("");
  }

  function handleSubmit(e: Event) {
    e.preventDefault();
    setFormError("");
    createMut.mutate({
      name: name(),
      source: { instance: srcInstance(), cluster: srcCluster() },
      target: { instance: tgtInstance(), cluster: tgtCluster() },
      pathPrefix: pathPrefix(),
    });
  }

  function handleDelete(name: string) {
    if (!confirm(`Delete route "${name}"? This cannot be undone.`)) return;
    deleteMut.mutate(name);
  }

  return (
    <div class="max-w-7xl">
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-2xl font-bold text-gray-900 dark:text-gray-100">Routes</h1>
          <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Proxy routes between LightweightAuth instances</p>
        </div>
        <button
          class="inline-flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 shadow-sm"
          onClick={() => (showForm() ? resetForm() : setShowForm(true))}
        >
          <Plus size={16} />
          Create Route
        </button>
      </div>

      <Show when={showForm()}>
        <form
          onSubmit={handleSubmit}
          class="mb-6 bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-5 space-y-4"
        >
          <div class="grid grid-cols-2 gap-4">
            <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
              Route name
              <input
                class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
                placeholder="payments-to-orders"
                value={name()}
                onInput={(e) => setName(e.currentTarget.value)}
                required
              />
            </label>
            <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
              Path prefix
              <input
                class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
                placeholder="/api/orders"
                value={pathPrefix()}
                onInput={(e) => setPathPrefix(e.currentTarget.value)}
                required
              />
            </label>
            <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
              Source instance
              <input
                class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
                value={srcInstance()}
                onInput={(e) => setSrcInstance(e.currentTarget.value)}
                required
              />
            </label>
            <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
              Source cluster
              <input
                class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
                value={srcCluster()}
                onInput={(e) => setSrcCluster(e.currentTarget.value)}
                required
              />
            </label>
            <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
              Target instance
              <input
                class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
                value={tgtInstance()}
                onInput={(e) => setTgtInstance(e.currentTarget.value)}
                required
              />
            </label>
            <label class="text-xs font-medium text-gray-700 dark:text-gray-300">
              Target cluster
              <input
                class="mt-1.5 block w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
                value={tgtCluster()}
                onInput={(e) => setTgtCluster(e.currentTarget.value)}
                required
              />
            </label>
          </div>
          {formError() && <p class="text-red-600 dark:text-red-400 text-xs font-medium">{formError()}</p>}
          <div class="flex justify-end gap-3 pt-2 border-t border-gray-100 dark:border-gray-800">
            <button
              type="button"
              onClick={resetForm}
              class="px-4 py-2.5 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              class="px-5 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 shadow-sm"
              disabled={createMut.isPending}
            >
              {createMut.isPending ? "Creating…" : "Create Route"}
            </button>
          </div>
        </form>
      </Show>

      <div class="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm overflow-hidden">
        {routesQuery.isLoading && (
          <div class="px-5 py-12 text-center text-sm text-gray-400 dark:text-gray-500">Loading routes…</div>
        )}
        {routesQuery.isError && (
          <div class="px-5 py-12 text-center text-sm text-red-500 dark:text-red-400">
            Failed to load: {(routesQuery.error as Error).message}
          </div>
        )}
        {routesQuery.data && routesQuery.data.length === 0 && (
          <div class="px-5 py-16 text-center">
            <RouteIcon size={40} class="mx-auto text-gray-300 dark:text-gray-700 mb-3" />
            <p class="text-sm font-medium text-gray-700 dark:text-gray-300">No routes yet</p>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Create a route to proxy traffic between instances</p>
          </div>
        )}
        {routesQuery.data && routesQuery.data.length > 0 && (
          <table class="w-full text-sm">
            <thead>
              <tr class="bg-gray-50/80 dark:bg-gray-800/50 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider border-b border-gray-100 dark:border-gray-800">
                <th class="px-5 py-3">Name</th>
                <th class="px-5 py-3">Source</th>
                <th class="px-5 py-3">Target</th>
                <th class="px-5 py-3">Path Prefix</th>
                <th class="px-5 py-3">Health</th>
                <th class="px-5 py-3">Latency (p99)</th>
                <th class="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
              <For each={routesQuery.data}>
                {(route: Route) => (
                  <tr class="hover:bg-gray-50/50 dark:hover:bg-gray-800/40 transition-colors">
                    <td class="px-5 py-3.5 font-medium text-gray-900 dark:text-gray-100">{route.name}</td>
                    <td class="px-5 py-3.5 text-gray-600 dark:text-gray-400">
                      {route.source.instance}<span class="text-gray-300 dark:text-gray-700">@</span>{route.source.cluster}
                    </td>
                    <td class="px-5 py-3.5 text-gray-600 dark:text-gray-400">
                      {route.target.instance}<span class="text-gray-300 dark:text-gray-700">@</span>{route.target.cluster}
                    </td>
                    <td class="px-5 py-3.5 font-mono text-xs text-gray-500 dark:text-gray-400">{route.pathPrefix}</td>
                    <td class="px-5 py-3.5">
                      <span
                        class={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${
                          route.status.healthy
                            ? "bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400"
                            : "bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400"
                        }`}
                        title={route.status.error}
                      >
                        <span class={`w-1.5 h-1.5 rounded-full ${route.status.healthy ? "bg-green-500" : "bg-red-500"}`} />
                        {route.status.healthy ? "Healthy" : "Unhealthy"}
                      </span>
                    </td>
                    <td class="px-5 py-3.5 text-gray-600 dark:text-gray-400 font-mono text-xs">
                      {route.status.latencyP99 ?? "—"}
                    </td>
                    <td class="px-5 py-3.5 text-right">
                      <button
                        class="inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 font-medium"
                        onClick={() => handleDelete(route.name)}
                        disabled={deleteMut.isPending}
                      >
                        <Trash2 size={13} />
                        Delete
                      </button>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
