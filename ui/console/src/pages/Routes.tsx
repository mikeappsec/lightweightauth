import { createSignal, For, Show } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { listRoutes, createRoute, deleteRoute, type Route, type CreateRouteRequest } from "../api/client";

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
  const [tgtPath, setTgtPath] = createSignal("");

  function resetForm() {
    setShowForm(false);
    setName("");
    setSrcInstance("");
    setSrcCluster("");
    setTgtInstance("");
    setTgtCluster("");
    setTgtPath("");
  }

  function handleSubmit(e: Event) {
    e.preventDefault();
    createMut.mutate({
      name: name(),
      source: { instance: srcInstance(), cluster: srcCluster() },
      target: { instance: tgtInstance(), cluster: tgtCluster(), pathPrefix: tgtPath() || undefined },
    });
  }

  return (
    <div>
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-bold">Routes</h2>
        <button
          class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm"
          onClick={() => setShowForm(!showForm())}
        >
          {showForm() ? "Cancel" : "Create Route"}
        </button>
      </div>

      <Show when={showForm()}>
        <form onSubmit={handleSubmit} class="mb-6 p-4 bg-gray-50 rounded border space-y-3">
          <div class="grid grid-cols-2 gap-4">
            <input
              class="border rounded px-3 py-2 text-sm"
              placeholder="Route name"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              required
            />
            <div />
            <input
              class="border rounded px-3 py-2 text-sm"
              placeholder="Source instance"
              value={srcInstance()}
              onInput={(e) => setSrcInstance(e.currentTarget.value)}
              required
            />
            <input
              class="border rounded px-3 py-2 text-sm"
              placeholder="Source cluster"
              value={srcCluster()}
              onInput={(e) => setSrcCluster(e.currentTarget.value)}
              required
            />
            <input
              class="border rounded px-3 py-2 text-sm"
              placeholder="Target instance"
              value={tgtInstance()}
              onInput={(e) => setTgtInstance(e.currentTarget.value)}
              required
            />
            <input
              class="border rounded px-3 py-2 text-sm"
              placeholder="Target cluster"
              value={tgtCluster()}
              onInput={(e) => setTgtCluster(e.currentTarget.value)}
              required
            />
            <input
              class="border rounded px-3 py-2 text-sm"
              placeholder="Path prefix (optional)"
              value={tgtPath()}
              onInput={(e) => setTgtPath(e.currentTarget.value)}
            />
          </div>
          <button
            type="submit"
            class="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 text-sm"
            disabled={createMut.isPending}
          >
            {createMut.isPending ? "Creating..." : "Create"}
          </button>
        </form>
      </Show>

      <Show when={routesQuery.isLoading}>
        <p class="text-gray-500">Loading routes...</p>
      </Show>

      <Show when={routesQuery.data}>
        <table class="w-full text-sm border-collapse">
          <thead>
            <tr class="border-b text-left text-gray-600">
              <th class="py-2 px-3">Name</th>
              <th class="py-2 px-3">Source</th>
              <th class="py-2 px-3">Target</th>
              <th class="py-2 px-3">Health</th>
              <th class="py-2 px-3">Latency</th>
              <th class="py-2 px-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            <For each={routesQuery.data}>
              {(route: Route) => (
                <tr class="border-b hover:bg-gray-50">
                  <td class="py-2 px-3 font-medium">{route.name}</td>
                  <td class="py-2 px-3">{route.source.instance}@{route.source.cluster}</td>
                  <td class="py-2 px-3">
                    {route.target.instance}@{route.target.cluster}
                    {route.target.pathPrefix && <span class="text-gray-500 ml-1">{route.target.pathPrefix}</span>}
                  </td>
                  <td class="py-2 px-3">
                    <span
                      class={`inline-block w-2 h-2 rounded-full mr-1 ${route.status.healthy ? "bg-green-500" : "bg-red-500"}`}
                    />
                    {route.status.healthy ? "Healthy" : "Unhealthy"}
                  </td>
                  <td class="py-2 px-3">
                    {route.status.latencyMs != null ? `${route.status.latencyMs}ms` : "—"}
                  </td>
                  <td class="py-2 px-3">
                    <button
                      class="text-red-600 hover:underline text-xs"
                      onClick={() => deleteMut.mutate(route.name)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Show>
    </div>
  );
}
