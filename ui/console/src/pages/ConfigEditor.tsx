import { createSignal, Show } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { useParams } from "@solidjs/router";
import {
  getConfig,
  pushConfig,
  getConfigHistory,
  rollbackConfig,
} from "../api/client";
import type { ConfigVersion } from "../api/client";

export default function ConfigEditor() {
  const params = useParams<{ cluster: string; name: string }>();
  const queryClient = useQueryClient();
  const [editorContent, setEditorContent] = createSignal("");
  const [comment, setComment] = createSignal("");
  const [validationError, setValidationError] = createSignal("");
  const [showHistory, setShowHistory] = createSignal(false);
  const [diffFrom, setDiffFrom] = createSignal<ConfigVersion | null>(null);

  const config = createQuery(() => ({
    queryKey: ["config", params.cluster, params.name],
    queryFn: () => getConfig(params.cluster, params.name),
    refetchInterval: 30_000,
  }));

  const history = createQuery(() => ({
    queryKey: ["config-history", params.cluster, params.name],
    queryFn: () => getConfigHistory(params.cluster, params.name),
    enabled: showHistory(),
  }));

  // Seed editor with current config when loaded.
  const loadedVersion = () => {
    if (config.data && !editorContent()) {
      setEditorContent(config.data.content);
    }
    return config.data;
  };

  const pushMut = createMutation(() => ({
    mutationFn: () =>
      pushConfig(params.cluster, params.name, {
        content: editorContent(),
        comment: comment(),
      }),
    onSuccess: () => {
      setComment("");
      setValidationError("");
      queryClient.invalidateQueries({ queryKey: ["config", params.cluster, params.name] });
      queryClient.invalidateQueries({ queryKey: ["config-history", params.cluster, params.name] });
    },
    onError: (err: Error) => setValidationError(err.message),
  }));

  const rollbackMut = createMutation(() => ({
    mutationFn: (version: number) =>
      rollbackConfig(params.cluster, params.name, version),
    onSuccess: (v) => {
      setEditorContent(v.content);
      queryClient.invalidateQueries({ queryKey: ["config", params.cluster, params.name] });
      queryClient.invalidateQueries({ queryKey: ["config-history", params.cluster, params.name] });
    },
  }));

  const validateJSON = (text: string) => {
    try {
      JSON.parse(text);
      setValidationError("");
    } catch (e: any) {
      setValidationError(e.message);
    }
  };

  const handleEditorChange = (value: string) => {
    setEditorContent(value);
    validateJSON(value);
  };

  return (
    <div>
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-2xl font-semibold">
          Config: <span class="font-mono">{params.cluster}/{params.name}</span>
        </h2>
        <button
          class="px-3 py-1.5 text-sm border border-gray-300 rounded hover:bg-gray-50"
          onClick={() => setShowHistory(!showHistory())}
        >
          {showHistory() ? "Hide History" : "Show History"}
        </button>
      </div>

      {config.isLoading && <p class="text-gray-500">Loading config…</p>}
      {config.isError && config.error?.message !== "no config stored for this instance" && (
        <p class="text-red-600">Error: {(config.error as Error).message}</p>
      )}

      {/* Seed editor on initial load */}
      {void loadedVersion()}

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Editor */}
        <div class="lg:col-span-2">
          <div class="border border-gray-200 rounded-lg overflow-hidden">
            <div class="bg-gray-50 px-3 py-2 border-b border-gray-200 flex items-center justify-between">
              <span class="text-sm text-gray-600">
                AuthConfig (JSON)
                {config.data && (
                  <span class="ml-2 text-xs text-gray-400">
                    v{config.data.version}
                  </span>
                )}
              </span>
              <div class="flex gap-2">
                <input
                  type="text"
                  placeholder="Change comment…"
                  value={comment()}
                  onInput={(e) => setComment(e.currentTarget.value)}
                  class="border border-gray-300 rounded px-2 py-1 text-xs w-48"
                />
                <button
                  onClick={() => pushMut.mutate()}
                  disabled={pushMut.isPending || !!validationError()}
                  class="px-3 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700 disabled:opacity-50"
                >
                  {pushMut.isPending ? "Saving…" : "Apply"}
                </button>
              </div>
            </div>
            <textarea
              value={editorContent()}
              onInput={(e) => handleEditorChange(e.currentTarget.value)}
              class="w-full h-96 p-3 font-mono text-sm resize-none focus:outline-none"
              spellcheck={false}
            />
          </div>
          {validationError() && (
            <p class="mt-2 text-sm text-red-600">
              Validation: {validationError()}
            </p>
          )}
        </div>

        {/* History sidebar */}
        <Show when={showHistory()}>
          <div class="border border-gray-200 rounded-lg p-3 max-h-[500px] overflow-auto">
            <h3 class="font-medium text-sm text-gray-700 mb-3">Version History</h3>
            {history.isLoading && <p class="text-gray-500 text-xs">Loading…</p>}
            {history.data && history.data.length === 0 && (
              <p class="text-gray-500 text-xs">No versions yet.</p>
            )}
            {history.data && history.data.length > 0 && (
              <div class="space-y-2">
                {[...history.data].reverse().map((v) => (
                  <div
                    class={`border rounded p-2 text-xs ${
                      v.rollback ? "border-amber-300 bg-amber-50" : "border-gray-200"
                    }`}
                  >
                    <div class="flex items-center justify-between">
                      <span class="font-medium">v{v.version}</span>
                      <span class="text-gray-400">
                        {new Date(v.timestamp).toLocaleString()}
                      </span>
                    </div>
                    {v.comment && (
                      <p class="text-gray-600 mt-0.5">{v.comment}</p>
                    )}
                    {v.author && (
                      <p class="text-gray-400 mt-0.5">by {v.author}</p>
                    )}
                    {v.rollback && (
                      <p class="text-amber-700 mt-0.5">
                        ↩ Rolled back to v{v.targetVersion}
                      </p>
                    )}
                    <div class="mt-1 flex gap-2">
                      <button
                        class="text-blue-600 hover:underline"
                        onClick={() => {
                          setEditorContent(v.content);
                          validateJSON(v.content);
                        }}
                      >
                        View
                      </button>
                      <button
                        class="text-amber-600 hover:underline"
                        onClick={() => rollbackMut.mutate(v.version)}
                        disabled={rollbackMut.isPending}
                      >
                        Rollback
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Show>
      </div>
    </div>
  );
}
