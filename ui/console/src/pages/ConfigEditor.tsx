import { createSignal, Show } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { useParams, A } from "@solidjs/router";
import {
  getConfig,
  pushConfig,
  getConfigHistory,
  rollbackConfig,
} from "../api/client";
import { History, ChevronLeft, Eye, Pencil } from "lucide-solid";
import { CodeBlock } from "../components/CodeBlock";

type Mode = "preview" | "edit";

export default function ConfigEditor() {
  const params = useParams<{ cluster: string; name: string }>();
  const queryClient = useQueryClient();
  const [editorContent, setEditorContent] = createSignal("");
  const [comment, setComment] = createSignal("");
  const [validationError, setValidationError] = createSignal("");
  const [showHistory, setShowHistory] = createSignal(false);
  const [mode, setMode] = createSignal<Mode>("preview");

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

  // Seed editor with current config when loaded; jump straight to Edit
  // mode when there's nothing to preview yet.
  const loadedVersion = () => {
    if (config.data && !editorContent()) {
      setEditorContent(config.data.content);
    } else if (config.isError && config.error?.message === "no config stored for this instance") {
      setMode("edit");
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
      setMode("preview");
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
      setMode("preview");
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
    <div class="max-w-7xl">
      <div class="flex items-center justify-between mb-6">
        <div>
          <A
            href={`/instances/${params.cluster}/${params.name}`}
            class="inline-flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 mb-1"
          >
            <ChevronLeft size={12} />
            Back to instance
          </A>
          <h1 class="text-2xl font-bold text-gray-900 dark:text-gray-100">
            Config: <span class="font-mono">{params.cluster}/{params.name}</span>
          </h1>
        </div>
        <button
          class="inline-flex items-center gap-2 px-4 py-2.5 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800"
          onClick={() => setShowHistory(!showHistory())}
        >
          <History size={16} />
          {showHistory() ? "Hide History" : "Show History"}
        </button>
      </div>

      {config.isLoading && <p class="text-sm text-gray-400 mb-4">Loading config…</p>}
      {config.isError && config.error?.message === "no config stored for this instance" && (
        <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">
          No config has been pushed to this instance yet — write one below and click Apply.
        </p>
      )}
      {config.isError && config.error?.message !== "no config stored for this instance" && (
        <p class="text-sm text-red-600 dark:text-red-400 mb-4">Error: {(config.error as Error).message}</p>
      )}

      {/* Seed editor on initial load */}
      {void loadedVersion()}

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Editor */}
        <div class="lg:col-span-2">
          <div class="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm overflow-hidden">
            <div class="bg-gray-50/80 dark:bg-gray-900 px-4 py-3 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between flex-wrap gap-2">
              <div class="flex items-center gap-3">
                <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                  AuthConfig (JSON)
                  {config.data && (
                    <span class="ml-2 text-xs text-gray-400 dark:text-gray-500 font-mono">
                      v{config.data.version}
                    </span>
                  )}
                </span>
                <div class="flex gap-1 bg-gray-100 dark:bg-gray-800 rounded-lg p-0.5">
                  <button
                    type="button"
                    onClick={() => setMode("preview")}
                    class={`inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                      mode() === "preview"
                        ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 shadow-sm"
                        : "text-gray-500 dark:text-gray-400"
                    }`}
                  >
                    <Eye size={12} />
                    Preview
                  </button>
                  <button
                    type="button"
                    onClick={() => setMode("edit")}
                    class={`inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                      mode() === "edit"
                        ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 shadow-sm"
                        : "text-gray-500 dark:text-gray-400"
                    }`}
                  >
                    <Pencil size={12} />
                    Edit
                  </button>
                </div>
              </div>
              <div class="flex gap-2">
                <input
                  type="text"
                  placeholder="Change comment…"
                  value={comment()}
                  onInput={(e) => setComment(e.currentTarget.value)}
                  class="border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg px-2.5 py-1.5 text-xs w-48 focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition-all"
                />
                <button
                  onClick={() => pushMut.mutate()}
                  disabled={pushMut.isPending || !!validationError()}
                  class="px-3 py-1.5 bg-blue-600 text-white text-xs font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 shadow-sm"
                >
                  {pushMut.isPending ? "Saving…" : "Apply"}
                </button>
              </div>
            </div>
            <Show
              when={mode() === "preview"}
              fallback={
                <textarea
                  value={editorContent()}
                  onInput={(e) => handleEditorChange(e.currentTarget.value)}
                  class="w-full h-96 p-3 font-mono text-sm resize-none focus:outline-none bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100"
                  spellcheck={false}
                />
              }
            >
              <div class="p-3">
                <CodeBlock code={editorContent()} language="json" maxHeight="24rem" />
              </div>
            </Show>
          </div>
          {validationError() && (
            <p class="mt-2 text-sm text-red-600 dark:text-red-400">
              Validation: {validationError()}
            </p>
          )}
        </div>

        {/* History sidebar */}
        <Show when={showHistory()}>
          <div class="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-4 max-h-[500px] overflow-auto">
            <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-3">Version History</h3>
            {history.isLoading && <p class="text-gray-400 text-xs">Loading…</p>}
            {history.data && history.data.length === 0 && (
              <p class="text-gray-500 dark:text-gray-400 text-xs">No versions yet.</p>
            )}
            {history.data && history.data.length > 0 && (
              <div class="space-y-2">
                {[...history.data].reverse().map((v) => (
                  <div
                    class={`border rounded-lg p-2.5 text-xs ${
                      v.rollback
                        ? "border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-500/10"
                        : "border-gray-200 dark:border-gray-800"
                    }`}
                  >
                    <div class="flex items-center justify-between">
                      <span class="font-semibold text-gray-900 dark:text-gray-100">v{v.version}</span>
                      <span class="text-gray-400 dark:text-gray-500">
                        {new Date(v.timestamp).toLocaleString()}
                      </span>
                    </div>
                    {v.comment && (
                      <p class="text-gray-600 dark:text-gray-400 mt-0.5">{v.comment}</p>
                    )}
                    {v.author && (
                      <p class="text-gray-400 dark:text-gray-500 mt-0.5">by {v.author}</p>
                    )}
                    {v.rollback && (
                      <p class="text-amber-700 dark:text-amber-400 mt-0.5">
                        ↩ Rolled back to v{v.targetVersion}
                      </p>
                    )}
                    <div class="mt-1.5 flex gap-3">
                      <button
                        class="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium"
                        onClick={() => {
                          setEditorContent(v.content);
                          validateJSON(v.content);
                          setMode("preview");
                        }}
                      >
                        View
                      </button>
                      <button
                        class="text-amber-600 dark:text-amber-400 hover:text-amber-700 dark:hover:text-amber-300 font-medium disabled:opacity-50"
                        onClick={() => {
                          if (!confirm(`Roll back to v${v.version}? This creates a new version with that content.`)) return;
                          rollbackMut.mutate(v.version);
                        }}
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
