import { createMemo, createSignal, For, Show } from "solid-js";
import { Copy, Check, Eye, EyeOff } from "lucide-solid";
import { highlight, containsSecrets, type CodeLanguage, type TokenKind } from "../lib/highlight";

const SECRET_MASK = "••••••••••";

const TOKEN_CLASS: Record<TokenKind, string> = {
  key: "text-sky-700 dark:text-sky-400",
  string: "text-emerald-700 dark:text-emerald-400",
  number: "text-amber-700 dark:text-amber-400",
  boolean: "text-purple-700 dark:text-purple-400",
  comment: "text-gray-400 dark:text-gray-500 italic",
  punctuation: "text-gray-500 dark:text-gray-400",
  secret: "text-rose-700 dark:text-rose-400",
  plain: "text-gray-800 dark:text-gray-200",
};

// Read-only, syntax-highlighted YAML/JSON viewer used for policy-engine
// config previews (the create-node wizard's generated config, and the
// pushed instance config in ConfigEditor). Secret-shaped fields
// (signingKey, clientSecret, password, token, ...) are masked by
// default — see src/lib/highlight.ts for the exact key patterns.
export function CodeBlock(props: {
  code: string;
  language: CodeLanguage;
  label?: string;
  maxHeight?: string;
}) {
  const [redact, setRedact] = createSignal(true);
  const [copied, setCopied] = createSignal(false);

  const lines = createMemo(() => highlight(props.code, props.language));
  const hasSecrets = createMemo(() => containsSecrets(props.code, props.language));

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard permission denied — no-op, button just won't confirm */
    }
  };

  return (
    <div class="rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-950 overflow-hidden">
      <div class="flex items-center justify-between px-3 py-2 border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
        <div class="flex items-center gap-2 min-w-0">
          <span class="text-[10px] font-semibold uppercase tracking-wide text-gray-400 dark:text-gray-500 shrink-0">
            {props.language}
          </span>
          <Show when={props.label}>
            <span class="text-xs text-gray-500 dark:text-gray-400 truncate">{props.label}</span>
          </Show>
        </div>
        <div class="flex items-center gap-1 shrink-0">
          <Show when={hasSecrets()}>
            <button
              type="button"
              onClick={() => setRedact((r) => !r)}
              class="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded-md text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              title={redact() ? "Reveal secret values" : "Hide secret values"}
            >
              {redact() ? <EyeOff size={12} /> : <Eye size={12} class="text-rose-500" />}
              {redact() ? "Secrets hidden" : "Secrets shown"}
            </button>
          </Show>
          <button
            type="button"
            onClick={copy}
            class="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium rounded-md text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          >
            {copied() ? <Check size={12} class="text-emerald-500" /> : <Copy size={12} />}
            {copied() ? "Copied" : "Copy"}
          </button>
        </div>
      </div>
      <pre
        class="overflow-auto p-3 text-xs font-mono leading-relaxed m-0"
        style={props.maxHeight ? { "max-height": props.maxHeight } : undefined}
      >
        <code>
          <For each={lines()}>
            {(lineTokens, i) => (
              <div class="flex">
                <span class="shrink-0 w-8 pr-3 text-right select-none text-gray-300 dark:text-gray-700 text-[11px] tabular-nums">
                  {i() + 1}
                </span>
                <span class="whitespace-pre-wrap break-all min-w-0">
                  <For each={lineTokens}>
                    {(t) => (
                      <span class={TOKEN_CLASS[t.kind]}>
                        {t.kind === "secret" && redact() ? SECRET_MASK : t.text}
                      </span>
                    )}
                  </For>
                  <Show when={lineTokens.length === 0}>{" "}</Show>
                </span>
              </div>
            )}
          </For>
        </code>
      </pre>
    </div>
  );
}
