import { createSignal, createResource, For, Show, Switch, Match, createEffect } from "solid-js";
import { createStore, produce, type SetStoreFunction } from "solid-js/store";
import { createMutation } from "@tanstack/solid-query";
import { Transition } from "solid-transition-group";
import { CodeBlock } from "../components/CodeBlock";
import {
  listModules,
  listPresets,
  createInstance,
  previewCreate,
  probeURL,
  ApiError,
  type ModuleCatalogue,
  type ModuleInfo,
  type ModuleEntry,
  type InfrastructureReq,
  type CreateInstanceRequest,
  type Preset,
  type PreviewResponse,
  type ValidationError,
} from "../api/client";
import {
  X,
  ChevronLeft,
  ChevronRight,
  Zap,
  Eye,
  Check,
  AlertCircle,
  Plus,
  Trash2,
  Loader,
  CheckCircle,
  XCircle,
} from "lucide-solid";

interface Props {
  onClose: () => void;
  onCreated: () => void;
}

const STEPS = ["Basics", "Identity", "Authorization", "Response", "Infrastructure"] as const;
type Step = (typeof STEPS)[number];

// Maps a backend ValidationError.field (e.g. "name", "identifiers[0].name",
// "authorizers") to the wizard step that owns it, so a failed submit can
// jump the operator back to the right place instead of leaving them on
// the last step with no visible error.
function stepForField(field: string): number {
  if (field.startsWith("identifiers")) return 1;
  if (field.startsWith("authorizers")) return 2;
  if (field.startsWith("mutators")) return 3;
  if (field.startsWith("infrastructure")) return 4;
  return 0; // name, replicas, namespace, cluster, ...
}

export default function CreateInstanceWizard(props: Props) {
  const [step, setStep] = createSignal(0);
  const [error, setError] = createSignal("");
  const [validationErrors, setValidationErrors] = createSignal<ValidationError[]>([]);
  const [showPreview, setShowPreview] = createSignal(false);
  const [previewData, setPreviewData] = createSignal<PreviewResponse | null>(null);
  const [previewTab, setPreviewTab] = createSignal<"yaml" | "helm">("yaml");
  const [nextBusy, setNextBusy] = createSignal(false);

  // Form state.
  const [name, setName] = createSignal("");
  const [namespace, setNamespace] = createSignal("lwauth-system");
  const [cluster, setCluster] = createSignal("local");
  const [replicas, setReplicas] = createSignal(1);
  const [imageTag, setImageTag] = createSignal("");
  const [selectedPreset, setSelectedPreset] = createSignal("");
  const [identifiers, setIdentifiers] = createStore<ModuleEntry[]>([]);
  const [authorizers, setAuthorizers] = createStore<ModuleEntry[]>([]);
  const [mutators, setMutators] = createStore<ModuleEntry[]>([]);
  const [infra, setInfra] = createSignal<InfrastructureReq>({
    cacheBackend: "memory",
    networkPolicy: true,
  });

  // Load catalogue and presets.
  const [catalogue] = createResource(listModules);
  const [presets] = createResource(listPresets);

  const createMut = createMutation(() => ({
    mutationFn: (req: CreateInstanceRequest) => createInstance(req),
    onSuccess: () => props.onCreated(),
    onError: (err: Error) => {
      setError(err.message);
      // A 422 from POST /instances/create carries field-level errors
      // (validationErrors) alongside the generic message — surface them
      // on the actual form fields via fieldError(), and jump back to
      // the earliest step that has one so the operator isn't left
      // staring at the last step with no clue what to fix.
      if (err instanceof ApiError && err.validationErrors?.length) {
        setValidationErrors(err.validationErrors);
        const earliest = Math.min(...err.validationErrors.map((e) => stepForField(e.field)));
        if (earliest < step()) setStep(earliest);
      }
    },
  }));

  const handlePresetSelect = (preset: Preset) => {
    setSelectedPreset(preset.name);
    setIdentifiers(structuredClone(preset.identifiers));
    setAuthorizers(structuredClone(preset.authorizers));
    setMutators(structuredClone(preset.mutators));
    setInfra(structuredClone(preset.infrastructure));
    // Jump past identity/auth/response/infra to let them review.
    setStep(1);
  };

  const handlePreview = async () => {
    try {
      const data = await previewCreate(buildRequest());
      setPreviewData(data);
      setShowPreview(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleSubmit = () => {
    setError("");
    setValidationErrors([]);
    createMut.mutate(buildRequest());
  };

  // Probe all JWKS URLs from jwt-type identifiers before leaving step 1.
  // Returns true if all are reachable (or if there are none), false + sets
  // error if any are unreachable.
  const validateJwksUrls = async (): Promise<boolean> => {
    const jwtEntries = identifiers.filter((e) => e.type === "jwt");
    const urlsToCheck = jwtEntries
      .map((e) => e.config?.jwksUrl as string | undefined)
      .filter((u): u is string => typeof u === "string" && u.startsWith("https://"));
    if (urlsToCheck.length === 0) return true;

    const results = await Promise.all(urlsToCheck.map((u) => probeURL(u).catch(() => ({ reachable: false, statusCode: 0, error: "probe failed" }))));
    const failed = results
      .map((r, i) => ({ url: urlsToCheck[i], ...r }))
      .filter((r) => !r.reachable);
    if (failed.length > 0) {
      setError(
        `JWKS endpoint unreachable: ${failed[0].url}${failed[0].error ? ` — ${failed[0].error}` : ` (HTTP ${failed[0].statusCode})`}. ` +
        `Fix the URL or verify the IdP is reachable from this network before creating the node.`
      );
      return false;
    }
    return true;
  };

  const handleNext = async () => {
    setError("");
    if (step() === 1) {
      // Identity step: probe JWKS URLs before advancing.
      setNextBusy(true);
      try {
        if (!(await validateJwksUrls())) return;
      } finally {
        setNextBusy(false);
      }
    }
    setStep(step() + 1);
  };

  const buildRequest = (): CreateInstanceRequest => ({
    name: name(),
    namespace: namespace(),
    cluster: cluster(),
    replicas: replicas(),
    imageTag: imageTag() || undefined,
    preset: selectedPreset() || undefined,
    identifiers: [...identifiers],
    authorizers: [...authorizers],
    mutators: [...mutators],
    infrastructure: infra(),
  });

  const canProceed = (): boolean => {
    switch (step()) {
      case 0:
        return name().length > 0;
      case 1:
        return identifiers.length > 0;
      case 2:
        return authorizers.length > 0;
      default:
        return true;
    }
  };

  const fieldError = (field: string) =>
    validationErrors().find((e) => e.field === field)?.message;

  return (
    <div class="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div class="bg-white dark:bg-[#12141f] rounded-2xl shadow-2xl w-full max-w-3xl max-h-[90vh] flex flex-col border border-gray-100 dark:border-white/[0.08] animate-scale-in">
        {/* Header */}
        <div class="flex items-center justify-between px-4 sm:px-6 py-4 border-b border-gray-100 dark:border-white/[0.08]">
          <div class="min-w-0">
            <h3 class="font-display text-lg font-bold text-gray-900 dark:text-gray-100">Create LwAuth Node</h3>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5 truncate">
              Step {step() + 1} of {STEPS.length}: {STEPS[step()]}
            </p>
          </div>
          <button onClick={props.onClose} class="p-1.5 hover:bg-gray-100 dark:hover:bg-white/[0.06] rounded-lg transition-colors shrink-0">
            <X size={18} class="text-gray-400" />
          </button>
        </div>

        {/* Step indicators — numbered circles only on mobile (the header
            above already spells out the current step name in full), full
            text labels at sm+ where there's room for five of them. */}
        <div class="flex px-4 sm:px-6 pt-4 gap-1">
          <For each={STEPS}>
            {(s, i) => (
              <button
                class={`flex-1 py-1.5 text-xs font-medium rounded-md transition-all duration-300 truncate ${
                  i() === step()
                    ? "bg-gradient-to-r from-indigo-600 to-violet-600 text-white shadow-[0_0_16px_-4px_rgba(99,102,241,0.6)]"
                    : i() < step()
                    ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400"
                    : "bg-gray-100 dark:bg-white/[0.06] text-gray-400 dark:text-gray-500"
                }`}
                onClick={() => i() <= step() && setStep(i())}
              >
                <span class="sm:hidden">{i() + 1}</span>
                <span class="hidden sm:inline">{s}</span>
              </button>
            )}
          </For>
        </div>

        {/* Body */}
        <div class="flex-1 overflow-y-auto px-4 sm:px-6 py-5">
          <Transition name="wizard-step" mode="outin">
          <Switch>
            <Match when={step() === 0}>
              <StepBasics
                name={name()}
                setName={setName}
                namespace={namespace()}
                setNamespace={setNamespace}
                cluster={cluster()}
                setCluster={setCluster}
                replicas={replicas()}
                setReplicas={setReplicas}
                imageTag={imageTag()}
                setImageTag={setImageTag}
                presets={presets()}
                onPresetSelect={handlePresetSelect}
                selectedPreset={selectedPreset()}
                fieldError={fieldError}
              />
            </Match>
            <Match when={step() === 1}>
              <StepIdentity
                modules={catalogue()?.identifiers ?? []}
                entries={identifiers}
                setEntries={setIdentifiers}
                fieldError={fieldError}
              />
            </Match>
            <Match when={step() === 2}>
              <StepAuthorization
                modules={catalogue()?.authorizers ?? []}
                entries={authorizers}
                setEntries={setAuthorizers}
                fieldError={fieldError}
              />
            </Match>
            <Match when={step() === 3}>
              <StepResponse
                modules={catalogue()?.mutators ?? []}
                entries={mutators}
                setEntries={setMutators}
              />
            </Match>
            <Match when={step() === 4}>
              <StepInfrastructure
                infra={infra()}
                setInfra={setInfra}
                cacheBackends={catalogue()?.cacheBackends ?? []}
                revocationBackends={catalogue()?.revocationBackends ?? []}
                fieldError={fieldError}
              />
            </Match>
          </Switch>
          </Transition>
        </div>

        {/* Error display */}
        <Show when={error()}>
          <div class="mx-4 sm:mx-6 mb-2 p-3 bg-red-50 dark:bg-red-500/10 border border-red-100 dark:border-red-500/20 rounded-lg flex items-start gap-2">
            <AlertCircle size={16} class="text-red-500 mt-0.5 shrink-0" />
            <p class="text-sm text-red-700 dark:text-red-400">{error()}</p>
          </div>
        </Show>

        {/* Footer */}
        <div class="flex flex-wrap items-center justify-between gap-2 px-4 sm:px-6 py-4 border-t border-gray-100 dark:border-white/[0.08]">
          <button
            onClick={() => setStep(Math.max(0, step() - 1))}
            disabled={step() === 0}
            class="inline-flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-white/[0.06] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft size={16} />
            Back
          </button>

          <div class="flex gap-2">
            <Show when={step() === STEPS.length - 1}>
              <button
                onClick={handlePreview}
                class="inline-flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-white/[0.12] rounded-lg hover:bg-gray-50 dark:hover:bg-white/[0.04] transition-colors"
              >
                <Eye size={16} />
                Preview
              </button>
              <button
                onClick={handleSubmit}
                disabled={createMut.isPending}
                class="inline-flex items-center gap-1.5 px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm font-medium rounded-lg disabled:opacity-50 shadow-sm transition-all"
              >
                <Check size={16} />
                {createMut.isPending ? "Creating…" : "Create Node"}
              </button>
            </Show>
            <Show when={step() < STEPS.length - 1}>
              <button
                onClick={handleNext}
                disabled={!canProceed() || nextBusy()}
                class="inline-flex items-center gap-1.5 px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm font-medium rounded-lg disabled:opacity-50 shadow-sm transition-all"
              >
                <Show when={nextBusy()} fallback={<><span>Next</span><ChevronRight size={16} /></>}>
                  <Loader size={16} class="animate-spin" />
                  <span>Checking…</span>
                </Show>
              </button>
            </Show>
          </div>
        </div>
      </div>

      {/* Preview modal */}
      <Show when={showPreview() && previewData()}>
        <PreviewModal
          data={previewData()!}
          tab={previewTab()}
          setTab={setPreviewTab}
          onClose={() => setShowPreview(false)}
        />
      </Show>
    </div>
  );
}

// ── Step 1: Basics ──────────────────────────────────────────────────────

function StepBasics(props: {
  name: string;
  setName: (v: string) => void;
  namespace: string;
  setNamespace: (v: string) => void;
  cluster: string;
  setCluster: (v: string) => void;
  replicas: number;
  setReplicas: (v: number) => void;
  imageTag: string;
  setImageTag: (v: string) => void;
  presets?: Preset[];
  onPresetSelect: (p: Preset) => void;
  selectedPreset: string;
  fieldError: (field: string) => string | undefined;
}) {
  return (
    <div class="space-y-6">
      {/* Presets */}
      <Show when={props.presets && props.presets.length > 0}>
        <div>
          <label class="text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Quick Start Preset</label>
          <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5 mb-3">Select a preset to pre-fill the form, then customize as needed.</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <For each={props.presets}>
              {(preset) => (
                <button
                  class={`text-left p-3 rounded-xl border transition-all ${
                    props.selectedPreset === preset.name
                      ? "border-indigo-500 bg-indigo-50/50 dark:bg-indigo-500/10 ring-1 ring-indigo-500/20"
                      : "border-gray-200 dark:border-white/[0.1] hover:border-gray-300 dark:hover:border-white/[0.2] hover:bg-gray-50/50 dark:hover:bg-white/[0.04]"
                  }`}
                  onClick={() => props.onPresetSelect(preset)}
                >
                  <div class="flex items-center gap-2">
                    <Zap size={14} class={props.selectedPreset === preset.name ? "text-indigo-600 dark:text-indigo-400" : "text-gray-400 dark:text-gray-500"} />
                    <span class="text-sm font-medium text-gray-900 dark:text-gray-100">{preset.displayName}</span>
                  </div>
                  <p class="text-xs text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">{preset.description}</p>
                </button>
              )}
            </For>
          </div>
        </div>
      </Show>

      {/* Form fields */}
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <FormField label="Node Name" required error={props.fieldError("name")}>
          <input
            type="text"
            value={props.name}
            onInput={(e) => props.setName(e.currentTarget.value)}
            placeholder="payments-auth"
            class="form-input"
            required
          />
        </FormField>
        <FormField label="Namespace">
          <input
            type="text"
            value={props.namespace}
            onInput={(e) => props.setNamespace(e.currentTarget.value)}
            class="form-input"
          />
        </FormField>
        <FormField label="Cluster">
          <input
            type="text"
            value={props.cluster}
            onInput={(e) => props.setCluster(e.currentTarget.value)}
            class="form-input"
          />
        </FormField>
        <FormField label="Replicas">
          <input
            type="number"
            min="1"
            max="10"
            value={props.replicas}
            onInput={(e) => props.setReplicas(parseInt(e.currentTarget.value) || 1)}
            class="form-input"
          />
        </FormField>
        <FormField label="Image Version">
          <input
            type="text"
            value={props.imageTag}
            onInput={(e) => props.setImageTag(e.currentTarget.value)}
            placeholder="latest"
            class="form-input"
          />
        </FormField>
      </div>
    </div>
  );
}

// ── Step 2: Identity ────────────────────────────────────────────────────

function StepIdentity(props: {
  modules: ModuleInfo[];
  entries: ModuleEntry[];
  setEntries: SetStoreFunction<ModuleEntry[]>;
  fieldError: (field: string) => string | undefined;
}) {
  return (
    <ModuleListEditor
      title="Identity Modules"
      description="Select one or more identity verification methods. Requests must match at least one."
      modules={props.modules}
      entries={props.entries}
      setEntries={props.setEntries}
      fieldPrefix="identifiers"
      fieldError={props.fieldError}
    />
  );
}

// ── Step 3: Authorization ───────────────────────────────────────────────

function StepAuthorization(props: {
  modules: ModuleInfo[];
  entries: ModuleEntry[];
  setEntries: SetStoreFunction<ModuleEntry[]>;
  fieldError: (field: string) => string | undefined;
}) {
  return (
    <ModuleListEditor
      title="Authorization Engine"
      description="Select an authorization engine to evaluate access decisions."
      modules={props.modules}
      entries={props.entries}
      setEntries={props.setEntries}
      fieldPrefix="authorizers"
      fieldError={props.fieldError}
    />
  );
}

// ── Step 4: Response Mutators ───────────────────────────────────────────

function StepResponse(props: {
  modules: ModuleInfo[];
  entries: ModuleEntry[];
  setEntries: SetStoreFunction<ModuleEntry[]>;
}) {
  return (
    <ModuleListEditor
      title="Response Mutators"
      description="Optionally add response mutators to inject headers or mint tokens for the upstream."
      modules={props.modules}
      entries={props.entries}
      setEntries={props.setEntries}
      fieldPrefix="mutators"
      fieldError={() => undefined}
    />
  );
}

// ── Step 5: Infrastructure ──────────────────────────────────────────────

function StepInfrastructure(props: {
  infra: InfrastructureReq;
  setInfra: (v: InfrastructureReq) => void;
  cacheBackends: string[];
  revocationBackends: string[];
  fieldError: (field: string) => string | undefined;
}) {
  const update = (patch: Partial<InfrastructureReq>) =>
    props.setInfra({ ...props.infra, ...patch });

  return (
    <div class="space-y-5">
      <div>
        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-1">Infrastructure Settings</h4>
        <p class="text-xs text-gray-500 dark:text-gray-400 mb-4">Configure caching, rate limiting, and network settings.</p>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <FormField label="Cache Backend">
          <select
            value={props.infra.cacheBackend ?? "memory"}
            onChange={(e) => update({ cacheBackend: e.currentTarget.value })}
            class="form-input"
          >
            <For each={props.cacheBackends}>{(b) => <option value={b}>{b}</option>}</For>
          </select>
        </FormField>
        <Show when={props.infra.cacheBackend === "valkey" || props.infra.cacheBackend === "tiered"}>
          <FormField label="Cache Address">
            <input
              type="text"
              value={props.infra.cacheAddr ?? ""}
              onInput={(e) => update({ cacheAddr: e.currentTarget.value })}
              placeholder="valkey:6379"
              class="form-input"
            />
          </FormField>
        </Show>
      </div>

      {/* Rate Limiting */}
      <div class="border border-gray-200 dark:border-white/[0.1] rounded-xl p-4">
        <label class="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={props.infra.rateLimiting?.enabled ?? false}
            onChange={(e) =>
              update({
                rateLimiting: {
                  enabled: e.currentTarget.checked,
                  rps: props.infra.rateLimiting?.rps ?? 100,
                  burst: props.infra.rateLimiting?.burst ?? 200,
                },
              })
            }
            class="rounded border-gray-300 dark:border-white/[0.2] dark:bg-white/[0.06] text-indigo-600 focus:ring-indigo-500/30"
          />
          <span class="text-sm font-medium text-gray-900 dark:text-gray-100">Enable Rate Limiting</span>
        </label>
        <Show when={props.infra.rateLimiting?.enabled}>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-3 pl-6">
            <FormField label="RPS">
              <input
                type="number"
                value={props.infra.rateLimiting?.rps ?? 100}
                onInput={(e) =>
                  update({
                    rateLimiting: {
                      ...props.infra.rateLimiting!,
                      rps: parseInt(e.currentTarget.value) || 100,
                    },
                  })
                }
                class="form-input"
              />
            </FormField>
            <FormField label="Burst">
              <input
                type="number"
                value={props.infra.rateLimiting?.burst ?? 200}
                onInput={(e) =>
                  update({
                    rateLimiting: {
                      ...props.infra.rateLimiting!,
                      burst: parseInt(e.currentTarget.value) || 200,
                    },
                  })
                }
                class="form-input"
              />
            </FormField>
          </div>
        </Show>
      </div>

      {/* Revocation */}
      <div class="border border-gray-200 dark:border-white/[0.1] rounded-xl p-4">
        <label class="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={props.infra.revocation?.enabled ?? false}
            onChange={(e) =>
              update({
                revocation: {
                  enabled: e.currentTarget.checked,
                  backend: props.infra.revocation?.backend ?? "memory",
                },
              })
            }
            class="rounded border-gray-300 dark:border-white/[0.2] dark:bg-white/[0.06] text-indigo-600 focus:ring-indigo-500/30"
          />
          <span class="text-sm font-medium text-gray-900 dark:text-gray-100">Enable Revocation</span>
        </label>
        <Show when={props.infra.revocation?.enabled}>
          <div class="mt-3 pl-6">
            <FormField label="Backend">
              <select
                value={props.infra.revocation?.backend ?? "memory"}
                onChange={(e) =>
                  update({
                    revocation: { ...props.infra.revocation!, backend: e.currentTarget.value },
                  })
                }
                class="form-input"
              >
                <For each={props.revocationBackends}>
                  {(b) => <option value={b}>{b}</option>}
                </For>
              </select>
            </FormField>
          </div>
        </Show>
      </div>

      {/* Gateway */}
      <div class="border border-gray-200 dark:border-white/[0.1] rounded-xl p-4">
        <label class="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={props.infra.gateway?.enabled ?? false}
            onChange={(e) =>
              update({
                gateway: {
                  enabled: e.currentTarget.checked,
                  upstreamHost: props.infra.gateway?.upstreamHost ?? "",
                  upstreamPort: props.infra.gateway?.upstreamPort ?? 8000,
                },
              })
            }
            class="rounded border-gray-300 dark:border-white/[0.2] dark:bg-white/[0.06] text-indigo-600 focus:ring-indigo-500/30"
          />
          <span class="text-sm font-medium text-gray-900 dark:text-gray-100">Enable Envoy Gateway Sidecar</span>
        </label>
        <Show when={props.infra.gateway?.enabled}>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-3 pl-6">
            <FormField label="Upstream Service">
              <input
                type="text"
                value={props.infra.gateway?.upstreamHost ?? ""}
                onInput={(e) =>
                  update({
                    gateway: { ...props.infra.gateway!, upstreamHost: e.currentTarget.value },
                  })
                }
                placeholder="app-svc.default.svc"
                class="form-input"
              />
            </FormField>
            <FormField label="Upstream Port">
              <input
                type="number"
                value={props.infra.gateway?.upstreamPort ?? 8000}
                onInput={(e) =>
                  update({
                    gateway: {
                      ...props.infra.gateway!,
                      upstreamPort: parseInt(e.currentTarget.value) || 8000,
                    },
                  })
                }
                class="form-input"
              />
            </FormField>
          </div>
        </Show>
      </div>

      {/* TLS */}
      <div class="border border-gray-200 dark:border-white/[0.1] rounded-xl p-4">
        <label class="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={props.infra.tls?.enabled ?? false}
            onChange={(e) =>
              update({
                tls: {
                  enabled: e.currentTarget.checked,
                  secretName: props.infra.tls?.secretName ?? "",
                },
              })
            }
            class="rounded border-gray-300 dark:border-white/[0.2] dark:bg-white/[0.06] text-indigo-600 focus:ring-indigo-500/30"
          />
          <span class="text-sm font-medium text-gray-900 dark:text-gray-100">Enable TLS</span>
        </label>
        <Show when={props.infra.tls?.enabled}>
          <div class="mt-3 pl-6">
            <FormField
              label="TLS Secret Name"
              required
              description="An existing Kubernetes TLS Secret (tls.crt + tls.key) in this node's namespace. The node switches its HTTP listener — and its liveness/readiness probes — to HTTPS, so the pod will crash-loop if this secret doesn't exist yet."
              error={props.fieldError("infrastructure.tls.secretName")}
            >
              <input
                type="text"
                value={props.infra.tls?.secretName ?? ""}
                onInput={(e) =>
                  update({
                    tls: { ...props.infra.tls!, secretName: e.currentTarget.value },
                  })
                }
                placeholder="payments-auth-tls"
                class="form-input"
              />
            </FormField>
          </div>
        </Show>
      </div>

      {/* Network Policy */}
      <label class="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={props.infra.networkPolicy}
          onChange={(e) => update({ networkPolicy: e.currentTarget.checked })}
          class="rounded border-gray-300 dark:border-white/[0.2] dark:bg-white/[0.06] text-indigo-600 focus:ring-indigo-500/30"
        />
        <span class="text-sm font-medium text-gray-900 dark:text-gray-100">Enable Network Policy</span>
      </label>
    </div>
  );
}

// ── Shared: Module list editor ──────────────────────────────────────────

function ModuleListEditor(props: {
  title: string;
  description: string;
  modules: ModuleInfo[];
  entries: ModuleEntry[];
  setEntries: SetStoreFunction<ModuleEntry[]>;
  fieldPrefix: string;
  fieldError: (field: string) => string | undefined;
}) {
  const [addingType, setAddingType] = createSignal("");

  // These mutate the store in place at a path (index/key) instead of
  // replacing the whole array — <For> below keys rows by object
  // identity, and identity-preserving store updates are what let a
  // single row re-render in place instead of the whole row (and its
  // focused <input>) being torn down and recreated on every keystroke.
  const addModule = () => {
    const mod = props.modules.find((m) => m.type === addingType());
    if (!mod) return;
    const defaultConfig: Record<string, unknown> = {};
    for (const f of mod.fields) {
      if (f.default !== undefined) {
        defaultConfig[f.name] = f.default;
      }
    }
    props.setEntries(
      produce((entries) => {
        entries.push({ name: `${mod.type}-${entries.length + 1}`, type: mod.type, config: defaultConfig });
      }),
    );
    setAddingType("");
  };

  const removeModule = (idx: number) => {
    props.setEntries(produce((entries) => { entries.splice(idx, 1); }));
  };

  const updateEntry = (idx: number, patch: Partial<ModuleEntry>) => {
    props.setEntries(idx, patch);
  };

  const updateConfig = (idx: number, key: string, value: unknown) => {
    props.setEntries(idx, "config", (prev: Record<string, unknown> | undefined) => ({
      ...(prev ?? {}),
      [key]: value,
    }));
  };

  return (
    <div class="space-y-4">
      <div>
        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100">{props.title}</h4>
        <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{props.description}</p>
      </div>

      <Show when={props.fieldError(props.fieldPrefix)}>
        <p class="text-xs text-red-600 dark:text-red-400 flex items-center gap-1">
          <AlertCircle size={12} />
          {props.fieldError(props.fieldPrefix)}
        </p>
      </Show>

      <For each={props.entries}>
        {(entry, idx) => {
          const mod = () => props.modules.find((m) => m.type === entry.type);
          return (
            <div class="border border-gray-200 dark:border-white/[0.1] rounded-xl p-4 space-y-3 bg-gray-50/30 dark:bg-white/[0.03]">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                  <span class="text-xs font-bold text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-500/10 px-2 py-0.5 rounded-full uppercase">
                    {entry.type}
                  </span>
                  <span class="text-sm font-medium text-gray-700 dark:text-gray-300">{mod()?.displayName ?? entry.type}</span>
                </div>
                <button
                  onClick={() => removeModule(idx())}
                  class="p-1 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg text-gray-400 dark:text-gray-500 hover:text-red-500 dark:hover:text-red-400 transition-colors"
                >
                  <Trash2 size={14} />
                </button>
              </div>

              <FormField label="Instance Name" error={props.fieldError(`${props.fieldPrefix}[${idx()}].name`)}>
                <input
                  type="text"
                  value={entry.name}
                  onInput={(e) => updateEntry(idx(), { name: e.currentTarget.value })}
                  class="form-input"
                />
              </FormField>

              <Show when={mod()}>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <For each={mod()!.fields}>
                    {(field) => (
                      <ModuleFieldInput
                        field={field}
                        value={entry.config?.[field.name]}
                        onChange={(val) => updateConfig(idx(), field.name, val)}
                      />
                    )}
                  </For>
                </div>
              </Show>
            </div>
          );
        }}
      </For>

      {/* Add module */}
      <div class="flex items-center gap-2">
        <select
          value={addingType()}
          onChange={(e) => setAddingType(e.currentTarget.value)}
          class="form-input flex-1"
        >
          <option value="">Select a module type…</option>
          <For each={props.modules}>
            {(m) => (
              <option value={m.type}>
                {m.displayName} — {m.description}
              </option>
            )}
          </For>
        </select>
        <button
          onClick={addModule}
          disabled={!addingType()}
          class="inline-flex items-center gap-1.5 px-4 py-2.5 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white text-sm font-medium rounded-lg disabled:opacity-40 shadow-sm transition-all"
        >
          <Plus size={16} />
          Add
        </button>
      </div>
    </div>
  );
}

// ── Module field input renderer ─────────────────────────────────────────

function ModuleFieldInput(props: {
  field: { name: string; type: string; required: boolean; placeholder?: string; description?: string; options?: string[]; default?: unknown };
  value: unknown;
  onChange: (val: unknown) => void;
}) {
  const f = props.field;

  return (
    <FormField label={f.name} required={f.required} description={f.description}>
      <Switch fallback={
        <input
          type="text"
          value={String(props.value ?? "")}
          onInput={(e) => props.onChange(e.currentTarget.value)}
          placeholder={f.placeholder}
          class="form-input"
        />
      }>
        {/* Special: JWKS URL — show inline reachability probe */}
        <Match when={f.name === "jwksUrl"}>
          <JwksUrlInput
            value={String(props.value ?? "")}
            placeholder={f.placeholder}
            onChange={props.onChange}
          />
        </Match>
        <Match when={f.type === "boolean"}>
          <label class="flex items-center gap-2 mt-1">
            <input
              type="checkbox"
              checked={Boolean(props.value ?? f.default)}
              onChange={(e) => props.onChange(e.currentTarget.checked)}
              class="rounded border-gray-300 dark:border-white/[0.2] dark:bg-white/[0.06] text-indigo-600 focus:ring-indigo-500/30"
            />
            <span class="text-xs text-gray-600 dark:text-gray-400">{f.description}</span>
          </label>
        </Match>
        <Match when={f.type === "number"}>
          <input
            type="number"
            value={Number(props.value ?? f.default ?? 0)}
            onInput={(e) => props.onChange(parseFloat(e.currentTarget.value))}
            placeholder={f.placeholder}
            class="form-input"
          />
        </Match>
        <Match when={f.type === "select"}>
          <select
            value={String(props.value ?? f.default ?? "")}
            onChange={(e) => props.onChange(e.currentTarget.value)}
            class="form-input"
          >
            <For each={f.options ?? []}>{(opt) => <option value={opt}>{opt}</option>}</For>
          </select>
        </Match>
        <Match when={f.type === "stringArray"}>
          <input
            type="text"
            value={Array.isArray(props.value) ? (props.value as string[]).join(", ") : String(props.value ?? "")}
            onInput={(e) =>
              props.onChange(
                e.currentTarget.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
              )
            }
            placeholder={f.placeholder ?? "value1, value2"}
            class="form-input"
          />
        </Match>
        <Match when={f.type === "object"}>
          <textarea
            value={typeof props.value === "string" ? props.value : JSON.stringify(props.value ?? {}, null, 2)}
            onInput={(e) => {
              try {
                props.onChange(JSON.parse(e.currentTarget.value));
              } catch {
                // Keep raw string until valid JSON.
              }
            }}
            placeholder='{"key": "value"}'
            rows={3}
            class="form-input font-mono text-xs"
          />
        </Match>
      </Switch>
    </FormField>
  );
}

// ── JWKS URL input with inline reachability probe ───────────────────────

type ProbeState = "idle" | "checking" | "ok" | "error";

function JwksUrlInput(props: {
  value: string;
  placeholder?: string;
  onChange: (val: unknown) => void;
}) {
  const [probeState, setProbeState] = createSignal<ProbeState>("idle");
  const [probeMsg, setProbeMsg] = createSignal("");

  // Reset probe status whenever the value changes.
  createEffect(() => {
    props.value; // track
    setProbeState("idle");
    setProbeMsg("");
  });

  const runProbe = async () => {
    const url = props.value.trim();
    if (!url) return;
    if (!url.startsWith("https://")) {
      setProbeState("error");
      setProbeMsg("Must be an https:// URL");
      return;
    }
    setProbeState("checking");
    setProbeMsg("");
    try {
      const result = await probeURL(url);
      if (result.reachable) {
        setProbeState("ok");
        setProbeMsg(`Reachable (HTTP ${result.statusCode})`);
      } else {
        setProbeState("error");
        setProbeMsg(result.error ?? `HTTP ${result.statusCode} — endpoint returned an error`);
      }
    } catch {
      setProbeState("error");
      setProbeMsg("Probe request failed — check network connectivity");
    }
  };

  return (
    <div class="space-y-1.5">
      <div class="flex gap-2">
        <input
          type="url"
          value={props.value}
          onInput={(e) => props.onChange(e.currentTarget.value)}
          placeholder={props.placeholder ?? "https://auth.example.com/.well-known/jwks.json"}
          class="form-input flex-1"
        />
        <button
          type="button"
          onClick={runProbe}
          disabled={probeState() === "checking" || !props.value.startsWith("https://")}
          class="shrink-0 inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-40 transition-colors"
        >
          <Switch>
            <Match when={probeState() === "checking"}>
              <Loader size={13} class="animate-spin" />
              <span>Checking</span>
            </Match>
            <Match when={probeState() === "ok"}>
              <CheckCircle size={13} class="text-green-500" />
              <span>Test URL</span>
            </Match>
            <Match when={probeState() === "error"}>
              <XCircle size={13} class="text-red-500" />
              <span>Retry</span>
            </Match>
            <Match when={probeState() === "idle"}>
              <span>Test URL</span>
            </Match>
          </Switch>
        </button>
      </div>
      <Show when={probeState() !== "idle"}>
        <p class={`text-xs flex items-center gap-1 ${probeState() === "ok" ? "text-green-600 dark:text-green-400" : probeState() === "error" ? "text-red-600 dark:text-red-400" : "text-gray-500 dark:text-gray-400"}`}>
          <Switch>
            <Match when={probeState() === "ok"}><CheckCircle size={11} /></Match>
            <Match when={probeState() === "error"}><XCircle size={11} /></Match>
            <Match when={probeState() === "checking"}><Loader size={11} class="animate-spin" /></Match>
          </Switch>
          {probeMsg() || "Checking reachability…"}
        </p>
      </Show>
    </div>
  );
}

// ── Preview modal ───────────────────────────────────────────────────────

function PreviewModal(props: {
  data: PreviewResponse;
  tab: "yaml" | "helm";
  setTab: (v: "yaml" | "helm") => void;
  onClose: () => void;
}) {
  const content = () => (props.tab === "yaml" ? props.data.authConfig : props.data.helmValues);

  return (
    <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-[60] p-4">
      <div class="bg-white dark:bg-[#12141f] rounded-2xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col border border-gray-100 dark:border-white/[0.08] animate-scale-in">
        <div class="flex flex-wrap items-center justify-between gap-2 px-5 py-3 border-b border-gray-100 dark:border-white/[0.08]">
          <div class="flex gap-1 flex-wrap">
            <button
              class={`px-3 py-1.5 text-xs font-medium rounded-md transition-all whitespace-nowrap ${
                props.tab === "yaml"
                  ? "bg-indigo-600 text-white"
                  : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-white/[0.06]"
              }`}
              onClick={() => props.setTab("yaml")}
            >
              Auth Config (YAML)
            </button>
            <button
              class={`px-3 py-1.5 text-xs font-medium rounded-md transition-all whitespace-nowrap ${
                props.tab === "helm"
                  ? "bg-indigo-600 text-white"
                  : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-white/[0.06]"
              }`}
              onClick={() => props.setTab("helm")}
            >
              Helm Values
            </button>
          </div>
          <button onClick={props.onClose} class="p-1 hover:bg-gray-100 dark:hover:bg-white/[0.06] rounded-lg">
            <X size={16} class="text-gray-400" />
          </button>
        </div>
        <div class="flex-1 overflow-hidden p-4">
          <CodeBlock code={content()} language="yaml" maxHeight="calc(80vh - 130px)" />
        </div>
      </div>
    </div>
  );
}

// ── Shared form helpers ─────────────────────────────────────────────────

function FormField(props: {
  label: string;
  required?: boolean;
  error?: string;
  description?: string;
  children: any;
}) {
  return (
    <label class="block text-xs font-medium text-gray-700 dark:text-gray-300">
      <span>
        {props.label}
        {props.required && <span class="text-red-500 ml-0.5">*</span>}
      </span>
      <Show when={props.description}>
        <p class="font-normal text-gray-400 dark:text-gray-500 mt-0.5">{props.description}</p>
      </Show>
      <div class="mt-1.5">{props.children}</div>
      <Show when={props.error}>
        <p class="text-red-600 dark:text-red-400 mt-1 flex items-center gap-1">
          <AlertCircle size={11} />
          {props.error}
        </p>
      </Show>
    </label>
  );
}
