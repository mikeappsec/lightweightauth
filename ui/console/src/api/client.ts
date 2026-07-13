// API client for the lwauth control-plane REST API.

const BASE = "/v1/controlplane";

export interface Instance {
  name: string;
  cluster: string;
  namespace?: string;
  adminUrl: string;
  grpcUrl?: string;
  status: InstanceStatus;
  source: "auto" | "manual";
  lastSeen: string;
}

export interface InstanceStatus {
  healthy: boolean;
  ready: boolean;
  configVersion?: string;
  replicas?: string;
  lastCheck: string;
  error?: string;
}

export interface HealthResponse {
  status: string;
  totalInstances: number;
  healthyInstances: number;
}

export interface RegisterRequest {
  name: string;
  cluster: string;
  adminUrl: string;
  grpcUrl?: string;
  tls?: { caBundle?: string; clientCert?: string };
}

export interface CreateInstanceRequest {
  name: string;
  namespace?: string;
  cluster?: string;
  replicas?: number;
  version?: string;
  image?: string;
  config?: string;
  // Structured fields from module-aware wizard.
  imageTag?: string;
  preset?: string;
  identifiers?: ModuleEntry[];
  authorizers?: ModuleEntry[];
  mutators?: ModuleEntry[];
  infrastructure?: InfrastructureReq;
}

// --- Module catalogue types (Phase A) ---

export interface ModuleField {
  name: string;
  type: "string" | "number" | "boolean" | "stringArray" | "object" | "select";
  required: boolean;
  default?: unknown;
  placeholder?: string;
  description?: string;
  options?: string[];
}

export interface ModuleInfo {
  type: string;
  displayName: string;
  description: string;
  builtIn: boolean;
  fields: ModuleField[];
}

export interface ModuleCatalogue {
  identifiers: ModuleInfo[];
  authorizers: ModuleInfo[];
  mutators: ModuleInfo[];
  cacheBackends: string[];
  revocationBackends: string[];
}

export interface ModuleEntry {
  name: string;
  type: string;
  config?: Record<string, unknown>;
}

export interface InfrastructureReq {
  cacheBackend?: string;
  cacheAddr?: string;
  rateLimiting?: { enabled: boolean; rps?: number; burst?: number };
  revocation?: { enabled: boolean; backend?: string };
  gateway?: { enabled: boolean; upstreamHost?: string; upstreamPort?: number };
  // Mirrors Go provisioner.TLSReq — enabling switches the node's HTTP
  // listener (and kubelet probes) to HTTPS using a cert/key pair from
  // an existing Kubernetes TLS Secret in the node's namespace.
  tls?: { enabled: boolean; secretName?: string };
  networkPolicy: boolean;
}

export interface Preset {
  name: string;
  displayName: string;
  description: string;
  identifiers: ModuleEntry[];
  authorizers: ModuleEntry[];
  mutators: ModuleEntry[];
  infrastructure: InfrastructureReq;
}

export interface PreviewResponse {
  authConfig: string;
  helmValues: string;
}

export interface ValidationError {
  field: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors?: ValidationError[];
}

// Thrown by fetchJSON on non-2xx responses. Carries the backend's
// field-level validation errors (POST /instances/create returns
// {"error": "...", "validationErrors": [...]} on 422) so callers like
// the create-instance wizard can route them back onto the offending
// form fields instead of only showing the generic message.
export class ApiError extends Error {
  validationErrors?: ValidationError[];
}

export interface ClusterInfo {
  name: string;
  apiServer?: string;
  instanceCount: number;
}

export interface ClusterAddRequest {
  name: string;
  apiServer?: string;
  token?: string;
  caBundle?: string;
  kubeconfigPath?: string;
  kubeconfigContext?: string;
}

export interface ConfigVersion {
  version: number;
  content: string;
  author?: string;
  timestamp: string;
  comment?: string;
  rollback?: boolean;
  targetVersion?: number;
}

export interface ConfigPushRequest {
  content: string;
  author?: string;
  comment?: string;
}

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    ...init,
  });
  if (res.status === 401) {
    // Session expired or missing — notify the auth layer to show the login screen.
    window.dispatchEvent(new CustomEvent("lwauth:unauthenticated"));
    throw new Error("authentication required");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err = new ApiError((body as any).error || `HTTP ${res.status}`);
    if (Array.isArray((body as any).validationErrors)) {
      err.validationErrors = (body as any).validationErrors;
    }
    throw err;
  }
  // DELETE endpoints (and any other 204) respond with no body — res.json()
  // throws a SyntaxError on empty input, which would otherwise turn every
  // successful delete into a rejected promise.
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

// --- Authentication ---

export interface SessionInfo {
  authenticated: boolean;
  user: string;
  authEnabled: boolean;
}

export function getSession(): Promise<SessionInfo> {
  return fetchJSON<SessionInfo>("/auth/session");
}

export function login(username: string, password: string): Promise<SessionInfo> {
  return fetchJSON<SessionInfo>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function logout(): Promise<{ authenticated: boolean }> {
  return fetchJSON<{ authenticated: boolean }>("/auth/logout", { method: "POST" });
}

// --- URL probe (JWKS reachability) ---

export interface ProbeResult {
  reachable: boolean;
  statusCode: number;
  error?: string;
}

export function probeURL(url: string): Promise<ProbeResult> {
  return fetchJSON<ProbeResult>(`/probe/url?url=${encodeURIComponent(url)}`);
}

// --- Instances ---

export function listInstances(cluster?: string): Promise<Instance[]> {
  const qs = cluster ? `?cluster=${encodeURIComponent(cluster)}` : "";
  return fetchJSON<Instance[]>(`/instances${qs}`);
}

export function getInstance(cluster: string, name: string): Promise<Instance> {
  return fetchJSON<Instance>(`/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}`);
}

export function registerInstance(req: RegisterRequest): Promise<Instance> {
  return fetchJSON<Instance>("/instances/register", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function createInstance(req: CreateInstanceRequest): Promise<Record<string, unknown>> {
  return fetchJSON<Record<string, unknown>>("/instances/create", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function deleteInstance(cluster: string, name: string): Promise<void> {
  return fetchJSON<void>(
    `/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}`,
    { method: "DELETE" },
  );
}

// --- Module catalogue (Phase A) ---

export function listModules(): Promise<ModuleCatalogue> {
  return fetchJSON<ModuleCatalogue>("/modules");
}

export function listPresets(): Promise<Preset[]> {
  return fetchJSON<Preset[]>("/presets");
}

export function previewCreate(req: Partial<CreateInstanceRequest>): Promise<PreviewResponse> {
  return fetchJSON<PreviewResponse>("/instances/create/preview", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function validateCreate(req: Partial<CreateInstanceRequest>): Promise<ValidationResult> {
  return fetchJSON<ValidationResult>("/instances/create/validate", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

// --- Endpoints + Quick Test (Phase B) ---

export interface EndpointPair {
  internal: string;
  external?: string;
}

export interface ExtAuthzInfo {
  address: string;
  port: number;
  envoyClusterConfig: string;
}

export interface LoadBalancingInfo {
  strategy: string;
  readyReplicas: number;
  totalReplicas: number;
  podIPs?: string[];
}

export interface NodeEndpoints {
  proxyPath: string;     // e.g. /v1/proxy/local/payments-auth — prepend window.location.origin
  http: EndpointPair;
  grpc: EndpointPair;
  extAuthz: ExtAuthzInfo;
  loadBalancing: LoadBalancingInfo;
}

export interface QuickTestRequest {
  protocol: "http" | "grpc" | "ext_authz";
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface QuickTestResponse {
  status: string;
  statusCode: number;
  latency?: string;
  headers?: Record<string, string>;
  identity?: Record<string, unknown>;
  denyReason?: string;
  rawResponse?: Record<string, unknown>;
  error?: string;
}

export function getEndpoints(cluster: string, name: string): Promise<NodeEndpoints> {
  return fetchJSON<NodeEndpoints>(
    `/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}/endpoints`,
  );
}

export function quickTest(cluster: string, name: string, req: QuickTestRequest): Promise<QuickTestResponse> {
  return fetchJSON<QuickTestResponse>(
    `/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}/test`,
    { method: "POST", body: JSON.stringify(req) },
  );
}

export function getHealth(): Promise<HealthResponse> {
  return fetchJSON<HealthResponse>("/health");
}

// --- Clusters ---

export function listClusters(): Promise<ClusterInfo[]> {
  return fetchJSON<ClusterInfo[]>("/clusters");
}

export function addCluster(req: ClusterAddRequest): Promise<ClusterAddRequest> {
  return fetchJSON<ClusterAddRequest>("/clusters", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function deleteCluster(name: string): Promise<void> {
  return fetchJSON<void>(`/clusters/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
}

// --- Config ---

export function getConfig(cluster: string, name: string): Promise<ConfigVersion> {
  return fetchJSON<ConfigVersion>(
    `/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}/config`,
  );
}

export function pushConfig(cluster: string, name: string, req: ConfigPushRequest): Promise<ConfigVersion> {
  return fetchJSON<ConfigVersion>(
    `/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}/config`,
    { method: "POST", body: JSON.stringify(req) },
  );
}

export function getConfigHistory(cluster: string, name: string): Promise<ConfigVersion[]> {
  return fetchJSON<ConfigVersion[]>(
    `/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}/config/history`,
  );
}

export function rollbackConfig(
  cluster: string,
  name: string,
  version: number,
  author?: string,
): Promise<ConfigVersion> {
  return fetchJSON<ConfigVersion>(
    `/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}/config/rollback`,
    { method: "POST", body: JSON.stringify({ version, author }) },
  );
}

// --- Routes ---

export interface RouteEnd {
  instance: string;
  cluster: string;
}

export interface RouteStatus {
  healthy: boolean;
  lastProbe?: string;
  latencyP99?: string;
  error?: string;
}

export interface Route {
  name: string;
  source: RouteEnd;
  target: RouteEnd;
  pathPrefix: string;
  timeout?: string;
  failureMode?: string;
  status: RouteStatus;
  createdAt: string;
}

export interface CreateRouteRequest {
  name: string;
  source: RouteEnd;
  target: RouteEnd;
  pathPrefix: string;
  timeout?: string;
  failureMode?: string;
}

export function listRoutes(): Promise<Route[]> {
  return fetchJSON<Route[]>("/routes");
}

export function getRoute(name: string): Promise<Route> {
  return fetchJSON<Route>(`/routes/${encodeURIComponent(name)}`);
}

export function createRoute(req: CreateRouteRequest): Promise<Route> {
  return fetchJSON<Route>("/routes", { method: "POST", body: JSON.stringify(req) });
}

export function deleteRoute(name: string): Promise<void> {
  return fetchJSON<void>(`/routes/${encodeURIComponent(name)}`, { method: "DELETE" });
}

// --- Metrics (Phase 4) ---

export interface InstanceMetrics {
  instance: string;
  cluster: string;
  decisionRate: number;
  denyRate: number;
  cacheHitRatio: number;
  errorRate: number;
  latencyP50Ms: number;
  latencyP99Ms: number;
  lastScrape: string;
  stale: boolean;
}

export interface ClusterRollup {
  cluster: string;
  totalDecisions: number;
  totalDenies: number;
  avgCacheHit: number;
  instanceCount: number;
}

export interface GlobalRollup {
  totalDecisionRate: number;
  totalDenyRate: number;
  avgCacheHitRatio: number;
  totalErrorRate: number;
  clusters: ClusterRollup[];
}

export interface MetricsSnapshot {
  timestamp: string;
  global: GlobalRollup;
  instances: InstanceMetrics[];
}

export interface Decision {
  timestamp: string;
  instance: string;
  cluster: string;
  subject: string;
  path: string;
  method: string;
  verdict: "allow" | "deny";
  reason?: string;
  tenant?: string;
  durationMs: number;
}

export function getGlobalMetrics(): Promise<GlobalRollup> {
  return fetchJSON<GlobalRollup>("/metrics");
}

export function getInstanceMetrics(cluster: string, name: string): Promise<InstanceMetrics> {
  return fetchJSON<InstanceMetrics>(`/metrics/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}`);
}

// WebSocket URL helpers.
export function decisionStreamUrl(filter?: { cluster?: string; tenant?: string; verdict?: string }): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams();
  if (filter?.cluster) params.set("cluster", filter.cluster);
  if (filter?.tenant) params.set("tenant", filter.tenant);
  if (filter?.verdict) params.set("verdict", filter.verdict);
  const qs = params.toString();
  return `${proto}//${location.host}${BASE}/stream/decisions${qs ? "?" + qs : ""}`;
}

export function metricsStreamUrl(): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}${BASE}/stream/metrics`;
}

// --- Alerts (Phase 2 — request/policy-engine triage) ---

// Severity/state string unions mirror the Go
// internal/controlplane/alerting/types.go constants. Asserted via TS
// only — the wire stays string-typed so the backend extending the
// catalog never breaks the client.
export type Severity = "info" | "warning" | "critical";
export type AlertState = "open" | "acknowledged" | "resolved";
export type AlertEventType = "open" | "acked" | "resolved";

export interface MetricValue {
  value: number;
  threshold: number;
  // Raw Go time.Duration, marshaled as nanoseconds (no custom JSON
  // codec on the Go side) — divide by 1e9 for seconds. NOT seconds.
  window: number;
  comparator: ">" | "<" | ">=" | "<=";
}

export interface ReasonContributor {
  dimension: string;
  value: string;
  share?: number;
}

export interface ReasonFailure {
  timestamp: string;
  method?: string;
  path?: string;
  subject_hash?: string;
  reason?: string;
  tenant?: string;
}

export interface ReasonCorrelated {
  rule: string;
  value?: string;
  note?: string;
}

export interface ReasonPayload {
  headline: string;
  top_contributors?: ReasonContributor[];
  recent_failures?: ReasonFailure[];
  correlated?: ReasonCorrelated[];
}

export interface Scope { [key: string]: string }

export interface Alert {
  id: string;
  rule: string;
  severity: Severity;
  state: AlertState;
  fired_at: string;
  resolved_at?: string;
  acked_at?: string;
  acked_by?: string;
  ack_note?: string;
  snooze_until?: string;
  scope: Scope;
  metric?: MetricValue;
  reason?: ReasonPayload;
}

export interface ListAlertsResponse {
  alerts: Alert[];
  enabled: boolean;
  degraded: { prometheus: boolean; loki: boolean };
}

export interface Rule {
  name: string;
  description?: string;
  severity: Severity;
  source: "prometheus" | "loki";
  query: string;
  comparator: ">" | "<" | ">=" | "<=";
  threshold: number;
  // Raw Go time.Duration values, marshaled as nanoseconds (no custom
  // JSON codec on the Go side) — divide by 1e9 for seconds. NOT seconds.
  for: number;
  window: number;
  scope_labels?: string[];
  enabled: boolean;
  is_default?: boolean;
}

export interface AlertEvent {
  type: AlertEventType;
  alert: Alert;
  timestamp: string;
}

export function listAlerts(filter?: {
  state?: string;
  severity?: string;
  rule?: string;
}): Promise<ListAlertsResponse> {
  const params = new URLSearchParams();
  if (filter?.state) params.set("state", filter.state);
  if (filter?.severity) params.set("severity", filter.severity);
  if (filter?.rule) params.set("rule", filter.rule);
  const qs = params.toString();
  return fetchJSON<ListAlertsResponse>(`/alerts${qs ? "?" + qs : ""}`);
}

export function ackAlert(id: string, note?: string): Promise<{ acked: boolean; id: string; by: string }> {
  return fetchJSON<{ acked: boolean; id: string; by: string }>(
    `/alerts/${encodeURIComponent(id)}/ack`,
    { method: "POST", body: JSON.stringify({ note: note ?? "" }) },
  );
}

export function listAlertRules(): Promise<Rule[]> {
  return fetchJSON<Rule[]>("/alerts/rules");
}

export function putAlertRules(overrides: Rule[]): Promise<{ accepted: boolean; overrides: number }> {
  return fetchJSON<{ accepted: boolean; overrides: number }>("/alerts/rules", {
    method: "PUT",
    body: JSON.stringify({ overrides }),
  });
}

export function alertStreamUrl(filter?: { severity?: string; state?: string; rule?: string }): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams();
  if (filter?.severity) params.set("severity", filter.severity);
  if (filter?.state) params.set("state", filter.state);
  if (filter?.rule) params.set("rule", filter.rule);
  const qs = params.toString();
  return `${proto}//${location.host}${BASE}/stream/alerts${qs ? "?" + qs : ""}`;
}

// --- Analytics (Phase 4 — Decision Inspector + Policy Analytics) ---

export interface TimeSeriesPoint {
  timestamp: number; // Unix ms
  value: number;
}

export interface TimeSeriesRow {
  name: string;
  label?: Record<string, string>;
  color?: string;
  data: TimeSeriesPoint[];
}

export interface TimeSeriesResponse {
  series: TimeSeriesRow[];
}

export interface HistogramBucket {
  le: string;
  count: number;
}

export interface HistogramResponse {
  buckets: HistogramBucket[];
  count: number;
}

export interface PolicyVersionStats {
  policy_version: string;
  allow_count: number;
  deny_count: number;
  error_count: number;
  total_count: number;
  deny_rate: number;
  error_rate: number;
  shadow_disagreement: number;
  canary_disagreement: number;
}

export interface PolicyBreakdownResponse {
  versions: PolicyVersionStats[];
}

export interface TopDimension {
  label: string;
  count: number;
  share?: number;
}

export interface TopDimensionResponse {
  dimension: string;
  items: TopDimension[];
}

export function getDecisionTimeSeries(opts?: {
  window?: string;
  step?: string;
  groupBy?: string;
}): Promise<TimeSeriesResponse> {
  const params = new URLSearchParams();
  if (opts?.window) params.set("window", opts.window);
  if (opts?.step) params.set("step", opts.step);
  if (opts?.groupBy) params.set("groupBy", opts.groupBy);
  const qs = params.toString();
  return fetchJSON<TimeSeriesResponse>(`/analytics/decisions${qs ? "?" + qs : ""}`);
}

export function getLatencyHistogram(window?: string): Promise<HistogramResponse> {
  const qs = window ? `?window=${encodeURIComponent(window)}` : "";
  return fetchJSON<HistogramResponse>(`/analytics/latency${qs}`);
}

export function getLatencyQuantiles(opts?: {
  window?: string;
  step?: string;
}): Promise<TimeSeriesResponse> {
  const params = new URLSearchParams();
  if (opts?.window) params.set("window", opts.window);
  if (opts?.step) params.set("step", opts.step);
  const qs = params.toString();
  return fetchJSON<TimeSeriesResponse>(`/analytics/latency/quantiles${qs ? "?" + qs : ""}`);
}

export function getPolicyBreakdown(window?: string): Promise<PolicyBreakdownResponse> {
  const qs = window ? `?window=${encodeURIComponent(window)}` : "";
  return fetchJSON<PolicyBreakdownResponse>(`/analytics/policy${qs}`);
}

export function getTopDimension(
  dimension: string,
  opts?: { window?: string; limit?: number },
): Promise<TopDimensionResponse> {
  const params = new URLSearchParams();
  if (opts?.window) params.set("window", opts.window);
  if (opts?.limit) params.set("limit", String(opts.limit));
  const qs = params.toString();
  return fetchJSON<TopDimensionResponse>(
    `/analytics/top/${encodeURIComponent(dimension)}${qs ? "?" + qs : ""}`,
  );
}
