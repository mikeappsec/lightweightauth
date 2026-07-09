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
    throw new Error((body as any).error || `HTTP ${res.status}`);
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
  pathPrefix?: string;
}

export interface RouteStatus {
  healthy: boolean;
  lastProbe?: string;
  latencyMs?: number;
}

export interface Route {
  name: string;
  source: RouteEnd;
  target: RouteEnd;
  status: RouteStatus;
  createdAt: string;
}

export interface CreateRouteRequest {
  name: string;
  source: RouteEnd;
  target: RouteEnd;
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
  return fetch(`${BASE}/routes/${encodeURIComponent(name)}`, { method: "DELETE" }).then((r) => {
    if (!r.ok) throw new Error(`DELETE /routes/${name}: ${r.status}`);
  });
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
  window: number; // seconds (Go time.Duration.ns / 1e9)
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
  for: number;      // seconds
  window: number;   // seconds
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
