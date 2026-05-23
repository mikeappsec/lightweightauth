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
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as any).error || `HTTP ${res.status}`);
  }
  return res.json();
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

export function deleteInstance(cluster: string, name: string): Promise<void> {
  return fetchJSON<void>(
    `/instances/${encodeURIComponent(cluster)}/${encodeURIComponent(name)}`,
    { method: "DELETE" },
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
