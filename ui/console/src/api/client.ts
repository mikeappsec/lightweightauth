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
