export type Topology = {
  ok: boolean;
  nodes: Array<{ id: string; label: string; type: string; service?: string | null; ips?: string[]; restricted?: boolean; allowed_wan?: boolean }>;
  edges: Array<{ from: string; to: string; type: string; allowed?: boolean }>;
  allowed_services?: string[];
};

export type Status = {
  ok: boolean;
  iptables: { chain: string; enabled: boolean; rule_count: number; allow_ips: string[] };
  allowed_services: Record<string, string[]>;
  restricted_containers: string[];
};

export const API_BASE = process.env.NEXT_PUBLIC_FIREWALL_API_URL || "https://localhost:9444";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers || {}) },
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export const api = {
  topology: () => req<Topology>(`/topology`),
  status: () => req<Status>(`/status`),
  enable: () => req(`/enable`, { method: 'POST' }),
  disable: () => req(`/disable`, { method: 'POST' }),
};
