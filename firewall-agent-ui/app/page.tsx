"use client";
import { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";

// react-cytoscapejs uses window; load dynamically on client
const CytoscapeComponent = dynamic(() => import("react-cytoscapejs"), { ssr: false });

type Topology = {
  ok: boolean;
  nodes: Array<{ id: string; label: string; type: string; service?: string | null; ips?: string[]; restricted?: boolean; allowed_wan?: boolean }>;
  edges: Array<{ from: string; to: string; type: string; allowed?: boolean }>;
};

const API_BASE = process.env.NEXT_PUBLIC_FIREWALL_API_URL || "https://localhost:8443";

export default function HomePage() {
  const [data, setData] = useState<Topology | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const res = await fetch(`${API_BASE}/topology`, { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (!cancelled) setData(json);
      } catch (e: any) {
        if (!cancelled) setError(e.message || String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    const id = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const elements = useMemo(() => {
    if (!data) return [] as any[];
    const els: any[] = [];
    for (const n of data.nodes) {
      const color = n.type === 'wan' ? '#0ea5e9' : n.type === 'network' ? '#94a3b8' : (n.allowed_wan ? '#22c55e' : (n.restricted ? '#ef4444' : '#eab308'));
      els.push({ data: { id: n.id, label: n.label, type: n.type }, style: { 'background-color': color, 'label': n.label } });
    }
    for (const e of data.edges) {
      let color = '#94a3b8';
      if (e.type === 'wan') color = e.allowed ? '#22c55e' : '#ef4444';
      els.push({ data: { id: `${e.from}->${e.to}:${e.type}`, source: e.from, target: e.to }, style: { 'line-color': color, 'target-arrow-color': color } });
    }
    return els;
  }, [data]);

  const layout = { name: 'cose', animate: true } as any;

  return (
    <main style={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header style={{ padding: '8px 12px', borderBottom: '1px solid #e5e7eb', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1 style={{ fontSize: 18, margin: 0 }}>firewall-agent UI</h1>
        <div style={{ fontSize: 12, color: '#64748b' }}>API: {API_BASE}</div>
      </header>
      {loading && <div style={{ padding: 16 }}>Loading topology…</div>}
      {error && <div style={{ padding: 16, color: 'crimson' }}>Error: {error}</div>}
      {!loading && data && (
        <div style={{ flex: 1 }}>
          <CytoscapeComponent elements={elements} style={{ width: '100%', height: '100%' }} layout={layout} cy={(cy) => {
            cy.style().fromJson([
              { selector: 'node', style: { 'label': 'data(label)', 'text-valign': 'center', 'color': '#111827', 'font-size': 10, 'text-outline-width': 0 } },
              { selector: 'edge', style: { 'width': 2, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle' } },
            ]).update();
          }} />
        </div>
      )}
    </main>
  );
}

