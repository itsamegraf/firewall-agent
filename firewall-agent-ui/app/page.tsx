"use client";
import { useCallback, useEffect, useState } from "react";
import { api, API_BASE, Topology } from "./lib/api";
import { Legend } from "./components/Legend";
import { Controls } from "./components/Controls";
import { CytoGraph } from "./graph/CytoGraph";

export default function HomePage() {
  const [data, setData] = useState<Topology | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [auto, setAuto] = useState<boolean>(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const topo = await api.topology();
      setData(topo);
      setError(null);
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    load();
    const id = setInterval(() => { if (!cancelled && auto) load(); }, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [auto, load]);

  const doEnable = useCallback(async () => {
    try { await api.enable(); await load(); } catch (e: any) { setError(e.message || String(e)); }
  }, [load]);
  const doDisable = useCallback(async () => {
    try { await api.disable(); await load(); } catch (e: any) { setError(e.message || String(e)); }
  }, [load]);

  return (
    <main style={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header style={{ padding: '8px 12px', borderBottom: '1px solid #e5e7eb', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16 }}>
        <h1 style={{ fontSize: 18, margin: 0 }}>firewall-agent UI</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <Legend />
          <div style={{ fontSize: 12, color: '#64748b' }}>API: {API_BASE}</div>
        </div>
      </header>
      <div style={{ padding: 8, display: 'flex', gap: 12, alignItems: 'center' }}>
        <button onClick={load} style={btn}>Refresh</button>
        <button onClick={doEnable} style={btn}>Enable Policy</button>
        <button onClick={doDisable} style={btn}>Disable Policy</button>
        <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12, color: '#334155' }}>
          <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
          Auto-refresh
        </label>
        {loading && <span style={{ fontSize: 12, color: '#64748b' }}>Loading…</span>}
        {error && <span style={{ fontSize: 12, color: 'crimson' }}>Error: {error}</span>}
      </div>
      <div style={{ flex: 1 }}>
        {data && <CytoGraph data={{ nodes: data.nodes, edges: data.edges }} />}
      </div>
    </main>
  );
}

const btn: React.CSSProperties = {
  padding: '6px 10px',
  border: '1px solid #cbd5e1',
  background: '#f8fafc',
  borderRadius: 6,
  cursor: 'pointer',
};
