"use client";
import { useState } from 'react';

export function Controls({ onRefresh, onEnable, onDisable }: { onRefresh: () => void; onEnable: () => void; onDisable: () => void; }) {
  const [auto, setAuto] = useState(true);
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
      <button onClick={onRefresh} style={btn}>Refresh</button>
      <button onClick={onEnable} style={btn}>Enable Policy</button>
      <button onClick={onDisable} style={btn}>Disable Policy</button>
      <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12, color: '#334155' }}>
        <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
        Auto-refresh
      </label>
    </div>
  );
}

const btn: React.CSSProperties = {
  padding: '6px 10px',
  border: '1px solid #cbd5e1',
  background: '#f8fafc',
  borderRadius: 6,
  cursor: 'pointer',
};

