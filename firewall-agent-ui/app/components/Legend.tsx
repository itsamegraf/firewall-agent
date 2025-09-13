export function Legend() {
  const item = (color: string, label: string) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <span style={{ width: 12, height: 12, background: color, borderRadius: 4, display: 'inline-block' }} />
      <span>{label}</span>
    </div>
  );
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'auto auto', gap: 8, fontSize: 12 }}>
      {item('#0ea5e9', 'WAN')}
      {item('#94a3b8', 'Network')}
      {item('#22c55e', 'Allowed container')}
      {item('#ef4444', 'Restricted container')}
      {item('#eab308', 'Other container')}
      <div style={{ gridColumn: '1 / -1', color: '#64748b' }}>WAN edges: green=allowed, red=blocked</div>
    </div>
  );
}

