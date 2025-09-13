"use client";
import dynamic from 'next/dynamic';
import cytoscape from 'cytoscape';
import fcose from 'cytoscape-fcose';
import popper from 'cytoscape-popper';
import tippy, { Props } from 'tippy.js';
import 'tippy.js/dist/tippy.css';
import { useMemo } from 'react';

// Register plugins
if ((cytoscape as any).registeredFcose !== true) {
  cytoscape.use(fcose);
  (cytoscape as any).registeredFcose = true;
}
if ((cytoscape as any).registeredPopper !== true) {
  cytoscape.use(popper);
  (cytoscape as any).registeredPopper = true;
}

const CytoscapeComponent = dynamic(() => import('react-cytoscapejs'), { ssr: false });

export type GraphData = {
  nodes: Array<{ id: string; label: string; type: string; service?: string | null; ips?: string[]; restricted?: boolean; allowed_wan?: boolean }>;
  edges: Array<{ from: string; to: string; type: string; allowed?: boolean }>;
};

export function CytoGraph({ data }: { data: GraphData }) {
  const elements = useMemo(() => {
    const els: any[] = [];
    for (const n of data.nodes) {
      const color = n.type === 'wan' ? '#0ea5e9' : n.type === 'network' ? '#94a3b8' : (n.allowed_wan ? '#22c55e' : (n.restricted ? '#ef4444' : '#eab308'));
      els.push({ data: { id: n.id, label: n.label, type: n.type, service: n.service || '', ips: (n.ips || []).join(', ') }, style: { 'background-color': color, 'label': n.label } });
    }
    for (const e of data.edges) {
      let color = '#94a3b8';
      if (e.type === 'wan') color = e.allowed ? '#22c55e' : '#ef4444';
      els.push({ data: { id: `${e.from}->${e.to}:${e.type}`, source: e.from, target: e.to, kind: e.type, allowed: e.allowed ? '1' : '' }, style: { 'line-color': color, 'target-arrow-color': color } });
    }
    return els;
  }, [data]);

  const layout = { name: 'fcose', animate: true, randomize: true, nodeSeparation: 100, idealEdgeLength: 120 } as any;

  return (
    <CytoscapeComponent
      elements={elements}
      style={{ width: '100%', height: '100%' }}
      layout={layout}
      cy={(cy) => {
        cy.style().fromJson([
          { selector: 'node', style: { 'label': 'data(label)', 'text-valign': 'center', 'color': '#111827', 'font-size': 10, 'text-outline-width': 0, 'width': 18, 'height': 18 } },
          { selector: 'node[type = "network"]', style: { 'shape': 'diamond' } },
          { selector: 'node[type = "wan"]', style: { 'shape': 'round-rectangle', 'width': 40, 'height': 18 } },
          { selector: 'edge', style: { 'width': 2, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle' } },
        ]).update();

        // Tooltips for containers
        cy.nodes().forEach((n) => {
          const type = n.data('type');
          if (type !== 'container') return;
          const ref = n.popperRef();
          const content = document.createElement('div');
          content.innerHTML = `<div style="font-size:12px"><strong>${n.data('label')}</strong><br/>Service: ${n.data('service') || '-'}<br/>IPs: ${n.data('ips') || '-'}<br/></div>`;
          tippy(ref as any, { content, trigger: 'manual', placement: 'top', hideOnClick: false } as Partial<Props>);
        });

        cy.on('tap', 'node', (evt) => {
          const node = evt.target as any;
          const type = node.data('type');
          // Toggle tooltip
          if (type === 'container') {
            const t = (node as any)._tippy as any;
            if (t) t.state.isVisible ? t.hide() : t.show();
          }
          cy.fit(node, 50);
        });
      }}
    />
  );
}

