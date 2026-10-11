'use client';

import { Background, Controls, Edge, Node, ReactFlow } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { AttackGraph } from '@/lib/types';

const TYPE_COLOR: Record<string, string> = {
  USER: '#38bdf8',
  IP: '#64748b',
  ENDPOINT: '#f59e0b',
  VULNERABILITY: '#ef4444',
  ASSET: '#a855f7',
};

export function AttackGraphView({ graph }: { graph: AttackGraph }): React.ReactElement {
  const nodes: Node[] = graph.nodes.map((n, i) => ({
    id: n.id,
    position: { x: (i % 3) * 220, y: Math.floor(i / 3) * 110 },
    data: { label: n.label },
    style: {
      background: '#0f172a',
      border: `2px solid ${TYPE_COLOR[n.type] ?? '#475569'}`,
      color: '#e2e8f0',
      borderRadius: 8,
      padding: 8,
      fontSize: 12,
      width: 200,
    },
  }));

  const edges: Edge[] = graph.edges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.type,
    animated: true,
    style: { stroke: '#475569' },
    labelStyle: { fill: '#94a3b8', fontSize: 10 },
  }));

  return (
    <div style={{ height: 360, width: '100%' }} className="bg-slate-950 border border-slate-800 rounded-xl">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
        <Background color="#1e293b" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
