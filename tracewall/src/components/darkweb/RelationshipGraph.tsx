import { ReactFlow, Controls, Background, MiniMap, MarkerType } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useMemo, useState, useCallback } from 'react';
import type { ComponentType } from 'react';
import { dw } from '../../lib/darkweb/styles';
import { buildGraph, NODE_TYPE_CONFIG, confidenceColor, type GraphNodeData } from '../../lib/darkweb/graphData';
import { EntityDetailPanel } from './EntityDetailPanel';
import { Search, RotateCcw, Shield, MousePointer, Key, Wallet, Globe, Server, Database, FileText, Activity, Network, ShoppingBag } from 'lucide-react';
import type { Node, Edge, NodeTypes } from '@xyflow/react';

const ICON_MAP: Record<string, ComponentType<{ size?: number; className?: string }>> = {
  actor: Shield, handle: MousePointer, pgp: Key, wallet: Wallet, domain: Globe,
  ip: Server, tls: Server, evidence: FileText, forum: Database, marketplace: ShoppingBag,
  onion: Globe, persona: MousePointer, relationship: Network,
};

function isoTurn(type: string, conf?: number): string {
  const base = NODE_TYPE_CONFIG[type]?.colorVar ?? 'var(--tw-dust)';
  return conf !== undefined ? confidenceColor(conf) : base;
}

function DefaultNode({ data }: { data: any }) {
  const iconType = data.type as string;
  const Icon = ICON_MAP[iconType] ?? FileText;
  const color = (data as GraphNodeData).color ?? isoTurn(iconType, (data as any).confidence);
  return (
    <div className="px-2.5 py-1.5 rounded-sm border shadow-sm text-center min-w-[110px]" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
      <div style={{ color }}>{<Icon size={13} className="mx-auto mb-0.5" />}</div>
      <p className="font-mono text-[9px] leading-tight" style={dw.text}>{data.label}</p>
      {(data as any).confidence !== undefined && (
        <p className="font-mono text-[8px] mt-0.5" style={{ color: confidenceColor((data as any).confidence) }}>{(data as any).confidence}%</p>
      )}
    </div>
  );
}

function ActorNode({ data }: { data: any }) {
  return (
    <div className="px-2.5 py-1.5 rounded-sm border shadow-sm min-w-[120px]" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-critical) 15%, transparent)', borderColor: 'var(--tw-critical)' }}>
      <p className="font-mono text-[10px] font-medium" style={dw.critical}>{(data as any).label}</p>
      <p className="font-mono text-[8px] leading-tight" style={dw.muted}>{(data as any).meta?.aliases?.[0] ?? ''}</p>
      {(data as any).confidence !== undefined && <p className="font-mono text-[8px] mt-0.5" style={dw.text}>conf {(data as any).confidence}%</p>}
    </div>
  );
}

const nodeTypes: NodeTypes = { actor: ActorNode, handle: DefaultNode, pgp: DefaultNode, wallet: DefaultNode, domain: DefaultNode, ip: DefaultNode, tls: DefaultNode, evidence: DefaultNode, forum: DefaultNode, marketplace: DefaultNode, relationship: DefaultNode, onion: DefaultNode, persona: DefaultNode };

export interface RelationshipGraphProps {
  seed?: string;
  heightClass?: string;
}

export function RelationshipGraph({ seed, heightClass = 'h-[520px]' }: RelationshipGraphProps) {
  const built = useMemo(() => buildGraph(seed), [seed]);
  const [nodes, setNodes] = useState<Node[]>(built.nodes);
  const [edges, setEdges] = useState<Edge[]>(built.edges);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [nodeFilter, setNodeFilter] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');

  const onNodesChange = useCallback((changes: any) => setNodes((n) => n), []);
  const onEdgesChange = useCallback((changes: any) => setEdges((e) => e), []);

  const filteredNodes = useMemo(() => {
    let ns = nodes;
    if (nodeFilter.size) ns = ns.filter(n => (n.type && nodeFilter.has(n.type)) ?? false);
    if (search.trim()) {
      const q = search.toLowerCase();
      ns = ns.filter(n => (n.data?.label?.toString().toLowerCase().includes(q)) || n.id.toLowerCase().includes(q));
    }
    return ns;
  }, [nodes, nodeFilter, search]);

  const filteredEdges = useMemo(() => {
    const visibleIds = new Set(filteredNodes.map(n => n.id));
    return edges.filter(e => visibleIds.has(e.source) && visibleIds.has(e.target));
  }, [edges, filteredNodes]);

  const nodeTypesList: string[] = useMemo(() => Array.from(new Set(nodes.map(n => n.type ?? 'base'))), [nodes]);
  const toggleFilter = (t: string) => setNodeFilter(prev => { const n = new Set(prev); if (n.has(t)) n.delete(t); else n.add(t); return n; });
  const resetFilters = () => setNodeFilter(new Set());

  const onNodeClick = (_: any, node: Node) => setSelectedNode(node);
  const onPaneClick = () => setSelectedNode(null);

  return (
    <div className={`flex ${heightClass} rounded-sm border overflow-hidden relative`} style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
      <div className="absolute z-10 m-2 flex gap-1.5 items-center flex-wrap" style={{ top: 8, left: 8 }}>
        <div className="relative">
          <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" style={{ color: 'var(--tw-text-faint)' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="font-mono text-[10px] pl-6 pr-2 py-1 rounded-sm focus:outline-none"
            style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text)' }}
            placeholder="Search nodes…"
          />
        </div>
        <button onClick={resetFilters} className="font-mono text-[10px] px-2 py-1 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }} title="Reset filters"><RotateCcw size={11} /></button>
        <div className="flex flex-wrap gap-1 items-center">
          {nodeTypesList.map(t => (
            <button key={t} onClick={() => toggleFilter(t)}
              className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border"
              style={{
                backgroundColor: nodeFilter.has(t) ? 'transparent' : 'color-mix(in srgb, var(--tw-dust) 18%, transparent)',
                borderColor: 'var(--tw-border-mid)',
                color: nodeFilter.has(t) ? 'var(--tw-text-muted)' : 'var(--tw-text-faint)',
              }}>
              {t}
            </button>
          ))}
        </div>
      </div>
      <ReactFlow
        nodes={filteredNodes}
        edges={filteredEdges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        fitView
        fitViewOptions={{ maxZoom: 1.2, minZoom: 0.2 }}
        defaultEdgeOptions={{ animated: true, style: { strokeWidth: 2 }, markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12 } }}
      >
        <Controls position="bottom-left" />
        <Background gap={16} />
        <MiniMap position="bottom-right" nodeColor="var(--tw-burgundy)" />
      </ReactFlow>
      {selectedNode && (
        <div className="absolute inset-y-0 right-0 w-80 border-l overflow-y-auto z-20" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border-mid)' }}>
          <EntityDetailPanel node={selectedNode as any} onClose={() => setSelectedNode(null)} />
        </div>
      )}
    </div>
  );
}
