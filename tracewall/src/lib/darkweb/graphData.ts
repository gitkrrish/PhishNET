// ============================================================
// PhishNet — Dark Web Graph data builder.
//
// The graph is no longer built from the static seed: nodes, edges
// and layout are derived from the central intelligence dataset, so
// a relationship created seconds ago is renderable immediately and
// removed records disappear from the graph.
// ============================================================
import type { Node, Edge } from '@xyflow/react';
import type { Relationship, Evidence } from '../../data/darkWebData';
import {
  buildIntelligenceGraph,
  confidenceColor,
  resolveGraphNodeId,
  DEFAULT_GRAPH_FILTERS,
  NODE_TYPE_CONFIG,
  type GraphFilters,
  type GraphNodeData,
} from '../intelligence/derive';
import { liveDataset, darkWebEvidenceById, darkWebRelationships } from './liveData';

export { confidenceColor, NODE_TYPE_CONFIG, DEFAULT_GRAPH_FILTERS };
export type { GraphNodeData, GraphFilters };

/** Nodes + edges for the whole dataset, or a focused view around one seed. */
export function buildGraph(seed?: string, filters?: GraphFilters): { nodes: Node[]; edges: Edge[] } {
  return buildIntelligenceGraph(liveDataset(), seed, filters);
}

/** Build a single edge for a stored relationship, resolving entity references. */
export function relationshipToEdge(rel: Relationship): Edge {
  const dataset = liveDataset();
  const source = resolveGraphNodeId(dataset, rel.sourceEntity, rel.sourceType);
  const target = resolveGraphNodeId(dataset, rel.targetEntity, rel.targetType);
  if (!source || !target) {
    return { id: `e_${rel.id}`, source: rel.sourceEntity, target: rel.targetEntity, label: rel.type, data: { label: rel.type, confidence: rel.confidence } };
  }
  return {
    id: `e_${rel.id}`,
    source,
    target,
    label: rel.type.replace(/_/g, ' '),
    data: { label: rel.type.replace(/_/g, ' '), confidence: rel.confidence },
  };
}

export { darkWebEvidenceById as getEvidenceById, darkWebRelationships as getRelationships };
export type { Evidence };
