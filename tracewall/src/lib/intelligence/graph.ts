// ============================================================
// Graph path analysis.
//
// A path through the intelligence graph is a statement about the
// model, not about the world. Two entities being two hops apart
// means this dataset records a chain of relationships between them;
// it does not mean the subject at one end controls or knows the one
// at the other. Every result here is therefore reported with the
// relationships that form it, so a reader can judge each hop rather
// than accept the path as a conclusion.
//
// Three distinctions the search respects:
//
//   Direction. Some relationships are symmetric (two subjects share
//   a key) and some are directed (an actor uses a handle). Traversing
//   a directed edge backwards would invent paths that the record
//   does not support, so `SHARED_*`/`ASSOCIATED_WITH` are walked both
//   ways and everything else only forwards.
//
//   Strength. "Shortest" is ambiguous. A one-hop path at 30% confidence
//   is weaker evidence than a three-hop path where every hop is 95%.
//   Both are offered: fewest hops, and fewest hops among the most
//   confident routes.
//
//   Absence. No path means this dataset records no chain. It is not
//   evidence that no relationship exists, and the graph only contains
//   what has been collected.
// ============================================================

import type { IntelligenceDataset } from './types';

/** Relationship types that carry no inherent direction. */
const SYMMETRIC_TYPES = new Set([
  'SHARED_HANDLE', 'SHARED_PGP', 'SHARED_WALLET', 'SHARED_INFRASTRUCTURE',
  'ASSOCIATED_WITH', 'ASSOCIATED_WITH_TTP', 'ASSOCIATED_WITH_CVE',
  'ASSOCIATED_WITH_TRANSACTION', 'SIMILAR_PERSONA', 'TEMPORAL_OVERLAP',
  'SHARED_BEHAVIOR', 'PART_OF_CLUSTER',
]);

export type PathStrategy = 'HOPS' | 'CONFIDENCE';

export interface GraphNode {
  id: string;
  /** Short human label resolved from the dataset. */
  label: string;
  type: string;
}

export interface GraphHop {
  from: string;
  to: string;
  relationshipId: string;
  relationshipType: string;
  confidence: number;
  evidenceIds: string[];
  explanation: string;
  /** True when the edge was traversed against its stored direction. */
  reversed: boolean;
}

export interface GraphPath {
  nodes: string[];
  hops: GraphHop[];
  /** Number of relationships traversed. */
  length: number;
  /** Product of hop confidences, 0-100. Never presented as a probability. */
  pathStrength: number;
  /** The lowest-confidence hop, which is where the chain is weakest. */
  weakestHop: GraphHop | null;
  strategy: PathStrategy;
}

export interface NoPath {
  nodes: [string, string];
  reason: 'NO_ROUTE' | 'UNKNOWN_ENTITY' | 'SAME_ENTITY';
  detail: string;
}

export type PathResult = GraphPath | NoPath;

export interface BridgeScore {
  id: string;
  label: string;
  score: number;
  share: number;
}

export interface AnalysisGraph {
  nodes: Map<string, GraphNode>;
  /** Adjacency: node id -> traversable edges. */
  adjacency: Map<string, Array<GraphHop & { cost: number }>>;
}

export interface GraphAnalysis {
  graph: AnalysisGraph;
  betweenness: Array<{ id: string; label: string; score: number; share: number }>;
  articulation: string[];
  components: string[][];
  density: number;
  isolated: string[];
  /** Standing limits on reading any path or centrality figure. */
  caveats: string[];
}

/** Entity labels the graph can show for a node id. */
function labelFor(dataset: IntelligenceDataset, id: string): { label: string; type: string } {
  const actor = dataset.lookups.actorsById[id];
  if (actor) return { label: actor.aliases[0] ?? actor.id, type: 'actor' };
  if (id.startsWith('h_')) {
    const handle = dataset.lookups.handlesById?.[id.slice(2)];
    return { label: handle ? `@${handle.value}` : id.slice(2), type: 'handle' };
  }
  if (id.startsWith('k_')) {
    const key = dataset.lookups.pgpById?.[id.slice(2)];
    return { label: key ? `PGP ${key.id}` : id.slice(2), type: 'pgp' };
  }
  if (id.startsWith('w_')) {
    const wallet = dataset.lookups.walletsById?.[id.slice(2)];
    return { label: wallet ? wallet.address : id.slice(2), type: 'wallet' };
  }
  if (id.startsWith('i_')) {
    const infra = dataset.lookups.infraById?.[id.slice(2)];
    return { label: infra ? infra.value : id.slice(2), type: 'infrastructure' };
  }
  if (id.startsWith('src_')) {
    const source = dataset.lookups.sourcesById?.[id.slice(6)];
    return { label: source ? source.name : id.slice(6), type: 'source' };
  }
  if (id.startsWith('ev_')) {
    return { label: id.slice(3), type: 'evidence' };
  }
  return { label: id, type: 'unknown' };
}

/** True when a relationship may be traversed in both directions. */
export function isSymmetric(type: string): boolean {
  return SYMMETRIC_TYPES.has(type);
}

/** Build the traversable graph from stored relationships. */
export function buildAnalysisGraph(dataset: IntelligenceDataset): AnalysisGraph {
  const nodes = new Map<string, GraphNode>();
  const adjacency = new Map<string, Array<GraphHop & { cost: number }>>();

  const ensure = (id: string) => {
    if (!nodes.has(id)) {
      const { label, type } = labelFor(dataset, id);
      nodes.set(id, { id, label, type });
      adjacency.set(id, []);
    }
    return id;
  };

  for (const rel of dataset.relationships) {
    if (!rel.sourceEntity || !rel.targetEntity) continue;
    // Node ids are stored on the relationship as rendered by the graph.
    const from = ensure(rel.sourceEntity);
    const to = ensure(rel.targetEntity);
    if (from === to) continue;

    const base: Omit<GraphHop, 'reversed'> = {
      from, to,
      relationshipId: rel.id,
      relationshipType: rel.type,
      confidence: rel.confidence,
      evidenceIds: rel.evidenceIds ?? [],
      explanation: rel.explanation,
    };
    const symmetric = isSymmetric(rel.type);
    adjacency.get(from)!.push({ ...base, reversed: false, cost: rel.confidence });
    if (symmetric) {
      adjacency.get(to)!.push({ ...base, from: to, to: from, reversed: true, cost: rel.confidence });
    }
  }

  return { nodes, adjacency };
}

/**
 * Hop-limited search. `HOPS` returns the route with fewest relationships;
 * `CONFIDENCE` returns the route that maximises the product of hop
 * confidences, which is a ranking heuristic and not a probability.
 */
export function shortestPath(
  graph: AnalysisGraph,
  from: string,
  to: string,
  options: { strategy?: PathStrategy; maxHops?: number } = {},
): PathResult {
  const strategy = options.strategy ?? 'HOPS';
  const maxHops = options.maxHops ?? 8;

  if (!graph.nodes.has(from) || !graph.nodes.has(to)) {
    const missing = !graph.nodes.has(from) ? from : to;
    return {
      nodes: [from, to],
      reason: 'UNKNOWN_ENTITY',
      detail: `${missing} is not a node in this graph. The graph only contains entities that have been collected and linked, so its absence means it was never connected, not that it does not exist.`,
    };
  }
  if (from === to) {
    return { nodes: [from, to], reason: 'SAME_ENTITY', detail: 'The start and end are the same entity, so there is nothing to traverse.' };
  }

  // Priority queue keyed by cumulative cost; a simple linear scan is used
  // because the graph is small enough that a heap would not pay for itself.
  const best = new Map<string, number>([[from, 0]]);
  const previous = new Map<string, GraphHop>();
  const visited = new Set<string>();
  const frontier: string[] = [from];

  while (frontier.length) {
    // Ascending cost: this is a min-priority queue, so the cheapest frontier
    // entry must be settled first or the search returns a worse route.
    frontier.sort((a, b) => (best.get(a) ?? Infinity) - (best.get(b) ?? Infinity));
    const current = frontier.shift()!;
    if (visited.has(current)) continue;
    visited.add(current);
    if (current === to) break;

    for (const edge of graph.adjacency.get(current) ?? []) {
      if (visited.has(edge.to)) continue;
      // Hop count leads, so one extra hop always costs more than any
      // confidence difference; the fractional part breaks ties in favour of
      // the better-supported edge. A confidence of 0 must not make an edge
      // free, because an unrated link is not evidence.
      const step = strategy === 'HOPS'
        ? 1 + (100 - edge.confidence) / 1000
        : Math.max(1, 100 - edge.confidence);
      const cost = (best.get(current) ?? 0) + step;
      if (cost < (best.get(edge.to) ?? Infinity)) {
        best.set(edge.to, cost);
        previous.set(edge.to, { ...edge, reversed: edge.reversed });
        frontier.push(edge.to);
      }
    }
  }

  if (!previous.has(to)) {
    return {
      nodes: [from, to],
      reason: 'NO_ROUTE',
      detail: 'No chain of stored relationships connects these two entities. That is a gap in what has been collected and linked, not a finding that they are unrelated.',
    };
  }

  // Reconstruct the route.
  const hops: GraphHop[] = [];
  let cursor = to;
  const guard = new Set<string>();
  while (cursor !== from && !guard.has(cursor)) {
    guard.add(cursor);
    const hop = previous.get(cursor);
    if (!hop) break;
    hops.unshift(hop);
    cursor = hop.from;
  }
  if (cursor !== from || hops.length > maxHops) {
    return {
      nodes: [from, to],
      reason: 'NO_ROUTE',
      detail: `A route exists but exceeds the ${maxHops}-hop limit, or could not be reconstructed. A long route is usually a sign that the direct link was never collected.`,
    };
  }

  const pathStrength = Math.round(hops.reduce((product, hop) => product * (hop.confidence / 100), 1) * 100);
  const weakestHop = hops.reduce<GraphHop | null>(
    (worst, hop) => (!worst || hop.confidence < worst.confidence ? hop : worst),
    null,
  );

  return {
    nodes: [from, ...hops.map(h => h.to)],
    hops,
    length: hops.length,
    pathStrength,
    weakestHop,
    strategy,
  };
}

export function isPath(result: PathResult): result is GraphPath {
  return 'hops' in result;
}

/**
 * Betweenness centrality over unweighted shortest paths: which entities
 * most often sit on the shortest route between others. A high score means
 * an entity is a structural bridge in this dataset, not that it is
 * influential in the real world.
 */
export function betweennessCentrality(graph: AnalysisGraph, limit = 12): BridgeScore[] {
  const ids = [...graph.nodes.keys()];
  const scores = new Map<string, number>();
  for (const id of ids) scores.set(id, 0);

  for (const source of ids) {
    // Brandes' algorithm, single-source variant.
    const stack: string[] = [];
    const predecessors = new Map<string, string[]>();
    const sigma = new Map<string, number>(ids.map(id => [id, 0]));
    const distance = new Map<string, number>();
    sigma.set(source, 1);
    distance.set(source, 0);
    const queue: string[] = [source];

    while (queue.length) {
      const v = queue.shift()!;
      stack.push(v);
      for (const edge of graph.adjacency.get(v) ?? []) {
        const w = edge.to;
        const d = (distance.get(v) ?? 0) + 1;
        if (!distance.has(w)) {
          distance.set(w, d);
          queue.push(w);
        }
        if (distance.get(w) === d) {
          sigma.set(w, (sigma.get(w) ?? 0) + (sigma.get(v) ?? 0));
          predecessors.set(w, [...(predecessors.get(w) ?? []), v]);
        }
      }
    }

    const delta = new Map<string, number>(ids.map(id => [id, 0]));
    while (stack.length) {
      const w = stack.pop()!;
      for (const v of predecessors.get(w) ?? []) {
        // The "1 +" is the count of shortest paths that end at w; without it
        // the dependency never propagates and every score collapses to zero.
        const share = ((sigma.get(v) ?? 0) / (sigma.get(w) || 1)) * (1 + (delta.get(w) ?? 0));
        delta.set(v, (delta.get(v) ?? 0) + share);
      }
      if (w !== source) scores.set(w, (scores.get(w) ?? 0) + (delta.get(w) ?? 0));
    }
  }

  const total = [...scores.values()].reduce((a, b) => a + b, 0);
  return [...scores.entries()]
    .filter(([, score]) => score > 0)
    .map(([id, score]) => ({
      id,
      label: graph.nodes.get(id)?.label ?? id,
      score: Math.round(score * 100) / 100,
      share: total ? Math.round((score / total) * 1000) / 10 : 0,
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}

/**
 * Articulation points: entities whose removal would split the graph.
 * These are the points where a single missing record changes the
 * connectivity of everything else.
 */
export function articulationPoints(graph: AnalysisGraph): string[] {
  const ids = [...graph.nodes.keys()];
  const discovery = new Map<string, number>();
  const low = new Map<string, number>();
  const parent = new Map<string, string | null>();
  const found: string[] = [];
  let timer = 0;

  const visit = (node: string) => {
    discovery.set(node, timer);
    low.set(node, timer);
    timer++;
    let children = 0;
    for (const edge of graph.adjacency.get(node) ?? []) {
      const next = edge.to;
      if (!discovery.has(next)) {
        children++;
        parent.set(next, node);
        visit(next);
        low.set(node, Math.min(low.get(node)!, low.get(next)!));
        // A non-root node with a child that cannot reach above it.
        if (parent.get(node) !== null && low.get(next)! >= discovery.get(node)!) found.push(node);
      } else if (parent.get(node) !== next) {
        low.set(node, Math.min(low.get(node)!, discovery.get(next)!));
      }
    }
    if (parent.get(node) === null && children > 1) found.push(node);
  };

  for (const id of ids) if (!discovery.has(id)) { parent.set(id, null); visit(id); }
  return Array.from(new Set(found));
}

/** Connected components, largest first. */
export function connectedComponents(graph: AnalysisGraph): string[][] {
  const seen = new Set<string>();
  const components: string[][] = [];
  for (const id of graph.nodes.keys()) {
    if (seen.has(id)) continue;
    const component: string[] = [];
    const queue = [id];
    seen.add(id);
    while (queue.length) {
      const current = queue.shift()!;
      component.push(current);
      for (const edge of graph.adjacency.get(current) ?? []) {
        if (!seen.has(edge.to)) { seen.add(edge.to); queue.push(edge.to); }
      }
    }
    components.push(component);
  }
  return components.sort((a, b) => b.length - a.length);
}

export function analyseGraph(dataset: IntelligenceDataset): GraphAnalysis {
  const graph = buildAnalysisGraph(dataset);
  const components = connectedComponents(graph);
  const nodeCount = graph.nodes.size;
  const edgeCount = [...graph.adjacency.values()].reduce((sum, list) => sum + list.length, 0);
  const possibleEdges = nodeCount * (nodeCount - 1);

  return {
    graph,
    betweenness: betweennessCentrality(graph),
    articulation: articulationPoints(graph),
    components,
    density: possibleEdges > 0 ? Math.round((edgeCount / possibleEdges) * 10000) / 10000 : 0,
    isolated: [...graph.nodes.keys()].filter(id => (graph.adjacency.get(id) ?? []).length === 0),
    caveats: [
      'A path is a chain of recorded relationships, not a causal chain. Two entities at the ends of a path are not thereby related; only the hops in between are claimed.',
      'A path carries no direction of influence. Traversing it does not show that the first entity acts on the last.',
      'No path means this dataset records no chain. It is not evidence that no relationship exists.',
      'Centrality and articulation describe the shape of what has been collected. An entity scoring highly may simply be well recorded, not important.',
      'The product of hop confidences is a ranking heuristic for comparing routes. It is not a probability and must not be read as one.',
    ],
  };
}
