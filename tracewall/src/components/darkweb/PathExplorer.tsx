import { useMemo, useState } from 'react';
import { Route, ArrowRight, AlertTriangle } from 'lucide-react';
import { dw } from '../../lib/darkweb/styles';
import { useIntelligence } from '../../lib/intelligence/IntelligenceContext';
import { analyseGraph, shortestPath, isPath, type PathStrategy } from '../../lib/intelligence/graph';
import { MetaCell } from './EntityWorkspace';

/**
 * Path explorer.
 *
 * The result is presented hop by hop rather than as a single line from A to
 * B, because only the individual relationships are claimed. A rendered
 * "A → B" would invite the reader to treat the endpoints as related, which
 * is not what the graph says.
 */
export function PathExplorer() {
  const { dataset } = useIntelligence();
  const analysis = useMemo(() => analyseGraph(dataset), [dataset]);

  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [strategy, setStrategy] = useState<PathStrategy>('HOPS');

  const options = useMemo(
    () => [...analysis.graph.nodes.values()].sort((a, b) => a.label.localeCompare(b.label)),
    [analysis],
  );

  const result = useMemo(() => {
    if (!from || !to) return null;
    return shortestPath(analysis.graph, from, to, { strategy });
  }, [analysis, from, to, strategy]);

  return (
    <div className="rounded-sm border p-4 space-y-3" style={dw.panel}>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <p className="font-mono text-[10px] tracking-widest uppercase flex items-center gap-1.5" style={dw.muted}>
          <Route size={12} /> Path analysis
        </p>
        <span className="font-mono text-[9px]" style={dw.faint}>
          {analysis.graph.nodes.size} nodes · {analysis.components.length} component{analysis.components.length === 1 ? '' : 's'} · density {analysis.density}
        </span>
      </div>

      <div className="grid md:grid-cols-[1fr_auto_1fr_auto] gap-2 items-end">
        <label className="block">
          <span className="font-mono text-[9px] uppercase block mb-1" style={dw.faint}>From</span>
          <select
            value={from}
            onChange={e => setFrom(e.target.value)}
            className="w-full font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
            style={{ backgroundColor: 'var(--tw-panel-alt)', border: '1px solid var(--tw-border-mid)', color: 'var(--tw-text)' }}
          >
            <option value="">Select an entity…</option>
            {options.map(node => <option key={node.id} value={node.id}>{node.label} ({node.type})</option>)}
          </select>
        </label>
        <ArrowRight size={13} className="mb-2.5 shrink-0" style={dw.faint} />
        <label className="block">
          <span className="font-mono text-[9px] uppercase block mb-1" style={dw.faint}>To</span>
          <select
            value={to}
            onChange={e => setTo(e.target.value)}
            className="w-full font-mono text-[10px] px-2 py-1.5 rounded-sm focus:outline-none"
            style={{ backgroundColor: 'var(--tw-panel-alt)', border: '1px solid var(--tw-border-mid)', color: 'var(--tw-text)' }}
          >
            <option value="">Select an entity…</option>
            {options.map(node => <option key={node.id} value={node.id}>{node.label} ({node.type})</option>)}
          </select>
        </label>
        <button
          onClick={() => setStrategy(s => (s === 'HOPS' ? 'CONFIDENCE' : 'HOPS'))}
          className="font-mono text-[10px] px-2.5 py-1.5 rounded-sm border shrink-0 mb-0.5"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-burgundy)' }}
          title="Switch between fewest relationships and the best-supported route"
        >
          {strategy === 'HOPS' ? 'FEWEST HOPS' : 'BEST SUPPORTED'}
        </button>
      </div>

      {result && !isPath(result) && (
        <div className="p-3 rounded-sm border font-mono text-[10px] flex items-start gap-2" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
          <AlertTriangle size={12} className="mt-0.5 shrink-0" style={dw.medium} />
          <div>
            <p style={dw.medium}>
              {result.reason === 'UNKNOWN_ENTITY' ? 'Entity not in this graph'
                : result.reason === 'SAME_ENTITY' ? 'Same entity'
                  : 'No recorded route'}
            </p>
            <p className="mt-1 leading-relaxed" style={dw.muted}>{result.detail}</p>
          </div>
        </div>
      )}

      {result && isPath(result) && (
        <div className="space-y-2">
          <div className="grid sm:grid-cols-4 gap-3">
            <MetaCell label="Relationships" value={result.length} />
            <MetaCell
              label="Chain strength"
              value={`${result.pathStrength}/100`}
              color={result.pathStrength >= 50 ? dw.moss.color : dw.medium.color}
            />
            <MetaCell
              label="Weakest link"
              value={result.weakestHop ? `${result.weakestHop.confidence}%` : '—'}
              color={result.weakestHop && result.weakestHop.confidence < 60 ? dw.critical.color : undefined}
            />
            <MetaCell label="Strategy" value={result.strategy === 'HOPS' ? 'fewest relationships' : 'best supported'} />
          </div>

          <ol className="space-y-1.5">
            {result.hops.map((hop, index) => {
              const fromNode = analysis.graph.nodes.get(hop.from);
              const toNode = analysis.graph.nodes.get(hop.to);
              return (
                <li key={`${hop.relationshipId}-${index}`} className="p-2.5 rounded-sm border font-mono text-[10px]" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)' }}>
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span style={dw.text}>
                      {index === 0 ? fromNode?.label : fromNode?.label}
                      {' → '}
                      {toNode?.label}
                    </span>
                    <span style={dw.faint}>{hop.confidence}%</span>
                  </div>
                  <p className="mt-1" style={dw.burg}>
                    {hop.relationshipType.replace(/_/g, ' ')}
                    {hop.reversed && <span style={dw.faint}> · traversed against its stored direction (symmetric relationship)</span>}
                  </p>
                  {hop.explanation && <p className="mt-1 leading-relaxed" style={dw.muted}>{hop.explanation}</p>}
                  <p className="mt-1" style={dw.faint}>
                    {hop.relationshipId}
                    {hop.evidenceIds.length > 0 && ` · evidence ${hop.evidenceIds.join(', ')}`}
                    {hop.evidenceIds.length === 0 && ' · no evidence cited'}
                  </p>
                </li>
              );
            })}
          </ol>

          <p className="font-mono text-[9px] leading-relaxed" style={dw.faint}>
            Each row above is a relationship this dataset records. The chain is not a claim that
            {' '}{analysis.graph.nodes.get(result.nodes[0])?.label ?? result.nodes[0]} and
            {' '}{analysis.graph.nodes.get(result.nodes[result.nodes.length - 1])?.label ?? result.nodes[result.nodes.length - 1]}
            {' '}are related to one another, and it shows no direction of influence. Chain strength is the
            product of the hop confidences, used to rank routes against each other — it is not a probability.
          </p>
        </div>
      )}

      {analysis.betweenness.length > 0 && (
        <div>
          <p className="font-mono text-[9px] tracking-widest uppercase mb-1.5" style={dw.muted}>Structural bridges</p>
          <div className="flex flex-wrap gap-1.5">
            {analysis.betweenness.slice(0, 6).map(node => (
              <span key={node.id} className="font-mono text-[9px] px-1.5 py-0.5 rounded-sm border" style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-info)' }}>
                {node.label} · {node.score}
              </span>
            ))}
          </div>
          <p className="font-mono text-[9px] mt-1 leading-relaxed" style={dw.faint}>
            Entities that most often sit on the shortest route between others in this dataset. That makes them
            useful to watch for a missing record, not important in themselves — a well-documented entity scores
            highly whether or not it is central to anything.
          </p>
        </div>
      )}

      <div className="p-2.5 rounded-sm border font-mono text-[9px] leading-relaxed space-y-1" style={{ backgroundColor: 'var(--tw-canvas-mid)', borderColor: 'var(--tw-border-mid)' }}>
        {analysis.caveats.map(caveat => <p key={caveat} style={dw.faint}>· {caveat}</p>)}
      </div>
    </div>
  );
}
