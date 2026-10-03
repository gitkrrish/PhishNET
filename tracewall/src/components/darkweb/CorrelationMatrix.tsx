import { useMemo } from 'react';
import { dw } from '../../lib/darkweb/styles';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { identityCorrelationMatrix, type IdentityRecord } from '../../lib/darkweb/aiEngine';

export function CorrelationMatrix({ actorIds }: { actorIds: string[] }) {
  const { darkWebActorsById } = useIntelligenceData();

  const identities: IdentityRecord[] = useMemo(() => {
    const actors = actorIds.map(id => darkWebActorsById[id]).filter(Boolean);
    const allHandles = Array.from(new Set(actors.flatMap(a => a.handles)));
    return allHandles.flatMap(h => identityCorrelationMatrix(h));
  }, [actorIds, darkWebActorsById]);

  return (
    <div className="overflow-x-auto rounded-sm border" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
      <table className="w-full text-[10px] font-mono">
        <thead>
          <tr style={{ backgroundColor: 'var(--tw-panel-alt)' }}>
            <th className="text-left p-2" style={dw.text}>Platform</th>
            <th className="text-left p-2" style={dw.text}>Handle</th>
            <th className="text-left p-2" style={dw.text}>Observed</th>
            <th className="text-left p-2" style={dw.text}>Confidence</th>
            <th className="text-left p-2" style={dw.text}>Shared Indicators</th>
            <th className="text-left p-2" style={dw.text}>Relationship</th>
          </tr>
        </thead>
        <tbody>
          {identities.map((i, idx) => (
            <tr key={idx} className="border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <td className="p-2" style={dw.text}>{i.platform}</td>
              <td className="p-2" style={dw.burg}>{i.handle}</td>
              <td className="p-2" style={dw.muted}>{new Date(i.observedDate).toLocaleDateString()}</td>
              <td className="p-2" style={dw.text}>{i.confidence}%</td>
              <td className="p-2" style={dw.faint}>{i.sharedIndicators.join(', ') || '—'}</td>
              <td className="p-2" style={dw.info}>{i.relationship ?? '—'}</td>
            </tr>
          ))}
          {!identities.length && <tr><td colSpan={6} className="p-4 text-center" style={dw.faint}>No matching identities found.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
