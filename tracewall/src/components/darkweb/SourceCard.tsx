import { type DarkWebSource } from '../../data/darkWebData';
import { dw } from '../../lib/darkweb/styles';
import { Shield, Globe, Database, FileText, AlertTriangle, MessageSquare, Wifi, BarChart2 } from 'lucide-react';

const typeIcons: Record<DarkWebSource['type'], React.ComponentType<{ size?: number; className?: string }>> = {
  FORUM: Database, MARKETPLACE: ShoppingBag, PASTE: FileText, LEAK_SITE: AlertTriangle,
  MESSAGING: MessageSquare, THREAT_FEED: BarChart2, ONION_SERVICE: Globe,
};
import { ShoppingBag } from 'lucide-react';

export function SourceCard({ source }: { source: DarkWebSource }) {
  const Icon = typeIcons[source.type];
  return (
    <div className="rounded-sm border overflow-hidden" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
      <div className="p-5 space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <span style={{ color: 'var(--tw-burgundy)' }}><Icon size={18} /></span>
            <p className="font-serif text-lg" style={dw.text}>{source.name}</p>
          </div>
          <span className="font-mono text-[10px] tracking-widest uppercase px-2 py-0.5 rounded-sm"
            style={{
              color: source.status === 'ACTIVE' ? 'var(--tw-low)' : 'var(--tw-medium)',
              backgroundColor: 'color-mix(in srgb, var(--tw-low) 18%, transparent)',
            }}>
            {source.status}
          </span>
        </div>
        <p className="text-xs" style={dw.muted}>{source.description}</p>
        <div className="grid grid-cols-2 gap-2 text-[10px]">
          <div><span style={dw.faint}>Reliability</span><div className="font-mono" style={dw.text}>R{source.reliabilityScore} — {source.type}</div></div>
          <div><span style={dw.faint}>Activity</span><div className="font-mono" style={dw.text}>{source.activityLevel}</div></div>
          <div><span style={dw.faint}>First seen</span><div className="font-mono" style={dw.text}>{new Date(source.firstObserved).toLocaleDateString()}</div></div>
          <div><span style={dw.faint}>Last seen</span><div className="font-mono" style={dw.text}>{new Date(source.lastObserved).toLocaleDateString()}</div></div>
          <div><span style={dw.faint}>Actors</span><div className="font-mono" style={dw.text}>{source.actorCount}</div></div>
          <div><span style={dw.faint}>Indicators</span><div className="font-mono" style={dw.text}>{source.indicatorCount}</div></div>
          <div className="col-span-2"><span style={dw.faint}>Collected</span><div className="font-mono" style={dw.text}>{new Date(source.collectionTimestamp).toLocaleString()}</div></div>
        </div>
        {source.onionAddress && <p className="font-mono text-[10px]" style={dw.faint}>🧅 {source.onionAddress}</p>}
      </div>
    </div>
  );
}
