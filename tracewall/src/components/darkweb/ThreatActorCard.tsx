import { Link } from 'react-router-dom';
import { ConfidenceBar } from '../ui/ConfidenceBar';
import { DemoLabel } from '../ui/DemoLabel';
import { RiskBadge } from '../ui/RiskBadge';
import { dw } from '../../lib/darkweb/styles';
import { User } from 'lucide-react';
import type { ThreatActor } from '../../data/darkWebData';
import type { RiskLevel } from '../../lib/intelligence/types-protection';

interface ThreatActorCardProps {
  actor: ThreatActor;
  compact?: boolean;
  /** Computed threat-risk level; when omitted no badge is rendered. */
  risk?: RiskLevel;
}

export function ThreatActorCard({ actor, compact = false, risk }: ThreatActorCardProps) {
  const firstAlias = actor.aliases[0] ?? actor.id;
  const handleCount = new Set(actor.handles).size;
  return (
    <Link to={`/app/darkweb/actors/${actor.id}`} className="block group" style={{ textDecoration: 'none', color: 'inherit' }}>
      <div
        className="rounded-sm border overflow-hidden transition-all duration-200 group-hover:translate-y-[-2px]"
        style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}
      >
        <div className={`p-${compact ? '4' : '5'}`}>
          <div className="flex items-start justify-between gap-3">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-[10px] tracking-wider" style={dw.burg}>{actor.id}</span>
                {actor.isSynthetic && <DemoLabel />}
              </div>
              <p className="font-serif text-lg group-hover:underline" style={dw.text}>{firstAlias}</p>
              <div className="flex flex-wrap gap-1.5">
                <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-burgundy) 15%, transparent)', color: 'var(--tw-burgundy)' }}>{handleCount} handles</span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-brass) 15%, transparent)', color: 'var(--tw-brass)' }}>{actor.pgpFingerprints.length} PGP</span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-info) 15%, transparent)', color: 'var(--tw-info)' }}>{actor.walletAddrs.length} wallets</span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-medium) 15%, transparent)', color: 'var(--tw-medium)' }}>{actor.domains.length} domains</span>
              </div>
            </div>
            <div className="text-right shrink-0">
              <span className="font-mono text-xs" style={dw.text}>{actor.confidenceScore}%</span>
            </div>
          </div>
          {!compact && (
            <div className="mt-3 space-y-2">
              <ConfidenceBar value={actor.confidenceScore} />
              <div className="flex flex-wrap gap-1">
                {actor.platforms.map(p => (
                  <span key={p} className="font-mono text-[10px] px-2 py-0.5 rounded-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-dust) 18%, transparent)', color: 'var(--tw-dust)' }}>{p}</span>
                ))}
              </div>
              {actor.primaryMotivation && <p className="font-mono text-[10px] mt-1.5" style={dw.faint}>{actor.primaryMotivation}</p>}
            </div>
          )}
        </div>
        <div className="px-5 py-2 border-t flex items-center justify-between" style={dw.borderMid}>
          <span className={`font-mono text-[10px] tracking-widest uppercase`} style={{ color: actor.status === 'ACTIVE' ? 'var(--tw-critical)' : actor.status === 'DORMANT' ? 'var(--tw-medium)' : 'var(--tw-dust)' }}>{actor.status}</span>
          <div className="flex items-center gap-2">
            {risk !== undefined && <RiskBadge risk={risk} dot={false} />}
            <User size={13} style={dw.burg} />
          </div>
        </div>
      </div>
    </Link>
  );
}
