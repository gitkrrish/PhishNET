import clsx from 'clsx';
import { chipStyle } from '../../lib/styles';
import type { ThreatScore } from '../../lib/intelligence/types-protection';
import { riskLevelColor, responsePriorityColor } from '../../lib/intelligence/protection';

interface ThreatScoreBadgeProps {
  score: ThreatScore;
  compact?: boolean;
  className?: string;
}

/** Threat score (0–100) with a risk-level ring and response priority marker. */
export function ThreatScoreBadge({ score, compact = false, className }: ThreatScoreBadgeProps) {
  const color = riskLevelColor(score.riskLevel);
  const priorityColor = responsePriorityColor(score.responsePriority);
  return (
    <span
      className={clsx(
        'font-mono text-[10px] font-medium tracking-widest uppercase rounded-full border inline-flex items-center gap-1',
        compact ? 'px-1.5 py-0.5 text-[8px]' : 'px-2 py-0.5',
        className,
      )}
      style={{
        ...chipStyle(color),
        backgroundColor: `color-mix(in srgb, ${color} 20%, transparent)`,
      }}
    >
      <span
        className="w-2 h-2 rounded-full"
        style={{ backgroundColor: color, boxShadow: `0 0 5px ${priorityColor}` }}
      />
      <span style={{ color }}>{score.value}</span>
    </span>
  );
}
