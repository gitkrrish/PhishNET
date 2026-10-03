import clsx from 'clsx';
import { chipStyle } from '../../lib/styles';
import type { RiskLevel } from '../../lib/intelligence/types-protection';
import { riskLevelColor } from '../../lib/intelligence/protection';

interface RiskBadgeProps {
  risk: RiskLevel;
  className?: string;
  dot?: boolean;
}

/** Reads a computed threat risk level and renders it as a terminal-style chip. */
export function RiskBadge({ risk, className, dot = true }: RiskBadgeProps) {
  const color = riskLevelColor(risk);
  const label = risk === 'INACTIVE' ? 'Inactive' : risk.charAt(0) + risk.slice(1).toLowerCase();
  return (
    <span
      className={clsx(
        'font-mono text-[10px] font-medium tracking-widest uppercase px-2 py-0.5 rounded-sm border inline-flex items-center gap-1',
        className,
      )}
      style={chipStyle(color)}
    >
      {dot && (
        <span
          className="w-1.5 h-1.5 rounded-full"
          style={{ backgroundColor: color, boxShadow: `0 0 4px ${color}` }}
        />
      )}
      {label}
    </span>
  );
}
