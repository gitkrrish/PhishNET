import clsx from 'clsx';
import { chipStyle, severityColor } from '../../lib/styles';

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const color = severityColor(severity);
  return (
    <span
      className={clsx(
        'font-mono text-[10px] font-medium tracking-widest uppercase px-2 py-0.5 rounded-sm border',
        className
      )}
      style={chipStyle(color)}
    >
      {severity.charAt(0) + severity.slice(1).toLowerCase()}
    </span>
  );
}
