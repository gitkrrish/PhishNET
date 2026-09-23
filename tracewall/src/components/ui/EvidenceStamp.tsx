import clsx from 'clsx';

interface EvidenceStampProps {
  verdict: string;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

const verdictVars: Record<string, string> = {
  'LEGITIMATE':  'var(--tw-low)',
  'REVIEW':      'var(--tw-dust)',
  'SUSPICIOUS':  'var(--tw-medium)',
  'HIGH RISK':   'var(--tw-critical)',
  'CONTAIN':     'var(--tw-critical)',
  'CRITICAL':    'var(--tw-critical)',
};

const sizeClasses = {
  sm: 'text-xs px-2 py-0.5',
  md: 'text-sm px-3 py-1',
  lg: 'text-base px-4 py-1.5',
};

export function EvidenceStamp({ verdict, className, size = 'md' }: EvidenceStampProps) {
  const color = verdictVars[verdict] || 'var(--tw-text)';
  return (
    <span
      className={clsx(
        'font-mono font-medium tracking-widest uppercase border-2 inline-block -rotate-1 rounded-sm',
        sizeClasses[size],
        className
      )}
      style={{ color, borderColor: color }}
    >
      {verdict}
    </span>
  );
}
