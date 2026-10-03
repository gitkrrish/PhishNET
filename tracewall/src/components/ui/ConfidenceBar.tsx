interface ConfidenceBarProps {
  value: number;
  label?: boolean;
}

export function ConfidenceBar({ value, label = true }: ConfidenceBarProps) {
  const color = value >= 80 ? 'var(--tw-critical)' : value >= 60 ? 'var(--tw-medium)' : 'var(--tw-low)';
  return (
    <div className="space-y-1">
      {label && (
        <div className="flex justify-between items-center">
          <span className="font-mono text-[10px] tracking-widest uppercase" style={{ color: 'var(--tw-text-muted)' }}>
            Confidence
          </span>
          <span className="font-mono text-xs" style={{ color: 'var(--tw-text)' }}>{value}%</span>
        </div>
      )}
      <div className="confidence-bar w-full">
        <div className="confidence-fill" style={{ width: `${value}%`, background: color }} />
      </div>
    </div>
  );
}
