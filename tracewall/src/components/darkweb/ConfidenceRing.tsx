import { dw } from '../../lib/darkweb/styles';

interface ConfidenceRingProps {
  value: number;
  size?: number;
  label?: string;
  sublabel?: string;
}

export function ConfidenceRing({ value, size = 72, label, sublabel }: ConfidenceRingProps) {
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;
  const color = value >= 90 ? 'var(--tw-critical)' : value >= 75 ? 'var(--tw-high)' : value >= 60 ? 'var(--tw-medium)' : 'var(--tw-low)';
  return (
    <div className="flex flex-col items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={radius * (size / 72)} strokeWidth={4} fill="transparent"
          stroke="var(--tw-border-mid)" opacity={0.4} />
        <circle cx={size / 2} cy={size / 2} r={radius * (size / 72)} strokeWidth={4} fill="transparent"
          stroke={color} strokeDasharray={circumference * (size / 72)} strokeDashoffset={offset * (size / 72)}
          style={{ transition: 'stroke-dashoffset 0.6s ease' }} />
      </svg>
      <div className="text-center">
        <p className="font-mono text-xs font-medium" style={dw.text}>{value}%</p>
        {label && <p className="font-mono text-[9px]" style={dw.faint}>{label}</p>}
        {sublabel && <p className="font-mono text-[9px]" style={dw.faint}>{sublabel}</p>}
      </div>
    </div>
  );
}
