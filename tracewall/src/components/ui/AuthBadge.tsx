import { chipStyle } from '../../lib/styles';

interface AuthBadgeProps {
  result: string;
  label: string;
  detail?: string;
  explanation?: string;
}

const resultColors: Record<string, string> = {
  PASS:        'var(--tw-low)',
  FAIL:        'var(--tw-critical)',
  SOFTFAIL:    'var(--tw-medium)',
  NONE:        'var(--tw-dust)',
  NEUTRAL:     'var(--tw-dust)',
  UNAVAILABLE: 'var(--tw-text-faint)',
  Success:     'var(--tw-low)',
  'No data':   'var(--tw-dust)',
  Timeout:     'var(--tw-medium)',
  'Rate limited': 'var(--tw-medium)',
};

export function AuthBadge({ result, label, detail, explanation }: AuthBadgeProps) {
  const color = resultColors[result] || resultColors.UNAVAILABLE;
  return (
    <div
      className="rounded-sm p-3 space-y-1.5 border"
      style={chipStyle(color)}
    >
      <div className="flex items-center justify-between gap-2">
        <span
          className="font-mono text-[10px] tracking-widest uppercase"
          style={{ color: 'var(--tw-text-muted)' }}
        >
          {label}
        </span>
        <div className="flex items-center gap-1.5">
          <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
          <span className="font-mono text-xs font-medium" style={{ color }}>{result}</span>
        </div>
      </div>
      {detail && (
        <p className="text-xs" style={{ color: 'var(--tw-text)' }}>{detail}</p>
      )}
      {explanation && (
        <p className="text-xs leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>{explanation}</p>
      )}
    </div>
  );
}
