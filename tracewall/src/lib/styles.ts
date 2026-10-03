/**
 * Shared inline-style helpers for theme-aware CSS variable colors.
 */

export const tv = {
  // ── Surfaces ──
  canvas:       { backgroundColor: 'var(--tw-canvas)' },
  canvasMid:    { backgroundColor: 'var(--tw-canvas-mid)' },
  canvasWarm:   { backgroundColor: 'var(--tw-canvas-warm)' },
  panel:        { backgroundColor: 'var(--tw-panel)' },
  panelAlt:     { backgroundColor: 'var(--tw-panel-alt)' },
  panelInset:   { backgroundColor: 'var(--tw-panel-inset)' },
  panelBorder:  { backgroundColor: 'var(--tw-panel)', borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--tw-border)' },

  // ── Text ──
  text:         { color: 'var(--tw-text)' },
  muted:        { color: 'var(--tw-text-muted)' },
  faint:        { color: 'var(--tw-text-faint)' },

  // ── Brand ──
  burg:         { color: 'var(--tw-burgundy)' },
  brass:        { color: 'var(--tw-brass)' },
  moss:         { color: 'var(--tw-moss)' },
  dust:         { color: 'var(--tw-dust)' },

  // ── Threat text ──
  critical:     { color: 'var(--tw-critical)' },
  high:         { color: 'var(--tw-high)' },
  medium:       { color: 'var(--tw-medium)' },
  low:          { color: 'var(--tw-low)' },
  info:         { color: 'var(--tw-info)' },

  // ── Borders ──
  border:       { borderColor: 'var(--tw-border)' },
  borderMid:    { borderColor: 'var(--tw-border-mid)' },
  borderStrong: { borderColor: 'var(--tw-border-strong)' },

  // ── Inputs ──
  input: {
    backgroundColor: 'var(--tw-input-bg)',
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: 'var(--tw-input-border)',
    color: 'var(--tw-text)',
  },

  // ── Inset notice boxes ──
  notice: {
    backgroundColor: 'var(--tw-canvas-mid)',
    borderWidth: '1px',
    borderStyle: 'solid',
    borderColor: 'var(--tw-border)',
  },
} as const;

/** Hover handlers — compatible with both light and dark */
export function hoverHandlers(hoverBg = 'var(--tw-hover)') {
  return {
    onMouseEnter: (e: React.MouseEvent<HTMLElement>) => {
      (e.currentTarget as HTMLElement).style.backgroundColor = hoverBg;
    },
    onMouseLeave: (e: React.MouseEvent<HTMLElement>) => {
      (e.currentTarget as HTMLElement).style.backgroundColor = '';
    },
  };
}

/** Returns inline styles for a severity/status chip that stay readable in dark mode.
 *  Uses solid border + semi-transparent bg (25% opacity) instead of tiny 5–10% mix. */
export function chipStyle(colorVar: string): React.CSSProperties {
  return {
    color: colorVar,
    borderColor: colorVar,
    // Use a fixed opacity that's readable in both themes
    backgroundColor: `color-mix(in srgb, ${colorVar} 18%, transparent)`,
  };
}

/** Severity token → CSS variable string */
export function severityColor(s: string): string {
  const m: Record<string, string> = {
    CRITICAL: 'var(--tw-critical)',
    HIGH:     'var(--tw-high)',
    MEDIUM:   'var(--tw-medium)',
    LOW:      'var(--tw-low)',
    INFO:     'var(--tw-info)',
  };
  return m[s] ?? m.INFO;
}

/** Status label → CSS variable */
export function statusColor(s: string): string {
  const m: Record<string, string> = {
    AWAITING_APPROVAL: 'var(--tw-medium)',
    REMEDIATED:        'var(--tw-low)',
    MONITORING:        'var(--tw-dust)',
    OPEN:              'var(--tw-critical)',
    CONTAINED:         'var(--tw-moss)',
    Investigating:     'var(--tw-critical)',
    Triage:            'var(--tw-medium)',
    Contained:         'var(--tw-moss)',
    Remediated:        'var(--tw-low)',
    Closed:            'var(--tw-dust)',
    'False Positive':  'var(--tw-dust)',
  };
  return m[s] ?? 'var(--tw-dust)';
}
