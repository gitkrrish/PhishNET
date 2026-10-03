// ============================================================
// PhishNet — Dark Web Intelligence shared style tokens
// Reuses the app's existing CSS variable design system.
// ============================================================
import { type CSSProperties } from 'react';
import { severityColor, statusColor } from '../../lib/styles';

export const dw = {
  canvas:       { backgroundColor: 'var(--tw-canvas)' },
  canvasMid:    { backgroundColor: 'var(--tw-canvas-mid)' },
  panel:        { backgroundColor: 'var(--tw-panel)', border: '1px solid var(--tw-border)' },
  panelAlt:     { backgroundColor: 'var(--tw-panel-alt)' },
  panelBorder:  { backgroundColor: 'var(--tw-panel)', borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--tw-border)' },
  text:         { color: 'var(--tw-text)' },
  muted:        { color: 'var(--tw-text-muted)' },
  faint:        { color: 'var(--tw-text-faint)' },
  burg:         { color: 'var(--tw-burgundy)' },
  brass:        { color: 'var(--tw-brass)' },
  moss:         { color: 'var(--tw-moss)' },
  critical:     { color: 'var(--tw-critical)' },
  high:         { color: 'var(--tw-high)' },
  medium:       { color: 'var(--tw-medium)' },
  low:          { color: 'var(--tw-low)' },
  info:         { color: 'var(--tw-info)' },
  borderMid:    { borderColor: 'var(--tw-border-mid)' },
  border:       { borderColor: 'var(--tw-border)' },
  bgBurg:       { backgroundColor: 'var(--tw-burgundy)' },
} as const;

export function sectionStyle(): CSSProperties {
  return { backgroundColor: 'var(--tw-canvas)', minHeight: 'calc(100vh - 9.5rem)' };
}

export { severityColor, statusColor };
