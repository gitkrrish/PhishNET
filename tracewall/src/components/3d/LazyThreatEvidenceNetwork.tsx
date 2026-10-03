import { Suspense, lazy } from 'react';
import type { ComponentProps } from 'react';

const ThreatEvidenceNetwork = lazy(() => import('./ThreatEvidenceNetwork'));

type Props = ComponentProps<typeof ThreatEvidenceNetwork>;

/**
 * The evidence network embeds a large set of per-page datasets, so it is
 * fetched on demand rather than shipping inside the main bundle that every
 * public page downloads. The placeholder mirrors the real panel's chrome and
 * height so surrounding content does not shift while the chunk is in flight.
 */
export default function LazyThreatEvidenceNetwork(props: Props) {
  return (
    <Suspense
      fallback={
        <div
          className="rounded-sm overflow-hidden border"
          style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-panel-alt)' }}
        >
          <div
            className="flex items-center justify-between px-3 py-2 border-b"
            style={{ borderColor: 'var(--tw-border-mid)' }}
          >
            <span className="font-mono text-[9px] tracking-wider uppercase" style={{ color: 'var(--tw-text-muted)' }}>
              Threat Evidence Network
            </span>
          </div>
          <div className="relative" style={{ height: 'clamp(210px, 26vh, 300px)' }} />
        </div>
      }
    >
      <ThreatEvidenceNetwork {...props} />
    </Suspense>
  );
}
