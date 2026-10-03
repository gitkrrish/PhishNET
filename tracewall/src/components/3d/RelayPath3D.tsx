import { useEffect, useRef } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

interface RelayHop {
  num: number;
  hostname: string;
  ip: string;
  countryName: string;
  country: string;
  asnName: string;
  reliability: 'VERIFIED' | 'SENDER_CONTROLLED' | 'INFERRED' | 'UNAVAILABLE';
  isCloud?: boolean;
  note?: string;
}

// Lightweight Canvas-based relay path with depth visualization
function RelayPath3DInner({ hops }: { hops: RelayHop[] }) {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // The hop path is fixed once the analysis is parsed, so it is painted on
  // mount and on resize instead of on every animation frame.
  useEffect(() => {
    if (!enabled || performanceTier === 'low' || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reliabilityColors: Record<string, string> = {
      VERIFIED: '#305530',
      SENDER_CONTROLLED: '#835518',
      INFERRED: '#3E4B56',
      UNAVAILABLE: '#6E7B85',
    };

    const draw = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (!width || !height) return;
      ctx.setTransform(quality.pixelRatio, 0, 0, quality.pixelRatio, 0, 0);
      ctx.clearRect(0, 0, width, height);

      // Draw relay path with depth
      const hopSpacing = width / (hops.length + 1);
      const centerY = height / 2;
      const nodeSize = Math.max(18, Math.min(24, hopSpacing * 0.7));

      hops.forEach((hop, index) => {
        const x = hopSpacing * (index + 1);
        const y = centerY;

        // Draw connection line to next hop
        if (index < hops.length - 1) {
          const nextX = hopSpacing * (index + 2);

          const isVerified = hop.reliability === 'VERIFIED';
          ctx.strokeStyle = isVerified ? 'rgba(48, 85, 48, 0.4)' : 'rgba(184, 188, 181, 0.3)';
          ctx.lineWidth = 1;
          ctx.setLineDash(isVerified ? [] : [4, 4]);

          ctx.beginPath();
          ctx.moveTo(x, y);
          ctx.lineTo(nextX, y);
          ctx.stroke();

          ctx.setLineDash([]);

          // Draw arrow for message flow direction
          const midX = (x + nextX) / 2;
          ctx.fillStyle = 'rgba(126, 29, 47, 0.3)';
          ctx.beginPath();
          ctx.moveTo(midX, y - 3);
          ctx.lineTo(midX + 5, y);
          ctx.lineTo(midX, y + 3);
          ctx.closePath();
          ctx.fill();
        }

        // Draw hop node
        const nodeColor = reliabilityColors[hop.reliability] || '#6E7B85';

        // Node shadow for depth
        ctx.fillStyle = nodeColor + '20';
        ctx.beginPath();
        ctx.arc(x + 2, y + 2, nodeSize / 2, 0, Math.PI * 2);
        ctx.fill();

        // Node body
        ctx.fillStyle = nodeColor;
        ctx.beginPath();
        ctx.arc(x, y, nodeSize / 2, 0, Math.PI * 2);
        ctx.fill();

        // Hop number
        ctx.fillStyle = '#FBFAF6';
        ctx.font = '9px "IBM Plex Mono", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(hop.num.toString(), x, y);

        // Country label below
        if (performanceTier === 'high') {
          ctx.fillStyle = 'rgba(110, 123, 133, 0.7)';
          ctx.font = '8px "IBM Plex Mono", monospace';
          ctx.fillText(hop.country, x, y + nodeSize / 2 + 12);
        }
      });
    };

    const resizeCanvas = () => {
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * quality.pixelRatio;
      canvas.height = rect.height * quality.pixelRatio;
      draw();
    };

    resizeCanvas();
    const resizeObserver = new ResizeObserver(resizeCanvas);
    resizeObserver.observe(canvas);

    return () => resizeObserver.disconnect();
  }, [enabled, performanceTier, quality.pixelRatio, hops]);

  if (!enabled) {
    return null;
  }

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-full"
      style={{ display: 'block' }}
    />
  );
}

// Fallback 2D visualization
function RelayPath2D({ hops }: { hops: RelayHop[] }) {
  return (
    <div className="w-full h-full flex items-center justify-center">
      <div className="flex items-center gap-4">
        {hops.map((hop, index) => (
          <div key={hop.num} className="flex items-center">
            <div
              className="w-6 h-6 rounded-sm flex items-center justify-center text-[9px] font-mono font-medium text-[#FBFAF6]"
              style={{
                backgroundColor:
                  hop.reliability === 'VERIFIED'
                    ? 'var(--tw-low)'
                    : hop.reliability === 'SENDER_CONTROLLED'
                    ? 'var(--tw-medium)'
                    : hop.reliability === 'INFERRED'
                    ? 'var(--tw-dust)'
                    : 'var(--tw-text-faint)',
              }}
            >
              {hop.num}
            </div>
            {index < hops.length - 1 && (
              <div
                className="w-8 h-px mx-2"
                style={{
                  backgroundColor: 'var(--tw-border-strong)',
                  borderStyle: hop.reliability === 'VERIFIED' ? 'solid' : 'dashed',
                }}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// Main component with error boundary and fallbacks
export default function RelayPath3D({ hops }: { hops: RelayHop[] }) {
  const { enabled, performanceTier } = useThreeD();

  if (performanceTier === 'low' || !enabled) {
    return <RelayPath2D hops={hops} />;
  }

  return (
    <ThreeDErrorBoundary fallback={<RelayPath2D hops={hops} />}>
      <RelayPath3DInner hops={hops} />
    </ThreeDErrorBoundary>
  );
}
