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
  const animationRef = useRef<number>(0);

  useEffect(() => {
    if (!enabled || performanceTier === 'low' || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    const resizeCanvas = () => {
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * quality.pixelRatio;
      canvas.height = rect.height * quality.pixelRatio;
      ctx.scale(quality.pixelRatio, quality.pixelRatio);
    };
    resizeCanvas();

    let time = 0;
    const animate = () => {
      const width = canvas.width / quality.pixelRatio;
      const height = canvas.height / quality.pixelRatio;

      ctx.clearRect(0, 0, width, height);

      // Draw relay path with depth
      const hopSpacing = width / (hops.length + 1);
      const centerY = height / 2;

      hops.forEach((hop, index) => {
        const x = hopSpacing * (index + 1);
        const depthOffset = Math.sin(time * 0.5 + index * 0.5) * 5;
        const depthScale = 1 + (depthOffset / 50);
        const y = centerY + depthOffset;

        // Draw connection line to next hop
        if (index < hops.length - 1) {
          const nextX = hopSpacing * (index + 2);
          const nextDepthOffset = Math.sin(time * 0.5 + (index + 1) * 0.5) * 5;
          const nextY = centerY + nextDepthOffset;

          const isVerified = hop.reliability === 'VERIFIED';
          ctx.strokeStyle = isVerified ? 'rgba(48, 85, 48, 0.4)' : 'rgba(184, 188, 181, 0.3)';
          ctx.lineWidth = 1;
          ctx.setLineDash(isVerified ? [] : [4, 4]);

          ctx.beginPath();
          ctx.moveTo(x, y);
          ctx.lineTo(nextX, nextY);
          ctx.stroke();

          ctx.setLineDash([]);

          // Draw arrow for message flow direction
          const midX = (x + nextX) / 2;
          const midY = (y + nextY) / 2;
          ctx.fillStyle = 'rgba(126, 29, 47, 0.3)';
          ctx.beginPath();
          ctx.moveTo(midX, midY - 3);
          ctx.lineTo(midX + 5, midY);
          ctx.lineTo(midX, midY + 3);
          ctx.closePath();
          ctx.fill();
        }

        // Draw hop node with depth
        const nodeSize = 24 * depthScale;
        const reliabilityColors: Record<string, string> = {
          VERIFIED: '#305530',
          SENDER_CONTROLLED: '#835518',
          INFERRED: '#3E4B56',
          UNAVAILABLE: '#6E7B85',
        };
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

      time += 0.02 * quality.animationSpeed;
      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [enabled, performanceTier, quality, hops]);

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
