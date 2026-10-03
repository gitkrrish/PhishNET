import { useEffect, useRef } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

interface ClusterNode {
  id: string;
  x: number;
  y: number;
  z: number;
  size: number;
  color: string;
  label: string;
}

// Lightweight Canvas-based campaign cluster visualization with depth
function CampaignCluster3DInner({ clusters }: { clusters: Array<{ id: string; name: string; relatedEmails: number; riskLevel: string }> }) {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>(0);

  // Convert campaigns to cluster nodes
  const nodes: ClusterNode[] = clusters.map((campaign, index) => {
    const angle = (index / clusters.length) * Math.PI * 2;
    const radius = 60 + (campaign.relatedEmails * 2);
    const riskColors: Record<string, string> = {
      HIGH: '#8B1E30',
      MEDIUM: '#835518',
      LOW: '#305530',
    };
    return {
      id: campaign.id,
      x: Math.cos(angle) * radius,
      y: Math.sin(angle) * radius,
      z: (index % 3) * 20 - 20,
      size: 15 + Math.min(campaign.relatedEmails, 10),
      color: riskColors[campaign.riskLevel] || '#657581',
      label: campaign.name.split(' ').slice(0, 2).join(' '),
    };
  });

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
      const centerX = width / 2;
      const centerY = height / 2;

      ctx.clearRect(0, 0, width, height);

      // Draw cluster connections
      nodes.forEach((node, i) => {
        nodes.forEach((otherNode, j) => {
          if (i >= j) return;
          
          const distance = Math.sqrt(
            Math.pow(node.x - otherNode.x, 2) +
            Math.pow(node.y - otherNode.y, 2)
          );

          if (distance < 150) {
            const opacity = (1 - distance / 150) * 0.3;
            ctx.strokeStyle = `rgba(126, 29, 47, ${opacity})`;
            ctx.lineWidth = 1;
            ctx.setLineDash([2, 4]);

            ctx.beginPath();
            ctx.moveTo(centerX + node.x, centerY + node.y);
            ctx.lineTo(centerX + otherNode.x, centerY + otherNode.y);
            ctx.stroke();

            ctx.setLineDash([]);
          }
        });
      });

      // Draw nodes with depth
      // Sort by z-depth for proper rendering order
      const sortedNodes = [...nodes].sort((a, b) => b.z - a.z);

      sortedNodes.forEach((node) => {
        const depthScale = 1 + (node.z / 100);
        const size = node.size * depthScale;
        const depthAlpha = 0.6 + (node.z / 100) * 0.4;

        // Node shadow for depth
        ctx.fillStyle = node.color + '20';
        ctx.beginPath();
        ctx.arc(centerX + node.x + 2, centerY + node.y + 2, size / 2, 0, Math.PI * 2);
        ctx.fill();

        // Node body
        ctx.fillStyle = node.color + Math.floor(depthAlpha * 255).toString(16).padStart(2, '0');
        ctx.beginPath();
        ctx.arc(centerX + node.x, centerY + node.y, size / 2, 0, Math.PI * 2);
        ctx.fill();

        // Node border
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Label for larger nodes
        if (node.size > 20 && performanceTier === 'high') {
          ctx.fillStyle = 'rgba(110, 123, 133, 0.8)';
          ctx.font = '8px "IBM Plex Mono", monospace';
          ctx.textAlign = 'center';
          ctx.fillText(node.label, centerX + node.x, centerY + node.y + size / 2 + 10);
        }
      });

      time += 0.01 * quality.animationSpeed;
      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [enabled, performanceTier, quality, nodes]);

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
function CampaignCluster2D({ clusters }: { clusters: Array<{ id: string; name: string; relatedEmails: number; riskLevel: string }> }) {
  return (
    <div className="w-full h-full flex items-center justify-center">
      <div className="flex flex-wrap gap-3 justify-center p-4">
        {clusters.map((campaign) => {
          const riskColors: Record<string, string> = {
            HIGH: 'var(--tw-critical)',
            MEDIUM: 'var(--tw-medium)',
            LOW: 'var(--tw-low)',
          };
          return (
            <div
              key={campaign.id}
              className="rounded-sm px-3 py-2 border"
              style={{
                borderColor: riskColors[campaign.riskLevel],
                backgroundColor: riskColors[campaign.riskLevel] + '20',
              }}
            >
              <p className="font-mono text-[10px]" style={{ color: riskColors[campaign.riskLevel] }}>
                {campaign.name.split(' ').slice(0, 2).join(' ')}
              </p>
              <p className="font-mono text-[9px]" style={{ color: 'var(--tw-text-muted)' }}>
                {campaign.relatedEmails} emails
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Main component with error boundary and fallbacks
export default function CampaignCluster3D({ clusters }: { clusters: Array<{ id: string; name: string; relatedEmails: number; riskLevel: string }> }) {
  const { enabled, performanceTier } = useThreeD();

  if (performanceTier === 'low' || !enabled) {
    return <CampaignCluster2D clusters={clusters} />;
  }

  return (
    <ThreeDErrorBoundary fallback={<CampaignCluster2D clusters={clusters} />}>
      <CampaignCluster3DInner clusters={clusters} />
    </ThreeDErrorBoundary>
  );
}
