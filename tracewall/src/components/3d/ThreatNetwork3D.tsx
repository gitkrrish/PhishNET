import { useEffect, useRef, useState } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

interface Node {
  id: string;
  type: 'actor' | 'handle' | 'pgp' | 'wallet' | 'infrastructure' | 'evidence' | 'case';
  label: string;
  x: number;
  y: number;
  z: number;
}

/**
 * The landing canvas shows the central intelligence model, not a
 * message: a threat actor resolved into the handles, cryptographic
 * identity, payment identifiers and infrastructure it was observed
 * using, with the evidence and investigation case those feed.
 */
const initialNodes: Node[] = [
  { id: 'actor', type: 'actor', label: 'ACTOR', x: 0, y: 0, z: 0 },
  { id: 'handle', type: 'handle', label: 'HANDLE', x: -60, y: -25, z: 30 },
  { id: 'pgp', type: 'pgp', label: 'PGP', x: 60, y: -25, z: -30 },
  { id: 'wallet', type: 'wallet', label: 'WALLET', x: -60, y: 27, z: -30 },
  { id: 'infra', type: 'infrastructure', label: 'INFRA', x: 60, y: 27, z: 30 },
  { id: 'evidence', type: 'evidence', label: 'EVIDENCE', x: -85, y: 0, z: 15 },
  { id: 'case', type: 'case', label: 'CASE', x: 85, y: 0, z: -15 },
];

// Lightweight Canvas-based threat network visualization with subtle depth
function ThreatNetwork3DInner() {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes] = useState<Node[]>(initialNodes);

  // The diagram is static, so it is painted on mount and on resize rather than
  // on every animation frame.
  useEffect(() => {
    if (!enabled || performanceTier === 'low' || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const nodeColors: Record<Node['type'], string> = {
      actor: '#7E1D2F',
      handle: '#A47535',
      pgp: '#596E5B',
      wallet: '#657581',
      infrastructure: '#481521',
      evidence: '#835518',
      case: '#A47535',
    };

    const draw = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (!width || !height) return;
      ctx.setTransform(quality.pixelRatio, 0, 0, quality.pixelRatio, 0, 0);
      ctx.clearRect(0, 0, width, height);

      const centerX = width / 2;
      const centerY = height / 2;

      // Uniform scale keeps every node inside the panel on small screens.
      const maxExtent = Math.max(
        ...nodes.map(node => Math.max(Math.abs(node.x), Math.abs(node.y)) * (1 + node.z / 200) + 24),
      );
      const fit = Math.max(0.3, Math.min(1.2, (Math.min(width, height) / 2) / maxExtent));

      // Draw connections
      ctx.strokeStyle = 'rgba(184, 188, 181, 0.3)';
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 4]);

      nodes.slice(1).forEach((node) => {
        const depthScale = 1 + (node.z / 200);
        const x = centerX + node.x * depthScale * fit;
        const y = centerY + node.y * depthScale * fit;

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(x, y);
        ctx.stroke();
      });

      ctx.setLineDash([]);

      // Draw nodes
      nodes.forEach((node) => {
        const depthScale = 1 + (node.z / 200);
        const x = centerX + node.x * depthScale * fit;
        const y = centerY + node.y * depthScale * fit;
        const size = 40 * depthScale * fit;

        // Draw node background
        ctx.fillStyle = nodeColors[node.type] + '33';
        ctx.strokeStyle = nodeColors[node.type];
        ctx.lineWidth = 1.5;

        // Rounded rectangle
        const radius = 3;
        ctx.beginPath();
        ctx.roundRect(x - size / 2, y - size / 4, size, size / 2, radius);
        ctx.fill();
        ctx.stroke();

        // Draw label
        ctx.fillStyle = nodeColors[node.type];
        ctx.font = `${Math.max(7, Math.min(10, 9 * fit))}px "IBM Plex Mono", monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.label.toUpperCase(), x, y);
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
  }, [enabled, performanceTier, quality.pixelRatio, nodes]);

  // If 3D is disabled, return null (fallback will be handled by parent)
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

// Fallback 2D SVG visualization
function ThreatNetwork2D() {
  const nodeColors: Record<Node['type'], string> = {
    actor: '#7E1D2F',
    handle: '#A47535',
    pgp: '#596E5B',
    wallet: '#657581',
    infrastructure: '#481521',
    evidence: '#835518',
    case: '#A47535',
  };

  const nodes: Node[] = [
    { id: 'actor', type: 'actor', label: 'ACTOR', x: 200, y: 100, z: 0 },
    { id: 'handle', type: 'handle', label: 'HANDLE', x: 80, y: 50, z: 0 },
    { id: 'pgp', type: 'pgp', label: 'PGP', x: 320, y: 50, z: 0 },
    { id: 'wallet', type: 'wallet', label: 'WALLET', x: 80, y: 155, z: 0 },
    { id: 'infra', type: 'infrastructure', label: 'INFRA', x: 320, y: 155, z: 0 },
    { id: 'evidence', type: 'evidence', label: 'EVIDENCE', x: 30, y: 100, z: 0 },
    { id: 'case', type: 'case', label: 'CASE', x: 370, y: 100, z: 0 },
  ];

  return (
    <svg viewBox="-12 0 424 200" className="w-full h-full">
      {/* Connection lines */}
      {nodes.slice(1).map((node) => (
        <line
          key={`line-${node.id}`}
          x1="200"
          y1="100"
          x2={node.x}
          y2={node.y}
          stroke="var(--tw-border-strong)"
          strokeWidth="1"
          strokeDasharray="4,4"
          opacity="0.4"
        />
      ))}
      {/* Nodes */}
      {nodes.map((node) => (
        <g key={node.id}>
          <rect
            x={node.x - 40}
            y={node.y - 15}
            width="80"
            height="30"
            rx="2"
            fill={nodeColors[node.type] + '20'}
            stroke={nodeColors[node.type]}
            strokeWidth="1.5"
          />
          <text
            x={node.x}
            y={node.y + 4}
            textAnchor="middle"
            fill={nodeColors[node.type]}
            fontSize="9"
            fontFamily="IBM Plex Mono"
            style={{ textTransform: 'uppercase', letterSpacing: '0.1em' }}
          >
            {node.label}
          </text>
        </g>
      ))}
    </svg>
  );
}

// Main component with error boundary and fallbacks
export default function ThreatNetwork3D() {
  const { enabled, performanceTier } = useThreeD();

  // Low performance tier always uses 2D fallback
  if (performanceTier === 'low' || !enabled) {
    return <ThreatNetwork2D />;
  }

  return (
    <ThreeDErrorBoundary fallback={<ThreatNetwork2D />}>
      <ThreatNetwork3DInner />
    </ThreeDErrorBoundary>
  );
}
