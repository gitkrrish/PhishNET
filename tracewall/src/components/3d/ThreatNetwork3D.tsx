import { useEffect, useRef, useState } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

interface Node {
  id: string;
  type: 'email' | 'domain' | 'ip' | 'url' | 'campaign' | 'case';
  label: string;
  x: number;
  y: number;
  z: number;
}

const initialNodes: Node[] = [
  { id: 'sender', type: 'email', label: 'SENDER', x: 0, y: 0, z: 0 },
  { id: 'lookalike', type: 'domain', label: 'LOOKALIKE', x: -60, y: -25, z: 30 },
  { id: 'replyto', type: 'domain', label: 'REPLY-TO', x: 60, y: -25, z: -30 },
  { id: 'relayde', type: 'ip', label: 'RELAY · DE', x: -60, y: 27, z: -30 },
  { id: 'relaypl', type: 'ip', label: 'RELAY · PL', x: 60, y: 27, z: 30 },
  { id: 'campaign', type: 'campaign', label: 'CAMPAIGN', x: -85, y: 0, z: 15 },
  { id: 'exposure', type: 'case', label: 'EXPOSURE', x: 85, y: 0, z: -15 },
];

// Lightweight Canvas-based threat network visualization with subtle depth
function ThreatNetwork3DInner() {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes] = useState<Node[]>(initialNodes);
  const animationRef = useRef<number>(0);

  // Canvas animation
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

    const nodeColors: Record<Node['type'], string> = {
      email: '#7E1D2F',
      domain: '#A47535',
      ip: '#596E5B',
      url: '#657581',
      campaign: '#481521',
      case: '#835518',
    };

    let time = 0;
    const animate = () => {
      const width = canvas.width / quality.pixelRatio;
      const height = canvas.height / quality.pixelRatio;
      const centerX = width / 2;
      const centerY = height / 2;

      ctx.clearRect(0, 0, width, height);

      // Draw connections
      ctx.strokeStyle = 'rgba(184, 188, 181, 0.3)';
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 4]);

      nodes.slice(1).forEach((node) => {
        const depthScale = 1 + (node.z / 200);
        const x = centerX + node.x * depthScale;
        const y = centerY + node.y * depthScale;

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(x, y);
        ctx.stroke();
      });

      ctx.setLineDash([]);

      // Draw nodes
      nodes.forEach((node) => {
        const depthScale = 1 + (node.z / 200);
        const x = centerX + node.x * depthScale;
        const y = centerY + node.y * depthScale;
        const size = 40 * depthScale;

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
        ctx.font = '9px "IBM Plex Mono", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.label.toUpperCase(), x, y);
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
    email: '#7E1D2F',
    domain: '#A47535',
    ip: '#596E5B',
    url: '#657581',
    campaign: '#481521',
    case: '#835518',
  };

  const nodes: Node[] = [
    { id: 'sender', type: 'email', label: 'SENDER', x: 200, y: 100, z: 0 },
    { id: 'lookalike', type: 'domain', label: 'LOOKALIKE', x: 80, y: 50, z: 0 },
    { id: 'replyto', type: 'domain', label: 'REPLY-TO', x: 320, y: 50, z: 0 },
    { id: 'relayde', type: 'ip', label: 'RELAY · DE', x: 80, y: 155, z: 0 },
    { id: 'relaypl', type: 'ip', label: 'RELAY · PL', x: 320, y: 155, z: 0 },
    { id: 'campaign', type: 'campaign', label: 'CAMPAIGN', x: 30, y: 100, z: 0 },
    { id: 'exposure', type: 'case', label: 'EXPOSURE', x: 370, y: 100, z: 0 },
  ];

  return (
    <svg viewBox="0 0 400 200" className="w-full h-full">
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
