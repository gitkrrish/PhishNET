import { useEffect, useRef, useState } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

interface Node {
  id: string;
  type: string;
  label: string;
  x: number;
  y: number;
  z?: number;
  color: string;
}

interface Edge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

// Lightweight Canvas-based 3D graph visualization with depth
function IntelligenceGraph3DInner({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>(0);
  const [rotation, setRotation] = useState({ x: 0, y: 0 });

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

    let time = 0;
    const animate = () => {
      const width = canvas.width / quality.pixelRatio;
      const height = canvas.height / quality.pixelRatio;
      const centerX = width / 2;
      const centerY = height / 2;

      ctx.clearRect(0, 0, width, height);

      // Subtle auto-rotation
      const autoRotation = quality.animationSpeed * 0.001;
      setRotation(prev => ({
        x: prev.x + autoRotation * 0.3,
        y: prev.y + autoRotation * 0.5,
      }));

      // Draw edges with depth
      edges.forEach((edge) => {
        const sourceNode = nodes.find(n => n.id === edge.source);
        const targetNode = nodes.find(n => n.id === edge.target);
        if (!sourceNode || !targetNode) return;

        // Apply rotation and depth
        const source = project3D(sourceNode, rotation, centerX, centerY);
        const target = project3D(targetNode, rotation, centerX, centerY);

        const depthAlpha = 0.3 + (((sourceNode.z || 0) + (targetNode.z || 0)) / 400) * 0.4;

        ctx.strokeStyle = `rgba(184, 188, 181, ${depthAlpha})`;
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 4]);

        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);
        ctx.stroke();

        ctx.setLineDash([]);

        // Draw edge label if present
        if (edge.label) {
          const midX = (source.x + target.x) / 2;
          const midY = (source.y + target.y) / 2;
          ctx.fillStyle = 'rgba(110, 123, 133, 0.7)';
          ctx.font = '8px "IBM Plex Mono", monospace';
          ctx.textAlign = 'center';
          ctx.fillText(edge.label, midX, midY);
        }
      });

      // Draw nodes with depth
      // Sort by z-depth for proper rendering order
      const sortedNodes = [...nodes].sort((a, b) => (b.z || 0) - (a.z || 0));

      sortedNodes.forEach((node) => {
        const projected = project3D(node, rotation, centerX, centerY);
        const nodeZ = node.z || 0;
        const depthScale = 1 + (nodeZ / 200);
        const size = 40 * depthScale;
        const depthAlpha = 0.6 + (nodeZ / 200) * 0.4;

        // Draw node background
        ctx.fillStyle = node.color + Math.floor(depthAlpha * 255).toString(16).padStart(2, '0');
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 1.5;

        // Rounded rectangle
        const radius = 3;
        ctx.beginPath();
        ctx.roundRect(projected.x - size / 2, projected.y - size / 4, size, size / 2, radius);
        ctx.fill();
        ctx.stroke();

        // Draw label
        ctx.fillStyle = node.color;
        ctx.font = '9px "IBM Plex Mono", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.label.toUpperCase(), projected.x, projected.y);
      });

      time += 0.01;
      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [enabled, performanceTier, quality, nodes, edges, rotation]);

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

// Project 3D coordinates to 2D with rotation
function project3D(
  node: Node,
  rotation: { x: number; y: number },
  centerX: number,
  centerY: number
) {
  const z = node.z || 0;
  // Apply rotation around Y axis
  const cosY = Math.cos(rotation.y);
  const sinY = Math.sin(rotation.y);
  const rotatedX = node.x * cosY - z * sinY;
  const rotatedZ = node.x * sinY + z * cosY;

  // Apply rotation around X axis
  const cosX = Math.cos(rotation.x);
  const sinX = Math.sin(rotation.x);
  const rotatedY = node.y * cosX - rotatedZ * sinX;
  const finalZ = node.y * sinX + rotatedZ * cosX;

  // Perspective projection
  const perspective = 500;
  const scale = perspective / (perspective + finalZ);

  return {
    x: centerX + rotatedX * scale,
    y: centerY + rotatedY * scale,
    z: finalZ,
  };
}

// Fallback 2D visualization (simple placeholder)
function IntelligenceGraph2D() {
  return (
    <div className="w-full h-full flex items-center justify-center">
      <p className="font-mono text-xs" style={{ color: 'var(--tw-text-muted)' }}>
        2D graph mode active
      </p>
    </div>
  );
}

// Main component with error boundary and fallbacks
export default function IntelligenceGraph3D({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  const { enabled, performanceTier } = useThreeD();

  if (performanceTier === 'low' || !enabled) {
    return <IntelligenceGraph2D />;
  }

  return (
    <ThreeDErrorBoundary fallback={<IntelligenceGraph2D />}>
      <IntelligenceGraph3DInner nodes={nodes} edges={edges} />
    </ThreeDErrorBoundary>
  );
}
