import { useEffect, useRef } from 'react';
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

interface Rotation {
  x: number;
  y: number;
}

// Project 3D coordinates to 2D with rotation
function project3D(
  node: Node,
  rotation: Rotation,
  centerX: number,
  centerY: number,
  fit: number
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
    x: centerX + rotatedX * scale * fit,
    y: centerY + rotatedY * scale * fit,
    z: finalZ,
  };
}

/**
 * Uniform scale that keeps the whole graph inside the canvas at any size, so
 * nodes are never cut off on short panels or narrow viewports.
 */
function fitScale(nodes: Node[], width: number, height: number) {
  if (!nodes.length || !width || !height) return 1;
  const maxRadius = Math.max(...nodes.map(node => Math.hypot(node.x, node.y))) || 1;
  return Math.max(0.25, Math.min(1.4, (Math.min(width, height) / 2 - 40) / maxRadius));
}

// Lightweight Canvas-based 3D graph visualization with depth
function IntelligenceGraph3DInner({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  // Rotation lives in a ref: driving it through state re-created this effect
  // (and the whole canvas) on every frame.
  const rotationRef = useRef<Rotation>({ x: 0, y: 0 });

  useEffect(() => {
    if (!enabled || performanceTier === 'low' || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const nodeById = new Map(nodes.map(node => [node.id, node]));

    const draw = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (!width || !height) return;
      ctx.setTransform(quality.pixelRatio, 0, 0, quality.pixelRatio, 0, 0);
      ctx.clearRect(0, 0, width, height);

      const rotation = rotationRef.current;
      const centerX = width / 2;
      const centerY = height / 2;
      const fit = fitScale(nodes, width, height);
      const labelSize = Math.max(8, Math.min(11, 9 * fit));

      // Draw edges with depth
      edges.forEach((edge) => {
        const sourceNode = nodeById.get(edge.source);
        const targetNode = nodeById.get(edge.target);
        if (!sourceNode || !targetNode) return;

        const source = project3D(sourceNode, rotation, centerX, centerY, fit);
        const target = project3D(targetNode, rotation, centerX, centerY, fit);

        const depthAlpha = 0.3 + (((sourceNode.z || 0) + (targetNode.z || 0)) / 400) * 0.4;

        ctx.strokeStyle = `rgba(184, 188, 181, ${Math.max(0.15, Math.min(0.7, depthAlpha))})`;
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
          ctx.font = `${labelSize - 1}px "IBM Plex Mono", monospace`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(edge.label, midX, midY);
        }
      });

      // Draw nodes with depth
      // Sort by z-depth for proper rendering order
      const sortedNodes = [...nodes].sort((a, b) => (b.z || 0) - (a.z || 0));

      sortedNodes.forEach((node) => {
        const projected = project3D(node, rotation, centerX, centerY, fit);
        const nodeZ = node.z || 0;
        const depthScale = fit * (1 + (nodeZ / 200));
        const size = 40 * depthScale;
        const depthAlpha = 0.6 + (nodeZ / 200) * 0.4;

        // Draw node background
        ctx.fillStyle = node.color + Math.floor(Math.max(0, Math.min(1, depthAlpha)) * 255).toString(16).padStart(2, '0');
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
        ctx.font = `${labelSize}px "IBM Plex Mono", monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.label.toUpperCase(), projected.x, projected.y);
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

    // Subtle auto-rotation, advanced on the ref so the component never re-renders per frame
    let frame: number | null = null;
    const animate = () => {
      const autoRotation = quality.animationSpeed * 0.001;
      rotationRef.current = {
        x: rotationRef.current.x + autoRotation * 0.3,
        y: rotationRef.current.y + autoRotation * 0.5,
      };
      draw();
      frame = requestAnimationFrame(animate);
    };

    // Only spin while the graph is on screen and the tab is foregrounded
    let tabVisible = document.visibilityState === 'visible';
    let onScreen = true;
    const syncAnimation = () => {
      if (tabVisible && onScreen) {
        if (frame === null) frame = requestAnimationFrame(animate);
      } else if (frame !== null) {
        cancelAnimationFrame(frame);
        frame = null;
      }
    };

    const onVisibilityChange = () => {
      tabVisible = document.visibilityState === 'visible';
      syncAnimation();
      if (tabVisible) draw();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);

    const intersectionObserver = new IntersectionObserver(
      entries => {
        onScreen = entries.some(entry => entry.isIntersecting);
        syncAnimation();
      },
      { threshold: 0 }
    );
    intersectionObserver.observe(canvas);

    syncAnimation();

    return () => {
      document.removeEventListener('visibilitychange', onVisibilityChange);
      intersectionObserver.disconnect();
      resizeObserver.disconnect();
      if (frame !== null) cancelAnimationFrame(frame);
    };
  }, [enabled, performanceTier, quality.pixelRatio, quality.animationSpeed, nodes, edges]);

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

// Fallback 2D visualization of the same nodes and edges
function IntelligenceGraph2D({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  if (!nodes.length) {
    return (
      <div className="w-full h-full flex items-center justify-center">
        <p className="font-mono text-xs" style={{ color: 'var(--tw-text-muted)' }}>
          No graph data available
        </p>
      </div>
    );
  }

  const positions = new Map<string, { x: number; y: number }>();
  nodes.forEach((node, index) => {
    const angle = (index / nodes.length) * Math.PI * 2 - Math.PI / 2;
    positions.set(node.id, { x: 200 + Math.cos(angle) * 130, y: 200 + Math.sin(angle) * 110 });
  });

  return (
    <div className="w-full h-full">
      <svg viewBox="0 0 400 400" className="w-full h-full" role="img" aria-label="Indicator relationship graph">
        {edges.map(edge => {
          const source = positions.get(edge.source);
          const target = positions.get(edge.target);
          if (!source || !target) return null;
          return <line key={edge.id} x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke="var(--tw-border-strong)" strokeWidth="1.5" strokeDasharray="5 5" />;
        })}
        {nodes.map(node => {
          const point = positions.get(node.id);
          if (!point) return null;
          return (
            <g key={node.id} transform={`translate(${point.x} ${point.y})`}>
              <circle r="26" fill="var(--tw-panel)" stroke={node.color} strokeWidth="2" />
              <circle r="19" fill={node.color} fillOpacity="0.17" />
              <text y="-2" textAnchor="middle" fill="var(--tw-text)" fontSize="9" fontFamily="IBM Plex Mono" fontWeight={600}>
                {node.label.slice(0, 14)}
              </text>
              <text y="11" textAnchor="middle" fill="var(--tw-text-muted)" fontSize="7" fontFamily="IBM Plex Mono">
                {(node.type || '').toUpperCase().slice(0, 12)}
              </text>
            </g>
          );
        })}
        {nodes.filter(node => !edges.some(edge => edge.source === node.id || edge.target === node.id)).map(node => {
          const point = positions.get(node.id);
          return point ? <circle key={`iso-${node.id}`} cx={point.x} cy={point.y} r="30" fill="none" stroke={node.color} strokeOpacity="0.22" strokeWidth="6" /> : null;
        })}
      </svg>
    </div>
  );
}

// Main component with error boundary and fallbacks
export default function IntelligenceGraph3D({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  const { enabled, performanceTier } = useThreeD();

  if (performanceTier === 'low' || !enabled) {
    return <IntelligenceGraph2D nodes={nodes} edges={edges} />;
  }

  return (
    <ThreeDErrorBoundary fallback={<IntelligenceGraph2D nodes={nodes} edges={edges} />}>
      <IntelligenceGraph3DInner nodes={nodes} edges={edges} />
    </ThreeDErrorBoundary>
  );
}
