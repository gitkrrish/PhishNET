import { useEffect, useRef, useState } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

// Subtle CSS 3D redaction/shield effect
function RedactionEffect3DInner({ children }: { children: React.ReactNode }) {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const containerRef = useRef<HTMLDivElement>(null);
  const [time, setTime] = useState(0);

  // Subtle animation - only if enabled and not reduced motion
  useEffect(() => {
    if (!enabled || performanceTier === 'low') return;

    const interval = setInterval(() => {
      setTime(prev => prev + 0.01 * quality.animationSpeed);
    }, 16);

    return () => clearInterval(interval);
  }, [enabled, performanceTier, quality.animationSpeed]);

  if (!enabled) {
    return <>{children}</>;
  }

  return (
    <div
      ref={containerRef}
      className="relative"
      style={{
        perspective: '1000px',
        transformStyle: 'preserve-3d',
      }}
    >
      {/* Subtle shield layers behind */}
      {quality.particles && (
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            transform: `translateZ(-10px) rotateX(${2 * Math.sin(time * 0.3)}deg)`,
            opacity: 0.1,
            background: 'linear-gradient(135deg, var(--tw-burgundy) 0%, transparent 50%)',
            filter: 'blur(20px)',
          }}
        />
      )}
      
      {/* Main content with subtle depth */}
      <div
        style={{
          transform: `translateZ(5px)`,
          transformStyle: 'preserve-3d',
        }}
      >
        {children}
      </div>

      {/* Subtle scanning line effect */}
      {quality.particles && (
        <div
          className="absolute inset-0 pointer-events-none overflow-hidden"
          style={{
            transform: 'translateZ(10px)',
          }}
        >
          <div
            className="absolute w-full h-px"
            style={{
              background: 'linear-gradient(90deg, transparent, var(--tw-burgundy)33, transparent)',
              top: `${(Math.sin(time * 0.5) * 0.5 + 0.5) * 100}%`,
              opacity: 0.3,
            }}
          />
        </div>
      )}
    </div>
  );
}

// Fallback - just render children
function RedactionEffect2D({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}

// Main component with error boundary and fallbacks
export default function RedactionEffect3D({ children }: { children: React.ReactNode }) {
  const { enabled, performanceTier } = useThreeD();

  if (performanceTier === 'low' || !enabled) {
    return <RedactionEffect2D>{children}</RedactionEffect2D>;
  }

  return (
    <ThreeDErrorBoundary fallback={<RedactionEffect2D>{children}</RedactionEffect2D>}>
      <RedactionEffect3DInner>{children}</RedactionEffect3DInner>
    </ThreeDErrorBoundary>
  );
}
