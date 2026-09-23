import { useEffect, useRef } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

// Lightweight Canvas-based analysis progress visualization with depth
function AnalysisProgress3DInner({ steps, currentStep }: { steps: string[]; currentStep: number }) {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);
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

    let time = 0;
    const animate = () => {
      const width = canvas.width / quality.pixelRatio;
      const height = canvas.height / quality.pixelRatio;

      ctx.clearRect(0, 0, width, height);

      // Draw layers representing analysis depth
      const layers = 5;
      for (let i = 0; i < layers; i++) {
        const depth = i * 20;
        const scale = 1 - (i * 0.1);
        const opacity = 0.3 - (i * 0.05);
        const xOffset = Math.sin(time * 0.5 + i) * 5;
        const yOffset = Math.cos(time * 0.3 + i) * 3;

        ctx.strokeStyle = `rgba(126, 29, 47, ${opacity})`;
        ctx.lineWidth = 1;

        // Draw layer outline
        ctx.beginPath();
        ctx.roundRect(
          (width - 200) / 2 + xOffset,
          (height - 120) / 2 + yOffset + depth,
          200 * scale,
          120 * scale,
          5
        );
        ctx.stroke();

        // Draw nodes on layer
        const nodeCount = Math.min(steps.length, 3);
        for (let j = 0; j < nodeCount; j++) {
          const nodeX = (width - 200) / 2 + xOffset + 40 + (j * 60);
          const nodeY = (height - 120) / 2 + yOffset + depth + 60;
          const stepIndex = Math.floor((currentStep / steps.length) * nodeCount);
          const isCompleted = j < stepIndex;
          const isCurrent = j === stepIndex;

          ctx.fillStyle = isCompleted
            ? 'rgba(48, 85, 48, 0.8)'
            : isCurrent
            ? 'rgba(126, 29, 47, 0.8)'
            : 'rgba(184, 188, 181, 0.3)';

          ctx.beginPath();
          ctx.arc(nodeX, nodeY, 6 * scale, 0, Math.PI * 2);
          ctx.fill();

          // Add glow for current step
          if (isCurrent && quality.particles) {
            ctx.beginPath();
            ctx.arc(nodeX, nodeY, 10 * scale, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(126, 29, 47, 0.3)';
            ctx.stroke();
          }
        }
      }

      time += 0.02 * quality.animationSpeed;
      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [enabled, performanceTier, quality, steps, currentStep]);

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
function AnalysisProgress2D({ steps, currentStep }: { steps: string[]; currentStep: number }) {
  return (
    <div className="w-full h-full flex items-center justify-center">
      <div className="relative w-48 h-32">
        {/* Static layered rectangles */}
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="absolute border rounded-sm"
            style={{
              left: `${i * 4}px`,
              top: `${i * 4}px`,
              width: 'calc(100% - 8px)',
              height: 'calc(100% - 8px)',
              borderColor: 'var(--tw-burgundy)',
              opacity: 0.3 - (i * 0.05),
            }}
          />
        ))}
        {/* Progress nodes */}
        <div className="absolute inset-0 flex items-center justify-center gap-4 pt-4">
          {[0, 1, 2].map((i) => {
            const stepIndex = Math.floor((currentStep / steps.length) * 3);
            const isCompleted = i < stepIndex;
            const isCurrent = i === stepIndex;

            return (
              <div
                key={i}
                className="w-3 h-3 rounded-full"
                style={{
                  backgroundColor: isCompleted
                    ? 'var(--tw-low)'
                    : isCurrent
                    ? 'var(--tw-burgundy)'
                    : 'var(--tw-border-strong)',
                }}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}

// Main component with error boundary and fallbacks
export default function AnalysisProgress3D({ steps, currentStep }: { steps: string[]; currentStep: number }) {
  const { enabled, performanceTier } = useThreeD();

  if (performanceTier === 'low' || !enabled) {
    return <AnalysisProgress2D steps={steps} currentStep={currentStep} />;
  }

  return (
    <ThreeDErrorBoundary fallback={<AnalysisProgress2D steps={steps} currentStep={currentStep} />}>
      <AnalysisProgress3DInner steps={steps} currentStep={currentStep} />
    </ThreeDErrorBoundary>
  );
}
