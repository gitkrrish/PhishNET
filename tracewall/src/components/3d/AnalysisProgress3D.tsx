import { useEffect, useRef } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

// Lightweight Canvas-based analysis progress visualization with depth
function AnalysisProgress3DInner({ steps, currentStep }: { steps: string[]; currentStep: number }) {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Progress only changes when the current step changes, so the layers are
  // repainted on mount, on resize and on step change.
  useEffect(() => {
    if (!enabled || performanceTier === 'low' || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const draw = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (!width || !height) return;
      ctx.setTransform(quality.pixelRatio, 0, 0, quality.pixelRatio, 0, 0);
      ctx.clearRect(0, 0, width, height);

      // Uniform scale so the layered plate fits small progress panels
      const fit = Math.max(0.45, Math.min(1.25, Math.min((width - 48) / 200, (height - 40) / 160)));
      const plateWidth = 200 * fit;
      const plateHeight = 120 * fit;
      const originX = (width - plateWidth) / 2;
      const originY = (height - plateHeight) / 2;

      // Draw layers representing analysis depth
      const layers = 5;
      for (let i = 0; i < layers; i++) {
        const depth = i * 20 * fit;
        const scale = 1 - (i * 0.1);
        const opacity = 0.3 - (i * 0.05);

        ctx.strokeStyle = `rgba(126, 29, 47, ${opacity})`;
        ctx.lineWidth = 1;

        // Draw layer outline
        ctx.beginPath();
        ctx.roundRect(originX, originY + depth, plateWidth * scale, plateHeight * scale, 5);
        ctx.stroke();

        // Draw nodes on layer
        const nodeCount = Math.min(steps.length, 3);
        for (let j = 0; j < nodeCount; j++) {
          const nodeX = originX + 40 * fit + (j * 60 * fit);
          const nodeY = originY + depth + 60 * fit;
          const stepIndex = Math.floor((currentStep / Math.max(1, steps.length)) * nodeCount);
          const isCompleted = j < stepIndex;
          const isCurrent = j === stepIndex;

          ctx.fillStyle = isCompleted
            ? 'rgba(48, 85, 48, 0.8)'
            : isCurrent
            ? 'rgba(126, 29, 47, 0.8)'
            : 'rgba(184, 188, 181, 0.3)';

          ctx.beginPath();
          ctx.arc(nodeX, nodeY, 6 * fit * scale, 0, Math.PI * 2);
          ctx.fill();

          // Add glow for current step
          if (isCurrent && quality.particles) {
            ctx.beginPath();
            ctx.arc(nodeX, nodeY, 10 * fit * scale, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(126, 29, 47, 0.3)';
            ctx.stroke();
          }
        }
      }
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
  }, [enabled, performanceTier, quality.pixelRatio, quality.particles, steps, currentStep]);

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
