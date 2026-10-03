import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import { detectPerformance, getRenderingQuality, type PerformanceTier } from '../lib/3d/performance';

interface ThreeDSettings {
  enabled: boolean;
  performanceTier: PerformanceTier;
  reducedMotion: boolean;
  toggleEnabled: () => void;
  forceTier: (tier: PerformanceTier) => void;
}

const ThreeDContext = createContext<ThreeDSettings | undefined>(undefined);

interface ThreeDProviderProps {
  children: ReactNode;
}

export function ThreeDProvider({ children }: ThreeDProviderProps) {
  const [enabled, setEnabled] = useState(true);
  const [performanceTier, setPerformanceTier] = useState<PerformanceTier>('medium');
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    // Detect performance on mount
    const metrics = detectPerformance();
    setPerformanceTier(metrics.tier);
    setReducedMotion(metrics.reducedMotion);

    // Disable 3D if reduced motion is preferred
    if (metrics.reducedMotion) {
      setEnabled(false);
    }

    // Listen for reduced motion changes
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const handleChange = (e: MediaQueryListEvent) => {
      setReducedMotion(e.matches);
      if (e.matches) {
        setEnabled(false);
      }
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  const toggleEnabled = () => {
    setEnabled(prev => !prev);
  };

  const forceTier = (tier: PerformanceTier) => {
    setPerformanceTier(tier);
  };

  return (
    <ThreeDContext.Provider value={{ enabled, performanceTier, reducedMotion, toggleEnabled, forceTier }}>
      {children}
    </ThreeDContext.Provider>
  );
}

export function useThreeD() {
  const context = useContext(ThreeDContext);
  if (context === undefined) {
    throw new Error('useThreeD must be used within a ThreeDProvider');
  }
  return context;
}

// Hook to get rendering quality settings
export function useRenderingQuality() {
  const { performanceTier } = useThreeD();
  return getRenderingQuality(performanceTier);
}
