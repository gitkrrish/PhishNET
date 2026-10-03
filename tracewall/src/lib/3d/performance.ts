// Performance detection for 3D rendering
// Safely determines device capability without expensive operations

export type PerformanceTier = 'high' | 'medium' | 'low';

interface PerformanceMetrics {
  tier: PerformanceTier;
  webglAvailable: boolean;
  webgl2Available: boolean;
  reducedMotion: boolean;
  deviceMemory: number;
  hardwareConcurrency: number;
}

// Simple WebGL availability check
// Each version needs its own canvas: a canvas can only ever hand out one
// WebGL context type, so asking a 'webgl' canvas for 'webgl2' returns null.
// Every context is released again because browsers cap the number of live
// contexts per page, and this runs during startup.
function contextAvailable(contextType: string): boolean {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext(contextType) as WebGLRenderingContext | WebGL2RenderingContext | null;
    if (!gl) return false;
    gl.getExtension('WEBGL_lose_context')?.loseContext();
    return true;
  } catch {
    return false;
  }
}

function checkWebGL(): { webgl: boolean; webgl2: boolean } {
  return {
    webgl: contextAvailable('webgl') || contextAvailable('experimental-webgl'),
    webgl2: contextAvailable('webgl2'),
  };
}

// Check for reduced motion preference
function checkReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// Determine performance tier based on available metrics
function determinePerformanceTier(metrics: Omit<PerformanceMetrics, 'tier'>): PerformanceTier {
  // If reduced motion is enabled, always use low tier
  if (metrics.reducedMotion) {
    return 'low';
  }

  // If WebGL is not available, use low tier
  if (!metrics.webglAvailable) {
    return 'low';
  }

  // Determine tier based on hardware capabilities
  const hasGoodMemory = metrics.deviceMemory >= 4; // 4GB+
  const hasGoodCores = metrics.hardwareConcurrency >= 4;
  const hasWebGL2 = metrics.webgl2Available;

  if (hasGoodMemory && hasGoodCores && hasWebGL2) {
    return 'high';
  }

  if (hasGoodMemory || hasGoodCores) {
    return 'medium';
  }

  return 'low';
}

// Get device memory (returns 0 if not available)
function getDeviceMemory(): number {
  return (navigator as any).deviceMemory || 0;
}

// Get hardware concurrency (returns 2 if not available)
function getHardwareConcurrency(): number {
  return navigator.hardwareConcurrency || 2;
}

// Main performance detection function
export function detectPerformance(): PerformanceMetrics {
  const webgl = checkWebGL();
  const reducedMotion = checkReducedMotion();
  const deviceMemory = getDeviceMemory();
  const hardwareConcurrency = getHardwareConcurrency();

  const metrics: Omit<PerformanceMetrics, 'tier'> = {
    webglAvailable: webgl.webgl,
    webgl2Available: webgl.webgl2,
    reducedMotion,
    deviceMemory,
    hardwareConcurrency,
  };

  const tier = determinePerformanceTier(metrics);

  return {
    ...metrics,
    tier,
  };
}

// Get rendering quality settings based on performance tier
export function getRenderingQuality(tier: PerformanceTier) {
  switch (tier) {
    case 'high':
      return {
        pixelRatio: Math.min(window.devicePixelRatio, 2),
        antialias: true,
        shadows: false,
        particles: true,
        maxNodes: 50,
        animationSpeed: 1.0,
      };
    case 'medium':
      return {
        pixelRatio: Math.min(window.devicePixelRatio, 1.5),
        antialias: true,
        shadows: false,
        particles: true,
        maxNodes: 30,
        animationSpeed: 0.7,
      };
    case 'low':
      return {
        pixelRatio: 1,
        antialias: false,
        shadows: false,
        particles: false,
        maxNodes: 15,
        animationSpeed: 0.5,
      };
  }
}
