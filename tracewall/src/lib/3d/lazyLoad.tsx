import { lazy, Suspense, type ComponentType, useState, useEffect } from 'react';

// Lazy load a 3D component with error boundary and fallback
export function lazyLoad3D<T extends ComponentType<any>>(
  importFn: () => Promise<{ default: T }>,
  FallbackComponent: ComponentType<any>
) {
  const LazyComponent = lazy(importFn);

  return function Lazy3DWrapper(props: React.ComponentProps<T>) {
    return (
      <Suspense fallback={<FallbackComponent {...props} />}>
        <LazyComponent {...props} />
      </Suspense>
    );
  };
}

// Intersection observer hook for lazy loading when in viewport
export function useIntersectionObserver(
  ref: React.RefObject<Element>,
  options: IntersectionObserverInit = {}
) {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setIsVisible(true);
        observer.disconnect();
      }
    }, options);

    if (ref.current) {
      observer.observe(ref.current);
    }

    return () => observer.disconnect();
  }, [ref, options]);

  return isVisible;
}
