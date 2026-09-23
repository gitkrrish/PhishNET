import { Component, type ReactNode } from 'react';

interface AnalysisErrorBoundaryProps {
  children: ReactNode;
}

interface AnalysisErrorBoundaryState {
  hasError: boolean;
}

export class AnalysisErrorBoundary extends Component<AnalysisErrorBoundaryProps, AnalysisErrorBoundaryState> {
  state: AnalysisErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): AnalysisErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Infrastructure analysis render error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center p-6" style={{ backgroundColor: 'var(--tw-canvas)' }}>
          <div className="max-w-xl rounded-sm border p-6 space-y-3" style={{ backgroundColor: 'var(--tw-panel)', borderColor: 'var(--tw-border)' }}>
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-critical)' }}>Analysis unavailable</p>
            <p className="font-mono text-sm" style={{ color: 'var(--tw-text)' }}>The analysis result could not be rendered. Start a new analysis to try again.</p>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
