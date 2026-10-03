import { Component, type ReactNode } from 'react';

interface ThreeDErrorBoundaryProps {
  children: ReactNode;
  fallback: ReactNode;
}

interface ThreeDErrorBoundaryState {
  hasError: boolean;
}

export class ThreeDErrorBoundary extends Component<ThreeDErrorBoundaryProps, ThreeDErrorBoundaryState> {
  constructor(props: ThreeDErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(_error: Error): ThreeDErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('3D Component Error:', error, errorInfo);
    // Log error safely without exposing sensitive information
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback;
    }

    return this.props.children;
  }
}
