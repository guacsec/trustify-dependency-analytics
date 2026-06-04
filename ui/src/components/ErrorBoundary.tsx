import React, { Component, ErrorInfo, ReactNode } from 'react';
import {
  Bullseye,
  EmptyState,
  EmptyStateBody,
  EmptyStateHeader,
  EmptyStateIcon,
  EmptyStateVariant,
} from '@patternfly/react-core';
import ExclamationCircleIcon from '@patternfly/react-icons/dist/esm/icons/exclamation-circle-icon';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Report rendering error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Bullseye style={{ backgroundColor: 'var(--pf-v5-global--BackgroundColor--200)', minHeight: '100vh' }}>
          <EmptyState variant={EmptyStateVariant.sm}>
            <EmptyStateHeader
              icon={<EmptyStateIcon icon={ExclamationCircleIcon} color="var(--pf-v5-global--danger-color--100)" />}
              titleText="Something went wrong"
              headingLevel="h2"
            />
            <EmptyStateBody>
              {this.state.error?.message || 'An unexpected error occurred while rendering the report.'}
            </EmptyStateBody>
          </EmptyState>
        </Bullseye>
      );
    }

    return this.props.children;
  }
}
