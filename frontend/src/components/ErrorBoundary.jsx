import { Component } from 'react';
import { AlertIcon } from './Icons.jsx';

/**
 * Catches errors thrown while rendering and shows a fallback page instead of a
 * blank screen. Pass a changing `resetKey` (e.g. the route path) to clear the
 * error when the user navigates elsewhere.
 */
export default class ErrorBoundary extends Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('Unexpected error caught by ErrorBoundary:', error, info.componentStack);
  }

  componentDidUpdate(prevProps) {
    if (this.state.error && prevProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return <ErrorFallback onRetry={() => this.setState({ error: null })} />;
    }
    return this.props.children;
  }
}

// Uses plain links, not the router, because it may render outside the router.
function ErrorFallback({ onRetry }) {
  return (
    <section className="status-page container" aria-labelledby="fallback-title">
      <span className="status-page__icon status-page__icon--danger" aria-hidden="true">
        <AlertIcon />
      </span>
      <p className="status-page__code">Unexpected error</p>
      <h1 id="fallback-title" tabIndex={-1}>Something went wrong</h1>
      <p className="status-page__text">
        PhishCheck hit a problem it did not expect. Nothing you entered was lost or shared. Try again, or go
        back to the home page.
      </p>
      <div className="button-row">
        <button type="button" className="button button--primary" onClick={onRetry}>
          Try again
        </button>
        <a className="button button--secondary" href="/">
          Go to the home page
        </a>
      </div>
    </section>
  );
}
