import { AlertIcon, CheckIcon, ShieldIcon } from './Icons.jsx';

export function LoadingState({ url }) {
  return (
    <div className="state-card card" role="status">
      <span className="spinner" aria-hidden="true" />
      <div>
        <p className="state-card__title">Analysing this address…</p>
        <p className="state-card__text mono break">{url}</p>
      </div>
    </div>
  );
}

const ERROR_TITLES = {
  network: 'Can’t reach the analysis server',
  timeout: 'The check took too long',
  'invalid-input': 'The server couldn’t check that address',
  busy: 'The server is busy',
  server: 'The analysis server had a problem',
  'bad-response': 'Unexpected response from the server',
};

export function ErrorAlert({ error, onRetry }) {
  const title = ERROR_TITLES[error?.kind] ?? 'Something went wrong';
  const canRetry = error?.kind !== 'invalid-input';

  return (
    <div className="alert alert--danger" role="alert">
      <AlertIcon className="alert__icon" />
      <div className="alert__body">
        <p className="alert__title">{title}</p>
        <p>{error?.message ?? 'Please try again.'}</p>
        {error?.requestId && <p className="muted">Reference: <span className="mono">{error.requestId}</span></p>}
        {canRetry && (
          <button type="button" className="button button--secondary" onClick={onRetry}>
            Try again
          </button>
        )}
      </div>
    </div>
  );
}

export function ServerOfflineNotice({ onRetry }) {
  return (
    <div className="alert alert--caution" role="status">
      <AlertIcon className="alert__icon" />
      <div className="alert__body">
        <p className="alert__title">The analysis server isn’t responding</p>
        <p>You can still enter an address, but checks will fail until the server is back.</p>
        <button type="button" className="button button--secondary" onClick={onRetry}>
          Check again
        </button>
      </div>
    </div>
  );
}

export function SuccessBanner({ elapsedMs }) {
  return (
    <p className="success-banner" role="status">
      <CheckIcon size={18} />
      Analysis complete{elapsedMs != null && ` in ${elapsedMs.toLocaleString()} ms`}
    </p>
  );
}

export function IdleState() {
  return (
    <div className="state-card state-card--idle card">
      <ShieldIcon size={32} />
      <div>
        <p className="state-card__title">Your result will appear here</p>
        <p className="state-card__text">
          You’ll get a trust score from 0 to 100, how confident the model is, and a plain-language explanation of
          anything suspicious in the address.
        </p>
      </div>
    </div>
  );
}
