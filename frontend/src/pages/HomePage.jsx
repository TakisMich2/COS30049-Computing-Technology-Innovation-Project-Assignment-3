import { useEffect, useRef, useState } from 'react';
import HowItWorks from '../components/HowItWorks.jsx';
import UrlForm from '../components/UrlForm.jsx';
import ResultPanel from '../components/ResultPanel.jsx';
import {
  ErrorAlert,
  IdleState,
  LoadingState,
  ServerOfflineNotice,
  SuccessBanner,
} from '../components/StatusMessages.jsx';
import { assessUrl, checkHealth } from '../api/assessUrl.js';
import { addToHistory } from '../utils/history.js';
import usePageTitle from '../hooks/usePageTitle.js';

export default function HomePage() {
  usePageTitle('Check a URL');
  const [status, setStatus] = useState('idle'); // 'idle' | 'loading' | 'success' | 'error'
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [currentUrl, setCurrentUrl] = useState('');
  const [elapsedMs, setElapsedMs] = useState(null);
  const [serverOnline, setServerOnline] = useState(true);
  const controllerRef = useRef(null);
  const resultHeadingRef = useRef(null);

  // Cancel any in-flight request if the user leaves the page.
  useEffect(() => () => controllerRef.current?.abort(), []);

  // Warn up front if the back end is down, rather than only after a failed check.
  async function refreshHealth(signal) {
    try {
      setServerOnline(await checkHealth({ signal }));
    } catch {
      // aborted on unmount
    }
  }
  useEffect(() => {
    const controller = new AbortController();
    refreshHealth(controller.signal);
    return () => controller.abort();
  }, []);

  // Move focus to the result so keyboard and screen reader users land on it.
  useEffect(() => {
    if (status === 'success') resultHeadingRef.current?.focus();
  }, [status]);

  async function runCheck(url) {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;

    setCurrentUrl(url);
    setStatus('loading');
    setError(null);
    setResult(null);
    const started = performance.now();

    try {
      const data = await assessUrl(url, { signal: controller.signal });
      setElapsedMs(Math.round(performance.now() - started));
      setResult(data);
      setStatus('success');
      setServerOnline(true);
      addToHistory(data);
    } catch (err) {
      if (err?.name === 'AbortError') return;
      setError(err);
      setStatus('error');
    }
  }

  return (
    <>
      <div className="container page">
        <section className="hero" aria-labelledby="page-title">
          <div className="hero__text">
            <p className="hero__lead">
              Paste a web address to get a trust score from our phishing-detection model, with a clear explanation
              of any part that looks suspicious.
            </p>
            <h1 id="page-title" className="hero__title">
              Is this link safe to open?
            </h1>
          </div>
          <div className="hero__art">
            <UrlForm onSubmit={runCheck} isLoading={status === 'loading'} />
          </div>
        </section>

        {!serverOnline && status !== 'error' && (
          <div className="result-area">
            <ServerOfflineNotice onRetry={() => refreshHealth()} />
          </div>
        )}

        <section className="result-area" aria-label="Result">
          {status === 'idle' && <IdleState />}
          {status === 'loading' && <LoadingState url={currentUrl} />}
          {status === 'error' && <ErrorAlert error={error} onRetry={() => runCheck(currentUrl)} />}
          {status === 'success' && result && (
            <>
              <SuccessBanner elapsedMs={elapsedMs} />
              <ResultPanel result={result} headingRef={resultHeadingRef} />
            </>
          )}
        </section>
      </div>
      <HowItWorks />
    </>
  );
}
