import { useState } from 'react';
import { Link } from 'react-router-dom';
import HistoryChart from '../components/charts/HistoryChart.jsx';
import { DownloadIcon, ShieldIcon, TrashIcon } from '../components/Icons.jsx';
import { clearHistory, exportHistoryCsv, loadHistory } from '../utils/history.js';
import { getBand, PHISHING_TRUST_THRESHOLD } from '../utils/scoring.js';
import usePageTitle from '../hooks/usePageTitle.js';

export default function HistoryPage() {
  usePageTitle('History');
  const [entries, setEntries] = useState(loadHistory);

  function handleClear() {
    if (window.confirm('Delete all saved checks from this browser? This cannot be undone.')) {
      clearHistory();
      setEntries([]);
    }
  }

  const flagged = entries.filter((e) => e.trust_score < PHISHING_TRUST_THRESHOLD).length;
  const average = entries.length
    ? Math.round(entries.reduce((sum, e) => sum + e.trust_score, 0) / entries.length)
    : 0;

  return (
    <div className="container page">
      <div className="page-header">
        <div>
          <h1>Your history</h1>
          <p className="muted">
            {entries.length === 1 ? '1 check' : `${entries.length} checks`}, saved only in this browser.
          </p>
        </div>
        {entries.length > 0 && (
          <div className="button-row">
            <button type="button" className="button button--secondary" onClick={() => exportHistoryCsv(entries)}>
              <DownloadIcon size={18} />
              Export CSV
            </button>
            <button type="button" className="button button--danger-outline" onClick={handleClear}>
              <TrashIcon size={18} />
              Clear history
            </button>
          </div>
        )}
      </div>

      {entries.length === 0 ? (
        <div className="state-card state-card--idle card">
          <ShieldIcon size={32} />
          <div>
            <p className="state-card__title">No checks yet</p>
            <p className="state-card__text">
              Addresses you check will appear here so you can compare them and export a report.
            </p>
            <Link className="button button--primary" to="/">
              Check a URL
            </Link>
          </div>
        </div>
      ) : (
        <>
          <dl className="stat-grid">
            <div className="stat card">
              <dt>Checks</dt>
              <dd>{entries.length}</dd>
            </div>
            <div className="stat card">
              <dt>Flagged as phishing</dt>
              <dd className={flagged ? 'text-danger' : undefined}>{flagged}</dd>
            </div>
            <div className="stat card">
              <dt>Average trust score</dt>
              <dd className={`text-${getBand(average).key}`}>{average}</dd>
            </div>
          </dl>

          <HistoryChart entries={entries} />

          <section className="card" aria-labelledby="history-table-title">
            <h2 id="history-table-title" className="section-title">
              All checks
            </h2>
            <div className="table-scroll" role="region" aria-labelledby="history-table-title" tabIndex={0}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Checked</th>
                    <th scope="col">URL</th>
                    <th scope="col">Trust score</th>
                    <th scope="col">Result</th>
                    <th scope="col">Warnings</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => {
                    const band = getBand(entry.trust_score);
                    return (
                      <tr key={entry.id}>
                        <td className="nowrap">{new Date(entry.checked_at).toLocaleString()}</td>
                        <td className="mono break">{entry.url}</td>
                        <td>
                          <span className={`score-pill score-pill--${band.key}`}>{entry.trust_score}</span>
                        </td>
                        <td>{band.label}</td>
                        <td>{entry.warning_count}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
