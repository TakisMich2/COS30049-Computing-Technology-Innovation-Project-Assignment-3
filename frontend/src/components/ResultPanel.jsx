import TrustGauge from './TrustGauge.jsx';
import ConfidenceChart from './charts/ConfidenceChart.jsx';
import WarningsChart from './charts/WarningsChart.jsx';
import WarningList from './WarningList.jsx';
import { AlertIcon, CheckIcon, InfoIcon } from './Icons.jsx';
import { getBand, getConfidence } from '../utils/scoring.js';

const BAND_ICONS = { danger: AlertIcon, caution: InfoIcon, safe: CheckIcon };

export default function ResultPanel({ result, headingRef }) {
  const band = getBand(result.trust_score);
  const confidence = getConfidence(result);
  const BandIcon = BAND_ICONS[band.key];

  return (
    <div className="result">
      {/* The verdict is the most prominent element: large gauge, large heading, colour + icon + text. */}
      <article className={`verdict card verdict--${band.key}`} aria-labelledby="verdict-title">
        <TrustGauge score={result.trust_score} band={band} />
        <div className="verdict__body">
          <p className={`verdict__eyebrow text-${band.key}`}>
            <BandIcon size={20} />
            Result
          </p>
          <h2 id="verdict-title" className="verdict__title" ref={headingRef} tabIndex={-1}>
            {band.label}
          </h2>
          <p className="verdict__confidence">
            Model confidence: <strong>{confidence}%</strong>
            <span className="muted"> · phishing probability {(result.phishing_probability * 100).toFixed(1)}%</span>
          </p>
          <p className="verdict__url mono break">{result.url}</p>
          {result.analysed_url && result.analysed_url !== result.url && (
            <p className="verdict__analysed">
              Browsers read this address as{' '}
              <span className="mono break">{result.analysed_url}</span>, so that is what we checked.
            </p>
          )}
          <p className="verdict__advice">{band.advice}</p>
        </div>
      </article>

      <div className="chart-grid">
        <ConfidenceChart probability={result.phishing_probability} />
        <WarningsChart warnings={result.warnings} />
      </div>

      <WarningList warnings={result.warnings} />

      <p className="result__note">
        <InfoIcon size={18} />
        {result.note}
      </p>
    </div>
  );
}
