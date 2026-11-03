import { bandColour } from '../utils/theme.js';

const SIZE = 200;
const STROKE = 16;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

/** Large circular trust score gauge (0-100), coloured by risk band. */
export default function TrustGauge({ score, band }) {
  const clamped = Math.max(0, Math.min(100, score));
  const offset = CIRCUMFERENCE * (1 - clamped / 100);

  return (
    <div className="gauge" role="img" aria-label={`Trust score ${clamped} out of 100: ${band.label}`}>
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="gauge__svg" aria-hidden="true">
        <circle cx={SIZE / 2} cy={SIZE / 2} r={RADIUS} fill="none" className="gauge__track" strokeWidth={STROKE} />
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke={bandColour[band.key]}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${SIZE / 2} ${SIZE / 2})`}
          className="gauge__value"
        />
      </svg>
      <div className="gauge__label" aria-hidden="true">
        <span className={`gauge__score text-${band.key}`}>{clamped}</span>
        <span className="gauge__max">/ 100</span>
        <span className="gauge__caption">Trust score</span>
      </div>
    </div>
  );
}
