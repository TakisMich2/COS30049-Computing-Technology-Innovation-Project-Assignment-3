import { palette } from '../../utils/theme.js';

/**
 * Shared frame for every chart: a titled figure with a one-line explanation of
 * the question it answers, and a text summary for screen reader users.
 */
export default function ChartCard({ id, title, description, summary, children }) {
  return (
    <figure className="card chart-card" aria-labelledby={`${id}-title`} aria-describedby={`${id}-summary`}>
      <figcaption>
        <h3 id={`${id}-title`} className="chart-card__title">
          {title}
        </h3>
        <p className="chart-card__description">{description}</p>
      </figcaption>
      <div className="chart-card__body">{children}</div>
      <p id={`${id}-summary`} className="sr-only">
        {summary}
      </p>
    </figure>
  );
}

// Shared Recharts styling so all charts look the same.
export const axisProps = {
  tick: { fill: palette.muted, fontSize: 13 },
  stroke: '#d6c6b6',
};

export const tooltipProps = {
  contentStyle: {
    borderRadius: 0,
    border: `1px solid ${palette.ink}`,
    boxShadow: 'none',
    fontSize: 14,
  },
  labelStyle: { color: palette.ink, fontWeight: 600 },
  cursor: { fill: 'rgba(194, 65, 12, 0.08)' },
};

export const legendProps = {
  iconType: 'square',
  wrapperStyle: { fontSize: 13, color: palette.ink },
};
