import { Bar, BarChart, CartesianGrid, Cell, Legend, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import ChartCard, { axisProps, legendProps, tooltipProps } from './ChartCard.jsx';
import { bandColour, palette } from '../../utils/theme.js';
import { getBand, PHISHING_TRUST_THRESHOLD } from '../../utils/scoring.js';

const MAX_BARS = 20;

function HistoryTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const entry = payload[0].payload;
  return (
    <div className="chart-tooltip" style={tooltipProps.contentStyle}>
      <p className="chart-tooltip__title">Check {entry.label}</p>
      <p className="mono break chart-tooltip__url">{entry.url}</p>
      <p>
        Trust score: <strong>{entry.score}</strong> ({getBand(entry.score).label})
      </p>
      <p className="muted">{new Date(entry.checkedAt).toLocaleString()}</p>
    </div>
  );
}

/** Question answered: how trustworthy were the links you checked recently, and how many crossed the line? */
export default function HistoryChart({ entries }) {
  const recent = entries.slice(0, MAX_BARS).reverse();
  const data = recent.map((entry, index) => ({
    label: `#${entries.length - recent.length + index + 1}`,
    score: entry.trust_score,
    url: entry.url,
    checkedAt: entry.checked_at,
    band: getBand(entry.trust_score).key,
  }));
  const flagged = data.filter((d) => d.band === 'danger').length;

  return (
    <ChartCard
      id="history-chart"
      title="How trustworthy were your recent checks?"
      description={`Trust score of ${data.length === 1 ? 'your latest check' : `your last ${data.length} checks, oldest on the left`}. Bars below the dashed line were flagged as phishing.`}
      summary={`${data.length} recent checks shown; ${flagged} scored below the phishing threshold of ${PHISHING_TRUST_THRESHOLD}.`}
    >
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data} margin={{ top: 8, right: 16, bottom: 24, left: 8 }} accessibilityLayer>
          <CartesianGrid vertical={false} stroke={palette.grid} />
          <XAxis
            dataKey="label"
            {...axisProps}
            label={{ value: 'Check number', position: 'insideBottom', offset: -16, fill: palette.muted, fontSize: 13 }}
          />
          <YAxis
            domain={[0, 100]}
            ticks={[0, 30, 70, 100]}
            width={48}
            {...axisProps}
            label={{ value: 'Trust score', angle: -90, position: 'insideLeft', offset: 4, fill: palette.muted, fontSize: 13, style: { textAnchor: 'middle' } }}
          />
          <Tooltip content={<HistoryTooltip />} cursor={tooltipProps.cursor} />
          <Legend
            {...legendProps}
            verticalAlign="top"
            height={32}
            payload={[
              { value: 'Likely safe (70–100)', type: 'square', color: bandColour.safe },
              { value: 'Be careful (30–69)', type: 'square', color: bandColour.caution },
              { value: 'Likely phishing (0–29)', type: 'square', color: bandColour.danger },
            ]}
          />
          <ReferenceLine y={PHISHING_TRUST_THRESHOLD} stroke={palette.ink} strokeDasharray="4 4" strokeWidth={1.5} />
          <Bar dataKey="score" name="Trust score" maxBarSize={36} radius={[4, 4, 0, 0]} isAnimationActive={false}>
            {data.map((d, i) => (
              <Cell key={i} fill={bandColour[d.band]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
