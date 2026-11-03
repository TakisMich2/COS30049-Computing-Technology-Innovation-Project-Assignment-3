import { Bar, BarChart, CartesianGrid, Cell, Legend, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import ChartCard, { axisProps, legendProps, tooltipProps } from './ChartCard.jsx';
import { palette } from '../../utils/theme.js';
import { PHISHING_PROBABILITY_THRESHOLD } from '../../utils/scoring.js';

/** Question answered: how sure is the model, and how close is this URL to the phishing cut-off? */
export default function ConfidenceChart({ probability }) {
  const phishing = Math.round(probability * 1000) / 10;
  const benign = Math.round((100 - phishing) * 10) / 10;
  const data = [
    { name: 'Phishing', value: phishing, fill: palette.danger },
    { name: 'Benign', value: benign, fill: palette.safe },
  ];

  return (
    <ChartCard
      id="confidence-chart"
      title="How sure is the model?"
      description={`The probability the model gives each outcome. A URL is flagged as phishing above the ${PHISHING_PROBABILITY_THRESHOLD}% line.`}
      summary={`Phishing probability ${phishing}%, benign probability ${benign}%. The phishing cut-off is ${PHISHING_PROBABILITY_THRESHOLD}%.`}
    >
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={data} layout="vertical" margin={{ top: 24, right: 24, bottom: 20, left: 0 }} accessibilityLayer>
          <CartesianGrid horizontal={false} stroke={palette.grid} />
          <XAxis
            type="number"
            domain={[0, 100]}
            ticks={[0, 25, 50, 75, 100]}
            unit="%"
            {...axisProps}
            label={{ value: 'Probability (%)', position: 'insideBottom', offset: -14, fill: palette.muted, fontSize: 13 }}
          />
          <YAxis type="category" dataKey="name" width={76} {...axisProps} />
          <Tooltip {...tooltipProps} formatter={(value) => [`${value}%`, 'Probability']} />
          <Legend
            {...legendProps}
            verticalAlign="top"
            height={28}
            payload={[
              { value: 'Phishing probability', type: 'square', color: palette.danger },
              { value: 'Benign probability', type: 'square', color: palette.safe },
              { value: 'Phishing cut-off', type: 'plainline', color: palette.ink, payload: { strokeDasharray: '4 4' } },
            ]}
          />
          <ReferenceLine x={PHISHING_PROBABILITY_THRESHOLD} stroke={palette.ink} strokeDasharray="4 4" strokeWidth={1.5} />
          <Bar dataKey="value" name="Probability" barSize={30} radius={[0, 4, 4, 0]} isAnimationActive={false}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.fill} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
