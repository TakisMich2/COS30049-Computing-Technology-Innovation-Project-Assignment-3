import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import ChartCard, { axisProps, legendProps, tooltipProps } from './ChartCard.jsx';
import { CheckIcon } from '../Icons.jsx';
import { palette } from '../../utils/theme.js';

const capitalise = (text) => text.charAt(0).toUpperCase() + text.slice(1);

/** Question answered: which parts of this URL raised warnings, and how many each? */
export default function WarningsChart({ warnings }) {
  const counts = new Map();
  for (const { part } of warnings) counts.set(part, (counts.get(part) ?? 0) + 1);
  const data = [...counts]
    .map(([part, count]) => ({ part: capitalise(part), count }))
    .sort((a, b) => b.count - a.count);

  const summary = data.length
    ? `Warnings by URL part: ${data.map((d) => `${d.part} ${d.count}`).join(', ')}.`
    : 'No URL parts raised warnings.';

  return (
    <ChartCard
      id="warnings-chart"
      title="Which parts of the URL raised warnings?"
      description="The number of warning signs found in each part of the address. Details are listed below."
      summary={summary}
    >
      {data.length === 0 ? (
        <div className="chart-empty">
          <CheckIcon size={28} />
          <p>No part of this address matched a known warning pattern.</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(200, 80 + data.length * 44)}>
          <BarChart data={data} layout="vertical" margin={{ top: 8, right: 24, bottom: 20, left: 0 }} accessibilityLayer>
            <CartesianGrid horizontal={false} stroke={palette.grid} />
            <XAxis
              type="number"
              allowDecimals={false}
              domain={[0, (max) => Math.max(3, max)]}
              {...axisProps}
              label={{ value: 'Number of warnings', position: 'insideBottom', offset: -14, fill: palette.muted, fontSize: 13 }}
            />
            <YAxis type="category" dataKey="part" width={128} {...axisProps} />
            <Tooltip {...tooltipProps} formatter={(value) => [value, 'Warnings']} />
            <Legend
              {...legendProps}
              verticalAlign="top"
              height={28}
              payload={[{ value: 'Warnings found in this part', type: 'square', color: palette.caution }]}
            />
            <Bar dataKey="count" name="Warnings" fill={palette.caution} barSize={26} radius={[0, 4, 4, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </ChartCard>
  );
}
