import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';

export default function ForecastTimeline({ data }) {
  // Synthesize timeline coordinates if data not populated yet
  const chartData = (data && data.length > 0) ? data : [
    { name: 'Week 1', growth: 1.2, mutation: 0.20, velocity: 1.0 },
    { name: 'Week 2', growth: 2.1, mutation: 0.35, velocity: 2.5 },
    { name: 'Week 3', growth: 3.5, mutation: 0.50, velocity: 4.0 },
    { name: 'Week 4', growth: 4.2, mutation: 0.67, velocity: 6.5 },
  ];

  return (
    <div className="glass p-5 space-y-4">
      <div>
        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Evolution Dynamics &amp; Threat Momentum</h4>
        <p className="text-sm text-slate-500 mt-0.5">Historical tracking of campaign expansion velocities and mutation rate variances</p>
      </div>

      <ResponsiveContainer width="100%" height={180}>
        <AreaChart data={chartData} margin={{ top: 5, right: 5, bottom: 0, left: -25 }}>
          <defs>
            <linearGradient id="colorGrowth" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25}/>
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
            </linearGradient>
            <linearGradient id="colorMutation" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.25}/>
              <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(255,255,255,0.03)" strokeDasharray="3 3" />
          <XAxis dataKey="name" tick={{ fill: '#475569', fontSize: 9 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#475569', fontSize: 9 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={{ background: '#090d16', border: '1px solid rgba(37,99,235,0.2)', borderRadius: '8px', fontSize: '10px' }} />
          <Area type="monotone" dataKey="growth" stroke="#3b82f6" fillOpacity={1} fill="url(#colorGrowth)" name="Growth Rate" strokeWidth={2} />
          <Area type="monotone" dataKey="mutation" stroke="#8b5cf6" fillOpacity={1} fill="url(#colorMutation)" name="Mutation Rate" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
