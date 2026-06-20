import { motion } from 'framer-motion';
import { TrendingUp, ShieldAlert, Award, RefreshCcw, Activity } from 'lucide-react';

export default function ForecastCard({ forecast }) {
  if (!forecast) return null;

  const {
    campaign_id, name, forecast_score, forecast_label, threat_momentum, momentum_value,
    predicted_variants_next_month, growth_rate, mutation_rate,
    forecast_confidence, expansion_score, reasons
  } = forecast;

  const getLabelColor = (label) => {
    if (label === 'HIGH_EVOLUTION_RISK') return '#ef4444'; // red
    if (label === 'EMERGING_CAMPAIGN') return '#8b5cf6'; // purple
    if (label === 'STEADY_PROLIFERATION') return '#f59e0b'; // amber
    return '#10b981'; // LOW_RISK / green
  };

  const getMomentumColor = (m) => {
    if (m === 'HIGH_MOMENTUM') return '#ef4444';
    if (m === 'MEDIUM_MOMENTUM') return '#f59e0b';
    return '#10b981';
  };

  return (
    <div className="glass p-5 flex flex-col justify-between border-l-4" style={{ borderLeftColor: getLabelColor(forecast_label) }}>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h4 className="text-sm font-bold text-slate-200">{name || campaign_id}</h4>
            <span className="text-[10px] font-mono text-slate-500">Forecasting Model ID: FC-{campaign_id.slice(0,6)}</span>
          </div>
          <div className="flex flex-col items-end gap-1">
            <span className="px-2.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-slate-900 border border-slate-800"
              style={{ color: getLabelColor(forecast_label) }}>
              {forecast_label?.replace(/_/g, ' ')}
            </span>
            <span className="px-2 py-0.5 rounded text-[8px] font-bold bg-slate-900/60"
              style={{ color: getMomentumColor(threat_momentum) }}>
              {threat_momentum} MOMENTUM ({momentum_value})
            </span>
            <span className="px-2 py-0.5 rounded text-[8px] font-bold bg-slate-900/60 text-blue-400 border border-blue-900/30">
              {forecast_confidence}% CONFIDENCE
            </span>
          </div>
        </div>

        {/* Forecast Score Display */}
        <div className="flex items-center gap-4 bg-slate-900/30 p-3.5 rounded-xl border border-slate-850">
          <div className="relative flex items-center justify-center w-14 h-14 rounded-full border-4 border-slate-800"
            style={{ borderTopColor: getLabelColor(forecast_label) }}>
            <span className="text-sm font-black text-slate-100">{Math.round(forecast_score)}%</span>
          </div>
          <div>
            <p className="text-[10px] text-slate-500 font-bold uppercase">Evolution Index</p>
            <p className="text-slate-300 text-xs mt-0.5 font-medium">Likelihood of mutation / variant generation</p>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-2.5 text-center">
          <div className="bg-slate-900/40 p-2.5 rounded-lg border border-slate-850">
            <TrendingUp size={12} className="mx-auto text-blue-400" />
            <span className="text-[8px] text-slate-500 uppercase block mt-1">Growth Velocity</span>
            <span className="text-[11px] text-slate-200 font-black">+{growth_rate} / day</span>
          </div>
          <div className="bg-slate-900/40 p-2.5 rounded-lg border border-slate-850">
            <Activity size={12} className="mx-auto text-purple-400" />
            <span className="text-[8px] text-slate-500 uppercase block mt-1">Mutation Index</span>
            <span className="text-[11px] text-slate-200 font-black">{mutation_rate}</span>
          </div>
          <div className="bg-slate-900/40 p-2.5 rounded-lg border border-slate-850">
            <ShieldAlert size={12} className="mx-auto text-amber-400" />
            <span className="text-[8px] text-slate-500 uppercase block mt-1">Next Month</span>
            <span className="text-[11px] text-slate-200 font-black">{predicted_variants_next_month} variants</span>
          </div>
        </div>

        {/* Explainability Matrix */}
        {reasons && reasons.length > 0 && (
          <div className="bg-slate-950/40 rounded-lg p-3 border border-slate-850">
            <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider block mb-1.5">Forecast Evidence</span>
            <ul className="space-y-1">
              {reasons.map((r, i) => (
                <li key={i} className="text-[10px] text-slate-400 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500/80 inline-block" />
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
