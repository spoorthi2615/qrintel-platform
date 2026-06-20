import { useState, useEffect } from 'react';
import { Activity, CheckCircle, XCircle, TrendingUp } from 'lucide-react';
import { getForecastValidation } from '../services/api';

export default function ForecastValidation() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getForecastValidation()
      .then((res) => {
        setData(res);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load validation:", err);
        setLoading(false);
      });
  }, []);

  if (loading) return <div className="text-slate-400 p-6 animate-pulse">Loading Validation Engine...</div>;
  if (!data || !data.metrics) return <div className="text-slate-400 p-6">No validation data available.</div>;

  const { metrics, records } = data;

  return (
    <div className="space-y-6">
      {/* Accuracy Header */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
          <div>
            <p className="text-slate-500 text-xs font-semibold uppercase tracking-wider mb-1">Mean Absolute Error</p>
            <p className="text-2xl font-bold text-slate-200">{metrics.mae}</p>
          </div>
          <Activity className="w-8 h-8 text-blue-500 opacity-50" />
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
          <div>
            <p className="text-slate-500 text-xs font-semibold uppercase tracking-wider mb-1">MAPE (%)</p>
            <p className="text-2xl font-bold text-slate-200">{metrics.mape}%</p>
          </div>
          <TrendingUp className="w-8 h-8 text-emerald-500 opacity-50" />
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
          <div>
            <p className="text-slate-500 text-xs font-semibold uppercase tracking-wider mb-1">RMSE</p>
            <p className="text-2xl font-bold text-slate-200">{metrics.rmse}</p>
          </div>
          <Activity className="w-8 h-8 text-indigo-500 opacity-50" />
        </div>
      </div>

      {/* Validation Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <h3 className="font-semibold text-slate-200">Prediction vs Actual Observation</h3>
          <span className="text-xs text-slate-500 px-2.5 py-1 bg-slate-800 rounded-md">SIMULATED DATA</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950/50 text-slate-400 text-xs uppercase font-semibold">
              <tr>
                <th className="px-6 py-3">Campaign ID</th>
                <th className="px-6 py-3">Predicted Vol</th>
                <th className="px-6 py-3">Actual Vol</th>
                <th className="px-6 py-3">Abs Error</th>
                <th className="px-6 py-3">% Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50 text-slate-300">
              {records.map((r, i) => (
                <tr key={i} className="hover:bg-slate-800/20 transition-colors">
                  <td className="px-6 py-4 font-mono text-xs text-blue-400">{r.campaign_id}</td>
                  <td className="px-6 py-4">{r.predicted_value}</td>
                  <td className="px-6 py-4">{r.actual_value}</td>
                  <td className="px-6 py-4">{Math.round(r.absolute_error)}</td>
                  <td className="px-6 py-4">{Math.round(r.percentage_error)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
