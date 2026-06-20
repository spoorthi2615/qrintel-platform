import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Award, Cpu, RefreshCw, FileSpreadsheet, CheckCircle,
  Database, ShieldAlert, BarChart3, TrendingUp, Clock
} from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, BarChart, Bar
} from 'recharts';
import { getEvaluationResults, runEvaluationBenchmark } from '../services/api';

// Data is fetched dynamically from the backend

function KpiCard({ title, value, sub }) {
  return (
    <div className="glass p-4 border border-slate-800 bg-[#070b1a]/20 flex flex-col justify-between">
      <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block">{title}</span>
      <span className="text-2xl font-black text-slate-100 block my-2 font-mono">
        {typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : value}
      </span>
      <span className="text-[9px] text-slate-500">{sub}</span>
    </div>
  );
}

export default function ResearchEvaluation() {
  const [metrics, setMetrics] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState(null);

  const fetchResults = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getEvaluationResults();
      if (data.error) {
        setError(data.error);
      } else {
        setMetrics(data);
      }
    } catch (e) {
      setError("No Evaluation Results Available");
      console.error("Failed to fetch evaluation results:", e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchResults();
  }, []);

  const triggerBenchmark = async () => {
    setIsRunning(true);
    try {
      const data = await runEvaluationBenchmark();
      setMetrics(data.metrics);
    } catch (e) {
      console.error("Benchmark execution failed:", e);
    } finally {
      setIsRunning(false);
    }
  };

  if (isLoading) {
    return (
      <div className="h-64 flex flex-col items-center justify-center gap-2">
        <div className="spinner" />
        <span className="text-xs text-slate-500">Compiling dataset records and evaluating confusion matrices...</span>
      </div>
    );
  }

  if (error || !metrics) {
    return (
      <div className="h-full flex flex-col items-center justify-center min-h-[400px] border border-dashed border-slate-800 rounded-xl bg-slate-900/10 p-8 text-center space-y-4">
        <div className="p-4 rounded-full bg-slate-900 border border-slate-800 text-slate-600">
          <Database size={32} />
        </div>
        <div>
          <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">No Evaluation Results Available</h3>
          <p className="text-xs text-slate-500 mt-2 max-w-sm mx-auto leading-relaxed">
            The analytics dashboard requires active benchmark data. To populate this view, please run the benchmark script via terminal:
          </p>
          <div className="mt-4 bg-slate-950 border border-slate-800 p-3 rounded-lg flex items-center justify-center">
            <code className="text-[11px] font-mono text-emerald-400">python evaluation/scripts/run_benchmark.py</code>
          </div>
        </div>
      </div>
    );
  }

  // Derived KPIs
  const cm = metrics.confusion_matrix || {};
  const meta = metrics.metadata || {};

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-900 pb-4">
        <div>
          <h2 className="text-sm font-extrabold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Award className="text-blue-500" />
            <span>Research &amp; Benchmark Evaluation Dashboard</span>
          </h2>
          <p className="text-[10px] text-slate-500 mt-1">Scientific indices generated across high-fidelity threat vector feeds.</p>
        </div>
        <button
          onClick={triggerBenchmark}
          disabled={isRunning}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-bold bg-blue-600 hover:bg-blue-700 text-white transition-all"
        >
          <RefreshCw size={11} className={isRunning ? "animate-spin" : ""} />
          <span>{isRunning ? "Running Benchmark..." : "Run Evaluation Suite"}</span>
        </button>
      </div>

      {/* KPI Card row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Model Accuracy" value={metrics.accuracy} sub="Correct classification index" />
        <KpiCard title="Model Precision" value={metrics.precision} sub="True threat capture probability" />
        <KpiCard title="Model Recall" value={metrics.recall} sub="Overall threat coverage index" />
        <KpiCard title="F1-Score" value={metrics.f1} sub="Harmonic mean of model accuracy" />
      </div>

      {/* Evaluation Provenance Panel */}
      <div className="glass p-5 border border-slate-800 bg-[#070b1a]/40 rounded-xl">
        <div className="flex items-center gap-2 mb-4">
          <CheckCircle size={15} className="text-emerald-500" />
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Evaluation Details (Provenance)</h3>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-xs">
          <div>
            <span className="text-slate-500 block text-[9px] uppercase font-bold mb-1">Dataset Source</span>
            <span className="text-slate-300 font-mono">OpenPhish</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase font-bold mb-1">Dataset Size</span>
            <span className="text-slate-300 font-mono">{meta.dataset_size} ({meta.phishing_samples} Phish / {meta.benign_samples} Benign)</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase font-bold mb-1">Execution Mode</span>
            <span className="text-slate-300 font-mono text-emerald-400 font-bold">Live Evaluation</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase font-bold mb-1">Engine Version</span>
            <span className="text-slate-300 font-mono">{meta.engine_version}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase font-bold mb-1">Timestamp</span>
            <span className="text-slate-300 font-mono">{meta.timestamp ? new Date(meta.timestamp).toLocaleString() : 'N/A'}</span>
          </div>
        </div>
      </div>

      {/* Heatmap Confusion Matrix & Latency Chart */}
      <div className="grid lg:grid-cols-3 gap-6">
        {/* Confusion Matrix Heatmap */}
        <div className="glass p-5 border border-slate-800 flex flex-col justify-between">
          <div>
            <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block">Confusion Matrix Heatmap</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">True vs. predicted classification boundaries</span>
          </div>

          <div className="grid grid-cols-3 gap-2 text-center text-[10px] font-bold uppercase tracking-wider mt-4">
            <div />
            <div className="bg-slate-900/60 p-2 rounded text-slate-400">Pred Safe</div>
            <div className="bg-slate-900/60 p-2 rounded text-slate-400">Pred Threat</div>

            <div className="bg-slate-900/60 p-2 rounded flex items-center justify-center text-slate-400">Act Safe</div>
            <div className="bg-emerald-500/20 text-emerald-400 p-4 rounded border border-emerald-500/30">
              <span className="text-sm font-black font-mono">{cm.tn}</span>
              <span className="text-[8px] block text-emerald-600 mt-1">True Negative</span>
            </div>
            <div className="bg-red-500/10 text-red-400 p-4 rounded border border-red-500/20">
              <span className="text-sm font-black font-mono">{cm.fp}</span>
              <span className="text-[8px] block text-red-600 mt-1">False Positive</span>
            </div>

            <div className="bg-slate-900/60 p-2 rounded flex items-center justify-center text-slate-400">Act Threat</div>
            <div className="bg-red-500/10 text-red-400 p-4 rounded border border-red-500/20">
              <span className="text-sm font-black font-mono">{cm.fn}</span>
              <span className="text-[8px] block text-red-600 mt-1">False Negative</span>
            </div>
            <div className="bg-emerald-500/20 text-emerald-400 p-4 rounded border border-emerald-500/30">
              <span className="text-sm font-black font-mono">{cm.tp}</span>
              <span className="text-[8px] block text-emerald-600 mt-1">True Positive</span>
            </div>
          </div>

          <div className="text-[9px] text-slate-500 border-t border-slate-900 pt-3 mt-4 flex items-center gap-1.5">
            <Database size={11} />
            <span>Based on {meta.dataset_size} total queries</span>
          </div>
        </div>

        {/* Performance Latency Profile */}
        <div className="glass p-5 border border-slate-800 lg:col-span-2 flex flex-col justify-center items-center text-slate-500">
          <div className="text-xs mb-2">Live Profiling Required</div>
          <div className="text-[10px]">Latency charts will populate after deep module tracing is enabled.</div>
        </div>
      </div>

      {/* Curves Cards */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* ROC Curve */}
        <div className="glass p-5 border border-slate-800">
          <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-4">Receiver Operating Characteristic (ROC)</span>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={metrics.roc} margin={{ top: 5, right: 10, bottom: 0, left: -20 }}>
              <CartesianGrid stroke="rgba(255,255,255,0.03)" strokeDasharray="3 3" />
              <XAxis dataKey="fpr" type="number" tick={{ fill: '#475569', fontSize: 9 }} domain={[0, 1]} />
              <YAxis type="number" tick={{ fill: '#475569', fontSize: 9 }} domain={[0, 1]} />
              <Tooltip />
              <Line type="monotone" dataKey="tpr" stroke="#3b82f6" strokeWidth={2.5} dot={{ r: 3 }} activeDot={{ r: 5 }} name="Model ROC" />
              <Line type="monotone" dataKey="baseline" stroke="#475569" strokeDasharray="5 5" strokeWidth={1} dot={false} name="Baseline" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* PR Curve */}
        <div className="glass p-5 border border-slate-800">
          <span className="text-slate-500 text-[10px] font-bold uppercase tracking-wider block mb-4">Precision-Recall Curve</span>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={metrics.pr} margin={{ top: 5, right: 10, bottom: 0, left: -20 }}>
              <CartesianGrid stroke="rgba(255,255,255,0.03)" strokeDasharray="3 3" />
              <XAxis dataKey="recall" type="number" tick={{ fill: '#475569', fontSize: 9 }} domain={[0, 1]} />
              <YAxis type="number" tick={{ fill: '#475569', fontSize: 9 }} domain={[0, 1]} />
              <Tooltip />
              <Line type="monotone" dataKey="precision" stroke="#a855f7" strokeWidth={2.5} dot={{ r: 3 }} activeDot={{ r: 5 }} name="Model PR" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* CSV download sheet link */}
      <div className="glass p-4 border border-slate-800 bg-[#070b1a]/20 flex items-center justify-between text-xs">
        <div className="flex items-center gap-2 text-slate-400">
          <FileSpreadsheet size={15} className="text-blue-500" />
          <span>Evaluation framework produces publication-ready benchmark arrays.</span>
        </div>
        <a
          href="/api/intelligence/evaluation/results"
          target="_blank"
          rel="noopener noreferrer"
          className="px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-950 border border-slate-800 text-blue-400 font-bold transition-all"
        >
          Export Raw CSV Array
        </a>
      </div>

    </div>
  );
}

function CyberTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass px-2.5 py-1.5 text-[10px] border border-slate-800 bg-slate-950/90 text-slate-300 font-semibold">
      <span>{payload[0].name}: </span>
      <span className="font-mono text-slate-100">{payload[0].value} ms</span>
    </div>
  );
}
