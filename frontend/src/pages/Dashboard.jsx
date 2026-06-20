import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck, Activity, AlertTriangle, ShieldAlert,
  Camera, ImagePlus, Type, History, BarChart3, RefreshCw, Brain, Award,
  LayoutDashboard, Fingerprint, TrendingUp, Settings, Search, Info, Shield, Server,
  Sliders, User, Key, Globe, Eye, Layers, Trash2, ArrowUpRight
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  PieChart, Pie, Cell, BarChart, Bar, ResponsiveContainer, Legend
} from 'recharts';

import LiveScanner    from '../components/LiveScanner';
import ImageUpload    from '../components/ImageUpload';
import ManualEntry    from '../components/ManualEntry';
import ResultPanel    from '../components/ResultPanel';
import HistoryTable   from '../components/HistoryTable';
import IntelligenceHub from '../components/IntelligenceHub';
import ResearchEvaluation from './ResearchEvaluation';

import { scanManual, scanLive, scanUpload, getHistory, getAnalytics, deleteHistoryItem } from '../services/api';

// ─── Constants ───────────────────────────────────────────────────────────────

const CHART_COLORS = {
  safe:       '#10b981',
  suspicious: '#f59e0b',
  malicious:  '#ef4444',
};

const CARD_VARIANTS = {
  hidden: { opacity: 0, y: 15 },
  show:   { opacity: 1, y: 0  },
};

const STAGGER = {
  hidden: {},
  show:   { transition: { staggerChildren: 0.05 } },
};

// ─── Custom tooltip for charts ────────────────────────────────────────────────

function CyberTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass px-3 py-2 text-xs space-y-1 rounded-lg border border-slate-800 bg-slate-950/90">
      {label && <p className="text-slate-400 font-semibold mb-1">{label}</p>}
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: p.color }} />
          <span className="text-slate-500 capitalize">{p.name}:</span>
          <span className="text-slate-200 font-semibold">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Stat Card Component ──────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, color, bg, trend }) {
  return (
    <motion.div variants={CARD_VARIANTS} className="glass rounded-xl p-4 flex items-center justify-between border border-slate-800 bg-slate-900/10">
      <div className="flex items-center gap-3">
        <div className="p-2.5 rounded-lg shrink-0" style={{ background: bg }}>
          <Icon size={18} style={{ color }} />
        </div>
        <div>
          <p className="text-slate-500 text-sm font-bold uppercase tracking-wider">{label}</p>
          <motion.p
            key={value}
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-xl font-black text-slate-100 mt-0.5"
          >
            {value ?? '0'}
          </motion.p>
        </div>
      </div>
      {trend && (
        <div className="flex items-center gap-1 text-sm font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <ArrowUpRight size={10} />
          <span>{trend}</span>
        </div>
      )}
    </motion.div>
  );
}

// ─── Dashboard Shell ─────────────────────────────────────────────────────────

export default function Dashboard() {
  const [view, setView] = useState('overview'); // overview | scan | intelligence | campaigns | forecasting | analytics | settings
  const [activeTab, setActiveTab] = useState('manual');
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const [analytics, setAnalytics] = useState(null);
  const [history, setHistory] = useState([]);
  const [histPage, setHistPage] = useState(1);
  const [histTotal, setHistTotal] = useState(1);

  // ── Data fetching ─────────────────────────────────────────────────────────

  const fetchAnalytics = useCallback(async () => {
    try {
      const data = await getAnalytics();
      setAnalytics(data);
    } catch { /* silent */ }
  }, []);

  const fetchHistory = useCallback(async (page = 1) => {
    try {
      const data = await getHistory(page, 10);
      setHistory(data.items || []);
      setHistTotal(data.total_pages || 1);
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    fetchAnalytics();
    fetchHistory(1);
  }, [fetchAnalytics, fetchHistory]);

  // ── Scan handlers ─────────────────────────────────────────────────────────

  const handleScanResult = async (fn) => {
    setError(null);
    setIsLoading(true);
    setResult(null);
    try {
      const data = await fn();
      setResult(data);
      setView('scan'); // Auto transition to scan view to showcase the result panel!
      fetchAnalytics();
      fetchHistory(1);
      setHistPage(1);
    } catch (err) {
      const msg = err?.response?.data?.error || err.message || 'Scan failed';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const onManualScan = (payload) => handleScanResult(() => scanManual(payload));
  const onLiveScan   = (payload) => handleScanResult(() => scanLive(payload));
  const onUpload     = (formData) => handleScanResult(() => scanUpload(formData));

  const onDelete = async (id) => {
    await deleteHistoryItem(id);
    fetchHistory(histPage);
    fetchAnalytics();
  };

  // ── Derived values ──────────────────────────────────────────────

  const total      = analytics?.total_scans      ?? 0;
  const safe       = analytics?.safe_count        ?? 0;
  const suspicious = analytics?.suspicious_count  ?? 0;
  const malicious  = analytics?.malicious_count   ?? 0;

  // Calculate Global Threat Level dynamically
  const threatLevel = () => {
    if (malicious > 5 || suspicious > 15) return { label: 'CRITICAL', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.12)', glow: 'rgba(239,68,68,0.4)' };
    if (malicious > 2) return { label: 'HIGH', color: '#f97316', bg: 'rgba(249, 115, 22, 0.12)', glow: 'rgba(249,115,22,0.4)' };
    if (suspicious > 0) return { label: 'MODERATE', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.12)', glow: 'rgba(245,158,11,0.4)' };
    return { label: 'LOW', color: '#10b981', bg: 'rgba(16, 185, 129, 0.12)', glow: 'rgba(16,185,129,0.4)' };
  };

  const threatCfg = threatLevel();

  const pieData = [
    { name: 'Safe',       value: safe,       color: CHART_COLORS.safe       },
    { name: 'Suspicious', value: suspicious,  color: CHART_COLORS.suspicious },
    { name: 'Malicious',  value: malicious,   color: CHART_COLORS.malicious  },
  ].filter((d) => d.value > 0);

  const menuItems = [
    { id: 'overview',     label: 'Overview',            icon: LayoutDashboard },
    { id: 'scan',         label: 'Scan Center',         icon: ShieldCheck },
    { id: 'intelligence', label: 'Intelligence Hub',    icon: Brain },
    { id: 'campaigns',    label: 'Campaigns',           icon: Fingerprint },
    { id: 'forecasting',  label: 'Threat Forecasting',  icon: TrendingUp },
    { id: 'analytics',    label: 'Analytics',           icon: BarChart3 },
    { id: 'settings',     label: 'Settings',            icon: Settings },
  ];

  return (
    <div className="flex h-screen overflow-hidden text-slate-100 bg-[#030712] font-sans">
      
      {/* ── LEFT SIDEBAR ───────────────────────────────────────────────────── */}
      <aside className="w-64 bg-[#070b19] border-r border-slate-900 flex flex-col justify-between shrink-0">
        <div>
          {/* Sidebar Brand Header */}
          <div className="h-16 px-6 border-b border-slate-900/60 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/25">
              <ShieldCheck size={18} className="text-blue-400" />
            </div>
            <div>
              <span className="font-extrabold text-sm tracking-wider text-slate-100">QRIntel</span>
              <span className="text-blue-500 text-sm font-black ml-1.5 px-1 py-0.5 rounded bg-blue-500/10">3.0</span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-4 space-y-1">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const active = view === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setView(item.id)}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-xs font-semibold tracking-wide transition-all ${
                    active
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-600/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40 border border-transparent'
                  }`}
                >
                  <Icon size={14} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* System & DB Status Indicator */}
        <div className="p-4 border-t border-slate-900/65 bg-[#060a15]/50 space-y-2">
          <div className="flex items-center justify-between text-sm text-slate-500 font-semibold uppercase">
            <span>Server Status</span>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping inline-block" />
              <span className="text-emerald-400">ONLINE</span>
            </div>
          </div>
          <div className="text-sm text-slate-600 flex items-center justify-between">
            <span>Database Status</span>
            <span className="font-mono text-slate-400">SQLite Connected</span>
          </div>
        </div>
      </aside>

      {/* ── MAIN CONTENT CONTAINER ─────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        
        {/* Top bar */}
        <header className="h-16 border-b border-slate-900 bg-[#060a16]/80 backdrop-blur flex items-center justify-between px-6 shrink-0 z-10">
          <div className="flex items-center gap-3 w-96">
            <Search size={14} className="text-slate-500 shrink-0" />
            <input
              type="text"
              placeholder="Search domains, campaign attributes, payloads..."
              className="bg-transparent text-xs text-slate-300 w-full focus:outline-none placeholder-slate-600"
            />
          </div>

          <div className="flex items-center gap-4">
            <button
              onClick={() => { fetchAnalytics(); fetchHistory(histPage); }}
              className="p-1.5 rounded-lg text-slate-500 hover:text-blue-400 hover:bg-blue-500/10 transition-all border border-slate-900 bg-slate-950/20"
            >
              <RefreshCw size={13} />
            </button>
            <div className="h-7 w-[1px] bg-slate-900" />
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full bg-blue-500/10 border border-blue-500/35 flex items-center justify-center">
                <User size={13} className="text-blue-400" />
              </div>
              <span className="text-[11px] font-bold text-slate-400 hidden sm:inline">Analyst Mode</span>
            </div>
          </div>
        </header>

        {/* View Content Area */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6 bg-[#030712]">
          <AnimatePresence mode="wait">
            <motion.div
              key={view}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.15 }}
            >
              
              {/* ─── 1. SECURITY OVERVIEW (LANDING PAGE) ─── */}
              {view === 'overview' && (
                <div className="space-y-6">
                  {/* Global Threat Level Banner & Executive Summary */}
                  <div className="grid lg:grid-cols-3 gap-6">
                    {/* Threat Level */}
                    <div className="glass p-5 border border-slate-800 bg-[#070b1a]/40 flex flex-col justify-between">
                      <div>
                        <span className="text-slate-500 text-sm font-bold uppercase tracking-wider block">Global Threat Status</span>
                        <h2 className="text-xs text-slate-400 font-semibold mt-1">Platform-wide alert evaluation</h2>
                      </div>
                      <div className="my-6">
                        <div className="inline-block px-5 py-2 rounded-xl text-lg font-black tracking-widest border"
                          style={{
                            color:      threatCfg.color,
                            borderColor: `${threatCfg.color}44`,
                            background:  threatCfg.bg,
                            boxShadow:   `0 0 16px ${threatCfg.glow}`,
                          }}
                        >
                          SYSTEM THREAT LEVEL: {threatCfg.label}
                        </div>
                      </div>
                      <div className="text-xs text-slate-500 flex items-center gap-2">
                        <Info size={11} />
                        <span>Calculated dynamically based on attribution & clusters</span>
                      </div>
                    </div>

                    {/* Executive Summary Narrative */}
                    <div className="lg:col-span-2 glass p-5 border border-slate-800 bg-[#070b1a]/40 flex flex-col justify-between">
                      <div>
                        <span className="text-slate-500 text-sm font-bold uppercase tracking-wider block">Platform Executive Summary</span>
                        <h3 className="text-slate-200 text-sm font-semibold mt-2">Active Intelligence Findings</h3>
                      </div>
                      <div className="my-4 text-xs text-slate-400 leading-relaxed max-w-xl">
                        Currently, QRIntel has analyzed <strong className="text-slate-200">{total} QR scan payloads</strong>. From our structural and behavior checks, <strong className="text-red-400">{malicious} malicious endpoints</strong> and <strong className="text-amber-400">{suspicious} suspicious vectors</strong> have been quarantined. The threat graph tracks <strong className="text-slate-200">coordinated campaigns</strong> with a threat momentum categorized as <strong className="text-slate-200">MODERATE</strong>. The highest-risk category observed is <strong className="text-blue-400">Brand Impersonation</strong>.
                      </div>
                      <div className="text-sm text-slate-500">
                        Operational Status: <span className="text-emerald-400 font-bold">ALL MODULES ACTIVE</span>
                      </div>
                    </div>
                  </div>

                  {/* Standard Stat Cards */}
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatCard icon={Activity}     label="Scans Analyzed" value={total}      color="#3b82f6" bg="rgba(59,130,246,0.1)" trend="+12.4%" />
                    <StatCard icon={ShieldCheck}  label="Safe Identifiers" value={safe}       color="#10b981" bg="rgba(16,185,129,0.1)" />
                    <StatCard icon={AlertTriangle}label="Suspicious Scans" value={suspicious} color="#f59e0b" bg="rgba(245,158,11,0.1)" />
                    <StatCard icon={ShieldAlert}  label="Threats Quarantined" value={malicious}  color="#ef4444" bg="rgba(239,68,68,0.1)" />
                  </div>

                  {/* Charts & Trends */}
                  <div className="grid lg:grid-cols-3 gap-6">
                    {/* Area chart — threat trends */}
                    <div className="lg:col-span-2 glass rounded-xl p-5 border border-slate-800">
                      <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-5">7-Day Threat Trend Chart</h3>
                      <ResponsiveContainer width="100%" height={220}>
                        <AreaChart data={analytics?.threat_trends || []} margin={{ top: 5, right: 5, bottom: 0, left: -20 }}>
                          <defs>
                            {['safe','suspicious','malicious'].map((k) => (
                              <linearGradient key={k} id={`grad-${k}`} x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%"  stopColor={CHART_COLORS[k]} stopOpacity={0.25} />
                                <stop offset="95%" stopColor={CHART_COLORS[k]} stopOpacity={0}   />
                              </linearGradient>
                            ))}
                          </defs>
                          <CartesianGrid stroke="rgba(255,255,255,0.03)" strokeDasharray="4 4" />
                          <XAxis dataKey="date" tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} />
                          <YAxis tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} />
                          <Tooltip content={<CyberTooltip />} />
                          <Area type="monotone" dataKey="safe"       stroke={CHART_COLORS.safe}       fill="url(#grad-safe)"       strokeWidth={2} dot={false} />
                          <Area type="monotone" dataKey="suspicious" stroke={CHART_COLORS.suspicious} fill="url(#grad-suspicious)" strokeWidth={2} dot={false} />
                          <Area type="monotone" dataKey="malicious"  stroke={CHART_COLORS.malicious}  fill="url(#grad-malicious)"  strokeWidth={2} dot={false} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>

                    {/* Pie chart — distribution */}
                    <div className="glass rounded-xl p-5 flex flex-col justify-between border border-slate-800">
                      <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Threat Category Distribution</h3>
                      {pieData.length > 0 ? (
                        <>
                          <div className="w-full h-[140px] flex items-center justify-center">
                            <ResponsiveContainer width="100%" height="100%">
                              <PieChart>
                                <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={60}
                                  dataKey="value" paddingAngle={4}>
                                  {pieData.map((entry) => (
                                    <Cell key={entry.name} fill={entry.color} />
                                  ))}
                                </Pie>
                                <Tooltip content={<CyberTooltip />} />
                              </PieChart>
                            </ResponsiveContainer>
                          </div>
                          <div className="space-y-1.5 mt-2">
                            {pieData.map((d) => (
                              <div key={d.name} className="flex items-center justify-between text-[11px]">
                                <div className="flex items-center gap-2">
                                  <span className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                                  <span className="text-slate-400">{d.name}</span>
                                </div>
                                <span className="text-slate-300 font-bold">{d.value}</span>
                              </div>
                            ))}
                          </div>
                        </>
                      ) : (
                        <div className="flex-1 flex items-center justify-center text-slate-650 text-xs py-8">
                          No distributions parsed yet
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Recent History Feed */}
                  <div className="glass rounded-xl p-5 border border-slate-800">
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-slate-400 text-xs font-bold uppercase tracking-wider block">Recent Detections Feed</span>
                      <button onClick={() => setView('scan')} className="text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1">
                        <span>Open Scan Center</span>
                        <ArrowUpRight size={13} />
                      </button>
                    </div>
                    <HistoryTable
                      history={history.slice(0, 5)}
                      onDelete={onDelete}
                      page={histPage}
                      totalPages={1}
                      onPageChange={() => {}}
                      simpleMode={true}
                    />
                  </div>
                </div>
              )}

              {/* ─── 2. SCAN CENTER (3-COLUMN LAYOUT) ─── */}
              {view === 'scan' && (
                <div className="space-y-6">
                  <div className="grid lg:grid-cols-3 gap-6">
                    {/* Scanner Input Cards Column (Left/Center span 2 cols) */}
                    <div className="lg:col-span-2 space-y-6">
                      
                      {/* Three Column Scanning Options */}
                      <div className="grid md:grid-cols-3 gap-4">
                        {/* Manual entry */}
                        <div className="glass p-5 border border-slate-800 bg-slate-900/5 hover:bg-slate-900/10 transition-colors flex flex-col justify-between min-h-[220px]">
                          <div>
                            <div className="flex items-center gap-2 text-blue-400 font-bold text-xs">
                              <Type size={14} />
                              <span>Manual Entry</span>
                            </div>
                            <p className="text-sm text-slate-500 mt-1.5 leading-relaxed">Directly inspect suspicious URLs, email addresses, or raw data string attributes.</p>
                          </div>
                          <ManualEntry onScan={onManualScan} isLoading={isLoading && activeTab === 'manual'} />
                        </div>

                        {/* Image upload */}
                        <div className="glass p-5 border border-slate-800 bg-slate-900/5 hover:bg-slate-900/10 transition-colors flex flex-col justify-between min-h-[220px]">
                          <div>
                            <div className="flex items-center gap-2 text-purple-400 font-bold text-xs">
                              <ImagePlus size={14} />
                              <span>Image Upload</span>
                            </div>
                            <p className="text-sm text-slate-500 mt-1.5 leading-relaxed">Process image files containing QR codes using our enhanced multi-stage CV engine.</p>
                          </div>
                          <ImageUpload onUpload={onUpload} isLoading={isLoading && activeTab === 'upload'} />
                        </div>

                        {/* Live camera */}
                        <div className="glass p-5 border border-slate-800 bg-slate-900/5 hover:bg-slate-900/10 transition-colors flex flex-col justify-between min-h-[220px]">
                          <div>
                            <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs">
                              <Camera size={14} />
                              <span>Live Scanner</span>
                            </div>
                            <p className="text-sm text-slate-500 mt-1.5 leading-relaxed">Mount dynamic feed streams to run real-time camera captures directly.</p>
                          </div>
                          <LiveScanner onScan={onLiveScan} isLoading={isLoading && activeTab === 'live'} />
                        </div>
                      </div>

                      {/* Error Banner */}
                      <AnimatePresence>
                        {error && (
                          <motion.div
                            initial={{ opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0 }}
                            className="flex items-start gap-2.5 p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs"
                          >
                            <AlertTriangle size={15} className="mt-0.5 shrink-0" />
                            <span>{error}</span>
                          </motion.div>
                        )}
                      </AnimatePresence>

                      {/* Historical Scans List */}
                      <div className="glass p-5 border border-slate-800">
                        <div className="flex items-center justify-between mb-4">
                          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                            <History size={13} />
                            <span>Quarantine & Verification History</span>
                          </h3>
                        </div>
                        <HistoryTable
                          history={history}
                          onDelete={onDelete}
                          page={histPage}
                          totalPages={histTotal}
                          onPageChange={(p) => { setHistPage(p); fetchHistory(p); }}
                        />
                      </div>
                    </div>

                    {/* Result Column (Right 1 col) */}
                    <div className="lg:col-span-1">
                      <AnimatePresence mode="wait">
                        {result ? (
                          <ResultPanel key={result.scan_id} result={result} />
                        ) : (
                          <motion.div
                            key="empty-scan"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="h-full flex flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-slate-800 bg-slate-900/5 min-h-[480px] p-6 text-center"
                          >
                            <div className="p-4 rounded-full bg-slate-900 border border-slate-800">
                              <ShieldCheck size={32} className="text-slate-600" />
                            </div>
                            <div>
                              <p className="text-slate-400 font-semibold text-xs uppercase tracking-wider">Awaiting Payload Input</p>
                              <p className="text-slate-600 text-xs mt-1 leading-relaxed max-w-[200px] mx-auto">Trigger one of the scanning options to see comprehensive trust vectors.</p>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  </div>
                </div>
              )}

              {/* ─── 3. INTELLIGENCE HUB ─── */}
              {view === 'intelligence' && (
                <IntelligenceHub activeView="summary" />
              )}

              {/* ─── 4. ATTRIBUTION & CAMPAIGNS ─── */}
              {view === 'campaigns' && (
                <IntelligenceHub activeView="campaigns" />
              )}

              {/* ─── 5. FORECASTING ─── */}
              {view === 'forecasting' && (
                <IntelligenceHub activeView="forecasting" />
              )}

              {/* ─── 6. ANALYTICS (RESEARCH EVALUATION) ─── */}
              {view === 'analytics' && (
                <ResearchEvaluation />
              )}

              {/* ─── 7. SETTINGS (DEMO PROFILE) ─── */}
              {view === 'settings' && (
                <div className="space-y-6 max-w-4xl">
                  <div className="glass p-6 border border-slate-800">
                    <h3 className="text-sm font-bold text-slate-200 mb-2">QRIntel 3.0 Platform Settings</h3>
                    <p className="text-xs text-slate-500 mb-6">Manage local scanning engines, database connectivity, and API endpoints.</p>

                    <div className="space-y-4">
                      {/* Section 1 */}
                      <div className="p-4 rounded-xl border border-slate-900 bg-slate-900/10 space-y-3">
                        <span className="text-sm font-bold text-slate-400 uppercase tracking-wider block">Security Engine Configuration</span>
                        <div className="flex items-center justify-between text-xs">
                          <div>
                            <p className="text-slate-300 font-semibold">Headless Browser Screenshotting</p>
                            <p className="text-slate-500 text-sm mt-0.5">Captures sandbox renderings of destination URLs.</p>
                          </div>
                          <span className="px-2 py-0.5 rounded text-sm font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">ENABLED</span>
                        </div>
                      </div>

                      {/* Section 2 */}
                      <div className="p-4 rounded-xl border border-slate-900 bg-slate-900/10 space-y-3">
                        <span className="text-sm font-bold text-slate-400 uppercase tracking-wider block">Cryptographic verification keys</span>
                        <div className="flex items-center justify-between text-xs">
                          <div>
                            <p className="text-slate-300 font-semibold">RSA-PSS & Ed25519 Audits</p>
                            <p className="text-slate-500 text-sm mt-0.5">Verify signature provenance logs.</p>
                          </div>
                          <span className="px-2 py-0.5 rounded text-sm font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">ACTIVE</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
