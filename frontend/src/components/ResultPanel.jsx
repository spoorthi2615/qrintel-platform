import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle, CheckCircle, ShieldAlert, Copy, Check,
  Globe, CreditCard, Mail, MessageSquare, Phone, Wifi,
  User, MapPin, Bitcoin, FileText, ChevronDown, ChevronUp,
  Brain, Fingerprint, Network, Shield, Eye, Layers
} from 'lucide-react';
import {
  Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer
} from 'recharts';
import RiskMeter from './RiskMeter';
import ScreenshotPreview from './ScreenshotPreview';

const TYPE_ICONS = {
  URL:    Globe,
  UPI:    CreditCard,
  EMAIL:  Mail,
  SMS:    MessageSquare,
  TEL:    Phone,
  WIFI:   Wifi,
  VCARD:  User,
  GEO:    MapPin,
  CRYPTO: Bitcoin,
  TEXT:   FileText,
};

const STATUS_ICON = {
  SAFE:       CheckCircle,
  SUSPICIOUS: AlertTriangle,
  MALICIOUS:  ShieldAlert,
};

const STATUS_COLOR = {
  SAFE:       '#10b981',
  SUSPICIOUS: '#f59e0b',
  MALICIOUS:  '#ef4444',
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button onClick={copy} className="p-1 rounded text-slate-500 hover:text-slate-300 transition-colors">
      {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
    </button>
  );
}

// Collapsible Info Card
function CollapsibleCard({ id, title, icon: Icon, color, defaultOpen = true, children }) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="glass overflow-hidden border border-slate-800/80 hover:border-slate-700/60 transition-all duration-200">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-4 text-xs font-bold text-slate-300 bg-slate-900/40 hover:bg-slate-900/60 transition-all"
      >
        <div className="flex items-center gap-2">
          <Icon size={14} style={{ color }} />
          <span>{title}</span>
        </div>
        {isOpen ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
      </button>
      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
          >
            <div className="p-4 border-t border-slate-800/40 text-xs text-slate-300 bg-slate-950/20">
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function ResultPanel({ result }) {
  if (!result) return null;

  const {
    payload, payload_type, payload_display,
    score, status, confidence, entropy, entropy_label,
    reasons, breakdown, screenshot, upi_fields,
    tamper_analysis, intelligence,
    content_intel, redirect_intel, brand_intel, visual_intel, infra_intel, threat_intel
  } = result;

  const TypeIcon   = TYPE_ICONS[payload_type] || FileText;
  const StatusIcon = STATUS_ICON[status]       || AlertTriangle;
  const color      = STATUS_COLOR[status]      || '#94a3b8';

  // Construct radar data safely
  const trustDimensions = intelligence?.trust?.dimensions || {
    lexical: { score: 100 - (breakdown?.url || 0) },
    structural: { score: 100 - (breakdown?.upi || 0) },
    protocol: { score: 100 - (breakdown?.crypto || 0) },
    historical: { score: 80 },
    entropy: { score: 100 - (breakdown?.entropy || 0) }
  };

  const radarData = Object.entries(trustDimensions).map(([key, val]) => ({
    subject: key.charAt(0).toUpperCase() + key.slice(1),
    value: Math.round(val.score ?? val),
  }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 15 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* ── Header summary ── */}
      <div
        className="glass p-4 flex items-center justify-between gap-3 border border-slate-800/80"
        style={{
          background: `linear-gradient(135deg, ${color}10 0%, transparent 100%)`,
          borderLeft: `3px solid ${color}`,
        }}
      >
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-lg shrink-0" style={{ background: `${color}15` }}>
            <StatusIcon size={20} style={{ color }} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <TypeIcon size={12} className="text-slate-500 shrink-0" />
              <span className="text-slate-400 text-sm font-semibold uppercase tracking-wider">{payload_display}</span>
            </div>
            <p className="text-slate-200 text-xs font-mono truncate mt-0.5 max-w-[280px] sm:max-w-md">{payload}</p>
          </div>
        </div>
        <CopyButton text={payload} />
      </div>

      {/* ── Star Visual Elements: Risk Gauge & Trust Radar ── */}
      <div className="grid md:grid-cols-2 gap-4">
        {/* Risk Gauge Card */}
        <div className="glass p-5 flex flex-col items-center justify-center border border-slate-800/80 bg-slate-900/20">
          <span className="text-slate-500 text-sm font-bold uppercase tracking-wider mb-4">Risk Assessment</span>
          <RiskMeter score={score} status={status} confidence={confidence} breakdown={breakdown} />
        </div>

        {/* Radar Chart Card */}
        <div className="glass p-5 flex flex-col items-center justify-center border border-slate-800/80 bg-slate-900/20 min-h-[250px]">
          <span className="text-slate-500 text-sm font-bold uppercase tracking-wider mb-2">Trust Vector Radar</span>
          <div className="w-full h-[180px] flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                <PolarGrid stroke="#334155" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#475569', fontSize: 8 }} />
                <Radar name="Trust Score" dataKey="value" stroke={color} fill={color} fillOpacity={0.25} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ── Phase B: Explainability Pipeline (WHY QRIntel FLAGGED THIS) ── */}
      {breakdown && Object.keys(breakdown).length > 0 && status !== 'SAFE' && (
        <div className="glass p-5 border border-slate-800/80 bg-slate-900/40 mt-4 mb-4">
          <h4 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-4 flex items-center gap-2">
            <Shield size={14} className="text-blue-400" />
            WHY QRIntel FLAGGED THIS
          </h4>
          <div className="space-y-3">
            {Object.entries(breakdown).map(([category, points], idx) => {
              if (points <= 0) return null;
              return (
                <div key={idx} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-1.5 h-1.5 rounded-full bg-blue-500"></div>
                    <span className="text-xs text-slate-300 font-medium">{category}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-slate-500 font-mono flex-grow whitespace-nowrap hidden sm:block">
                      ........................................
                    </span>
                    <span className="text-xs font-mono font-bold text-slate-100">{points}</span>
                  </div>
                </div>
              );
            })}
            <div className="pt-3 mt-3 border-t border-slate-800 flex items-center justify-between">
              <span className="text-xs font-bold text-slate-400">Final Risk Score</span>
              <span className="text-sm font-mono font-bold" style={{ color }}>{score}</span>
            </div>
          </div>
        </div>
      )}

      {/* ── Detection Analysis Reasons ── */}
      <div className="glass p-4 border border-slate-800/80 bg-slate-900/10 mb-4">
        <h4 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-3">Threat Detection Log</h4>
        {reasons && reasons.length > 0 ? (
          <div className="space-y-2">
            {reasons.map((r, i) => (
              <div
                key={i}
                className="flex items-start gap-2 p-2.5 rounded-lg text-xs"
                style={{ background: `${color}0b`, border: `1px solid ${color}15` }}
              >
                <AlertTriangle size={13} className="mt-0.5 shrink-0" style={{ color }} />
                <span className="text-slate-300 leading-snug">{r}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-2 text-emerald-500 font-semibold text-xs">
            <CheckCircle size={14} />
            <span>Clean scan: No heuristic or intelligence signals identified.</span>
          </div>
        )}
      </div>

      {/* ── Threat Intelligence (Feed Hits) ── */}
      {threat_intel?.found && (
        <div className="glass p-4 border border-red-500/50 bg-red-900/20 mb-4 rounded-lg">
          <h4 className="text-red-400 text-sm font-bold uppercase tracking-wider mb-3 flex items-center gap-2">
            <AlertTriangle size={14} className="text-red-500" />
            THREAT INTELLIGENCE
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Feed Source</span>
              <span className="text-sm font-bold text-red-400 capitalize">{threat_intel.source}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Confidence</span>
              <span className="text-sm font-mono font-bold text-slate-200">{threat_intel.confidence}%</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">First Seen</span>
              <span className="text-xs font-mono font-bold text-slate-400 truncate block">
                {threat_intel.first_seen ? threat_intel.first_seen.substring(0, 10) : 'Unknown'}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Last Seen</span>
              <span className="text-xs font-mono font-bold text-slate-400 truncate block">
                {threat_intel.last_seen ? threat_intel.last_seen.substring(0, 10) : 'Unknown'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ── Content Intelligence ── */}
      {content_intel?.content_available && (
        <div className="glass p-4 border border-slate-800/80 bg-slate-900/20 mb-4">
          <h4 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-3 flex items-center gap-2">
            <Eye size={14} className="text-purple-400" />
            CONTENT INTELLIGENCE
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-3">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Forms</span>
              <span className="text-sm font-mono font-bold text-slate-200">{content_intel.form_count || 0}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Password Fields</span>
              <span className={`text-sm font-mono font-bold ${content_intel.password_fields > 0 ? 'text-red-400' : 'text-slate-200'}`}>
                {content_intel.password_fields || 0}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">External Actions</span>
              <span className={`text-sm font-mono font-bold ${content_intel.external_actions > 0 ? 'text-red-400' : 'text-slate-200'}`}>
                {content_intel.external_actions || 0}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Target Brand</span>
              <span className={`text-sm font-bold ${brand_intel?.brand ? 'text-orange-400 capitalize' : 'text-slate-400'}`}>
                {brand_intel?.brand || 'None'}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 col-span-2">
              <span className="block text-sm text-slate-500 uppercase">Credential Harvesting Confidence</span>
              <div className="flex items-center gap-2 mt-0.5">
                <div className="flex-grow h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-red-500 rounded-full" style={{ width: `${content_intel.credential_harvesting_confidence || 0}%` }}></div>
                </div>
                <span className="text-sm font-mono font-bold text-red-400">{content_intel.credential_harvesting_confidence || 0}%</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Brand Intelligence ── */}
      {brand_intel?.techniques?.length > 0 && (
        <div className="glass p-4 border border-orange-500/50 bg-orange-900/20 mb-4 rounded-lg">
          <h4 className="text-orange-400 text-sm font-bold uppercase tracking-wider mb-3 flex items-center gap-2">
            <Eye size={14} className="text-orange-500" />
            BRAND INTELLIGENCE
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Target Brand</span>
              <span className="text-sm font-bold text-orange-400 capitalize">{brand_intel.brand}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Technique</span>
              <span className="text-sm font-bold text-slate-200 capitalize truncate block">
                {brand_intel.techniques.join(", ").replace(/_/g, " ")}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Confidence</span>
              <span className="text-sm font-mono font-bold text-slate-200">{brand_intel.confidence}%</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Official Domain</span>
              <span className="text-xs font-mono font-bold text-slate-400 truncate block">
                {brand_intel.official_domain}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ── Infrastructure Intelligence ── */}
      {infra_intel && (infra_intel.registrar || infra_intel.domain_age_days > 0) && (
        <div className="glass p-4 border border-slate-800/80 bg-slate-900/20 mb-4">
          <h4 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-3 flex items-center gap-2">
            <Globe size={14} className="text-blue-400" />
            INFRASTRUCTURE INTELLIGENCE
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Domain Age</span>
              <span className={`text-sm font-mono font-bold ${infra_intel.domain_age_days < 30 ? 'text-red-400' : 'text-slate-200'}`}>
                {infra_intel.domain_age_days} days
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 col-span-2 sm:col-span-1">
              <span className="block text-sm text-slate-500 uppercase">Registrar</span>
              <span className="text-sm font-bold text-slate-200 capitalize truncate block">
                {infra_intel.registrar || 'Hidden'}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">SSL Valid</span>
              <span className={`text-sm font-bold ${infra_intel.ssl_valid ? 'text-emerald-400' : 'text-red-400'}`}>
                {infra_intel.ssl_valid ? 'Yes' : 'No'}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Infra Risk Score</span>
              <span className={`text-sm font-mono font-bold ${infra_intel.risk_score > 20 ? 'text-red-400' : 'text-slate-200'}`}>
                {infra_intel.risk_score || 0}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ── DNS Intelligence ── */}
      {intelligence?.dns_intel && (
        <div className="glass p-4 border border-slate-800/80 bg-slate-900/20 mb-4">
          <h4 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-3 flex items-center gap-2">
            <Globe size={14} className="text-teal-400" />
            DNS INTELLIGENCE
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">A Records</span>
              <span className="text-sm font-mono font-bold text-slate-200">
                {intelligence.dns_intel.a_records?.length || 0}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">MX Records</span>
              <span className={`text-sm font-mono font-bold ${intelligence.dns_intel.mx_records?.length === 0 ? 'text-red-400' : 'text-slate-200'}`}>
                {intelligence.dns_intel.mx_records?.length || 0}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">ASN</span>
              <span className="text-sm font-mono font-bold text-slate-200 truncate block">
                {intelligence.dns_intel.asn || 'Unknown'}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">DNS Risk Score</span>
              <span className={`text-sm font-mono font-bold ${intelligence.dns_intel.dns_risk_score > 20 ? 'text-red-400' : 'text-slate-200'}`}>
                {intelligence.dns_intel.dns_risk_score || 0}
              </span>
            </div>
          </div>
          {intelligence.dns_intel.reasons?.length > 0 && (
            <div className="mt-3 bg-red-500/5 border border-red-500/10 rounded p-2 text-sm text-red-400">
              <ul className="list-disc list-inside space-y-0.5">
                {intelligence.dns_intel.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* ── Visual Intelligence ── */}
      {visual_intel?.target_brand && (
        <div className="glass p-4 border border-slate-800/80 bg-slate-900/20 mb-4">
          <h4 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-3 flex items-center gap-2">
            <Eye size={14} className="text-pink-400" />
            VISUAL INTELLIGENCE
          </h4>
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Visual Impersonation</span>
              <span className="text-sm font-bold text-pink-400 capitalize">{visual_intel.target_brand}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Similarity Score</span>
              <span className={`text-sm font-mono font-bold ${visual_intel.final_similarity > 85 ? 'text-red-400' : 'text-slate-200'}`}>
                {visual_intel.final_similarity}%
              </span>
            </div>
          </div>
          {visual_intel.final_similarity > 85 && (
            <div className="p-2.5 rounded-lg text-xs bg-red-900/20 border border-red-500/30 text-red-400 flex items-start gap-2">
              <AlertTriangle size={14} className="shrink-0 mt-0.5" />
              <span>High visual similarity to known login portal detected.</span>
            </div>
          )}
        </div>
      )}

      {/* ── Visual Brand Intelligence (OCR & Logo) ── */}
      {intelligence?.visual_brand_intel && (
        <div className="glass p-4 border border-slate-800/80 bg-slate-900/20 mb-4">
          <h4 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-3 flex items-center gap-2">
            <Eye size={14} className="text-purple-400" />
            VISUAL BRAND INTELLIGENCE
          </h4>
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">OCR Status</span>
              <span className={`text-sm font-mono font-bold ${intelligence.visual_brand_intel.ocr.status === 'MOCK/STUB' ? 'text-amber-400' : 'text-slate-200'}`}>
                {intelligence.visual_brand_intel.ocr.status}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className="block text-sm text-slate-500 uppercase">Logo Model Status</span>
              <span className={`text-sm font-mono font-bold ${intelligence.visual_brand_intel.logo.status === 'MOCK/STUB' ? 'text-amber-400' : 'text-slate-200'}`}>
                {intelligence.visual_brand_intel.logo.status}
              </span>
            </div>
          </div>
          {intelligence.visual_brand_intel.ocr.brands_detected?.length > 0 && (
            <div className="mb-2 p-2 rounded bg-slate-900/50 border border-slate-800">
              <span className="text-sm text-slate-400 block mb-1">OCR Brands Detected:</span>
              <div className="flex gap-2">
                {intelligence.visual_brand_intel.ocr.brands_detected.map((b, i) => (
                  <span key={i} className="px-2 py-0.5 bg-purple-500/20 text-purple-300 rounded text-xs font-bold capitalize">
                    {b}
                  </span>
                ))}
              </div>
            </div>
          )}
          {intelligence.visual_brand_intel.ocr.error && (
            <div className="p-2 rounded bg-red-900/20 border border-red-500/30 text-sm text-red-400 font-mono">
              {intelligence.visual_brand_intel.ocr.error}
            </div>
          )}
        </div>
      )}

      {/* ── Redirect Chain ── */}
      {redirect_intel?.redirect_chain && redirect_intel.redirect_chain.length > 1 && (
        <div className="glass p-4 border border-slate-800/80 bg-slate-900/10 mb-4">
          <h4 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-3 flex items-center gap-2">
            <Network size={14} className="text-amber-400" />
            REDIRECT CHAIN
          </h4>
          <div className="space-y-2">
            {redirect_intel.redirect_chain.map((hop, i) => (
              <div key={i} className="flex items-start gap-2">
                <div className="flex flex-col items-center shrink-0 mt-1">
                  <div className={`w-2 h-2 rounded-full ${i === 0 ? 'bg-blue-400' : i === redirect_intel.redirect_chain.length - 1 ? 'bg-red-400' : 'bg-amber-400'}`}></div>
                  {i < redirect_intel.redirect_chain.length - 1 && <div className="w-px h-6 bg-slate-700 mt-1"></div>}
                </div>
                <span className="text-xs text-slate-300 font-mono break-all">{hop}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Separate, Collapsible Intelligence Cards ── */}
      <div className="space-y-3">
        {/* Sprint 1: Trust Score */}
        {intelligence?.trust && (
          <CollapsibleCard id="trust" title="Trust Vector Analysis (Sprint 1)" icon={Shield} color="#3b82f6" defaultOpen={true}>
            <div className="space-y-3">
              <div className="flex justify-between items-center bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/60">
                <span className="text-slate-400 font-medium">Composite Trust Rating:</span>
                <span className="font-bold font-mono" style={{ color }}>
                  {intelligence.trust.trust_label} ({Math.round(intelligence.trust.composite)}/100)
                </span>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {Object.entries(intelligence.trust.dimensions || {}).map(([dim, val]) => (
                  <div key={dim} className="space-y-1">
                    <div className="flex justify-between text-sm text-slate-500 capitalize">
                      <span>{dim}</span>
                      <span>{Math.round(val.score)}%</span>
                    </div>
                    <div className="h-1 bg-slate-900 rounded-full overflow-hidden">
                      <div className="h-full rounded-full"
                        style={{
                          width: `${val.score}%`,
                          background: val.score > 70 ? '#10b981' : val.score > 40 ? '#f59e0b' : '#ef4444'
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
              {intelligence.trust.top_concerns?.length > 0 && (
                <div className="bg-red-500/5 border border-red-500/10 rounded-lg p-2 text-sm text-red-400">
                  <span className="font-semibold block mb-1">Key Concerns:</span>
                  <ul className="list-disc list-inside space-y-0.5">
                    {intelligence.trust.top_concerns.map((c, i) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </CollapsibleCard>
        )}

        {/* Sprint 2: QR Tampering */}
        {tamper_analysis && (
          <CollapsibleCard id="tamper" title="QR Tampering Analysis (Sprint 2)" icon={Layers} color="#a855f7" defaultOpen={false}>
            <div className="space-y-3">
              <div className="flex justify-between items-center bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/60">
                <span className="text-slate-400 font-medium">Physical Anomalies Probability:</span>
                <span className="font-bold text-purple-400">
                  {tamper_analysis.tampering_label} ({tamper_analysis.tampering_probability}%)
                </span>
              </div>
              {tamper_analysis.explanations?.length > 0 ? (
                <div className="space-y-1.5">
                  {tamper_analysis.explanations.map((exp, i) => (
                    <div key={i} className="flex justify-between p-2 rounded bg-slate-900/40 border border-slate-800/30 text-sm">
                      <span className={exp.passed ? "text-slate-400" : "text-amber-400 font-semibold"}>
                        {exp.check}: {exp.detail}
                      </span>
                      <span className={exp.passed ? "text-emerald-500" : "text-red-500 font-bold"}>
                        {exp.passed ? "PASS" : `FAIL (+${exp.risk})`}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-slate-500 italic">No physical anomalies detected.</div>
              )}
            </div>
          </CollapsibleCard>
        )}

        {/* Sprint 3: Visual Phishing */}
        {intelligence?.visual_phishing && (
          <CollapsibleCard id="phishing" title="Visual Phishing Engine (Sprint 3)" icon={Eye} color="#eab308" defaultOpen={false}>
            <div className="space-y-3">
              <div className="flex justify-between items-center bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/60">
                <span className="text-slate-400 font-medium">Brand Impersonation Risk:</span>
                <span className="font-bold text-amber-500">
                  {intelligence.visual_phishing.impersonation_label} ({intelligence.visual_phishing.impersonation_score}%)
                </span>
              </div>
              <div className="grid grid-cols-2 gap-3 bg-slate-900/30 p-2 rounded border border-slate-800/40">
                <div>
                  <span className="text-slate-500 block text-xs uppercase">Detected Brand</span>
                  <span className="text-slate-200 font-semibold">{intelligence.visual_phishing.brand_detected || "None"}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-xs uppercase">Triggered Signals</span>
                  <span className="text-slate-200 font-semibold">{intelligence.visual_phishing.triggered_signals}</span>
                </div>
              </div>
            </div>
          </CollapsibleCard>
        )}

        {/* Sprint 4: Behavioral Graph */}
        {intelligence?.graph && (
          <CollapsibleCard id="graph" title="Behavioral Trust Graph (Sprint 4)" icon={Network} color="#22c55e" defaultOpen={false}>
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-2 text-center bg-slate-900/40 p-3 rounded-lg border border-slate-800/40">
                <div>
                  <p className="text-slate-600 uppercase text-xs tracking-wider">New Vertex Anomaly</p>
                  <p className="text-slate-200 font-bold mt-0.5">{intelligence.graph.new_node_anomaly_score?.toFixed(1) || 0}</p>
                </div>
                <div>
                  <p className="text-slate-600 uppercase text-xs tracking-wider">Added Nodes</p>
                  <p className="text-slate-200 font-bold mt-0.5">{intelligence.graph.nodes_added ?? 0}</p>
                </div>
                <div>
                  <p className="text-slate-600 uppercase text-xs tracking-wider">Added Edges</p>
                  <p className="text-slate-200 font-bold mt-0.5">{intelligence.graph.edges_added ?? 0}</p>
                </div>
              </div>
              {intelligence.graph.alert && (
                <div className="bg-amber-500/10 border border-amber-500/30 rounded p-2 text-amber-400 font-medium">
                  {intelligence.graph.alert}
                </div>
              )}
            </div>
          </CollapsibleCard>
        )}

        {/* Sprint 5: Campaign Attribution */}
        {intelligence?.campaign && (
          <CollapsibleCard id="campaign" title="Campaign Attribution (Sprint 5)" icon={Fingerprint} color="#f43f5e" defaultOpen={false}>
            <div className="space-y-3">
              <div className="flex justify-between items-center bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/60">
                <span className="text-slate-400 font-medium">Associated Actor Group:</span>
                <span className="font-bold text-rose-500">
                  {intelligence.campaign.name}
                </span>
              </div>
              <div className="space-y-2 text-sm text-slate-400">
                <div className="flex justify-between">
                  <span>Jaccard Footprint Similarity:</span>
                  <span className="text-slate-200 font-bold">{(intelligence.campaign.similarity_score * 100).toFixed(0)}%</span>
                </div>
                <div className="flex justify-between">
                  <span>Tactical Threat Generation:</span>
                  <span className="text-slate-200 font-bold">Generation {intelligence.campaign.generation}</span>
                </div>
                {intelligence.campaign.ttp_fingerprint && (
                  <div className="border-t border-slate-800/50 pt-2 space-y-1.5">
                    <span className="font-semibold text-slate-300 block">TTP Indicators:</span>
                    <div className="grid grid-cols-2 gap-2 text-xs bg-slate-900/30 p-2 rounded">
                      <div>Keywords: <span className="text-slate-300 font-mono">[{intelligence.campaign.ttp_fingerprint.keywords?.join(', ')}]</span></div>
                      <div>TLDs: <span className="text-slate-300 font-mono">[{intelligence.campaign.ttp_fingerprint.tlds?.join(', ')}]</span></div>
                      <div>Path Profile: <span className="text-slate-300 font-mono">{intelligence.campaign.ttp_fingerprint.path_pattern || 'none'}</span></div>
                      <div>Payment Dest: <span className="text-slate-300 font-mono">{intelligence.campaign.ttp_fingerprint.payment_target || 'none'}</span></div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </CollapsibleCard>
        )}
        
        {/* Sprint 5: Related Threats */}
        {intelligence?.related_threats && (
          <CollapsibleCard id="related" title="Related Threats (Sprint 5)" icon={Network} color="#06b6d4" defaultOpen={false}>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="block text-sm text-slate-500 uppercase">Related Campaign</span>
                  <span className="text-sm font-bold text-cyan-400">
                    {intelligence.related_threats.related_campaigns?.length > 0 ? intelligence.related_threats.related_campaigns[0] : "None"}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="block text-sm text-slate-500 uppercase">Related URLs</span>
                  <span className="text-sm font-mono font-bold text-slate-200">
                    {intelligence.related_threats.related_urls?.length || 0}
                  </span>
                </div>
                <div className="col-span-2 p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="block text-sm text-slate-500 uppercase">Relationship Confidence</span>
                  <span className="text-sm font-mono font-bold text-cyan-400">
                    {intelligence.related_threats.relationship_confidence}%
                  </span>
                </div>
              </div>
            </div>
          </CollapsibleCard>
        )}
      </div>

      {/* UPI metadata if applicable */}
      {payload_type === 'UPI' && upi_fields && Object.keys(upi_fields).length > 0 && (
        <div className="glass p-4 border border-slate-800/80 bg-amber-500/5">
          <span className="text-sm font-bold text-amber-500 uppercase tracking-wider block mb-2">UPI Transaction Fields</span>
          <div className="grid grid-cols-2 gap-2">
            {Object.entries(upi_fields).map(([k, v]) => (
              <div key={k} className="p-2 rounded bg-slate-950/40 border border-slate-800/50 text-sm">
                <p className="text-slate-500 uppercase">{k}</p>
                <p className="text-slate-300 font-mono font-semibold mt-0.5 truncate">{v}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Screenshot sandboxed preview */}
      <ScreenshotPreview
        screenshot={screenshot}
        status={status}
        payloadUrl={payload_type === 'URL' ? payload : null}
      />
    </motion.div>
  );
}
