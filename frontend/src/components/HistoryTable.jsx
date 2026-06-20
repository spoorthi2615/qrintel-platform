import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Trash2, Shield, ChevronLeft, ChevronRight, Clock } from 'lucide-react';

const STATUS_STYLE = {
  SAFE:       { color: '#10b981', bg: 'rgba(16,185,129,0.12)',  border: 'rgba(16,185,129,0.3)'  },
  SUSPICIOUS: { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)',  border: 'rgba(245,158,11,0.3)'  },
  MALICIOUS:  { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.3)'   },
};

const TYPE_COLOR = {
  URL:    '#3b82f6',
  UPI:    '#8b5cf6',
  EMAIL:  '#06b6d4',
  SMS:    '#10b981',
  TEL:    '#f59e0b',
  WIFI:   '#ec4899',
  VCARD:  '#a78bfa',
  GEO:    '#34d399',
  CRYPTO: '#fbbf24',
  TEXT:   '#94a3b8',
};

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts + 'Z');
  return d.toLocaleString(undefined, {
    month:  'short', day: 'numeric',
    hour:   '2-digit', minute: '2-digit',
  });
}

function truncate(str, n = 40) {
  return str && str.length > n ? str.slice(0, n) + '…' : str;
}

export default function HistoryTable({
  history = [],
  onDelete,
  page = 1,
  totalPages = 1,
  onPageChange,
}) {
  const [deleting, setDeleting] = useState(null);

  const handleDelete = async (id) => {
    setDeleting(id);
    try { await onDelete(id); } finally { setDeleting(null); }
  };

  if (!history.length) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
        <div className="p-5 rounded-full" style={{ background: 'rgba(37,99,235,0.08)', border: '1px solid rgba(37,99,235,0.15)' }}>
          <Shield size={36} className="text-slate-600" />
        </div>
        <div>
          <p className="text-slate-400 font-medium">No scans yet</p>
          <p className="text-slate-600 text-sm mt-1">Your scan history will appear here</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Table */}
      <div className="overflow-x-auto rounded-xl" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'rgba(13,27,46,0.8)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              {['Time', 'Payload', 'Type', 'Score', 'Status', ''].map((h) => (
                <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <AnimatePresence initial={false}>
              {history.map((item, idx) => {
                const st  = STATUS_STYLE[item.status] || STATUS_STYLE.SAFE;
                const tc  = TYPE_COLOR[item.payload_type] || '#94a3b8';
                return (
                  <motion.tr
                    key={item.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 8 }}
                    transition={{ delay: idx * 0.03 }}
                    className="group transition-colors"
                    style={{
                      borderBottom: '1px solid rgba(255,255,255,0.04)',
                      background: idx % 2 === 0 ? 'rgba(13,27,46,0.3)' : 'transparent',
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(37,99,235,0.06)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = idx % 2 === 0 ? 'rgba(13,27,46,0.3)' : 'transparent'}
                  >
                    {/* Time */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 text-slate-500 text-xs">
                        <Clock size={11} />
                        {formatTime(item.timestamp)}
                      </div>
                    </td>

                    {/* Payload */}
                    <td className="px-4 py-3 max-w-xs">
                      <span className="text-slate-300 font-mono text-xs" title={item.payload}>
                        {truncate(item.payload, 45)}
                      </span>
                    </td>

                    {/* Type badge */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold"
                        style={{ background: `${tc}18`, color: tc, border: `1px solid ${tc}40` }}>
                        {item.payload_type}
                      </span>
                    </td>

                    {/* Score */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="font-bold text-sm" style={{ color: st.color }}>
                        {Math.round(item.risk_score)}
                      </span>
                    </td>

                    {/* Status badge */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold"
                        style={{ background: st.bg, color: st.color, border: `1px solid ${st.border}` }}>
                        {item.status}
                      </span>
                    </td>

                    {/* Delete */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <button
                        onClick={() => handleDelete(item.id)}
                        disabled={deleting === item.id}
                        className="p-1.5 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-40"
                      >
                        {deleting === item.id
                          ? <span className="spinner" style={{ width: 14, height: 14 }} />
                          : <Trash2 size={14} />
                        }
                      </button>
                    </td>
                  </motion.tr>
                );
              })}
            </AnimatePresence>
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 pt-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-white/5 transition-colors disabled:opacity-30"
          >
            <ChevronLeft size={16} />
          </button>
          <span className="text-slate-400 text-sm">
            Page <span className="text-slate-200 font-semibold">{page}</span> of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-white/5 transition-colors disabled:opacity-30"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
