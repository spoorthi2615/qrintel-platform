import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, ShieldAlert, Maximize2, Minimize2, ExternalLink } from 'lucide-react';

const STATUS_BORDER = {
  SAFE:       'rgba(16,185,129,0.4)',
  SUSPICIOUS: 'rgba(245,158,11,0.4)',
  MALICIOUS:  'rgba(239,68,68,0.4)',
};

export default function ScreenshotPreview({ screenshot, status = 'SAFE', payloadUrl }) {
  const [expanded, setExpanded] = useState(false);
  const borderColor = STATUS_BORDER[status] || STATUS_BORDER.SAFE;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          Sandboxed Preview
        </span>
        {screenshot && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-slate-500 hover:text-slate-300 transition-colors"
          >
            {expanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
        )}
      </div>

      <AnimatePresence mode="wait">
        {screenshot ? (
          <motion.div
            key="preview"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="relative rounded-xl overflow-hidden"
            style={{ border: `1px solid ${borderColor}`, boxShadow: `0 0 20px ${borderColor}44` }}
          >
            <img
              src={`data:image/png;base64,${screenshot}`}
              alt="Sandboxed preview"
              className="w-full object-cover"
              style={{ maxHeight: expanded ? '420px' : '180px', transition: 'max-height 0.3s ease' }}
            />

            {/* Overlay badge */}
            <div className="absolute top-2 left-2 flex items-center gap-1 px-2 py-1 rounded-md text-xs font-semibold"
              style={{ background: 'rgba(0,0,0,0.7)', color: '#94a3b8', backdropFilter: 'blur(4px)' }}
            >
              <Shield size={11} />
              Sandboxed Preview
            </div>

            {/* Open URL button */}
            {payloadUrl && (
              <div className="absolute top-2 right-2">
                <a
                  href={payloadUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-semibold transition-colors hover:bg-white/10"
                  style={{ background: 'rgba(0,0,0,0.7)', color: '#94a3b8', backdropFilter: 'blur(4px)' }}
                  onClick={(e) => { if (status === 'MALICIOUS') e.preventDefault(); }}
                >
                  <ExternalLink size={11} />
                  {status === 'MALICIOUS' ? 'Blocked' : 'Open'}
                </a>
              </div>
            )}
          </motion.div>
        ) : (
          <motion.div
            key="placeholder"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="flex flex-col items-center justify-center gap-3 rounded-xl py-8"
            style={{ border: '1px dashed rgba(255,255,255,0.08)', background: 'rgba(13,27,46,0.3)' }}
          >
            <ShieldAlert size={28} className="text-slate-600" />
            <div className="text-center">
              <p className="text-slate-500 text-sm font-medium">Secure Preview Unavailable</p>
              <p className="text-slate-600 text-xs mt-1">Screenshot capture failed or not applicable</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
