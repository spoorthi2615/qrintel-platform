import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const STATUS_CONFIG = {
  SAFE:       { color: '#10b981', glow: 'rgba(16,185,129,0.4)',  label: 'SAFE',       bg: 'rgba(16,185,129,0.1)'  },
  SUSPICIOUS: { color: '#f59e0b', glow: 'rgba(245,158,11,0.4)',  label: 'SUSPICIOUS', bg: 'rgba(245,158,11,0.1)'  },
  MALICIOUS:  { color: '#ef4444', glow: 'rgba(239,68,68,0.4)',   label: 'MALICIOUS',  bg: 'rgba(239,68,68,0.1)'   },
};

function useCountUp(target, duration = 1200) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (target === 0) { setCount(0); return; }
    const start  = performance.now();
    const tick   = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.round(eased * target));
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target, duration]);
  return count;
}

// Circular SVG gauge
function Gauge({ score, color, size = 160 }) {
  const r = (size - 20) / 2;
  const circ = 2 * Math.PI * r;
  const pct  = Math.min(score / 100, 1);

  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      {/* Track */}
      <circle cx={size/2} cy={size/2} r={r}
        fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={10} />
      {/* Progress */}
      <motion.circle
        cx={size/2} cy={size/2} r={r}
        fill="none"
        stroke={color}
        strokeWidth={10}
        strokeLinecap="round"
        strokeDasharray={circ}
        initial={{ strokeDashoffset: circ }}
        animate={{ strokeDashoffset: circ * (1 - pct) }}
        transition={{ duration: 1.2, ease: 'easeOut' }}
        style={{ filter: `drop-shadow(0 0 6px ${color})` }}
      />
    </svg>
  );
}

export default function RiskMeter({ score = 0, status = 'SAFE', confidence = 0, breakdown = {} }) {
  const cfg     = STATUS_CONFIG[status] || STATUS_CONFIG.SAFE;
  const display = useCountUp(Math.round(score));
  const confDisplay = useCountUp(Math.round(confidence));

  return (
    <div className="flex flex-col items-center gap-4">
      {/* Circular gauge */}
      <div className="relative" style={{ width: 160, height: 160 }}>
        <Gauge score={score} color={cfg.color} size={160} />
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-black" style={{ color: cfg.color, lineHeight: 1 }}>
            {display}
          </span>
          <span className="text-xs text-slate-500 mt-1">/ 100</span>
        </div>
      </div>

      {/* Status badge */}
      <AnimatePresence mode="wait">
        <motion.div
          key={status}
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.8, opacity: 0 }}
          transition={{ type: 'spring', stiffness: 300 }}
          className="px-5 py-1.5 rounded-full font-bold text-sm tracking-widest"
          style={{
            background: cfg.bg,
            color:      cfg.color,
            border:     `1px solid ${cfg.color}55`,
            boxShadow:  `0 0 16px ${cfg.glow}`,
          }}
        >
          {cfg.label}
        </motion.div>
      </AnimatePresence>

      {/* Confidence */}
      <p className="text-slate-500 text-xs">
        Confidence: <span className="text-slate-300 font-semibold">{confDisplay}%</span>
      </p>

      {/* Breakdown bars */}
      {Object.keys(breakdown).length > 0 && (
        <div className="w-full space-y-2 mt-1">
          {Object.entries(breakdown).map(([key, val]) => (
            <div key={key}>
              <div className="flex justify-between mb-1">
                <span className="text-slate-500 text-xs capitalize">{key}</span>
                <span className="text-slate-400 text-xs font-medium">{val.toFixed(1)}</span>
              </div>
              <div className="h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                <motion.div
                  className="h-full rounded-full"
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.min(val, 100)}%` }}
                  transition={{ duration: 0.8, delay: 0.2 }}
                  style={{ background: cfg.color, opacity: 0.7 }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
