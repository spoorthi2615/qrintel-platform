import { useState } from 'react';
import { motion } from 'framer-motion';
import { Type, Send, RotateCcw } from 'lucide-react';

const EXAMPLES = [
  'https://example.com',
  'upi://pay?pa=merchant@upi&am=100',
  'https://bit.ly/suspicious-link',
  'WIFI:S:MyNetwork;T:WPA;P:password;;',
  'BEGIN:VCARD\nFN:John Doe\nEND:VCARD',
];

export default function ManualEntry({ onScan, isLoading }) {
  const [value, setValue] = useState('');
  const [focused, setFocused] = useState(false);

  const handleScan = () => {
    const trimmed = value.trim();
    if (!trimmed) return;
    onScan(trimmed);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      handleScan();
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Type size={18} className="text-blue-400" />
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Manual Entry</h3>
      </div>

      {/* Textarea */}
      <div
        className="relative rounded-xl overflow-hidden transition-all duration-200"
        style={{
          border: focused
            ? '1px solid rgba(37,99,235,0.6)'
            : '1px solid rgba(37,99,235,0.2)',
          boxShadow: focused ? '0 0 0 3px rgba(37,99,235,0.1)' : 'none',
          background: 'rgba(13,27,46,0.6)',
        }}
      >
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          onKeyDown={handleKeyDown}
          placeholder="Paste QR payload, URL, UPI string, WiFi config… (Ctrl+Enter to scan)"
          rows={5}
          className="w-full bg-transparent text-slate-200 placeholder-slate-600 text-sm p-4 resize-none outline-none font-mono leading-relaxed"
          style={{ fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}
        />
        {value && (
          <button
            onClick={() => setValue('')}
            className="absolute top-3 right-3 p-1 rounded text-slate-500 hover:text-slate-300 transition-colors"
          >
            <RotateCcw size={13} />
          </button>
        )}
        {/* char count */}
        <div className="px-4 pb-2 text-right">
          <span className="text-slate-600 text-xs">{value.length} chars</span>
        </div>
      </div>

      {/* Example chips */}
      <div>
        <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Quick Examples</p>
        <div className="flex flex-wrap gap-2">
          {EXAMPLES.map((ex) => (
            <motion.button
              key={ex}
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.96 }}
              onClick={() => setValue(ex)}
              className="px-3 py-1 rounded-full text-xs font-medium transition-all truncate max-w-[200px]"
              style={{
                background: 'rgba(37,99,235,0.1)',
                border: '1px solid rgba(37,99,235,0.25)',
                color: '#93c5fd',
              }}
              title={ex}
            >
              {ex.length > 32 ? ex.slice(0, 32) + '…' : ex}
            </motion.button>
          ))}
        </div>
      </div>

      {/* Scan button */}
      <motion.button
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.97 }}
        onClick={handleScan}
        disabled={!value.trim() || isLoading}
        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold text-white text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed"
        style={{
          background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
          boxShadow: value.trim() && !isLoading ? '0 0 20px rgba(37,99,235,0.35)' : 'none',
        }}
      >
        {isLoading ? (
          <>
            <span className="spinner" />
            Scanning…
          </>
        ) : (
          <>
            <Send size={15} />
            Scan Payload
          </>
        )}
      </motion.button>
      <p className="text-slate-600 text-xs text-center">Ctrl+Enter to scan instantly</p>
    </div>
  );
}
