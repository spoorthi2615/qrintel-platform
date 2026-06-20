import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Camera, CameraOff, Zap, AlertTriangle } from 'lucide-react';

export default function LiveScanner({ onScan, isLoading }) {
  const scannerRef = useRef(null);
  const [scannerReady, setScannerReady] = useState(false);
  const [detected, setDetected]         = useState(false);
  const [error, setError]               = useState(null);
  const [started, setStarted]           = useState(false);
  const instanceRef = useRef(null);

  // Start camera
  const startScanner = () => {
    setError(null);
    setStarted(true);
  };

  useEffect(() => {
    if (!started) return;

    let scanner;
    import('html5-qrcode').then(({ Html5QrcodeScanner }) => {
      scanner = new Html5QrcodeScanner(
        'qr-reader',
        {
          fps: 10,
          qrbox: { width: 220, height: 220 },
          aspectRatio: 1.0,
          showTorchButtonIfSupported: true,
          rememberLastUsedCamera: true,
        },
        /* verbose= */ false
      );

      instanceRef.current = scanner;

      scanner.render(
        (decodedText) => {
          // Success
          setDetected(true);
          setTimeout(() => setDetected(false), 2000);
          onScan(decodedText);
        },
        (err) => {
          // Ignore "not found" scanning errors; only show permission errors
          if (typeof err === 'string' && err.includes('permission')) {
            setError('Camera permission denied. Please allow camera access and try again.');
          }
        }
      );

      setScannerReady(true);
    }).catch(() => {
      setError('Failed to load camera scanner. Please refresh and try again.');
    });

    return () => {
      if (instanceRef.current) {
        instanceRef.current.clear().catch(() => {});
        instanceRef.current = null;
      }
    };
  }, [started]); // eslint-disable-line

  const stopScanner = () => {
    if (instanceRef.current) {
      instanceRef.current.clear().catch(() => {});
      instanceRef.current = null;
    }
    setStarted(false);
    setScannerReady(false);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Camera size={18} className="text-blue-400" />
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Live Camera Scanner</h3>
      </div>

      {/* Error state */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="flex items-start gap-3 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm"
          >
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Detection flash */}
      <AnimatePresence>
        {detected && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 text-sm font-semibold"
          >
            <Zap size={15} />
            QR Code Detected — Analyzing…
          </motion.div>
        )}
      </AnimatePresence>

      {/* Camera viewport */}
      {started ? (
        <div className="relative rounded-xl overflow-hidden" style={{ background: '#040b14', border: '1px solid rgba(37,99,235,0.25)' }}>
          {/* Scan overlay */}
          <div className="scan-overlay" />

          {/* Corner brackets */}
          {scannerReady && (
            <>
              <div className="absolute top-4 left-4 w-8 h-8 border-t-2 border-l-2 border-blue-500 rounded-tl z-20 pointer-events-none" />
              <div className="absolute top-4 right-4 w-8 h-8 border-t-2 border-r-2 border-blue-500 rounded-tr z-20 pointer-events-none" />
              <div className="absolute bottom-14 left-4 w-8 h-8 border-b-2 border-l-2 border-blue-500 rounded-bl z-20 pointer-events-none" />
              <div className="absolute bottom-14 right-4 w-8 h-8 border-b-2 border-r-2 border-blue-500 rounded-br z-20 pointer-events-none" />
            </>
          )}

          <div id="qr-reader" className="w-full" />
        </div>
      ) : (
        /* Start prompt */
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex flex-col items-center justify-center gap-4 rounded-xl py-12"
          style={{ border: '1px dashed rgba(37,99,235,0.3)', background: 'rgba(13,27,46,0.4)' }}
        >
          <div className="p-4 rounded-full" style={{ background: 'rgba(37,99,235,0.1)', border: '1px solid rgba(37,99,235,0.25)' }}>
            <Camera size={32} className="text-blue-400" />
          </div>
          <div className="text-center">
            <p className="text-slate-300 font-medium">Camera Ready</p>
            <p className="text-slate-500 text-sm mt-1">Click Start to activate QR detection</p>
          </div>
          <motion.button
            whileHover={{ scale: 1.04 }}
            whileTap={{ scale: 0.97 }}
            onClick={startScanner}
            disabled={isLoading}
            className="px-6 py-2.5 rounded-lg font-semibold text-white text-sm transition-all disabled:opacity-50"
            style={{ background: 'linear-gradient(135deg, #2563eb, #1d4ed8)', boxShadow: '0 0 20px rgba(37,99,235,0.4)' }}
          >
            Start Camera
          </motion.button>
        </motion.div>
      )}

      {/* Stop button */}
      {started && (
        <motion.button
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.97 }}
          onClick={stopScanner}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold text-slate-300 transition-colors"
          style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)' }}
        >
          <CameraOff size={15} />
          Stop Camera
        </motion.button>
      )}

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-blue-400">
          <span className="spinner" />
          Analyzing QR payload…
        </div>
      )}
    </div>
  );
}
