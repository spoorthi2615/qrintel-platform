import { useRef, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, ImagePlus, X, ScanLine, AlertTriangle } from 'lucide-react';

export default function ImageUpload({ onUpload, isLoading }) {
  const [file, setFile]       = useState(null);
  const [preview, setPreview] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError]     = useState(null);
  const inputRef = useRef(null);

  const handleFile = useCallback((f) => {
    setError(null);
    if (!f) return;
    if (!f.type.startsWith('image/')) {
      setError('Please select a valid image file (PNG, JPG, WEBP, etc.)');
      return;
    }
    setFile(f);
    const reader = new FileReader();
    reader.onload = (e) => setPreview(e.target.result);
    reader.readAsDataURL(f);
  }, []);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    handleFile(f);
  }, [handleFile]);

  const onDragOver = (e) => { e.preventDefault(); setDragging(true); };
  const onDragLeave = () => setDragging(false);

  const clearFile = () => {
    setFile(null);
    setPreview(null);
    setError(null);
    if (inputRef.current) inputRef.current.value = '';
  };

  const handleUpload = () => {
    if (!file) return;
    const formData = new FormData();
    formData.append('image', file);
    onUpload(formData);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2">
        <ImagePlus size={18} className="text-blue-400" />
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Upload QR Image</h3>
      </div>

      {/* Error */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="flex items-start gap-2 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm"
          >
            <AlertTriangle size={15} className="mt-0.5 shrink-0" />
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Drop zone */}
      <AnimatePresence mode="wait">
        {!preview ? (
          <motion.div
            key="dropzone"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onClick={() => inputRef.current?.click()}
            whileHover={{ scale: 1.01 }}
            className="relative flex flex-col items-center justify-center gap-4 rounded-xl py-12 cursor-pointer transition-all"
            style={{
              border: dragging
                ? '2px dashed #3b82f6'
                : '2px dashed rgba(37,99,235,0.3)',
              background: dragging
                ? 'rgba(37,99,235,0.08)'
                : 'rgba(13,27,46,0.4)',
              boxShadow: dragging ? '0 0 20px rgba(37,99,235,0.2)' : 'none',
            }}
          >
            <motion.div
              animate={dragging ? { scale: 1.15 } : { scale: 1 }}
              transition={{ type: 'spring', stiffness: 300 }}
              className="p-4 rounded-full"
              style={{ background: 'rgba(37,99,235,0.1)', border: '1px solid rgba(37,99,235,0.25)' }}
            >
              <Upload size={28} className="text-blue-400" />
            </motion.div>
            <div className="text-center">
              <p className="text-slate-300 font-medium">
                {dragging ? 'Drop to upload' : 'Drag & drop your QR image'}
              </p>
              <p className="text-slate-500 text-sm mt-1">or click to browse • PNG, JPG, WEBP</p>
            </div>
            <input
              ref={inputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={(e) => handleFile(e.target.files[0])}
            />
          </motion.div>
        ) : (
          <motion.div
            key="preview"
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            className="relative rounded-xl overflow-hidden"
            style={{ border: '1px solid rgba(37,99,235,0.3)' }}
          >
            <img
              src={preview}
              alt="QR preview"
              className="w-full object-contain max-h-52"
              style={{ background: '#040b14' }}
            />
            {/* Remove button */}
            <button
              onClick={clearFile}
              className="absolute top-2 right-2 p-1.5 rounded-full bg-black/70 text-slate-300 hover:text-red-400 hover:bg-red-500/20 transition-colors"
            >
              <X size={14} />
            </button>
            {/* File name */}
            <div className="px-3 py-2 bg-cyber-900/80 border-t border-white/5">
              <p className="text-slate-400 text-xs truncate">{file?.name}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Analyze button */}
      <motion.button
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.97 }}
        onClick={handleUpload}
        disabled={!file || isLoading}
        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold text-white text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed"
        style={{
          background: 'linear-gradient(135deg, #2563eb, #7c3aed)',
          boxShadow: file && !isLoading ? '0 0 20px rgba(37,99,235,0.35)' : 'none',
        }}
      >
        {isLoading ? (
          <>
            <span className="spinner" />
            Analyzing with OpenCV…
          </>
        ) : (
          <>
            <ScanLine size={16} />
            Analyze with OpenCV
          </>
        )}
      </motion.button>
    </div>
  );
}
