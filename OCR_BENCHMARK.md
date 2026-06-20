# OCR & Visual Brand Benchmark

**Date:** 2026-06-20
**Module:** `backend/core/ocr_intelligence.py` & `backend/core/logo_detection.py`

## 1. Installation Audit
- **Tesseract Installed:** False
- **Logo Model Exists:** False

## 2. Benchmark Results
Because the underlying dependencies are missing from the host environment, the modules successfully caught the `TesseractNotFoundError` and missing `.pt` weights file, failing gracefully and marking the output as `MOCK/STUB`.

- **OCR Accuracy:** N/A (MOCK/STUB)
- **Extraction Success Rate:** 0% (Engine Unavailable)
- **Runtime:** < 1ms (Fast Fail)
- **False Positives:** 0
- **False Negatives:** 0

## 3. Targeted Evaluation

### Github Login
- **OCR Status:** `MOCK/STUB`
- **Logo Status:** `MOCK/STUB`
- **Latency:** 0.01 ms

### Google Login
- **OCR Status:** `MOCK/STUB`
- **Logo Status:** `MOCK/STUB`
- **Latency:** 0.0 ms

### Microsoft Login
- **OCR Status:** `MOCK/STUB`
- **Logo Status:** `MOCK/STUB`
- **Latency:** 0.0 ms

### Amazon Login
- **OCR Status:** `MOCK/STUB`
- **Logo Status:** `MOCK/STUB`
- **Latency:** 0.0 ms

### Paypal Login
- **OCR Status:** `MOCK/STUB`
- **Logo Status:** `MOCK/STUB`
- **Latency:** 0.0 ms
