# SafeQR 2.0 — QR Security Intelligence Platform

## Overview

SafeQR 2.0 is a production-quality QR code security scanning platform that detects phishing, malicious URLs, fake UPI payment strings, and tampered QR codes in real-time using a weighted multi-factor risk engine.

## Tech Stack

- **Frontend**: React + Vite + Tailwind CSS + Framer Motion + Recharts
- **Backend**: Python Flask
- **QR Decoding**: OpenCV QRCodeDetector (multi-strategy fallback)
- **Security Analysis**: Shannon Entropy + Heuristics + Weighted Risk Engine
- **Cryptography**: RSA / Ed25519 / AES-GCM / XChaCha20-Poly1305
- **Preview Engine**: Selenium Headless Chrome
- **Database**: SQLite

## Project Structure

```
safeqr/
├── backend/
│   ├── app.py                    # Flask entry point
│   ├── requirements.txt
│   ├── core/
│   │   ├── qr_decoder.py         # OpenCV multi-strategy QR decoding
│   │   ├── payload_classifier.py # Detect URL/UPI/WiFi/vCard/etc
│   │   ├── entropy.py            # Shannon entropy analysis
│   │   ├── heuristics.py         # URL heuristic checks
│   │   ├── url_analyzer.py       # URL intelligence engine
│   │   ├── upi_validator.py      # UPI string validation
│   │   ├── risk_engine.py        # Weighted risk scoring
│   │   ├── signature_verifier.py # RSA / Ed25519 verification
│   │   ├── decryptor.py          # AES-GCM decryption
│   │   └── screenshot.py         # Selenium headless preview
│   ├── routes/
│   │   ├── scan.py               # POST /api/scan/*
│   │   ├── history.py            # GET /api/history, /analytics
│   │   └── crypto.py             # POST /api/verify-signature, /decrypt
│   └── database/
│       └── history.db            # SQLite database (auto-created)
└── frontend/
    ├── src/
    │   ├── pages/Dashboard.jsx   # Main application dashboard
    │   ├── components/
    │   │   ├── LiveScanner.jsx
    │   │   ├── ImageUpload.jsx
    │   │   ├── ManualEntry.jsx
    │   │   ├── ResultPanel.jsx
    │   │   ├── RiskMeter.jsx
    │   │   ├── ScreenshotPreview.jsx
    │   │   └── HistoryTable.jsx
    │   ├── services/api.js
    │   └── index.css
    └── package.json
```

## Setup & Installation

### Prerequisites
- Python 3.9+
- Node.js 18+
- Google Chrome (for Selenium screenshot preview)

### Backend Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

## Running the Application

### Start Backend (Terminal 1)

```bash
cd backend
venv\Scripts\activate
python app.py
```

Backend runs on: http://localhost:5000

### Start Frontend (Terminal 2)

```bash
cd frontend
npm run dev
```

Frontend runs on: http://localhost:5173

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/scan/manual | Scan a manually entered payload |
| POST | /api/scan/upload | Scan a QR code image (OpenCV) |
| POST | /api/scan/live | Scan a live camera payload |
| GET | /api/history | Retrieve scan history |
| GET | /api/analytics | Get aggregate stats + charts |
| DELETE | /api/history/<id> | Delete a scan record |
| POST | /api/verify-signature | Verify digital signature |
| POST | /api/decrypt | Decrypt payload |
| GET | /api/health | Health check |

## Risk Scoring Model

| Factor | Weight |
|--------|--------|
| Entropy Score | 20% |
| URL Heuristics | 40% |
| Domain Intelligence | 20% |
| UPI Validation | 10% |
| Cryptographic Trust | 10% |

| Score | Status |
|-------|--------|
| 0–30 | ✅ SAFE |
| 31–60 | ⚠️ SUSPICIOUS |
| 61–100 | 🚨 MALICIOUS |

## Payload Types Supported

- 🌐 URL (http/https)
- 💸 UPI Payment (`upi://pay`)
- 📧 Email (`mailto:`)
- 📱 SMS
- 📞 Telephone
- 📶 WiFi
- 👤 vCard
- 📍 Geo Location
- 💰 Cryptocurrency Wallet
- 📝 Plain Text
