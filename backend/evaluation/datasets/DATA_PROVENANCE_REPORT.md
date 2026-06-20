# DATA_PROVENANCE_REPORT

## 1. Phishing Dataset Metrics
- **Total Phishing URLs Collected**: 500
- **Source Breakdown**:
  - `PhishDatabase (PhishTank/OpenPhish Feed)`: 500 URLs
- **Collection Dates**: 2026-06-19
- **Duplicate Removal Statistics**: 0 duplicates purged.
- **Dataset Quality**: High (real threat targets containing query parameters, obfuscated redirections, and unverified TLDs).

## 2. Dataset Realism Map (Provenance Integrity)
| Category | Data Type | Provenance / Methodology |
|---|---|---|
| **Benign QR** | `REAL_DATA` | Derived from Alexa top domains (government portals, educational portals, universities). |
| **Phishing QR** | `REAL_DATA` | Downloaded from PhishTank & OpenPhish live active link database. |
| **UPI Fraud QR** | `SYNTHETIC_DATA` | Research-created based on real-world refund scams & missing/malformed structures. |
| **QR Tampering** | `SYNTHETIC_DATA` | Generated using OpenCV overlay models (tampered finder zones & edge modifications). |
| **Brand Impersonation** | `SYNTHETIC_DATA` | Derived from real brands (Google, Paytm, SBI) using typosquatted layouts. |
| **Campaign Variants** | `SYNTHETIC_DATA` | Mapped lineages tracking generations 1-4 mutation patterns. |
| **Threat Forecasting** | `SYNTHETIC_DATA` | Simulated campaign evolution to benchmark growth prediction. |
