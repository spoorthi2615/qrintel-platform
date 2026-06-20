# SAFEQR_INTEL_DATASET Specifications

## 1. Dataset Categories & Statistics
- **Benign QR**: 500 samples (Real government/educational portals).
- **Phishing QR**: 500 samples (300 downloaded from live OpenPhish feed + 200 real historic patterns).
- **UPI Fraud QR**: 200 samples (Research-created malformed merchant addresses).
- **QR Tampering**: 200 samples (Simulated physical sticker replacements).
- **Brand Impersonation**: 200 samples (Impersonating Google, Paytm, SBI).
- **Campaign Variants**: 200 samples (Simulated tracking loops generations 1-4).

## 2. Collection Methodology & Ground Truth
- Phishing payloads were downloaded from the OpenPhish database and deduplicated.
- Ground truth variables specify brand target domain mapping and tamper indicators.

## 3. Limitations & Ethical Considerations
- Public feeds lack physical QR tampering patterns, requiring synthetic generation for verification. No active credentials were collected.
