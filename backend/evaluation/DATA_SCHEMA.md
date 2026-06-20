# QRIntel Data Schema Specification

Every sample in the metadata index JSON files follows this schema:

```json
{
  "sample_id": "benign_qr_001",
  "dataset": "QRIntel",
  "category": "benign_qr",
  "payload": "https://gov.in/portal/schemes",
  "label": "SAFE",
  "created_at": "2026-06-19T22:58:15Z",
  "ground_truth": {
    "domain": "gov.in",
    "category": "education_or_gov",
    "is_tampered": false
  },
  "notes": "Generated benchmark record for benign_qr"
}
```

## Key Properties
- `sample_id` (string): Unique identifier matching categories.
- `category` (string): Class labels (`benign_qr`, `phishing_qr`, `upi_fraud_qr`, `tampered_qr`, `impersonation_qr`, `campaign_variants`).
- `payload` (string): The raw decoded QR content.
- `label` (string): Ground truth verdict (`SAFE`, `SUSPICIOUS`, `MALICIOUS`).
- `ground_truth` (object): Specific variables containing impersonation, tampering, or TTP variables.
