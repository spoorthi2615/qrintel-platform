# QRIntel: Threat Intelligence Dataset & Reproducible Evaluation Suite

This package contains the **QRIntel Dataset** and the complete benchmarking scripts to validate detection, physical tampering, visual phishing, behavioral trust graphs, campaign attribution, and threat forecasting metrics.

## Package Manifest
- `datasets/`: Category indexes and metadata logs for 1,800 total samples.
  - `benign_qr/`: Legitimate domains, government websites, and banking ports.
  - `phishing_qr/`: OpenPhish & PhishTank-derived malicious URLs.
  - `upi_fraud_qr/`: UPI-specific cashback fraud and malformed VPA structures.
  - `tampered_qr/`: Pixel-altered finder patterns and overlays.
  - `impersonation_qr/`: Spoofed Google, Microsoft, SBI, and Paytm landing pages.
  - `campaign_variants/`: Multi-generation campaign iterations and mutations.
- `scripts/`: Benchmark engines.
  - `run_benchmark.py`: Runs core validation metrics.
  - `run_cross_validation.py`: Implements a 10-fold cross validation.
  - `run_module_benchmark.py`: Assesses individual module accuracies.
  - `generate_report.py`: Compiles SVG charts and HTML results.
- `results/`: Research matrices, accuracy spreadsheets, and latency curves.
