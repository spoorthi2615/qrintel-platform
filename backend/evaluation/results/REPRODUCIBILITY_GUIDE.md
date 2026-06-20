# QRIntel 2.3 Reproducibility Guide

## 1. Environment Setup
Verify that python and virtual environments are ready:
```bash
pip install -r requirements.txt
```

## 2. Ingesting Real-World Data
To fetch live phishing links:
```bash
python evaluation/scripts/ingest_real_phishing.py
```

## 3. Running Benchmark Suite
To compute confusion matrices and generate HTML reports:
```bash
python evaluation/scripts/run_benchmark.py
```
Outputs are stored in `evaluation/results/`.
