# QRIntel Benchmark Reproducibility Guide

Follow these steps to execute and reproduce the evaluation results:

## Quick Start
1. Navigate to the backend directory:
   ```bash
   cd "d:\projects\safe qr\backend"
   ```
2. Run the main evaluation benchmark pipeline:
   ```bash
   python evaluation/scripts/run_benchmark.py
   ```
3. This runs:
   - Module benchmarks (`run_module_benchmark.py`)
   - 10-fold cross-validation metrics (`run_cross_validation.py`)
   - SVGs and HTML compilation (`generate_report.py`)

## Outputs
All outputs are written to the `evaluation/results/` folder:
- **`evaluation_results.json`**: Compiles all metrics (Accuracy, FPR, Recall, stability).
- **`evaluation_results.csv`**: Raw spreadsheet dataset.
- **`cross_validation.json`**: Fold accuracy records.
- **`evaluation_report.html`**: A publication-grade static HTML summary report.
