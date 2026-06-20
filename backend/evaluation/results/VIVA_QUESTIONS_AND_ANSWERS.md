# QRIntel 2.3 Viva Q&amp;A Sheet

### Q1: How does the threat forecasting model predict campaign mutations?
**A**: It calculates a composite evolution risk index based on growth velocity, structural mutation rate (using Jaccard similarity distance over campaign TTPs), and degree centrality expansion in the behavioral trust graph.

### Q2: What is the novelty contribution of QRIntel compared to standard QR scanners?
**A**: Traditional tools perform only static signature detection. QRIntel introduces a unified pipeline that links detection with graph-level risk propagation, campaign attribution, and threat forecasting.

### Q3: Why did you use synthetic data for QR tampering and campaign forecasting?
**A**: Public threat databases do not index physical sticker-over-sticker attacks or campaign evolution lineages. Synthesizing these allows testing the correct performance limits of the OpenCV and attribution algorithms.
