# Comparative Evaluation Report

| Version | Accuracy | Precision | Recall | F1 Score |
| ------- | -------- | --------- | ------ | -------- |
| **QRIntel 3.0** (Synthetic) | 96.0% | 97.0% | 95.0% | 96.0% |
| **QRIntel 3.1** (Live)      | 39.7% | 100.0% | 30.0% | 46.2% |
| **QRIntel 3.2** (Live)      | 79.9% | 99.7% | 60.0% | 74.9% |

## Analysis
The transition from 3.1 to 3.2 demonstrates the impact of overriding heuristics with direct threat intelligence hits. By allowing known malicious domains to bypass conservative scoring engines, we significantly increased recall. The precision remained high because the OpenPhish and URLHaus feeds are heavily curated.
