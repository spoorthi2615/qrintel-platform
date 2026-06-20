# QRIntel Dataset Description

The **QRIntel Dataset** is a high-fidelity threat-intelligence repository built to address the lack of public evaluation corpora for advanced QR security solutions.

## Catalog Summary
| Category | Samples | Ground Truth Variables | Source Matrix |
|---|---|---|---|
| **Benign QR** | 500 | Domain name, verified category, tampering status | Government portals, educational portals, universities |
| **Phishing QR** | 500 | Malicious TLDs, suspicious domain keywords | OpenPhish feed, PhishTank indexes |
| **UPI Fraud QR** | 200 | Amount, VPA, target merchant | Refund campaigns, malformed schemes |
| **QR Tampering** | 200 | Distortion types, edge profiles | Sticker overlay simulations |
| **Brand Impersonation** | 200 | Mapped brand, impersonation flags | Google, Paytm, HDFC spoof sites |
| **Campaign Variants** | 200 | Lineage, generation loops (1-4), TTP signatures | Cross-generational campaign clusters |

---
*Total Sample Volume: 1,800 records.*
