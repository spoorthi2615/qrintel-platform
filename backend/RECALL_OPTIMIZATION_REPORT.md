# Recall Optimization Report

## Strategy Implementation
- **Threat Intelligence Priority**: Live threat intel hits now forcefully override downstream analysis, marking domains as `MALICIOUS` instantly.
- **Historical Threat DB**: All synced domains are stored locally in SQLite to prevent network timeouts from causing false negatives.
- **Anti-Bot & Dead Link Detection**: Identifies sites actively blocking programmatic access, preventing them from skewing the scoring algorithm towards "Safe".

## Final Measured Recall: 60.0%
