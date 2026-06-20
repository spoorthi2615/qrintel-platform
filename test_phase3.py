import os
import sys
import sqlite3
import json

sys.path.append(os.path.abspath('backend'))
from core.threat_feed_manager import get_feed_db
from routes.scan import scan_manual

# 1. DB counts
conn = get_feed_db()
cursor = conn.cursor()

print("--- Feed Statistics ---")
cursor.execute("SELECT source, COUNT(*) as count FROM feeds GROUP BY source")
for row in cursor.fetchall():
    print(f"{row['source']}: {row['count']}")
    
# 2. Get a known malicious URL
cursor.execute("SELECT url FROM feeds WHERE source='OpenPhish' LIMIT 1")
openphish_row = cursor.fetchone()
conn.close()

if openphish_row:
    malicious_url = openphish_row['url']
    print(f"\n--- Testing Known Malicious URL: {malicious_url} ---")
    
    # We must patch Flask request context for scan_manual, or just call the core logic
    # Actually, scan_manual relies on Flask request. Let's build a quick mock for the payload.
    from flask import Flask
    app = Flask(__name__)
    with app.test_request_context('/scan/manual', json={'payload': malicious_url}):
        res = scan_manual()
        data = res[0].get_json() if isinstance(res, tuple) else res.get_json()
        print(f"Status: {data['status']}")
        print(f"Score: {data['score']}")
        print(f"Reasons: {data['reasons']}")
        print(f"Threat Intel: {data.get('threat_intel')}")

print("\n--- Testing Known Benign URL: https://example.com ---")
with app.test_request_context('/scan/manual', json={'payload': 'https://example.com'}):
    res = scan_manual()
    data = res[0].get_json() if isinstance(res, tuple) else res.get_json()
    print(f"Status: {data['status']}")
    print(f"Score: {data['score']}")
    print(f"Reasons: {data['reasons']}")
    print(f"Threat Intel: {data.get('threat_intel')}")
