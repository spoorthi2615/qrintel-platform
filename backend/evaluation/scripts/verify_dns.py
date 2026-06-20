import sys
import os
import json
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.dns_intelligence import analyze_dns

def verify():
    test_domains = [
        "https://google.com",
        "https://github.com",
        "https://login-secure-update-123.xyz", # Suspicious
        "https://nidarosdiskgolf.no" # Known phishing / compromised
    ]
    
    results = {}
    for url in test_domains:
        start = time.time()
        res = analyze_dns(url)
        elapsed = time.time() - start
        
        results[url] = {
            "result": res,
            "latency_ms": round(elapsed * 1000, 2)
        }
        
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    verify()
