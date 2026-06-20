import sqlite3
import json
import os
import sys
import requests
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.url_analyzer import analyze_url

def analyze_fns():
    db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'database', 'historical_threats.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute('SELECT url FROM historical_threats LIMIT 500')
    phishing_urls = [r[0] for r in c.fetchall()]

    fns = []
    
    print("Finding current False Negatives...")
    for url in phishing_urls:
        res = analyze_url(url)
        if res['status'] not in ['MALICIOUS', 'SUSPICIOUS']:
            fns.append(url)

    print(f"Found {len(fns)} FNs.")

    forensics = []
    reasons_tally = {
        "dead_domain": 0,
        "unknown_brand": 0,
        "js_redirect": 0,
        "clean_url": 0
    }

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    for url in fns:
        reason = "clean_url"
        
        # Check if dead domain
        try:
            resp = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
            if resp.status_code >= 400:
                reason = "dead_domain"
            elif resp.status_code in [301, 302, 303, 307, 308]:
                # It's a redirect, check if it's external
                loc = resp.headers.get('Location', '')
                if loc and not loc.startswith('/'):
                    reason = "js_redirect" # Close enough classification for external redirect
        except requests.exceptions.RequestException:
            reason = "dead_domain"
            
        if reason == "clean_url":
            # Heuristic check for unknown brand
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if len(domain.split('.')) > 2 or '-' in domain:
                reason = "unknown_brand"
        
        reasons_tally[reason] += 1
        
        forensics.append({
            "url": url,
            "status": "missed",
            "reason": reason
        })

    md_content = "# False Negative Forensics\n\n"
    md_content += "## Summary\n\n"
    for k, v in reasons_tally.items():
        # Formatting keys to titles (e.g. dead_domain -> Dead Domains)
        title = k.replace('_', ' ').title()
        if title.endswith('s'):
            pass
        elif k == 'dead_domain': title += 's'
        elif k == 'unknown_brand': title += 's'
        elif k == 'js_redirect': title += 's'
        elif k == 'clean_url': title += 's'
            
        md_content += f"{title} .......... {v}\n"
        
    md_content += "\n## Detailed List\n\n```json\n"
    md_content += json.dumps(forensics, indent=2)
    md_content += "\n```\n"

    base_dir = r"C:\Users\SPOORTHI\.gemini\antigravity\brain\e399cbbe-fb7c-4537-8d56-75a9c29e146c"
    with open(os.path.join(base_dir, "FALSE_NEGATIVE_FORENSICS.md"), "w") as f:
        f.write(md_content)

    print("FALSE_NEGATIVE_FORENSICS.md generated.")

if __name__ == "__main__":
    analyze_fns()
