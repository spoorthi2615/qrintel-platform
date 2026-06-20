import os
import sys
import json
import concurrent.futures
from urllib.parse import urlparse

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from routes.scan import _analyze_payload

LEGITIMATE_LOGINS = [
    "https://github.com/login",
    "https://www.reddit.com/login",
    "https://login.live.com/",
    "https://www.paypal.com/signin",
    "https://www.netflix.com/login",
    "https://id.atlassian.com/login",
    "https://login.salesforce.com/",
    "https://app.slack.com/",
    "https://www.dropbox.com/login",
    "https://www.spotify.com/us/login/",
    "https://discord.com/login",
    "https://www.twitch.tv/login",
    "https://vimeo.com/log_in",
    "https://trello.com/login",
    "https://www.quora.com/",
    "https://wordpress.com/log-in"
]

BENIGN_URLS = [
    "https://gov.in", "https://nasa.gov", "https://mit.edu", "https://stanford.edu",
    "https://hdfcbank.com", "https://icicibank.com", "https://azure.microsoft.com",
    "https://pages.github.com", "https://netlify.app", "https://vercel.app",
    "https://railway.app", "https://typedream.app", "https://weebly.com",
    "https://carrd.co", "https://framer.website", "https://webflow.io",
    "https://notion.site", "https://about.google", "https://opensource.org",
    "https://en.wikipedia.org"
]

# We will simulate 100 phishing by grabbing from the DB or using known structures
PHISHING_URLS = [
    # Typosquats
    "http://paypaI.com",
    "http://rnicrosoft.com",
    "http://g00gle.com",
    "http://arnazon.com",
    # Free hosts with keywords
    "https://paypal-security-check.netlify.app",
    "https://microsoft-login-verify.vercel.app",
    "https://chase-secure.railway.app",
    # Shorteners (simulating redirect mismatches)
    "https://bit.ly/paypal-secure-auth",
    "https://tinyurl.com/ms-verify",
    # Deep paths
    "http://login.verification.secure.chase.com.update.account.xyz.com",
]

def load_openphish(limit=50):
    try:
        db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'database', 'historical_threats.db')
        import sqlite3
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT url FROM historical_threats LIMIT ?', (limit,))
        urls = [r[0] for r in c.fetchall()]
        conn.close()
        return urls
    except Exception:
        return []

def evaluate_url(url, label):
    try:
        res = _analyze_payload(url, scan_method="benchmark")
        is_malicious = res['status'] == 'MALICIOUS'
        is_suspicious = res['status'] == 'SUSPICIOUS'
        
        # We consider MALICIOUS as positive
        pred_positive = is_malicious
        actual_positive = (label == 'PHISHING')
        
        return {
            "url": url,
            "label": label,
            "pred": "MALICIOUS" if is_malicious else ("SUSPICIOUS" if is_suspicious else "SAFE"),
            "score": res['score'],
            "breakdown": res.get('breakdown', {}),
            "reasons": res.get('reasons', []),
            "content_intel": res.get('content_intel', {}),
            "redirect_intel": res.get('redirect_intel', {})
        }
    except Exception as e:
        return {"url": url, "label": label, "error": str(e)}

def run_benchmark():
    print("Starting Content Detection Benchmark...")
    
    # Compile dataset
    openphish = load_openphish(limit=20)
    phishing = PHISHING_URLS + openphish
    
    dataset = []
    for u in phishing:
        dataset.append((u, 'PHISHING'))
    for u in BENIGN_URLS[:10]:
        dataset.append((u, 'BENIGN'))
    for u in LEGITIMATE_LOGINS[:10]:
        dataset.append((u, 'BENIGN_LOGIN'))
        
    print(f"Total dataset: {len(dataset)} URLs")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(evaluate_url, u, l): (u, l) for u, l in dataset}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            print(f"Progress: {len(results)}/{len(dataset)}", end='\r')
            
    print("\nBenchmark complete. Calculating metrics...")
    
    tp = 0; fp = 0; tn = 0; fn = 0
    fps_list = []
    fns_list = []
    
    for r in results:
        if "error" in r:
            continue
            
        actual = r['label'] in ('PHISHING',)
        pred = r['pred'] == 'MALICIOUS'
        
        if actual and pred: tp += 1
        elif actual and not pred: 
            fn += 1
            fns_list.append(r)
        elif not actual and pred: 
            fp += 1
            fps_list.append(r)
        elif not actual and not pred: 
            tn += 1
            
    recall = tp / (tp + fn) if (tp+fn)>0 else 0
    precision = tp / (tp + fp) if (tp+fp)>0 else 0
    accuracy = (tp + tn) / len([r for r in results if "error" not in r])
    f1 = 2 * (precision * recall) / (precision + recall) if (precision+recall)>0 else 0
    
    print(f"Recall: {recall*100:.1f}%")
    print(f"Precision: {precision*100:.1f}%")
    print(f"Accuracy: {accuracy*100:.1f}%")
    
    with open("benchmark_results.json", "w") as f:
        json.dump({
            "metrics": {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "Recall": recall, "Precision": precision, "Accuracy": accuracy, "F1": f1},
            "fps": fps_list,
            "fns": fns_list
        }, f, indent=2)
        
    print("Saved to benchmark_results.json")

if __name__ == "__main__":
    run_benchmark()
