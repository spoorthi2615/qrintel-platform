import os
import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE_DIR))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")

# Ensure we have app context and paths set
from routes.scan import _analyze_payload

def _generate_benign_urls(count=500):
    base_domains = [
        "google.com", "github.com", "microsoft.com", "apple.com", "wikipedia.org",
        "amazon.com", "linkedin.com", "netflix.com", "cloudflare.com", "adobe.com",
        "gov.uk", "gov.in", "harvard.edu", "mit.edu", "stanford.edu", "nasa.gov",
        "bbc.co.uk", "nytimes.com", "wsj.com", "reuters.com", "bloomberg.com",
        "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
        "zoom.us", "slack.com", "salesforce.com", "oracle.com", "ibm.com",
        "aws.amazon.com", "azure.microsoft.com", "cloud.google.com", "digitalocean.com",
        "spotify.com", "twitch.tv", "reddit.com", "stackoverflow.com", "ycombinator.com",
        "mozilla.org", "apache.org", "linux.org", "ubuntu.com", "debian.org",
        "docker.com", "kubernetes.io", "nodejs.org", "python.org", "rust-lang.org", "golang.org"
    ]
    urls = []
    # Generate 500 by appending randomish paths or just using them multiple times 
    # to test latency and caching
    for i in range(count):
        domain = base_domains[i % len(base_domains)]
        if i < len(base_domains):
            urls.append(f"https://{domain}")
        else:
            urls.append(f"https://{domain}/path/to/page_{i}")
    return urls

def process_url(url: str, expected_status: str):
    start_time = time.time()
    try:
        res = _analyze_payload(url, scan_method='eval')
        latency = time.time() - start_time
        return {
            "url": url,
            "status": res.get("status", "SAFE"),
            "confidence": res.get("confidence", 0),
            "expected": expected_status,
            "latency": latency,
            "reasons": res.get("final_reasons", []),
            "error": None
        }
    except Exception as e:
        return {
            "url": url,
            "status": "ERROR",
            "confidence": 0,
            "expected": expected_status,
            "latency": time.time() - start_time,
            "reasons": [],
            "error": str(e)
        }

def run_evaluation() -> dict:
    print("[QRIntel Benchmark] Running REAL evaluation suite concurrently...")
    
    # Load Phishing
    phishing_path = os.path.join(DATASETS_DIR, 'phishing_qr', 'metadata.json')
    phishing_samples = []
    if os.path.exists(phishing_path):
        with open(phishing_path, 'r') as f:
            phishing_data = json.load(f)
        phishing_samples = [item['payload'] for item in phishing_data.get('samples', [])]
    
    # Cap at 500
    phishing_samples = phishing_samples[:500]
    benign_urls = _generate_benign_urls(500)
    
    print(f"Loaded {len(phishing_samples)} Phishing URLs and {len(benign_urls)} Benign URLs.")
    
    tasks = []
    for u in phishing_samples:
        tasks.append((u, "MALICIOUS"))
    for u in benign_urls:
        tasks.append((u, "SAFE"))
        
    results = []
    
    start_eval_time = time.time()
    
    # Use ThreadPoolExecutor to run 50 requests concurrently
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(process_url, task[0], task[1]): task for task in tasks}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                print(f"Processed {completed}/{len(tasks)} URLs...")
            results.append(future.result())

    total_time = time.time() - start_eval_time
    print(f"\nEvaluation completed in {total_time:.2f} seconds.")

    tp, fp, tn, fn = 0, 0, 0, 0
    errors = 0
    total_latency = 0
    
    false_positives_log = []
    false_negatives_log = []

    for r in results:
        total_latency += r["latency"]
        if r["status"] == "ERROR":
            errors += 1
            if r["expected"] == "MALICIOUS":
                fn += 1
                false_negatives_log.append(r)
            else:
                tn += 1 # If it errored on benign, we didn't flag it, so it's a TN practically, though technically an error
            continue

        if r["expected"] == "MALICIOUS":
            if r["status"] in ["MALICIOUS", "SUSPICIOUS"]:
                tp += 1
            else:
                fn += 1
                false_negatives_log.append(r)
        else:
            if r["status"] in ["MALICIOUS", "SUSPICIOUS"]:
                fp += 1
                false_positives_log.append(r)
            else:
                tn += 1

    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    avg_latency = (total_latency / len(results)) * 1000 if results else 0

    metrics = {
        "core_detection": {
            "accuracy": round(accuracy, 3),
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1, 3),
            "fpr": round(fpr, 3),
            "fnr": round(fnr, 3),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "errors": errors
        },
        "performance": {
            "avg_detection_latency_ms": round(avg_latency, 1),
            "total_samples_evaluated": len(results),
            "total_evaluation_time_sec": round(total_time, 1)
        },
        "logs": {
            "false_positives": false_positives_log,
            "false_negatives": false_negatives_log
        }
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(os.path.join(RESULTS_DIR, "real_evaluation_results.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("\n=== EVALUATION COMPLETE ===")
    print(f"Accuracy:  {accuracy:.1%}")
    print(f"Precision: {precision:.1%}")
    print(f"Recall:    {recall:.1%}")
    print(f"F1 Score:  {f1:.1%}")
    print(f"FPR:       {fpr:.1%}")
    print(f"FNR:       {fnr:.1%}")
    print(f"Errors:    {errors}")
    print("===========================\n")

    return metrics

if __name__ == "__main__":
    run_evaluation()
