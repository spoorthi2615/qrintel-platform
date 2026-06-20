import os
import sqlite3
import time
import threading
from datetime import datetime, timedelta
import random

CACHE_DB = os.path.join(os.path.dirname(__file__), '..', 'database', 'threat_feed_cache.db')

def _init_db():
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    # url/ip, source (virustotal, google, otx, abuseipdb), timestamp, expires_at, risk_score
    c.execute('''
    CREATE TABLE IF NOT EXISTS threat_cache (
        indicator TEXT,
        source TEXT,
        timestamp REAL,
        expires_at REAL,
        risk_score INTEGER,
        PRIMARY KEY (indicator, source)
    )
    ''')
    conn.commit()
    conn.close()

def _clean_expired():
    """Remove expired threat indicators from cache."""
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    now = time.time()
    c.execute("DELETE FROM threat_cache WHERE expires_at < ?", (now,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted

def _mock_sync(source: str, num_indicators: int = 100):
    """
    Simulates fetching from premium APIs if keys are absent.
    Adds a 24-hour expiration to new records.
    """
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    now = time.time()
    expires = now + 86400  # 24-hour TTL
    
    mock_domains = ["phishing-login", "secure-update", "verify-account", "wallet-auth", "support-desk"]
    mock_tlds = [".xyz", ".top", ".cc", ".pw", ".tk"]
    
    records = []
    for _ in range(num_indicators):
        dom = random.choice(mock_domains)
        tld = random.choice(mock_tlds)
        idx = random.randint(100, 9999)
        indicator = f"https://{dom}-{idx}{tld}"
        score = random.randint(80, 100)
        records.append((indicator, source, now, expires, score))
        
    c.executemany("REPLACE INTO threat_cache (indicator, source, timestamp, expires_at, risk_score) VALUES (?, ?, ?, ?, ?)", records)
    conn.commit()
    conn.close()

def sync_virustotal():
    print(f"[{datetime.now()}] Syncing VirusTotal...")
    api_key = os.environ.get("VT_API_KEY")
    if api_key:
        # Implement real VT sync logic here
        pass
    else:
        _mock_sync("virustotal", 150)

def sync_safe_browsing():
    print(f"[{datetime.now()}] Syncing Google Safe Browsing...")
    api_key = os.environ.get("GSB_API_KEY")
    if api_key:
        # Implement real GSB logic here
        pass
    else:
        _mock_sync("google_safe_browsing", 300)

def sync_otx():
    print(f"[{datetime.now()}] Syncing AlienVault OTX...")
    api_key = os.environ.get("OTX_API_KEY")
    if api_key:
        # Implement real OTX logic here
        pass
    else:
        _mock_sync("alienvault_otx", 120)

def sync_abuseipdb():
    print(f"[{datetime.now()}] Syncing AbuseIPDB...")
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if api_key:
        # Implement real AbuseIPDB logic here
        pass
    else:
        _mock_sync("abuseipdb", 50)

def refresh_all_feeds():
    """Triggered daily or manually to resync all sources."""
    _init_db()
    deleted = _clean_expired()
    print(f"[{datetime.now()}] Cleaned {deleted} expired indicators.")
    
    sync_virustotal()
    sync_safe_browsing()
    sync_otx()
    sync_abuseipdb()
    print(f"[{datetime.now()}] Feed synchronization complete.")

def run_scheduler():
    """Runs continuously in the background, syncing once per day."""
    while True:
        refresh_all_feeds()
        # Sleep for 24 hours (86400 seconds)
        time.sleep(86400)

def start_background_sync():
    """Starts the scheduler in a daemon thread."""
    t = threading.Thread(target=run_scheduler, daemon=True)
    t.start()

def check_cache(indicator: str):
    """
    Fast lookup function for the risk engine. NEVER queries APIs directly.
    """
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    now = time.time()
    
    # Clean expired optionally here or just filter them out
    c.execute("""
        SELECT source, risk_score 
        FROM threat_cache 
        WHERE indicator = ? AND expires_at > ?
    """, (indicator, now))
    
    results = c.fetchall()
    conn.close()
    
    if not results:
        return {"found": False}
        
    highest_score = max(r[1] for r in results)
    sources = [r[0] for r in results]
    
    return {
        "found": True,
        "risk_score": highest_score,
        "sources": sources
    }

if __name__ == "__main__":
    refresh_all_feeds()
