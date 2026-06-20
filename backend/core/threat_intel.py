import os
import sqlite3
import time
import requests
import urllib.parse
from typing import Dict, Any
from core.historical_threats import log_historical_threat

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'threat_intel.db')

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    return conn

def _init_db(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reputation_cache (
            url TEXT PRIMARY KEY,
            status TEXT,
            confidence INTEGER,
            source TEXT,
            timestamp REAL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feed_metadata (
            feed_name TEXT PRIMARY KEY,
            last_updated REAL
        )
    ''')
    conn.commit()

def _get_cached_reputation(url: str, max_age_seconds: int = 86400) -> Dict[str, Any]:
    conn = _get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reputation_cache WHERE url = ?", (url,))
    row = cursor.fetchone()
    conn.close()

    if row:
        if time.time() - row['timestamp'] < max_age_seconds:
            return {
                "triggered": row['status'] == 'MALICIOUS',
                "status": row['status'],
                "confidence": row['confidence'],
                "source": row['source'],
                "cached": True
            }
        else:
            # Clean up old cache
            conn = _get_db()
            conn.cursor().execute("DELETE FROM reputation_cache WHERE url = ?", (url,))
            conn.commit()
            conn.close()
    return None

def _set_cached_reputation(url: str, status: str, confidence: int, source: str):
    conn = _get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO reputation_cache (url, status, confidence, source, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (url, status, confidence, source, time.time()))
    conn.commit()
    conn.close()

def _check_urlhaus(url: str) -> Dict[str, Any]:
    """Check URLHaus API for malicious URL."""
    try:
        response = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('query_status') == 'ok':
                return {
                    "triggered": True,
                    "status": "MALICIOUS",
                    "confidence": 95,
                    "source": "URLHaus"
                }
    except Exception:
        pass
    return None

def _check_openphish(url: str) -> Dict[str, Any]:
    """Check OpenPhish active feed. For performance, we download and cache it."""
    # To keep the query fast, we maintain a background fetch or fetch on demand if expired
    conn = _get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT last_updated FROM feed_metadata WHERE feed_name = 'openphish'")
    row = cursor.fetchone()
    
    # Update feed every 1 hour
    if not row or (time.time() - row['last_updated'] > 3600):
        try:
            resp = requests.get("https://openphish.com/feed.txt", timeout=10)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                # Bulk insert into cache
                cursor.execute("DELETE FROM reputation_cache WHERE source = 'OpenPhish'")
                now = time.time()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        cursor.execute('''
                            INSERT OR REPLACE INTO reputation_cache (url, status, confidence, source, timestamp)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (line, 'MALICIOUS', 90, 'OpenPhish', now))
                cursor.execute('''
                    INSERT OR REPLACE INTO feed_metadata (feed_name, last_updated)
                    VALUES (?, ?)
                ''', ('openphish', now))
                conn.commit()
        except Exception as e:
            print(f"[Threat Intel] Failed to update OpenPhish feed: {e}")
            pass
    
    conn.close()
    
    # Check cache for openphish
    return _get_cached_reputation(url) # This will check if we just inserted it

def check_threat_intel(url: str) -> Dict[str, Any]:
    """
    Check URL against multiple threat intelligence feeds.
    Returns:
        dict: {
            "score": int (0-100),
            "status": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
            "confidence": int (0-100),
            "reasons": list[str],
            "details": dict
        }
    """
    # 1. Check local cache first
    cached = _get_cached_reputation(url)
    if cached and cached['triggered']:
        log_historical_threat(url, cached['source'], "MALICIOUS")
        return {
            "score": 100,
            "status": "MALICIOUS",
            "confidence": cached['confidence'],
            "reasons": [f"Known OpenPhish/URLHaus entry ({cached['source']} - Cached)"],
            "details": {"source": cached['source'], "cached": True, "override": True}
        }
    
    # 2. Check URLHaus API live
    urlhaus_result = _check_urlhaus(url)
    if urlhaus_result and urlhaus_result['triggered']:
        _set_cached_reputation(url, "MALICIOUS", urlhaus_result['confidence'], urlhaus_result['source'])
        log_historical_threat(url, urlhaus_result['source'], "MALICIOUS")
        return {
            "score": 100,
            "status": "MALICIOUS",
            "confidence": urlhaus_result['confidence'],
            "reasons": [f"Known OpenPhish/URLHaus entry ({urlhaus_result['source']})"],
            "details": {"source": urlhaus_result['source'], "cached": False, "override": True}
        }
        
    # 3. Check OpenPhish (will sync feed if expired)
    openphish_result = _check_openphish(url)
    if openphish_result and openphish_result['triggered']:
        log_historical_threat(url, openphish_result['source'], "MALICIOUS")
        return {
            "score": 100,
            "status": "MALICIOUS",
            "confidence": openphish_result['confidence'],
            "reasons": [f"Known OpenPhish/URLHaus entry ({openphish_result['source']})"],
            "details": {"source": openphish_result['source'], "cached": True, "override": True} # Always cached from feed
        }

    # If no flags
    _set_cached_reputation(url, "SAFE", 90, "ThreatIntel")
    return {
        "score": 0,
        "status": "SAFE",
        "confidence": 90,
        "reasons": [],
        "details": {"source": "ThreatIntel", "cached": False}
    }
