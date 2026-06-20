import os
import sys
import requests
import urllib.parse
from datetime import datetime

# Make sure we can import core components if run standalone
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.threat_feed_manager import get_feed_db, init_feed_db

OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv/"

def extract_domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.split(':')[0]
    except:
        return ""

def _log_sync(conn, source, added, updated, status, error=""):
    conn.execute('''
        INSERT INTO feed_sync_log (source, sync_time, records_added, records_updated, status, error)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (source, datetime.utcnow().isoformat(), added, updated, status, error))
    conn.commit()

def sync_openphish():
    init_feed_db()
    conn = get_feed_db()
    added = 0
    updated = 0
    
    try:
        print("Fetching OpenPhish feed...")
        resp = requests.get(OPENPHISH_URL, timeout=15)
        resp.raise_for_status()
        
        urls = [line.strip() for line in resp.text.split('\n') if line.strip()]
        now_str = datetime.utcnow().isoformat()
        
        cursor = conn.cursor()
        
        for url in urls:
            domain = extract_domain(url)
            cursor.execute("SELECT first_seen FROM feeds WHERE url = ?", (url,))
            row = cursor.fetchone()
            
            if row:
                cursor.execute('''
                    UPDATE feeds SET last_seen = ? WHERE url = ?
                ''', (now_str, url))
                updated += 1
            else:
                cursor.execute('''
                    INSERT INTO feeds (url, domain, source, first_seen, last_seen, confidence)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (url, domain, "OpenPhish", now_str, now_str, 100))
                added += 1
                
        conn.commit()
        _log_sync(conn, "OpenPhish", added, updated, "SUCCESS")
        print(f"OpenPhish Sync Complete: +{added} updated:{updated}")
        
    except Exception as e:
        print(f"OpenPhish Sync Failed: {e}")
        _log_sync(conn, "OpenPhish", 0, 0, "FAILED", str(e))
    finally:
        conn.close()

def sync_urlhaus():
    init_feed_db()
    conn = get_feed_db()
    added = 0
    updated = 0
    
    try:
        print("Fetching URLHaus feed...")
        resp = requests.get(URLHAUS_URL, timeout=15)
        resp.raise_for_status()
        
        lines = resp.text.split('\n')
        now_str = datetime.utcnow().isoformat()
        cursor = conn.cursor()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            parts = line.replace('"', '').split(',')
            if len(parts) > 2:
                url = parts[2]
                domain = extract_domain(url)
                
                cursor.execute("SELECT first_seen FROM feeds WHERE url = ?", (url,))
                row = cursor.fetchone()
                
                if row:
                    cursor.execute('''
                        UPDATE feeds SET last_seen = ? WHERE url = ?
                    ''', (now_str, url))
                    updated += 1
                else:
                    cursor.execute('''
                        INSERT INTO feeds (url, domain, source, first_seen, last_seen, confidence)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (url, domain, "URLHaus", now_str, now_str, 100))
                    added += 1
                    
        conn.commit()
        _log_sync(conn, "URLHaus", added, updated, "SUCCESS")
        print(f"URLHaus Sync Complete: +{added} updated:{updated}")
        
    except Exception as e:
        print(f"URLHaus Sync Failed: {e}")
        _log_sync(conn, "URLHaus", 0, 0, "FAILED", str(e))
    finally:
        conn.close()

def sync_all_feeds():
    sync_openphish()
    sync_urlhaus()

if __name__ == "__main__":
    sync_all_feeds()
