import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.threat_feed_manager import get_feed_db
from core.historical_threats import log_historical_threat

def lookup_threat(url: str, domain: str) -> dict:
    result = {
        "found": False,
        "source": None,
        "confidence": 0,
        "first_seen": None,
        "last_seen": None
    }
    
    try:
        conn = get_feed_db()
        cursor = conn.cursor()
        
        # Exact URL match first
        cursor.execute("SELECT source, confidence, first_seen, last_seen FROM feeds WHERE url = ?", (url,))
        row = cursor.fetchone()
        
        if not row:
            # Domain level match
            cursor.execute("SELECT source, confidence, first_seen, last_seen FROM feeds WHERE domain = ? LIMIT 1", (domain,))
            row = cursor.fetchone()
            
        if row:
            result.update({
                "found": True,
                "source": row["source"],
                "confidence": row["confidence"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"]
            })
            
            # Enrich historical threats DB on a feed hit (Step 8)
            try:
                log_historical_threat(
                    url=url,
                    feed_source=row["source"],
                    reputation="MALICIOUS"
                )
            except Exception as e:
                print(f"Historical Threat Enrichment Error: {e}")
            
    except Exception as e:
        print(f"Threat Lookup Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
            
    return result
