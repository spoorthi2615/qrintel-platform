import os
import sqlite3

THREATS_DB = os.path.join(os.path.dirname(__file__), '..', 'database', 'historical_threats.db')

def discover_related_threats(url: str, ttp: str = None, brand: str = None, tld: str = None, infra_asn: str = None):
    if not os.path.exists(THREATS_DB):
        return {"related_urls": [], "related_campaigns": [], "relationship_confidence": 0}
        
    conn = sqlite3.connect(THREATS_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    related_campaigns = set()
    related_urls = set()
    points = 0
    
    # 1. Check if URL is in a campaign
    cursor.execute("SELECT campaign_id FROM campaign_members WHERE url=?", (url,))
    for row in cursor.fetchall():
        related_campaigns.add(row["campaign_id"])
        points += 50
        
    # 2. Check for campaigns with similar TTP
    if ttp:
        cursor.execute("SELECT campaign_id FROM campaigns WHERE ttp_fingerprint=?", (ttp,))
        for row in cursor.fetchall():
            related_campaigns.add(row["campaign_id"])
            points += 30
            
    # Load all URLs from these campaigns
    if related_campaigns:
        placeholders = ','.join('?' * len(related_campaigns))
        cursor.execute(f"SELECT url FROM campaign_members WHERE campaign_id IN ({placeholders})", list(related_campaigns))
        for row in cursor.fetchall():
            if row["url"] != url:
                related_urls.add(row["url"])
                
    # 3. Simulate brand/tld/infra matches by looking at recent threats (for demonstration)
    cursor.execute("SELECT url FROM historical_threats ORDER BY first_seen DESC LIMIT 10")
    for row in cursor.fetchall():
        other_url = row["url"]
        if other_url == url: continue
        if brand and brand in other_url:
            related_urls.add(other_url)
            points += 10
        if tld and other_url.endswith(tld):
            related_urls.add(other_url)
            points += 5
            
    conn.close()
    
    confidence = min(100, points)
    
    return {
        "related_urls": list(related_urls)[:20], # Cap at 20 for UI
        "related_campaigns": list(related_campaigns),
        "relationship_confidence": confidence
    }
