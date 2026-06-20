import os
import sqlite3
import json
import hashlib
import re
from urllib.parse import urlparse
from collections import Counter
from itertools import combinations

# Known brands for feature extraction
TARGET_BRANDS = ["paypal", "microsoft", "amazon", "netflix", "apple", "chase", "wellsfargo", "bankofamerica", "facebook", "instagram", "google", "yahoo", "dhl", "fedex", "usps"]

# Deterministic simulated infrastructure mapping
HOSTING_PROVIDERS = ["Cloudflare", "Amazon AWS", "DigitalOcean", "Namecheap", "HostGator", "GoDaddy", "OVH", "Hetzner", "Linode", "Vultr"]

def get_infrastructure(domain):
    """Deterministic simulation of threat intelligence infrastructure resolution"""
    h = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
    provider = HOSTING_PROVIDERS[h % len(HOSTING_PROVIDERS)]
    asn = f"AS{10000 + (h % 50000)}"
    ip_prefix = f"{(h % 223) + 1}.{(h % 255)}"
    return provider, asn, ip_prefix

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    parts = domain.split('.')
    tld = f".{parts[-1]}" if len(parts) > 1 else ""
    
    # Extract keywords
    raw_words = re.split(r'[^a-z0-9]', domain + path)
    keywords = [w for w in raw_words if len(w) >= 3 and w not in ['com', 'www', 'http', 'https', 'php', 'html']]
    
    # Detect brands
    brands = [b for b in TARGET_BRANDS if b in domain or b in path]
    
    # Infrastructure
    provider, asn, ip_prefix = get_infrastructure(domain)
    
    features = set()
    if tld: features.add(f"tld:{tld}")
    for b in brands: features.add(f"brand:{b}")
    for k in keywords: features.add(f"keyword:{k}")
    features.add(f"asn:{asn}")
    features.add(f"provider:{provider}")
    
    return {
        "url": url,
        "tld": tld,
        "brands": brands,
        "keywords": keywords,
        "provider": provider,
        "asn": asn,
        "ip_prefix": ip_prefix,
        "feature_set": features
    }

def jaccard_similarity(set1, set2):
    if not set1 or not set2:
        return 0.0
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return intersection / union

def run_clustering():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'historical_threats.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("SELECT url, first_seen FROM historical_threats")
    rows = c.fetchall()
    
    print(f"Loaded {len(rows)} URLs for clustering.")
    
    # Extract features
    url_data = []
    for r in rows:
        url_data.append({
            "url": r['url'],
            "first_seen": r['first_seen'],
            "features": extract_features(r['url'])
        })
        
    # Rule-Based Similarity Clustering
    clusters = []
    SIMILARITY_THRESHOLD = 0.25 # Require 25% feature overlap
    
    for item in url_data:
        placed = False
        for cluster in clusters:
            # Compare to cluster centroid/members
            # We use average similarity to all members
            total_sim = 0
            for member in cluster['members']:
                total_sim += jaccard_similarity(item['features']['feature_set'], member['features']['feature_set'])
            avg_sim = total_sim / len(cluster['members'])
            
            if avg_sim >= SIMILARITY_THRESHOLD:
                cluster['members'].append(item)
                placed = True
                break
                
        if not placed:
            clusters.append({
                "id": f"CMP-{hashlib.md5(item['url'].encode()).hexdigest()[:6].upper()}",
                "members": [item]
            })

    print(f"Generated {len(clusters)} distinct clusters.")
    
    # Process clusters and write to DB
    c.execute("DELETE FROM campaigns")
    c.execute("DELETE FROM campaign_members")
    
    for cluster in clusters:
        # Ignore singletons for campaigns
        if len(cluster['members']) < 2:
            continue
            
        m_urls = [m['url'] for m in cluster['members']]
        
        # Compute cluster average similarity (pairwise)
        if len(m_urls) == 2:
            avg_sim = jaccard_similarity(cluster['members'][0]['features']['feature_set'], cluster['members'][1]['features']['feature_set'])
        else:
            sims = []
            for m1, m2 in combinations(cluster['members'], 2):
                sims.append(jaccard_similarity(m1['features']['feature_set'], m2['features']['feature_set']))
            avg_sim = sum(sims) / len(sims) if sims else 0
            
        confidence = min(0.5 + (avg_sim * 1.5), 0.99) # Scale similarity to a confidence score [0.5 - 0.99]
        
        all_brands = []
        all_tlds = []
        all_keywords = []
        all_providers = []
        
        for m in cluster['members']:
            f = m['features']
            all_brands.extend(f['brands'])
            if f['tld']: all_tlds.append(f['tld'])
            all_keywords.extend(f['keywords'])
            all_providers.append(f['provider'])
            
        top_brand = Counter(all_brands).most_common(1)
        top_brand_name = top_brand[0][0].capitalize() if top_brand else None
        
        top_keyword = Counter(all_keywords).most_common(1)
        top_keyword_name = top_keyword[0][0].capitalize() if top_keyword else "Unknown"
        
        top_tlds = [t[0] for t in Counter(all_tlds).most_common(3)]
        top_kws = [k[0] for k in Counter(all_keywords).most_common(5)]
        top_provs = [p[0] for p in Counter(all_providers).most_common(2)]
        
        if top_brand_name:
            name = f"{top_brand_name} Impersonation Operation"
        else:
            name = f"{top_keyword_name} Targeted Campaign"
            
        member_count = len(cluster['members'])
        if member_count >= 10:
            threat_level = "HIGH"
        elif member_count >= 4:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
            
        first_seen = min(m['first_seen'] for m in cluster['members'])
        first_seen_str = __import__('datetime').datetime.utcfromtimestamp(first_seen).isoformat() + "Z"
        
        ttp = {
            "brands": [b[0] for b in Counter(all_brands).most_common(2)],
            "keywords": top_kws,
            "tlds": top_tlds,
            "infrastructure": top_provs
        }
        
        c.execute('''
            INSERT INTO campaigns (campaign_id, name, threat_level, member_count, first_seen, ttp_fingerprint, average_similarity, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cluster['id'], name, threat_level, member_count, first_seen_str, json.dumps(ttp), round(avg_sim, 3), round(confidence, 3)))
        
        for url in m_urls:
            c.execute("INSERT INTO campaign_members (campaign_id, url) VALUES (?, ?)", (cluster['id'], url))
            
    conn.commit()
    conn.close()
    print("Campaigns successfully persisted to database.")

if __name__ == "__main__":
    run_clustering()
