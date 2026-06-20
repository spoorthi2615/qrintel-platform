import dns.resolver
import socket
from urllib.parse import urlparse
import json
import sqlite3
import time
import os

CACHE_DB = os.path.join(os.path.dirname(__file__), '..', 'database', 'dns_cache.db')

def _init_cache():
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS dns_cache (
        domain TEXT PRIMARY KEY,
        data TEXT,
        timestamp REAL
    )''')
    conn.commit()
    return conn

_init_cache().close()

def _get_domain(url: str) -> str:
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.netloc.split(':')[0].lower()

def get_a_records(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [r.to_text() for r in answers]
    except Exception:
        return []

def get_mx_records(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [r.exchange.to_text() for r in answers]
    except Exception:
        return []

def get_ns_records(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [r.target.to_text() for r in answers]
    except Exception:
        # Check root domain if subdomain fails
        parts = domain.split('.')
        if len(parts) > 2:
            root = ".".join(parts[-2:])
            try:
                answers = dns.resolver.resolve(root, 'NS')
                return [r.target.to_text() for r in answers]
            except Exception:
                pass
        return []

def get_asn(ip: str):
    # Stub for ASN lookup (would typically use Cymru IP-to-ASN DNS or ipwhois)
    try:
        # Team Cymru DNS IP-to-ASN
        rev_ip = ".".join(reversed(ip.split(".")))
        query = f"{rev_ip}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(query, 'TXT')
        result = [r.to_text() for r in answers][0]
        # Format: "ASN | IP | CIDR | CC | Registry | Date"
        asn = result.split('|')[0].strip(' "')
        return asn
    except Exception:
        return "UNKNOWN_ASN"

def check_passive_dns(domain: str):
    # Mock/Stub for Passive DNS history framework
    # In a real environment, this queries Farsight, VirusTotal, or RiskIQ.
    return {
        "status": "MOCK_STUB",
        "first_seen_ip": "unknown",
        "historical_ips": [],
        "domain_age_days": "unknown"
    }

def analyze_dns(url: str):
    domain = _get_domain(url)
    if not domain:
        return None
        
    # Check cache first (24 hour TTL = 86400 seconds)
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    try:
        c.execute("SELECT data, timestamp FROM dns_cache WHERE domain = ?", (domain,))
        row = c.fetchone()
        if row:
            data, timestamp = row
            if time.time() - timestamp < 86400:
                conn.close()
                return json.loads(data)
    except Exception:
        pass

    a_records = get_a_records(domain)
    mx_records = get_mx_records(domain)
    ns_records = get_ns_records(domain)
    
    asn = "UNKNOWN_ASN"
    if a_records:
        asn = get_asn(a_records[0])
        
    pdns = check_passive_dns(domain)
    
    risk_score = 0
    reasons = []
    
    # 1. No A records
    if not a_records:
        risk_score += 50
        reasons.append("No resolvable A records found for domain")
        
    # 2. Fast Flux (Many A records)
    if len(a_records) > 4:
        risk_score += 20
        reasons.append("Multiple A records detected (potential Fast-Flux)")
        
    # 3. No MX records (phishing domains often omit MX)
    if not mx_records and a_records:
        risk_score += 15
        reasons.append("No MX records (mail exchange) configured")
        
    # 4. Suspicious Nameservers (Free/cheap DNS providers)
    suspicious_ns = ["freenom", "hostinger", "000webhost", "epizy", "biz.nf"]
    for ns in ns_records:
        if any(s in ns.lower() for s in suspicious_ns):
            risk_score += 30
            reasons.append(f"Suspicious nameserver detected: {ns}")
            break
            
    # 5. ASN Checks
    bulletproof_asns = ["AS208046", "AS49981", "AS206349"] 
    if asn in bulletproof_asns:
        risk_score += 50
        reasons.append(f"IP hosted on known high-risk ASN ({asn})")
        
    result = {
        "domain": domain,
        "a_records": a_records,
        "mx_records": mx_records,
        "nameservers": ns_records,
        "asn": asn,
        "passive_dns": pdns,
        "dns_risk_score": min(100, risk_score),
        "reasons": reasons
    }
    
    # Save to cache
    try:
        c.execute("REPLACE INTO dns_cache (domain, data, timestamp) VALUES (?, ?, ?)", 
                  (domain, json.dumps(result), time.time()))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()
        
    return result
