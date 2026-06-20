import ssl
import socket
import whois
import urllib.parse
import tldextract
import sqlite3
import json
import os
import time
from datetime import datetime

SUSPICIOUS_REGISTRARS = [
    "namecheap", "freenom", "hostinger", "tucows", "reg.ru", "alibaba", "dnspod", "squarespace"
]

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'infra_cache.db')
TTL_SECONDS = 24 * 60 * 60

def _get_cache_db():
    # Ensure database directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS infra_cache (
            domain TEXT PRIMARY KEY,
            data TEXT,
            timestamp REAL
        )
    ''')
    return conn



def analyze_infrastructure(url: str) -> dict:
    """
    Perform deep infrastructure intelligence extraction.
    - WHOIS (Domain Age, Registrar)
    - SSL Certificate Verification
    - Nameserver Extraction
    """
    result = {
        "domain_age_days": 0,
        "registrar": "Unknown",
        "nameservers": [],
        "ssl_valid": False,
        "ssl_age_days": 0,
        "risk_score": 0,
        "reasons": []
    }
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(':')[0]
    if not domain:
        return result
        
    try:
        conn = _get_cache_db()
        cursor = conn.cursor()
        cursor.execute("SELECT data, timestamp FROM infra_cache WHERE domain = ?", (domain,))
        row = cursor.fetchone()
        
        if row:
            cached_data, timestamp = row
            if time.time() - timestamp < TTL_SECONDS:
                conn.close()
                return json.loads(cached_data)
    except Exception as e:
        print(f"Failed to access infra_cache: {e}")
        conn = None
        
    extracted = tldextract.extract(domain)
    registered_domain = f"{extracted.domain}.{extracted.suffix}"
    
    # 1. SSL Analysis
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["ssl_valid"] = True
                
                # Check cert age
                not_before = cert.get("notBefore")
                if not_before:
                    try:
                        cert_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                        age_days = (datetime.utcnow() - cert_date).days
                        result["ssl_age_days"] = max(0, age_days)
                        if age_days < 30:
                            result["risk_score"] += 15
                            result["reasons"].append(f"Newly issued SSL certificate ({age_days} days old)")
                    except Exception as e:
                        pass
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            result["risk_score"] += 30
            result["reasons"].append("Invalid or self-signed SSL certificate")
        else:
            result["risk_score"] += 10
            result["reasons"].append("No valid SSL configuration (port 443 unreachable)")
            
    # 2. WHOIS Analysis
    try:
        w = whois.whois(registered_domain)
        
        # Registrar
        if w.registrar:
            registrar = str(w.registrar).lower()
            result["registrar"] = w.registrar
            for sr in SUSPICIOUS_REGISTRARS:
                if sr in registrar:
                    result["risk_score"] += 15
                    result["reasons"].append(f"Domain registered with commonly abused registrar ({sr})")
                    break
        
        # Domain Age
        creation_date = w.creation_date
        if type(creation_date) is list:
            creation_date = creation_date[0]
            
        if creation_date:
            try:
                # remove timezone info if present
                if hasattr(creation_date, "replace"):
                    creation_date = creation_date.replace(tzinfo=None)
                age_days = (datetime.now() - creation_date).days
                result["domain_age_days"] = max(0, age_days)
                if age_days < 14:
                    result["risk_score"] += 50
                    result["reasons"].append(f"Newly registered domain ({age_days} days old)")
                elif age_days < 90:
                    result["risk_score"] += 20
                    result["reasons"].append(f"Recently registered domain ({age_days} days old)")
            except Exception as e:
                pass
                
        # Nameservers
        if w.name_servers:
            ns_list = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
            result["nameservers"] = [ns.lower() for ns in ns_list]

    except Exception as e:
        result["risk_score"] += 20
        result["reasons"].append("Failed to resolve WHOIS or domain is hidden")

    # Cap risk score
    result["risk_score"] = min(result["risk_score"], 100)
    
    if conn:
        try:
            cursor.execute('''
                INSERT INTO infra_cache (domain, data, timestamp)
                VALUES (?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    data=excluded.data,
                    timestamp=excluded.timestamp
            ''', (domain, json.dumps(result), time.time()))
            conn.commit()
        except Exception as e:
            print(f"Failed to write to infra_cache: {e}")
        finally:
            conn.close()
    
    return result
