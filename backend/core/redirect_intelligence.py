"""
redirect_intelligence.py
Resolves redirect chains and tracks shorteners, hops, and brand mismatches.
"""

import requests
from urllib.parse import urlparse
import tldextract

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'rb.gy', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'spoo.me', 'qrsu.io', 'shorturl.at',
    's-id.co', 'goo.su'
}

TARGET_BRANDS = [
    'microsoft', 'google', 'paypal', 'amazon', 'apple', 'netflix',
    'chase', 'wellsfargo', 'github', 'roblox', 'steam', 'meta', 'facebook'
]

def analyze_redirects(url: str) -> dict:
    """
    Follow redirects up to 10 hops.
    Return redirect chain, depth, final_url, final_domain, and threat scores.
    """
    result = {
        "redirect_chain": [],
        "redirect_depth": 0,
        "final_url": url,
        "final_domain": "",
        "brand_in_redirect": None,
        "brand_domain_mismatch": False,
        "score": 0,
        "reasons": [],
        "breakdown": {}
    }

    try:
        # We use a custom session with max_redirects
        session = requests.Session()
        session.max_redirects = 10
        
        # Use common user agent to avoid basic blocks
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Use stream=True to avoid downloading large bodies just for redirect tracking
        response = session.get(url, headers=headers, allow_redirects=True, stream=True, timeout=5)
        
        chain = [url]
        for r in response.history:
            if r.url not in chain:
                chain.append(r.url)
        if response.url not in chain:
            chain.append(response.url)
            
        result["redirect_chain"] = chain
        result["redirect_depth"] = max(0, len(chain) - 1)
        result["final_url"] = response.url
        
        parsed_final = urlparse(response.url)
        result["final_domain"] = parsed_final.netloc.lower()
        
    except requests.TooManyRedirects:
        result["score"] += 15
        result["reasons"].append("Excessive redirect chain (> 10 hops)")
        result["breakdown"]["Redirect Abuse"] = 15
        parsed = urlparse(url)
        result["final_domain"] = parsed.netloc.lower()
    except requests.RequestException:
        # Timeouts or connection errors
        parsed = urlparse(url)
        result["final_domain"] = parsed.netloc.lower()
        return result

    # Extract final domain root
    ext = tldextract.extract(result["final_domain"])
    final_root = f"{ext.domain}.{ext.suffix}".lower()
    
    # Evaluate Depth
    if result["redirect_depth"] > 3:
        result["score"] += 15
        result["reasons"].append(f"Excessive redirect chain ({result['redirect_depth']} hops)")
        result["breakdown"]["Redirect Abuse"] = 15
        
    # Evaluate Brand Mismatch across the chain
    # Check if a target brand appears in an early URL but final destination is not that brand
    brand_found = None
    
    for hop_url in result["redirect_chain"][:-1]:  # Check all URLs before the final one
        hop_parsed = urlparse(hop_url)
        hop_domain = hop_parsed.netloc.lower()
                
        # Check for brand mentions in the URL string
        for brand in TARGET_BRANDS:
            if brand in hop_url.lower() and brand not in hop_domain:
                brand_found = brand
                break
            # Also if the domain is a shortener and brand is in path
            # or if the brand is spoofed in a subdomain:
            elif brand in hop_domain:
                brand_found = brand
                break
                
    # If a brand was found in the chain, does the final domain match it?
    if brand_found:
        result["brand_in_redirect"] = brand_found
        if brand_found not in final_root:
            result["brand_domain_mismatch"] = True
            result["score"] += 30
            result["reasons"].append(f"Brand mismatch: Redirect contained '{brand_found}' but landed on '{final_root}'")
            result["breakdown"]["Redirect Mismatch"] = 30

    return result
