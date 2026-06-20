import os
import json
import urllib.parse
import tldextract
import re

BRANDS_FILE = os.path.join(os.path.dirname(__file__), '..', 'assets', 'brands.json')

# Load canonical brands
with open(BRANDS_FILE, 'r') as f:
    CANONICAL_BRANDS = json.load(f)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def detect_character_substitution(domain_word: str) -> str:
    """Returns the original brand if substitution detected."""
    sub_map = {
        '0': 'o',
        '1': 'i', # or l
        '@': 'a',
        '3': 'e',
        '5': 's',
        '!': 'i'
    }
    
    # Simple direct replacement check
    normalized = ""
    for char in domain_word:
        normalized += sub_map.get(char, char)
        
    for brand in CANONICAL_BRANDS.keys():
        if normalized == brand and domain_word != brand:
            return brand
            
    # Check alternate for '1' -> 'l'
    normalized_l = ""
    for char in domain_word:
        if char == '1':
            normalized_l += 'l'
        else:
            normalized_l += sub_map.get(char, char)
            
    for brand in CANONICAL_BRANDS.keys():
        if normalized_l == brand and domain_word != brand:
            return brand
            
    return None

def detect_homograph(domain: str) -> bool:
    """Returns True if punycode or unicode characters are present."""
    if "xn--" in domain:
        return True
    if not domain.isascii():
        return True
    return False

def analyze_brand_intelligence(url: str) -> dict:
    result = {
        "brand": None,
        "techniques": [],
        "confidence": 0,
        "official_domain": None,
        "risk_score": 0,
        "reasons": []
    }
    
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.split(':')[0].lower()
        if not domain:
            # Handle URLs without scheme
            domain = url.split('/')[0].split(':')[0].lower()
            
        extracted = tldextract.extract(domain)
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain
        
        # 1. Homograph Detection
        if detect_homograph(domain):
            result["techniques"].append("unicode_homograph")
            result["risk_score"] += 60
            result["reasons"].append("Unicode/Punycode homograph attack detected")
            
        # Extract word parts from domain (ignore TLD)
        full_string = f"{subdomain}.{extracted.domain}" if subdomain else extracted.domain
        domain_parts = re.split(r'[^a-zA-Z0-9]', full_string)
        domain_parts = [p for p in domain_parts if p]
        
        detected_brand = None
        official_domain = None
        
        for part in domain_parts:
            # 2. Character Substitution
            sub_brand = detect_character_substitution(part)
            if sub_brand:
                detected_brand = sub_brand
                if "character_substitution" not in result["techniques"]:
                    result["techniques"].append("character_substitution")
                    result["risk_score"] += 35
                    result["reasons"].append(f"Character substitution detected mimicking '{sub_brand}'")
                continue
                
            # 3. Levenshtein Detection
            # Only apply if length >= 4 to avoid short false positives
            if len(part) >= 4:
                for brand in CANONICAL_BRANDS.keys():
                    if part == brand:
                        # Exact match
                        detected_brand = brand
                        break
                    dist = levenshtein_distance(part, brand)
                    if dist > 0 and dist <= 2:
                        # Don't flag if it's just a completely different common word
                        # But for now, strictly follow the rule: distance <= 2
                        detected_brand = brand
                        if "levenshtein_typosquat" not in result["techniques"]:
                            result["techniques"].append("levenshtein_typosquat")
                            result["risk_score"] += 35
                            result["reasons"].append(f"Typosquatting detected (Levenshtein distance {dist} to '{brand}')")
                        break
        
        # 4. Brand Abuse Detection
        # Brand keyword appears in domain but registered domain != official domain
        if not detected_brand:
            for brand in CANONICAL_BRANDS.keys():
                if brand in domain:
                    detected_brand = brand
                    break
                    
        if detected_brand:
            result["brand"] = detected_brand
            official_domains = CANONICAL_BRANDS[detected_brand]
            result["official_domain"] = official_domains[0]
            
            # Check if registered domain is the official domain
            if registered_domain not in official_domains:
                if "brand_abuse" not in result["techniques"]:
                    result["techniques"].append("brand_abuse")
                    result["risk_score"] += 40
                    result["reasons"].append(f"Brand '{detected_brand}' used in non-official domain")
            else:
                # It's the official domain! Clear malicious techniques because it's legit
                result["techniques"] = []
                result["risk_score"] = 0
                result["reasons"] = []
                
        # Calculate Confidence
        if len(result["techniques"]) > 0:
            base_conf = 80
            boost = (len(result["techniques"]) - 1) * 10
            result["confidence"] = min(base_conf + boost, 100)
            
            if len(result["techniques"]) > 1:
                result["reasons"].append("Multiple impersonation techniques used simultaneously")
                
    except Exception as e:
        print(f"Brand Intelligence Error: {e}")
        
    return result
