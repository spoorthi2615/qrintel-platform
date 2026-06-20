import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, Optional

def fetch_html_safely(url: str, timeout: int = 5) -> Optional[str]:
    """Safely fetch HTML content with strict timeouts and safe headers."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if resp.status_code == 200:
            return resp.text
        return None
    except Exception:
        return None

def analyze_content(url: str, html: Optional[str] = None, http_status: Optional[int] = None) -> Dict[str, Any]:
    """
    Analyze HTML content for credential harvesting and phishing indicators.
    Returns:
        dict: {
            "score": int (0-100),
            "status": "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "BOT_BLOCKED" | "DEAD_LINK",
            "confidence": int (0-100),
            "reasons": list[str],
            "details": dict
        }
    """
    if not html:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
            }
            resp = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            html = resp.text
            http_status = resp.status_code
        except requests.exceptions.RequestException as e:
            return {
                "score": 0,
                "status": "DEAD_LINK",
                "confidence": 80,
                "reasons": [f"Connection failed or timed out: {type(e).__name__}"],
                "details": {"error": str(e)}
            }
    
    if not html:
        return {
            "score": 0,
            "status": "DEAD_LINK",
            "confidence": 80,
            "reasons": ["Empty response body"],
            "details": {"error": "Could not fetch HTML content"}
        }

    # Anti-bot detection
    lower_html = html.lower()
    is_bot_blocked = False
    bot_reasons = []

    if http_status in [403, 503]:
        if "cloudflare" in lower_html or "attention required" in lower_html or "cf-browser-verification" in lower_html:
            is_bot_blocked = True
            bot_reasons.append("Cloudflare challenge detected")
        elif "captcha" in lower_html or "recaptcha" in lower_html or "hcaptcha" in lower_html:
            is_bot_blocked = True
            bot_reasons.append("CAPTCHA challenge detected")
        else:
            is_bot_blocked = True
            bot_reasons.append(f"HTTP {http_status} access denied")

    if is_bot_blocked:
        return {
            "score": 0,
            "status": "BOT_BLOCKED",
            "confidence": 90,
            "reasons": bot_reasons,
            "details": {"http_status": http_status}
        }

    soup = BeautifulSoup(html, 'html.parser')
    
    score = 0
    reasons = []
    confidence_points = 0
    
    # Check 1: Forms requesting passwords
    forms = soup.find_all('form')
    has_login_form = False
    password_inputs = soup.find_all('input', {'type': 'password'})
    
    if password_inputs:
        has_login_form = True
        score += 40
        confidence_points += 30
        reasons.append("Contains password input field")
        
    for form in forms:
        action = form.get('action', '')
        # Form posts to external domain or relative empty
        if action.startswith('http') and not action.startswith(url):
            score += 30
            confidence_points += 20
            reasons.append("Form submits data to an external domain")
        elif not action or action == '#' or action == '':
            # Phishing kits often use PHP scripts locally or omit action and use JS
            pass
            
    # Check 2: Hidden elements often used in phishing kits
    hidden_inputs = soup.find_all('input', {'type': 'hidden'})
    phish_kit_markers = ['email', 'login', 'user', 'pass', 'token']
    hidden_matches = sum(1 for inp in hidden_inputs if any(marker in str(inp.get('name', '')).lower() for marker in phish_kit_markers))
    if hidden_matches > 2:
        score += 20
        confidence_points += 15
        reasons.append(f"Suspicious number of hidden credential fields ({hidden_matches})")

    # Check 3: External script inclusion (often used for keylogging or dynamic loading)
    scripts = soup.find_all('script', src=True)
    external_scripts = [s for s in scripts if s['src'].startswith('http') and url not in s['src']]
    if len(external_scripts) > 5:
        score += 15
        confidence_points += 10
        reasons.append("High number of external scripts included")

    # Check 4: Suspicious title terms
    title = soup.title.string.lower() if soup.title and soup.title.string else ""
    suspicious_terms = ['login', 'sign in', 'verify', 'update', 'account', 'secure', 'bank', 'confirm']
    if any(term in title for term in suspicious_terms) and has_login_form:
        score += 15
        confidence_points += 10
        reasons.append("Page title matches credential harvesting patterns")
        
    score = min(score, 100)
    
    if score >= 60:
        status = "MALICIOUS"
        confidence = min(60 + confidence_points, 99)
    elif score >= 30:
        status = "SUSPICIOUS"
        confidence = min(50 + confidence_points, 85)
    else:
        status = "SAFE"
        confidence = 80 # Confident it's safe if it lacks forms

    return {
        "score": score,
        "status": status,
        "confidence": confidence,
        "reasons": reasons,
        "details": {
            "forms_count": len(forms),
            "password_inputs": len(password_inputs),
            "has_login_form": has_login_form
        }
    }
