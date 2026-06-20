"""
content_intelligence.py
Fetches and analyzes HTML content for credential harvesting signals.
"""

import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

LOGIN_KEYWORDS = [
    'login', 'sign in', 'verify', 'authenticate', 'confirm',
    'secure account', 'update account', 'password reset',
    'otp', 'one time password', 'one-time password', 'verification code',
    'seed phrase', 'recovery phrase', 'mnemonic', 'secret phrase', 'import wallet',
    'wallet recovery', 'connect wallet', 'verify wallet',
    'credit card', 'card number', 'cvv', 'expiration date', 'billing address',
    'support portal', 'help desk', 'customer service', 'live chat support'
]

def analyze_content(url: str, final_domain: str = None) -> dict:
    """
    Fetch and analyze HTML content for credential harvesting.
    """
    result = {
        "content_available": False,
        "form_count": 0,
        "password_fields": 0,
        "email_fields": 0,
        "hidden_fields": 0,
        "external_actions": 0,
        "login_keywords_found": [],
        "credential_harvesting_confidence": 0,
        "score": 0,
        "reasons": [],
        "breakdown": {},
        "html_content": ""
    }
    
    if not final_domain:
        parsed = urlparse(url)
        final_domain = parsed.netloc.lower()

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        
        # Graceful failure on 403, 404, etc. We'll still try to parse if there's content, 
        # but if it's Cloudflare or heavily blocked, content_available = False
        if response.status_code >= 400:
            return result
            
        html = response.text
        if not html:
            return result
            
        result["html_content"] = html
        result["content_available"] = True
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Forms
        forms = soup.find_all('form')
        result["form_count"] = len(forms)
        
        # Inputs
        inputs = soup.find_all('input')
        for inp in inputs:
            typ = inp.get('type', '').lower()
            if typ == 'password':
                result["password_fields"] += 1
            elif typ == 'email':
                result["email_fields"] += 1
            elif typ == 'hidden':
                result["hidden_fields"] += 1
                
        # External Form Actions
        for form in forms:
            action = form.get('action', '')
            if action and action.startswith('http'):
                action_parsed = urlparse(action)
                if action_parsed.netloc.lower() != final_domain:
                    result["external_actions"] += 1
                    
        # Login Keywords
        page_text = soup.get_text(separator=' ', strip=True).lower()
        for kw in LOGIN_KEYWORDS:
            if kw in page_text:
                result["login_keywords_found"].append(kw)
                
        # Calculate Credential Harvesting Confidence
        conf = 0
        if result["password_fields"] > 0:
            conf += 25
            result["score"] += 25
            result["reasons"].append("Password field detected in DOM")
            result["breakdown"]["Credential Harvesting"] = result["breakdown"].get("Credential Harvesting", 0) + 25
            
            if result["email_fields"] > 0:
                conf += 20
                result["score"] += 20
                result["reasons"].append("Email and Password fields paired")
                result["breakdown"]["Credential Harvesting"] += 20
                
        if result["external_actions"] > 0:
            conf += 25
            result["score"] += 25
            result["reasons"].append("Form POST action targets external domain")
            result["breakdown"]["Credential Harvesting"] = result["breakdown"].get("Credential Harvesting", 0) + 25
            
        if result["hidden_fields"] > 0:
            conf += 10
            # Don't add to score automatically unless we know it's a login page
            if result["password_fields"] > 0:
                result["score"] += 10
                result["reasons"].append("Hidden inputs detected inside credential form")
                result["breakdown"]["Credential Harvesting"] += 10
                
        if len(result["login_keywords_found"]) > 0:
            conf += 10
            
        result["credential_harvesting_confidence"] = min(conf, 100)
        
    except Exception:
        # Timeouts or parsing errors -> graceful failure
        pass
        
    return result
