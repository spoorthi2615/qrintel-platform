"""
brand_detection.py
Detects brand impersonation in HTML content.
"""

from bs4 import BeautifulSoup
import re

TARGET_BRANDS = [
    'microsoft', 'google', 'paypal', 'amazon', 'apple', 'netflix',
    'chase', 'wellsfargo', 'github', 'roblox', 'steam', 'meta', 'facebook'
]

def analyze_brand(html_content: str) -> dict:
    """
    Scan HTML content for mentions of target brands in prominent elements.
    """
    result = {
        "brand": None,
        "confidence": 0,
        "score": 0,
        "reasons": [],
        "breakdown": {}
    }
    
    if not html_content:
        return result

    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Text from prominent tags
    title = soup.title.string.lower() if soup.title and soup.title.string else ""
    headers = " ".join([h.get_text(strip=True).lower() for h in soup.find_all(['h1', 'h2', 'h3'])])
    buttons = " ".join([b.get_text(strip=True).lower() for b in soup.find_all('button')])
    
    # We can also check all text but we want high confidence
    
    brand_scores = {}
    
    for brand in TARGET_BRANDS:
        confidence = 0
        
        # Exact word match to avoid substring false positives (e.g., 'steam' inside 'steaming')
        # We will use \b for word boundaries. But let's keep it simple first
        brand_pattern = re.compile(rf'\b{re.escape(brand)}\b', re.IGNORECASE)
        
        if brand_pattern.search(title):
            confidence += 40
        
        if brand_pattern.search(headers):
            confidence += 30
            
        if brand_pattern.search(buttons):
            confidence += 20
            
        if confidence > 0:
            brand_scores[brand] = confidence

    if brand_scores:
        # Get highest scoring brand
        top_brand = max(brand_scores.items(), key=lambda x: x[1])
        result["brand"] = top_brand[0]
        result["confidence"] = min(top_brand[1], 100)
        
        # Scoring logic: if confidence > 30, it's a solid brand mention
        if result["confidence"] >= 30:
            result["score"] += 10
            result["reasons"].append(f"Target brand detected in content: {result['brand'].capitalize()}")
            result["breakdown"]["Brand Detection"] = 10
            
    return result
