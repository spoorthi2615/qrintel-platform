"""
risk_engine.py
Weighted multi-factor risk scoring engine.
"""

def _estimate_confidence(score: float, reasons: list) -> float:
    base = 50.0
    reason_boost = min(len(reasons) * 8, 40)
    extremity_boost = abs(score - 50) * 0.2
    confidence = min(base + reason_boost + extremity_boost, 99.0)
    return round(confidence, 1)

def calculate_risk(
    payload: str,
    payload_type: str,
    analysis_results: dict
) -> tuple[float, str, float, dict, list]:
    """
    Dynamically weight risk based on content availability.
    """
    if payload_type != 'URL':
        # Existing logic for non-URL payloads
        score = analysis_results.get('score', 0)
        reasons = analysis_results.get('reasons', [])
        breakdown = analysis_results.get('breakdown', {})
        if score <= 30:
            status = 'SAFE'
        elif score <= 60:
            status = 'SUSPICIOUS'
        else:
            status = 'MALICIOUS'
        conf = _estimate_confidence(score, reasons)
        return {
            'score': score,
            'status': status,
            'confidence': conf,
            'breakdown': breakdown,
            'final_reasons': reasons
        }

    # Combine all pieces for URL
    heuristics = analysis_results.get('url', {})
    redirect_intel = analysis_results.get('redirect_intel', {})
    content_intel = analysis_results.get('content_intel', {})
    brand_intel = analysis_results.get('brand_intel', {})
    threat_intel = analysis_results.get('threat_intel', {})
    visual_intel = analysis_results.get('visual_intel', {})
    infra_intel = analysis_results.get('infra', {})
    dns_intel = analysis_results.get('dns_intel', {})

    # STEP 5: Immediate Override for Threat Intelligence
    if threat_intel and threat_intel.get('found'):
        source = threat_intel.get('source', 'Threat Feed')
        return {
            'score': 100,
            'status': 'MALICIOUS',
            'confidence': 99.0,
            'breakdown': {
                "Threat Intelligence": 100
            },
            'final_reasons': [
                "Known malicious URL",
                f"Source: {source}"
            ]
        }

    # Start with raw points from all modules
    total_score = 0
    final_reasons = []
    final_breakdown = {}

    def _merge(res):
        nonlocal total_score
        if not res: return
        total_score += res.get('score', 0)
        final_reasons.extend(res.get('reasons', []))
        for k, v in res.get('breakdown', {}).items():
            final_breakdown[k] = final_breakdown.get(k, 0) + v

    _merge(heuristics)
    _merge(redirect_intel)
    _merge(content_intel)
    
    # brand_intel uses "risk_score" rather than "score"
    if brand_intel and brand_intel.get('risk_score', 0) > 0:
        total_score += brand_intel['risk_score']
        final_reasons.extend(brand_intel.get('reasons', []))
        final_breakdown["Brand Intelligence"] = brand_intel['risk_score']
        
        # Override: multiple techniques force MALICIOUS
        if len(brand_intel.get('techniques', [])) > 1:
            return {
                'score': 100,
                'status': 'MALICIOUS',
                'confidence': 99.0,
                'breakdown': {
                    "Brand Intelligence": brand_intel['risk_score']
                },
                'final_reasons': brand_intel.get('reasons', [])
            }
    # infra_intel uses "risk_score" rather than "score"
    if infra_intel and infra_intel.get('risk_score', 0) > 0:
        total_score += infra_intel['risk_score']
        final_reasons.extend(infra_intel.get('reasons', []))
        final_breakdown["Infrastructure Intelligence"] = infra_intel['risk_score']
        
    if dns_intel and dns_intel.get('dns_risk_score', 0) > 0:
        total_score += dns_intel['dns_risk_score']
        final_reasons.extend(dns_intel.get('reasons', []))
        final_breakdown["DNS Intelligence"] = dns_intel['dns_risk_score']

    # Wait, the user asked for specific percentages:
    # URL Heuristics ............ 25%
    # Threat Intelligence ....... 20%
    # Redirect Intelligence ..... 10%
    # Content Intelligence ...... 25%
    # Brand Detection ........... 15%
    # Infrastructure ............. 5%
    # But then they also said:
    # "When content unavailable: Redistribute weights dynamically. Never reduce score because content could not be fetched."
    # The best way to implement "Never reduce score" is to use an additive model or scale the base scores properly.
    # Currently, QRIntel uses an additive point system (e.g. +25 points for password field) and capping at 100.
    # The percentages in the user's prompt (25%, 20%, 10%...) can represent the maximum contribution cap for each category to reach 100,
    # or they can be multipliers.
    # But wait, earlier we built it entirely around `total_score = min(sum(points), 100)`.
    # Let's adjust `total_score` based on the caps:
    
    # Calculate capped category scores:
    cat_scores = {
        'url': min(heuristics.get('score', 0), 100),
        'redirect': min(redirect_intel.get('score', 0), 100),
        'content': min(content_intel.get('score', 0), 100),
        'brand': min(brand_intel.get('risk_score', 0), 100),
        'infra': min(infra_intel.get('risk_score', 0), 100),
        'dns': min(dns_intel.get('dns_risk_score', 0), 100),
        'threat': 0 # threat override is handled above
    }
    
    has_content = content_intel.get('content_available', False)
    
    if has_content:
        weights = {
            'url': 0.25,
            'redirect': 0.10,
            'content': 0.25,
            'brand': 0.15,
            'infra': 0.05,
            'dns': 0.05,
            'threat': 0.15
        }
    else:
        # Redistribute Content (25%) and Brand (15%) = 40%
        # to URL (+20%), Redirect (+10%), Threat (+10%)
        weights = {
            'url': 0.45,
            'redirect': 0.20,
            'content': 0.0,
            'brand': 0.0,
            'infra': 0.05,
            'dns': 0.05,
            'threat': 0.25
        }
        
    weighted_score = sum(cat_scores[k] * weights[k] for k in weights)
    
    # However, since the engine used to just be additive, let's also ensure
    # we don't accidentally lower a highly suspicious URL score.
    # If the raw additive score is higher than the weighted one, we use the higher one,
    # ensuring we never regress on Recall.
    additive_score = total_score
    
    final_score = round(min(max(weighted_score, additive_score * 1.0), 100), 1)

    if final_score <= 30:
        status = 'SAFE'
    elif final_score <= 60:
        status = 'SUSPICIOUS'
    else:
        status = 'MALICIOUS'

    # --- Visual Intelligence Override ---
    visual_sim = visual_intel.get('final_similarity', 0)
    target_brand = visual_intel.get('target_brand')
    
    BRAND_DOMAINS = {
        'github': ['github.com'],
        'microsoft': ['microsoftonline.com', 'microsoft.com', 'live.com'],
        'google': ['google.com'],
        'paypal': ['paypal.com'],
        'amazon': ['amazon.com']
    }
    
    domain_mismatch = False
    if target_brand:
        domain = heuristics.get('domain', '')
        import tldextract
        extracted = tldextract.extract(domain)
        registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        official_domains = BRAND_DOMAINS.get(target_brand.lower(), [])
        if official_domains and registered_domain not in official_domains:
            domain_mismatch = True

    if visual_sim > 85 and domain_mismatch:
        status = 'MALICIOUS'
        final_score = max(final_score, 90)
        final_reasons.append(f"Visual login page impersonation detected ({target_brand})")
        final_breakdown["Visual Intelligence"] = 100

    conf = _estimate_confidence(final_score, final_reasons)
    
    return {
        'score': final_score,
        'status': status,
        'confidence': conf,
        'breakdown': final_breakdown,
        'final_reasons': final_reasons
    }
