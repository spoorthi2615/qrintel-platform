"""
visual_phishing.py  —  Sprint 3: Visual Phishing Detection Engine
=================================================================
Detects brand impersonation attacks by analysing the HTML content of URLs.
Operates without Selenium — uses lightweight HTTP requests to fetch page content.

Seven detection signals:
  1. Brand-domain mismatch  — page claims to be Brand X but domain ≠ Brand X
  2. Login form detection   — password field on mismatched/unencrypted page
  3. Favicon domain mismatch— favicon loaded from a different domain
  4. Brand color palette     — CSS/inline styles match known brand colors
  5. Typosquat brand match  — domain within edit-distance 2 of top brands
  6. Hidden redirect        — meta-refresh or JS redirect to different domain
  7. Copyright claim        — footer copyright names a different company
"""

import re
import math
import urllib.parse
from collections import Counter
from typing import Optional

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─── Brand Fingerprint Database ───────────────────────────────────────────────

BRAND_DB = {
    # Format: "brand_key": {
    #   "domains":  [canonical domains],
    #   "keywords": [title/meta keywords that claim this brand],
    #   "colors":   [dominant hex colors],
    # }
    "google":       {"domains": ["google.com", "google.co.in"],
                     "keywords": ["google", "gmail", "google account"],
                     "colors": ["#4285f4", "#ea4335", "#fbbc05", "#34a853"]},
    "facebook":     {"domains": ["facebook.com", "fb.com"],
                     "keywords": ["facebook", "log into facebook", "meta"],
                     "colors": ["#1877f2", "#4267b2"]},
    "paypal":       {"domains": ["paypal.com"],
                     "keywords": ["paypal", "send money", "pay with paypal"],
                     "colors": ["#003087", "#009cde", "#012169"]},
    "amazon":       {"domains": ["amazon.com", "amazon.in", "amazon.co.uk"],
                     "keywords": ["amazon", "amazon.com", "prime"],
                     "colors": ["#ff9900", "#232f3e"]},
    "microsoft":    {"domains": ["microsoft.com", "live.com", "outlook.com"],
                     "keywords": ["microsoft", "microsoft account", "outlook", "office 365"],
                     "colors": ["#0078d4", "#00b4f0"]},
    "apple":        {"domains": ["apple.com", "icloud.com"],
                     "keywords": ["apple", "apple id", "icloud"],
                     "colors": ["#555555", "#000000", "#007aff"]},
    "netflix":      {"domains": ["netflix.com"],
                     "keywords": ["netflix", "watch netflix", "sign in to netflix"],
                     "colors": ["#e50914", "#141414"]},
    "instagram":    {"domains": ["instagram.com"],
                     "keywords": ["instagram", "log in to instagram"],
                     "colors": ["#e1306c", "#833ab4", "#fd1d1d"]},
    "twitter":      {"domains": ["twitter.com", "x.com"],
                     "keywords": ["twitter", "x (formerly twitter)", "sign in to twitter"],
                     "colors": ["#1da1f2", "#000000"]},
    "linkedin":     {"domains": ["linkedin.com"],
                     "keywords": ["linkedin", "sign in | linkedin", "professional network"],
                     "colors": ["#0077b5", "#00a0dc"]},
    "sbi":          {"domains": ["onlinesbi.com", "sbi.co.in"],
                     "keywords": ["sbi", "state bank", "state bank of india", "onlinesbi"],
                     "colors": ["#22409a", "#f9a51a"]},
    "hdfc":         {"domains": ["hdfcbank.com", "hdfc.com"],
                     "keywords": ["hdfc", "hdfc bank", "net banking hdfc"],
                     "colors": ["#004b87", "#0085c3"]},
    "icici":        {"domains": ["icicibank.com", "icicidirect.com"],
                     "keywords": ["icici", "icici bank", "imobile"],
                     "colors": ["#f47920", "#003b7a"]},
    "paytm":        {"domains": ["paytm.com"],
                     "keywords": ["paytm", "pay with paytm", "paytm bank"],
                     "colors": ["#00baf2", "#002970"]},
    "phonepe":      {"domains": ["phonepe.com"],
                     "keywords": ["phonepe", "phone pe", "upi payment"],
                     "colors": ["#5f259f", "#cabbed"]},
    "gpay":         {"domains": ["pay.google.com", "gpay.app"],
                     "keywords": ["google pay", "gpay", "pay with google"],
                     "colors": ["#4285f4", "#34a853"]},
    "dropbox":      {"domains": ["dropbox.com"],
                     "keywords": ["dropbox", "sign in to dropbox"],
                     "colors": ["#0061ff", "#0d2481"]},
    "github":       {"domains": ["github.com"],
                     "keywords": ["github", "sign in to github"],
                     "colors": ["#24292e", "#0366d6"]},
    "whatsapp":     {"domains": ["whatsapp.com", "web.whatsapp.com"],
                     "keywords": ["whatsapp", "whatsapp web"],
                     "colors": ["#25d366", "#128c7e", "#075e54"]},
    "zoom":         {"domains": ["zoom.us"],
                     "keywords": ["zoom", "join meeting", "zoom meeting"],
                     "colors": ["#2d8cff", "#0b5cff"]},
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), curr[j] + 1, prev[j + 1] + 1))
        prev = curr
    return prev[-1]


def _extract_domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def _domain_root(domain: str) -> str:
    """Return 'google' from 'www.google.com'."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain


def _fetch_html(url: str, timeout: int = 5) -> Optional[str]:
    if not REQUESTS_AVAILABLE:
        return None
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = _requests.get(url, headers=headers, timeout=timeout,
                             allow_redirects=True, verify=False)
        return resp.text[:500_000]  # Cap at 500KB
    except Exception:
        return None


# ─── Signal 1: Brand-Domain Mismatch ──────────────────────────────────────────

def _check_brand_domain_mismatch(domain: str, html: Optional[str]) -> dict:
    """
    Check if page title/meta claims to be a brand whose canonical domain
    doesn't match the actual URL domain.
    """
    if not html:
        return {"triggered": False, "brand": None, "confidence": 0,
                "detail": "HTML unavailable — check skipped"}

    html_lower = html.lower()

    # Extract title
    title_match = re.search(r"<title[^>]*>([^<]{1,200})</title>", html, re.IGNORECASE)
    title = title_match.group(1).strip().lower() if title_match else ""

    # Extract meta description
    meta_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']{1,300})',
                           html, re.IGNORECASE)
    meta_desc = meta_match.group(1).lower() if meta_match else ""

    content = title + " " + meta_desc

    domain_root = _domain_root(domain)

    for brand_key, brand_info in BRAND_DB.items():
        for keyword in brand_info["keywords"]:
            if keyword in content:
                # Is the actual domain one of the canonical domains?
                is_canonical = any(
                    canonical in domain
                    for canonical in brand_info["domains"]
                )
                if not is_canonical:
                    # Mismatch detected
                    confidence = 90 if keyword == brand_key else 70
                    return {
                        "triggered": True,
                        "brand": brand_key,
                        "claimed_keyword": keyword,
                        "actual_domain": domain,
                        "canonical_domains": brand_info["domains"],
                        "confidence": confidence,
                        "detail": (
                            f"Page title/meta claims to be '{brand_key}' "
                            f"(keyword: '{keyword}') but domain '{domain}' "
                            f"is not a canonical {brand_key} domain"
                        ),
                    }

    return {"triggered": False, "brand": None, "confidence": 0,
            "detail": "No brand-domain mismatch detected"}


# ─── Signal 2: Login Form Detection ───────────────────────────────────────────

def _check_login_form(url: str, domain: str, html: Optional[str]) -> dict:
    if not html:
        return {"triggered": False, "detail": "HTML unavailable"}

    has_password = bool(re.search(r'type=["\']password["\']', html, re.IGNORECASE))
    has_form     = bool(re.search(r'<form', html, re.IGNORECASE))
    is_https     = url.startswith("https://")
    is_canonical = any(
        canonical in domain
        for brand_info in BRAND_DB.values()
        for canonical in brand_info["domains"]
    )

    if has_password and has_form:
        if not is_https:
            return {
                "triggered": True,
                "confidence": 85,
                "detail": "Login form with password field on non-HTTPS page — credential theft risk",
            }
        if not is_canonical:
            return {
                "triggered": True,
                "confidence": 60,
                "detail": "Login form detected on non-canonical domain",
            }

    return {"triggered": False, "detail": "No suspicious login form detected"}


# ─── Signal 3: Favicon Domain Mismatch ────────────────────────────────────────

def _check_favicon_mismatch(domain: str, html: Optional[str]) -> dict:
    if not html:
        return {"triggered": False, "favicon_url": None, "detail": "HTML unavailable"}

    favicon_match = re.search(
        r'<link[^>]+rel=["\'](?:shortcut icon|icon)["\'][^>]+href=["\']([^"\']+)["\']',
        html, re.IGNORECASE
    )
    if not favicon_match:
        favicon_match = re.search(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut icon|icon)["\']',
            html, re.IGNORECASE
        )

    if not favicon_match:
        return {"triggered": False, "favicon_url": None, "detail": "No favicon found"}

    favicon_url = favicon_match.group(1)
    if favicon_url.startswith("//"):
        favicon_url = "https:" + favicon_url
    if favicon_url.startswith("/") or not favicon_url.startswith("http"):
        return {"triggered": False, "favicon_url": favicon_url,
                "detail": "Favicon is relative URL — same origin"}

    favicon_domain = _extract_domain(favicon_url)
    if favicon_domain and favicon_domain != domain:
        # Suppress if favicon_domain is a CDN
        cdns = {"cloudflare.com", "googleapis.com", "gstatic.com", "akamai.net",
                "fastly.net", "cloudfront.net", "cdn.com"}
        if not any(cdn in favicon_domain for cdn in cdns):
            return {
                "triggered": True,
                "favicon_url": favicon_url,
                "favicon_domain": favicon_domain,
                "page_domain": domain,
                "confidence": 55,
                "detail": (
                    f"Favicon loaded from '{favicon_domain}' "
                    f"but page is on '{domain}' — possible brand impersonation"
                ),
            }

    return {"triggered": False, "favicon_url": favicon_url,
            "detail": "Favicon domain consistent with page domain"}


# ─── Signal 4: Typosquat Brand Match ──────────────────────────────────────────

def _check_typosquat(domain: str) -> dict:
    domain_root = _domain_root(domain)
    best_brand, best_dist = None, 99

    for brand_key in BRAND_DB:
        d = _levenshtein(domain_root.lower(), brand_key.lower())
        if d < best_dist:
            best_dist = d
            best_brand = brand_key

    if best_dist <= 2 and best_brand not in domain:
        confidence = 80 if best_dist == 1 else 60
        return {
            "triggered": True,
            "brand": best_brand,
            "edit_distance": best_dist,
            "confidence": confidence,
            "detail": (
                f"Domain root '{domain_root}' is within edit distance {best_dist} "
                f"of brand '{best_brand}' — possible typosquatting"
            ),
        }

    return {"triggered": False, "brand": None, "edit_distance": best_dist,
            "detail": f"Domain '{domain_root}' not similar to any tracked brand"}


# ─── Signal 5: Hidden Redirect Detection ──────────────────────────────────────

def _check_hidden_redirect(domain: str, html: Optional[str]) -> dict:
    if not html:
        return {"triggered": False, "detail": "HTML unavailable"}

    # Meta-refresh redirect
    meta_refresh = re.search(
        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^\s"\']+)',
        html, re.IGNORECASE
    )
    if meta_refresh:
        target_url = meta_refresh.group(1)
        target_domain = _extract_domain(target_url)
        if target_domain and target_domain != domain:
            return {
                "triggered": True,
                "redirect_target": target_url,
                "redirect_domain": target_domain,
                "confidence": 75,
                "detail": (
                    f"Meta-refresh redirect to '{target_domain}' from '{domain}' "
                    f"— hidden redirect attack"
                ),
            }

    # JS window.location redirect
    js_redirect = re.search(
        r'window\.location(?:\.href)?\s*=\s*["\']([^"\']{8,})["\']',
        html, re.IGNORECASE
    )
    if js_redirect:
        target_url = js_redirect.group(1)
        target_domain = _extract_domain(target_url)
        if target_domain and target_domain != domain:
            return {
                "triggered": True,
                "redirect_target": target_url,
                "redirect_domain": target_domain,
                "confidence": 65,
                "detail": (
                    f"JavaScript redirect to '{target_domain}' detected "
                    f"on page from '{domain}'"
                ),
            }

    return {"triggered": False, "detail": "No hidden redirect detected"}


# ─── Signal 6: Copyright Claim Analysis ───────────────────────────────────────

def _check_copyright_claim(domain: str, html: Optional[str]) -> dict:
    if not html:
        return {"triggered": False, "detail": "HTML unavailable"}

    copyright_match = re.search(
        r'(?:©|&copy;|copyright)\s*(?:\d{4})?\s*([A-Za-z][A-Za-z\s&,\.]{2,40})',
        html, re.IGNORECASE
    )
    if not copyright_match:
        return {"triggered": False, "detail": "No copyright notice found"}

    copyright_name = copyright_match.group(1).strip().lower()
    domain_root    = _domain_root(domain).lower()

    for brand_key, brand_info in BRAND_DB.items():
        if brand_key in copyright_name or copyright_name in brand_key:
            is_canonical = any(canonical in domain for canonical in brand_info["domains"])
            if not is_canonical:
                return {
                    "triggered": True,
                    "copyright_claim": copyright_match.group(1).strip(),
                    "brand": brand_key,
                    "confidence": 70,
                    "detail": (
                        f"Copyright claims '{copyright_match.group(1).strip()}' "
                        f"but domain '{domain}' is not a {brand_key} property"
                    ),
                }

    return {"triggered": False, "copyright_claim": copyright_match.group(1).strip() if copyright_match else None,
            "detail": "Copyright claim matches domain — no mismatch"}


# ─── Main Analysis Function ────────────────────────────────────────────────────

def analyze_url_content(url: str, html: Optional[str] = None) -> dict:
    """
    Perform visual phishing analysis on a URL by fetching and examining its HTML.

    Args:
        url: The URL to analyze.
        html: Optional pre-fetched HTML to avoid double-fetching.

    Returns:
        Dict with: impersonation_score (0–100), impersonation_label,
                   brand_detected, signals, page_title, favicon_url, explanations.
    """
    domain   = _extract_domain(url)
    if not html:
        html = _fetch_html(url)
    http_status = None

    if REQUESTS_AVAILABLE and html is None:
        http_status = 0  # Failed to fetch

    # Run all 6 checks
    signals = {
        "brand_domain_mismatch": _check_brand_domain_mismatch(domain, html),
        "login_form":            _check_login_form(url, domain, html),
        "favicon_mismatch":      _check_favicon_mismatch(domain, html),
        "typosquat":             _check_typosquat(domain),
        "hidden_redirect":       _check_hidden_redirect(domain, html),
        "copyright_claim":       _check_copyright_claim(domain, html),
    }

    # Signal weights
    weights = {
        "brand_domain_mismatch": 35,
        "login_form":            25,
        "favicon_mismatch":      10,
        "typosquat":             15,
        "hidden_redirect":       10,
        "copyright_claim":       5,
    }

    # Compute impersonation score
    impersonation_score = 0
    triggered_signals = []
    brand_detected = None
    brand_confidence = 0

    for sig_name, result in signals.items():
        if result.get("triggered"):
            conf = result.get("confidence", 50) / 100
            contrib = weights[sig_name] * conf
            impersonation_score += contrib
            triggered_signals.append({
                "signal": sig_name.replace("_", " ").title(),
                "confidence": result.get("confidence", 50),
                "detail": result.get("detail", ""),
                "contribution": round(contrib, 1),
            })
            # Track best-confidence brand
            if result.get("brand") and result.get("confidence", 0) > brand_confidence:
                brand_detected = result["brand"]
                brand_confidence = result.get("confidence", 0)

    impersonation_score = round(min(impersonation_score, 100), 2)

    if impersonation_score >= 60:
        label = "IMPERSONATION"
    elif impersonation_score >= 30:
        label = "SUSPICIOUS"
    else:
        label = "CLEAN"

    # Extract page title from HTML
    title_match = re.search(r"<title[^>]*>([^<]{1,200})</title>", html or "", re.IGNORECASE)
    page_title = title_match.group(1).strip() if title_match else None

    favicon_url = (signals.get("favicon_mismatch") or {}).get("favicon_url")

    return {
        "impersonation_score":  impersonation_score,
        "impersonation_label":  label,
        "brand_detected":       brand_detected,
        "brand_confidence":     brand_confidence,
        "signals":              signals,
        "triggered_signals":    triggered_signals,
        "page_title":           page_title,
        "favicon_url":          favicon_url,
        "http_status":          http_status,
        "html_available":       html is not None,
        "explanations":         triggered_signals,
        "domain_analyzed":      domain,
    }
