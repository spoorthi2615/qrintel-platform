"""
payload_classifier.py
Classifies QR code payloads into typed categories.
"""

import re

PAYLOAD_TYPES = {
    "URL":    {"display": "Website URL",         "icon": "globe"},
    "UPI":    {"display": "UPI Payment",          "icon": "indian-rupee"},
    "EMAIL":  {"display": "Email Address",        "icon": "mail"},
    "SMS":    {"display": "SMS Message",          "icon": "message-square"},
    "TEL":    {"display": "Phone Number",         "icon": "phone"},
    "WIFI":   {"display": "Wi-Fi Credentials",   "icon": "wifi"},
    "VCARD":  {"display": "Contact Card",         "icon": "user"},
    "GEO":    {"display": "Geo Location",         "icon": "map-pin"},
    "CRYPTO": {"display": "Crypto Wallet",        "icon": "bitcoin"},
    "TEXT":   {"display": "Plain Text",           "icon": "file-text"},
}

CRYPTO_PREFIXES = [
    "bitcoin:", "ethereum:", "litecoin:", "monero:",
    "ripple:", "dogecoin:", "dash:", "zcash:",
]


def classify_payload(payload: str) -> dict:
    """
    Classify a QR code payload string into a typed category.

    Args:
        payload: The raw string decoded from the QR code.

    Returns:
        A dict with keys: type, display, icon.
    """
    if not payload:
        return {"type": "TEXT", **PAYLOAD_TYPES["TEXT"]}

    p = payload.strip()
    pl = p.lower()

    # URL (scheme prefix or plain domain/URL pattern)
    if pl.startswith("http://") or pl.startswith("https://") or re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', pl):
        normalized = payload.strip()
        # Auto-prepend http:// if scheme is missing for downstream parsers
        if not (pl.startswith("http://") or pl.startswith("https://")):
            normalized = "http://" + normalized
        return {"type": "URL", "normalized": normalized, **PAYLOAD_TYPES["URL"]}

    # UPI
    if pl.startswith("upi://pay") or pl.startswith("upi://"):
        return {"type": "UPI", **PAYLOAD_TYPES["UPI"]}

    # Email
    if pl.startswith("mailto:"):
        return {"type": "EMAIL", **PAYLOAD_TYPES["EMAIL"]}

    # SMS
    if pl.startswith("sms:") or pl.startswith("smsto:"):
        return {"type": "SMS", **PAYLOAD_TYPES["SMS"]}

    # Telephone
    if pl.startswith("tel:"):
        return {"type": "TEL", **PAYLOAD_TYPES["TEL"]}

    # WiFi
    if pl.startswith("wifi:") or pl.startswith("wifi:"):
        return {"type": "WIFI", **PAYLOAD_TYPES["WIFI"]}

    # vCard
    if pl.startswith("begin:vcard"):
        return {"type": "VCARD", **PAYLOAD_TYPES["VCARD"]}

    # Geo
    if pl.startswith("geo:"):
        return {"type": "GEO", **PAYLOAD_TYPES["GEO"]}

    # Cryptocurrency wallets
    for prefix in CRYPTO_PREFIXES:
        if pl.startswith(prefix):
            return {"type": "CRYPTO", **PAYLOAD_TYPES["CRYPTO"]}

    # Fallback: Text
    return {"type": "TEXT", **PAYLOAD_TYPES["TEXT"]}
