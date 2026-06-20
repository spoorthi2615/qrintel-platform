"""
trust_scorer.py  —  Sprint 1: Trust Score Framework
====================================================
Produces a 5-dimensional trust vector with per-dimension explanations.
Higher score = more trusted.

Dimensions:
  1. Lexical Trust    — how "normal" the domain/payload looks
  2. Structural Trust — URL complexity, depth, parameter count
  3. Protocol Trust   — HTTPS, standard ports, clean scheme
  4. Historical Trust — reputation from our own scan database
  5. Entropy Trust    — payload randomness (low entropy = more trusted)

Composite trust = weighted mean (0–100, 100 = fully trusted).
Trust label: HIGH / MODERATE / LOW / UNTRUSTED
"""

import re
import math
import sqlite3
import urllib.parse
from collections import Counter

# ─── Known-good domains (lexical anchor list) ─────────────────────────────────

TRUSTED_DOMAINS = {
    "google", "youtube", "facebook", "wikipedia", "twitter", "instagram",
    "linkedin", "github", "microsoft", "apple", "amazon", "netflix",
    "reddit", "stackoverflow", "medium", "adobe", "dropbox", "spotify",
    "paypal", "stripe", "shopify", "cloudflare", "fastly", "akamai",
    "gov", "edu", "ac", "org",
}

TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co.uk",
                ".co.in", ".in", ".uk", ".ca", ".au", ".de", ".fr"}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".click", ".download", ".stream", ".info", ".biz", ".loan",
    ".work", ".men", ".date", ".review", ".kim",
}

# Common DGA (domain generation algorithm) character-bigram entropy threshold
_DGA_ENTROPY_THRESHOLD = 3.8


def _char_entropy(s: str) -> float:
    """Shannon entropy of a character string."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _levenshtein(a: str, b: str) -> int:
    """Levenshtein edit distance."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), curr[j] + 1, prev[j + 1] + 1))
        prev = curr
    return prev[-1]


def _closest_trusted_domain(domain: str) -> tuple[str, int]:
    """Return (closest trusted domain, edit distance)."""
    domain_root = domain.split(".")[0]
    best_dist = 99
    best_name = ""
    for trusted in TRUSTED_DOMAINS:
        d = _levenshtein(domain_root.lower(), trusted.lower())
        if d < best_dist:
            best_dist = d
            best_name = trusted
    return best_name, best_dist


# ─── Dimension 1: Lexical Trust ───────────────────────────────────────────────

def _lexical_trust(payload: str, payload_type: str) -> dict:
    """
    Analyse the lexical structure of the payload.
    Returns score (0–100) and list of factors.
    """
    score = 70  # Baseline
    factors = []

    if payload_type == "URL":
        try:
            parsed = urllib.parse.urlparse(payload)
            domain = parsed.netloc.lower().split(":")[0]
            domain_parts = domain.split(".")
            root = domain_parts[0] if domain_parts else ""

            # ── TLD check ──────────────────────────────────────────────────
            for tld in TRUSTED_TLDS:
                if domain.endswith(tld):
                    score += 10
                    factors.append(f"Uses trusted TLD ({tld})")
                    break
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    score -= 30
                    factors.append(f"Suspicious TLD detected ({tld})")
                    break

            # ── Known trusted domain ────────────────────────────────────────
            for td in TRUSTED_DOMAINS:
                if td in domain:
                    score += 15
                    factors.append(f"Domain contains known trusted name ({td})")
                    break

            # ── DGA-like domain (high character entropy) ────────────────────
            domain_entropy = _char_entropy(root)
            if domain_entropy > _DGA_ENTROPY_THRESHOLD:
                score -= 25
                factors.append(
                    f"Domain name appears algorithmically generated "
                    f"(entropy {domain_entropy:.2f} > {_DGA_ENTROPY_THRESHOLD})"
                )

            # ── Typosquat detection ─────────────────────────────────────────
            closest, dist = _closest_trusted_domain(domain)
            if 1 <= dist <= 2 and closest not in domain:
                score -= 20
                factors.append(
                    f"Domain may typosquat '{closest}' (edit distance {dist})"
                )

            # ── Excessively long domain ─────────────────────────────────────
            if len(domain) > 40:
                score -= 15
                factors.append(f"Unusually long domain ({len(domain)} chars)")

            # ── Numeric-heavy domain ────────────────────────────────────────
            digits_in_root = sum(c.isdigit() for c in root)
            if root and digits_in_root / len(root) > 0.5:
                score -= 10
                factors.append("Domain is mostly numeric (common in phishing)")

        except Exception:
            score -= 20
            factors.append("URL parsing failed")

    elif payload_type == "UPI":
        # VPA lexical check
        at_parts = payload.split("@")
        if len(at_parts) == 2:
            vpa_user = at_parts[0].replace("upi://pay?pa=", "").lower()
            for kw in ("lottery", "prize", "winner", "lucky", "refund", "cashback"):
                if kw in vpa_user:
                    score -= 30
                    factors.append(f"Suspicious keyword in VPA: '{kw}'")

    elif payload_type in ("TEXT", "GEO", "VCARD"):
        score = 80
        factors.append("Non-URL payload — lexical trust defaults to high")

    score = max(0, min(100, score))
    if not factors:
        factors.append("No lexical anomalies detected")

    return {"score": score, "factors": factors}


# ─── Dimension 2: Structural Trust ────────────────────────────────────────────

def _structural_trust(payload: str, payload_type: str) -> dict:
    score = 80
    factors = []

    if payload_type == "URL":
        try:
            parsed = urllib.parse.urlparse(payload)
            path   = parsed.path
            query  = parsed.query
            params = urllib.parse.parse_qs(query)

            # Path depth
            depth = len([p for p in path.split("/") if p])
            if depth <= 3:
                score += 5
                factors.append(f"Shallow URL path (depth {depth})")
            elif depth > 6:
                score -= 15
                factors.append(f"Deep URL path (depth {depth}) — common in redirect chains")

            # Parameter count
            n_params = len(params)
            if n_params == 0:
                score += 5
                factors.append("No query parameters — clean URL structure")
            elif n_params > 8:
                score -= 20
                factors.append(f"Excessive query parameters ({n_params}) — possible tracking/obfuscation")

            # Long parameter values
            long_vals = [k for k, v in params.items() if any(len(vv) > 100 for vv in v)]
            if long_vals:
                score -= 15
                factors.append(f"Long parameter values detected: {long_vals[:3]}")

            # Fragment (rarely used legitimately in QR)
            if parsed.fragment:
                score -= 5
                factors.append("URL fragment present — unusual for QR code links")

            # Total URL length
            if len(payload) < 80:
                score += 10
                factors.append("Short, clean URL length")
            elif len(payload) > 200:
                score -= 20
                factors.append(f"Very long URL ({len(payload)} chars)")

        except Exception:
            score -= 10
            factors.append("URL structure could not be parsed")

    elif payload_type == "UPI":
        score = 85
        factors.append("UPI structural format is well-defined")

    else:
        score = 90
        factors.append("Non-URL payload — no structural complexity concerns")

    score = max(0, min(100, score))
    return {"score": score, "factors": factors}


# ─── Dimension 3: Protocol Trust ──────────────────────────────────────────────

def _protocol_trust(payload: str, payload_type: str) -> dict:
    score = 80
    factors = []

    if payload_type == "URL":
        try:
            parsed = urllib.parse.urlparse(payload)

            # HTTPS
            if parsed.scheme == "https":
                score += 15
                factors.append("Uses HTTPS — encrypted connection")
            elif parsed.scheme == "http":
                score -= 25
                factors.append("Plain HTTP — unencrypted, susceptible to MITM")
            else:
                score -= 10
                factors.append(f"Non-standard scheme: {parsed.scheme}")

            # Non-standard port
            if parsed.port and parsed.port not in (80, 443):
                score -= 20
                factors.append(f"Non-standard port {parsed.port} — potential C2 or proxy")

            # @ in URL (credential embedding)
            if "@" in (parsed.netloc or ""):
                score -= 30
                factors.append("Credentials embedded in URL — classic phishing technique")

        except Exception:
            score -= 10

    elif payload_type == "UPI":
        score = 90
        factors.append("UPI scheme is standardized")

    else:
        score = 85
        factors.append("No protocol concerns for this payload type")

    score = max(0, min(100, score))
    return {"score": score, "factors": factors}


# ─── Dimension 4: Historical Trust ────────────────────────────────────────────

def _historical_trust(payload: str, payload_type: str, conn: sqlite3.Connection) -> dict:
    score = 65  # Unknown = slightly below neutral
    factors = []

    try:
        if payload_type == "URL":
            parsed = urllib.parse.urlparse(payload)
            domain = parsed.netloc.lower().split(":")[0]

            # Query scans for same domain
            rows = conn.execute(
                """SELECT status, risk_score, timestamp FROM scans
                   WHERE payload LIKE ? ORDER BY id DESC LIMIT 20""",
                (f"%{domain}%",)
            ).fetchall()

            if not rows:
                factors.append("No prior scans for this domain — first-seen")
                return {"score": score, "factors": factors}

            statuses = [r[0] for r in rows]
            scores   = [r[1] for r in rows]
            safe_pct = statuses.count("SAFE") / len(statuses) * 100

            if safe_pct >= 80:
                score = 90
                factors.append(f"Domain consistently safe ({safe_pct:.0f}% of {len(rows)} prior scans)")
            elif safe_pct >= 50:
                score = 60
                factors.append(f"Domain has mixed history ({safe_pct:.0f}% safe across {len(rows)} scans)")
            else:
                score = 15
                factors.append(f"Domain has poor history ({safe_pct:.0f}% safe — mostly malicious/suspicious)")

            avg_risk = sum(scores) / len(scores)
            factors.append(f"Average historical risk score: {avg_risk:.1f}/100")

        elif payload_type == "UPI":
            # Extract VPA
            match = re.search(r"pa=([^&]+)", payload, re.IGNORECASE)
            if match:
                vpa = match.group(1)
                rows = conn.execute(
                    "SELECT status FROM scans WHERE payload LIKE ? LIMIT 10",
                    (f"%{vpa}%",)
                ).fetchall()
                if rows:
                    safe_pct = [r[0] for r in rows].count("SAFE") / len(rows) * 100
                    score = int(safe_pct * 0.9)
                    factors.append(f"UPI VPA seen {len(rows)} times, {safe_pct:.0f}% safe")
                else:
                    factors.append("First-seen UPI VPA address")

        else:
            # Exact match for non-URL types
            rows = conn.execute(
                "SELECT status FROM scans WHERE payload = ? LIMIT 10",
                (payload,)
            ).fetchall()
            if rows:
                safe_pct = [r[0] for r in rows].count("SAFE") / len(rows) * 100
                score = int(safe_pct * 0.9)
                factors.append(f"Exact payload seen {len(rows)} times previously")
            else:
                factors.append("First-seen payload")

    except Exception as e:
        score = 50
        factors.append(f"Historical lookup error: {str(e)[:60]}")

    score = max(0, min(100, score))
    return {"score": score, "factors": factors}


# ─── Dimension 5: Entropy Trust ───────────────────────────────────────────────

def _entropy_trust(entropy: float, payload_type: str) -> dict:
    """Low entropy = more trusted (predictable/readable content)."""
    score = 80
    factors = []

    if entropy <= 3.5:
        score = 95
        factors.append(f"Low entropy ({entropy:.2f} bits) — human-readable, predictable payload")
    elif entropy <= 4.5:
        score = 75
        factors.append(f"Moderate entropy ({entropy:.2f} bits) — typical for URLs with parameters")
    elif entropy <= 5.5:
        score = 40
        factors.append(f"High entropy ({entropy:.2f} bits) — possible obfuscated tokens or tracking IDs")
    else:
        score = 10
        factors.append(f"Very high entropy ({entropy:.2f} bits) — payload likely contains encoded/encrypted data")

    return {"score": score, "factors": factors}


# ─── Composite Trust Score ─────────────────────────────────────────────────────

WEIGHTS = {
    "lexical":    0.25,
    "structural": 0.15,
    "protocol":   0.25,
    "historical": 0.25,
    "entropy":    0.10,
}


def _trust_label(composite: float) -> str:
    if composite >= 75:
        return "HIGH"
    elif composite >= 50:
        return "MODERATE"
    elif composite >= 25:
        return "LOW"
    return "UNTRUSTED"


def compute_trust_score(
    payload: str,
    payload_type: str,
    risk_data: dict,
    conn: sqlite3.Connection,
) -> dict:
    """
    Compute the full 5-dimension trust score for a payload.

    Args:
        payload:      Raw QR payload string.
        payload_type: Classification type (URL, UPI, TEXT, etc.).
        risk_data:    Output from risk_engine.calculate_risk().
        conn:         SQLite connection for historical lookups.

    Returns:
        Full trust result dict with dimensions, composite, label, explanations.
    """
    entropy = risk_data.get("entropy", 0.0)

    lex  = _lexical_trust(payload, payload_type)
    stru = _structural_trust(payload, payload_type)
    prot = _protocol_trust(payload, payload_type)
    hist = _historical_trust(payload, payload_type, conn)
    entr = _entropy_trust(entropy, payload_type)

    # Weighted composite
    composite = (
        lex["score"]  * WEIGHTS["lexical"]    +
        stru["score"] * WEIGHTS["structural"] +
        prot["score"] * WEIGHTS["protocol"]   +
        hist["score"] * WEIGHTS["historical"] +
        entr["score"] * WEIGHTS["entropy"]
    )
    composite = round(composite, 2)

    # Build unified explanation list ranked by impact
    all_factors = []
    for dim_name, dim_result, weight in [
        ("Lexical",    lex,  WEIGHTS["lexical"]),
        ("Structural", stru, WEIGHTS["structural"]),
        ("Protocol",   prot, WEIGHTS["protocol"]),
        ("Historical", hist, WEIGHTS["historical"]),
        ("Entropy",    entr, WEIGHTS["entropy"]),
    ]:
        for f in dim_result["factors"]:
            all_factors.append({
                "dimension": dim_name,
                "factor": f,
                "dimension_score": dim_result["score"],
                "weight": weight,
                "impact": round(dim_result["score"] * weight, 1),
            })

    # Sort by impact descending — most significant factors first
    all_factors.sort(key=lambda x: x["impact"], reverse=False)  # low impact = bigger concern

    return {
        "composite": composite,
        "trust_label": _trust_label(composite),
        "dimensions": {
            "lexical":    {"score": lex["score"],  "factors": lex["factors"]},
            "structural": {"score": stru["score"], "factors": stru["factors"]},
            "protocol":   {"score": prot["score"], "factors": prot["factors"]},
            "historical": {"score": hist["score"], "factors": hist["factors"]},
            "entropy":    {"score": entr["score"], "factors": entr["factors"]},
        },
        "weights": WEIGHTS,
        "explanations": all_factors,
        "payload_type": payload_type,
    }
