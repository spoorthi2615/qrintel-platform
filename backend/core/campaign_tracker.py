"""
campaign_tracker.py  —  Sprint 5: Campaign Evolution Tracking + TTP Fingerprinting
====================================================================================
Detects and tracks coordinated phishing campaigns across multiple QR scans.
Enables THREAT ACTOR ATTRIBUTION — the publishable contribution.

Pipeline:
  1. Build TTP fingerprint from payload (Tactics, Techniques, Procedures)
  2. Compare against existing campaign fingerprints (Jaccard similarity)
  3. If similarity > threshold: assign to existing campaign (with confidence %)
  4. If no match and risk > 50: create new campaign
  5. Record evolution chain (campaign pivots, infrastructure reuse)

TTP Fingerprint schema:
  {
    "keywords":        ["verify", "account", "secure"],
    "tlds":            [".xyz", ".top"],
    "path_pattern":    "/login/verify",
    "payment_target":  "UPI",
    "has_ip":          false,
    "shortener_used":  true,
    "entropy_bucket":  "HIGH",
    "subdomain_depth": 2,
    "port_nonstandard": false,
    "vpa_provider":    "upi",
    "payload_type":    "URL"
  }
"""

import re
import json
import uuid
import math
import sqlite3
import hashlib
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional


PHISHING_KEYWORDS = [
    "login", "verify", "update", "account", "secure", "bank", "confirm",
    "wallet", "password", "credential", "signin", "recover", "billing",
    "invoice", "auth", "webscr", "refund", "cashback", "prize", "lottery",
    "winner", "reward", "lucky", "gift", "urgent", "suspended", "limited",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy",
    "short.link", "cutt.ly", "is.gd", "buff.ly", "adf.ly",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".click", ".download", ".stream",
}

# Minimum similarity to attribute to an existing campaign
ATTRIBUTION_THRESHOLD = 0.55

# Minimum risk score to create a new campaign
MIN_RISK_FOR_CAMPAIGN = 40


# ─── TTP Fingerprint Builder ──────────────────────────────────────────────────

def build_ttp_fingerprint(payload: str, payload_type: str) -> dict:
    """
    Extract a Tactics, Techniques, and Procedures (TTP) fingerprint.

    This is the key innovation: instead of just classifying a QR as
    safe/malicious, we extract a structured fingerprint that enables
    campaign attribution across multiple scans.

    Returns:
        Structured TTP dict that can be compared with Jaccard similarity.
    """
    fp: dict = {"payload_type": payload_type}

    if payload_type == "URL":
        try:
            parsed = urllib.parse.urlparse(payload)
            domain = parsed.netloc.lower().split(":")[0]
            path   = parsed.path.lower()
            query  = parsed.query.lower()
            parts  = domain.split(".")

            # Keywords in path + query + domain
            all_text = f"{domain} {path} {query}".lower()
            found_kws = [kw for kw in PHISHING_KEYWORDS if kw in all_text]
            fp["keywords"] = sorted(set(found_kws))

            # TLD
            tld = f".{parts[-1]}" if parts else ""
            fp["tlds"] = [tld] if tld in SUSPICIOUS_TLDS else []

            # Path pattern (generalized)
            pattern = re.sub(r'[0-9a-f]{8,}', '<token>', path, flags=re.IGNORECASE)
            pattern = re.sub(r'/\d+', '/<id>', pattern)
            pattern = re.sub(r'=[^&]{20,}', '=<value>', pattern)
            fp["path_pattern"] = pattern[:60] if pattern else "/"

            # IP-based domain
            fp["has_ip"] = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain))

            # URL shortener
            fp["shortener_used"] = any(s in domain for s in URL_SHORTENERS)

            # Subdomain depth
            fp["subdomain_depth"] = max(0, len(parts) - 2)

            # Non-standard port
            fp["port_nonstandard"] = bool(parsed.port and parsed.port not in (80, 443))

            # Entropy bucket of the full URL
            entropy = _shannon_entropy(payload)
            if entropy > 5.5:
                fp["entropy_bucket"] = "VERY_HIGH"
            elif entropy > 4.5:
                fp["entropy_bucket"] = "HIGH"
            elif entropy > 3.5:
                fp["entropy_bucket"] = "MODERATE"
            else:
                fp["entropy_bucket"] = "LOW"

            # Payment detection
            payment_kws = ["pay", "payment", "upi", "transfer", "send"]
            fp["payment_target"] = "URL" if any(k in all_text for k in payment_kws) else None

        except Exception:
            fp["keywords"] = []
            fp["path_pattern"] = "/"

    elif payload_type == "UPI":
        match_pa = re.search(r"pa=([^&]+)", payload, re.IGNORECASE)
        match_pn = re.search(r"pn=([^&]+)", payload, re.IGNORECASE)
        vpa = match_pa.group(1).lower() if match_pa else ""
        provider = vpa.split("@")[-1] if "@" in vpa else ""

        kws = [kw for kw in PHISHING_KEYWORDS if kw in vpa]
        if match_pn:
            kws += [kw for kw in PHISHING_KEYWORDS if kw in match_pn.group(1).lower()]

        fp["keywords"]       = sorted(set(kws))
        fp["vpa_provider"]   = provider
        fp["payment_target"] = "UPI"
        fp["has_ip"]         = False
        fp["shortener_used"] = False
        fp["subdomain_depth"] = 0
        fp["port_nonstandard"] = False
        fp["entropy_bucket"] = "LOW"
        fp["tlds"]           = []
        fp["path_pattern"]   = "upi://pay"

    else:
        entropy = _shannon_entropy(payload)
        fp["keywords"]        = [kw for kw in PHISHING_KEYWORDS if kw in payload.lower()]
        fp["tlds"]            = []
        fp["path_pattern"]    = payload_type.lower()
        fp["has_ip"]          = False
        fp["shortener_used"]  = False
        fp["subdomain_depth"] = 0
        fp["port_nonstandard"] = False
        fp["payment_target"]  = None
        fp["entropy_bucket"]  = "HIGH" if entropy > 4.5 else "LOW"
        fp["vpa_provider"]    = None

    # Canonical fingerprint hash for exact-match fast lookup
    fp_str = json.dumps(fp, sort_keys=True)
    fp["fingerprint_hash"] = hashlib.sha256(fp_str.encode()).hexdigest()[:16]

    return fp


def _shannon_entropy(s: str) -> float:
    from collections import Counter
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


# ─── Jaccard Similarity ────────────────────────────────────────────────────────

def _fp_to_feature_set(fp: dict) -> set:
    """Convert a TTP fingerprint to a set of atomic features for Jaccard comparison."""
    features = set()

    # Keywords are high-signal
    for kw in fp.get("keywords", []):
        features.add(f"kw:{kw}")

    # TLDs
    for tld in fp.get("tlds", []):
        features.add(f"tld:{tld}")

    # Path pattern tokens
    path = fp.get("path_pattern", "")
    for token in re.split(r"[/\-_?&=]", path):
        if token and len(token) > 2:
            features.add(f"path:{token}")

    # Boolean signals
    if fp.get("has_ip"):
        features.add("signal:has_ip")
    if fp.get("shortener_used"):
        features.add("signal:shortener")
    if fp.get("port_nonstandard"):
        features.add("signal:nonstandard_port")

    # Entropy bucket
    features.add(f"entropy:{fp.get('entropy_bucket', 'UNKNOWN')}")

    # Payment target
    if fp.get("payment_target"):
        features.add(f"payment:{fp['payment_target']}")

    # VPA provider
    if fp.get("vpa_provider"):
        features.add(f"vpa:{fp['vpa_provider']}")

    # Payload type
    features.add(f"type:{fp.get('payload_type', 'UNKNOWN')}")

    return features


def compute_fingerprint_similarity(fp1: dict, fp2: dict) -> float:
    """Jaccard similarity between two TTP fingerprints. Range [0, 1]."""
    s1 = _fp_to_feature_set(fp1)
    s2 = _fp_to_feature_set(fp2)
    if not s1 and not s2:
        return 0.5
    intersection = len(s1 & s2)
    union        = len(s1 | s2)
    return intersection / union if union > 0 else 0.0


# ─── Campaign Name Generator ──────────────────────────────────────────────────

def _generate_campaign_name(fp: dict) -> str:
    """Generate a human-readable campaign name from its TTP fingerprint."""
    parts = []

    kws = fp.get("keywords", [])
    if kws:
        parts.append(kws[0].upper())

    tlds = fp.get("tlds", [])
    if tlds:
        parts.append(tlds[0].upper().lstrip("."))

    ptype = fp.get("payload_type", "")
    if ptype:
        parts.append(ptype)

    if not parts:
        parts.append("UNKNOWN")

    # Append short hash for uniqueness
    h = fp.get("fingerprint_hash", "0000")[:4].upper()
    return f"CAMPAIGN-{'-'.join(parts)}-{h}"


def _build_evolution_entry(scan_id: int, fp: dict, generation: int) -> dict:
    return {
        "scan_id":    scan_id,
        "generation": generation,
        "timestamp":  datetime.utcnow().isoformat(),
        "fingerprint_hash": fp.get("fingerprint_hash", ""),
        "keywords":   fp.get("keywords", []),
        "path_pattern": fp.get("path_pattern", ""),
    }


# ─── Campaign DB Operations ────────────────────────────────────────────────────

def find_similar_campaigns(fp: dict, risk_score: float,
                           conn: sqlite3.Connection) -> list[dict]:
    """
    Query existing campaigns and return those with similarity > threshold.
    """
    campaigns = conn.execute(
        """SELECT campaign_id, name, ttp_fingerprint, threat_level,
                  member_count, evolution_chain_json, first_seen, last_seen
           FROM campaigns WHERE active=1 ORDER BY last_seen DESC LIMIT 100"""
    ).fetchall()

    matches = []
    for row in campaigns:
        try:
            existing_fp = json.loads(row["ttp_fingerprint"] or "{}")
            sim = compute_fingerprint_similarity(fp, existing_fp)
            if sim >= ATTRIBUTION_THRESHOLD:
                matches.append({
                    "campaign_id":  row["campaign_id"],
                    "name":         row["name"],
                    "similarity":   round(sim, 3),
                    "confidence":   round(sim * 100, 1),
                    "threat_level": row["threat_level"],
                    "member_count": row["member_count"],
                    "first_seen":   row["first_seen"],
                    "last_seen":    row["last_seen"],
                })
        except Exception:
            continue

    return sorted(matches, key=lambda x: x["similarity"], reverse=True)


def create_campaign(
    payload: str,
    payload_type: str,
    fp: dict,
    risk_score: float,
    scan_id: int,
    conn: sqlite3.Connection,
) -> dict:
    """Create a new campaign record."""
    campaign_id  = str(uuid.uuid4())[:12]
    name         = _generate_campaign_name(fp)
    threat_level = "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 50 else "LOW"
    now          = datetime.utcnow().isoformat()
    evolution    = [_build_evolution_entry(scan_id, fp, generation=1)]

    conn.execute(
        """INSERT INTO campaigns
           (campaign_id, name, threat_level, first_seen, last_seen,
            member_count, active, ttp_fingerprint, evolution_chain_json, metadata_json)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            campaign_id, name, threat_level, now, now, 1, 1,
            json.dumps(fp),
            json.dumps(evolution),
            json.dumps({"payload_type": payload_type, "initial_risk": risk_score}),
        )
    )
    conn.commit()
    return {
        "campaign_id":  campaign_id,
        "name":         name,
        "threat_level": threat_level,
        "is_new":       True,
        "confidence":   100.0,
        "generation":   1,
    }


def assign_member_to_campaign(
    campaign_id: str,
    scan_id: int,
    fp: dict,
    similarity: float,
    conn: sqlite3.Connection,
) -> int:
    """
    Add a scan as a new member of an existing campaign.
    Determine its generation from evolution chain.
    """
    now = datetime.utcnow().isoformat()

    # Get current evolution chain and determine generation
    row = conn.execute(
        "SELECT evolution_chain_json, member_count FROM campaigns WHERE campaign_id=?",
        (campaign_id,)
    ).fetchone()

    evolution = json.loads(row["evolution_chain_json"] or "[]") if row else []
    generation = len(set(e.get("fingerprint_hash", "") for e in evolution)) + 1

    # Update evolution chain
    evolution.append(_build_evolution_entry(scan_id, fp, generation))

    # Merge TTP fingerprint (update campaign's aggregate fingerprint)
    campaign_fp_row = conn.execute(
        "SELECT ttp_fingerprint FROM campaigns WHERE campaign_id=?",
        (campaign_id,)
    ).fetchone()
    try:
        old_fp = json.loads(campaign_fp_row["ttp_fingerprint"] or "{}")
        # Merge keywords
        merged_kws = sorted(set(old_fp.get("keywords", []) + fp.get("keywords", [])))
        old_fp["keywords"] = merged_kws
        new_ttp = json.dumps(old_fp)
    except Exception:
        new_ttp = json.dumps(fp)

    # Update campaign record
    conn.execute(
        """UPDATE campaigns SET last_seen=?, member_count=member_count+1,
           evolution_chain_json=?, ttp_fingerprint=? WHERE campaign_id=?""",
        (now, json.dumps(evolution), new_ttp, campaign_id)
    )

    # Insert member record
    conn.execute(
        """INSERT INTO campaign_members
           (campaign_id, scan_id, member_fingerprint, similarity_score, joined_at, generation)
           VALUES (?,?,?,?,?,?)""",
        (campaign_id, scan_id, fp.get("fingerprint_hash", ""),
         round(similarity, 3), now, generation)
    )
    conn.commit()
    return generation


# ─── Main Attribution Function ─────────────────────────────────────────────────

def assign_to_campaign(
    scan_id: int,
    payload: str,
    payload_type: str,
    risk_score: float,
    conn: sqlite3.Connection,
) -> Optional[dict]:
    """
    Main entry point: build TTP fingerprint and attribute scan to a campaign.

    Called automatically after every scan in the intelligence pipeline.

    Returns:
        Campaign attribution dict, or None if not attributed.
    """
    fp = build_ttp_fingerprint(payload, payload_type)

    # Only attribute/create campaigns for suspicious/malicious scans
    if risk_score < MIN_RISK_FOR_CAMPAIGN:
        return {
            "attributed": False,
            "reason": f"Risk score {risk_score:.1f} below attribution threshold {MIN_RISK_FOR_CAMPAIGN}",
            "ttp_fingerprint": fp,
        }

    # Find existing similar campaigns
    matches = find_similar_campaigns(fp, risk_score, conn)

    if matches:
        best = matches[0]
        generation = assign_member_to_campaign(
            best["campaign_id"], scan_id, fp, best["similarity"], conn
        )
        return {
            "attributed":   True,
            "campaign_id":  best["campaign_id"],
            "campaign_name":best["name"],
            "confidence":   best["confidence"],
            "similarity":   best["similarity"],
            "threat_level": best["threat_level"],
            "member_count": best["member_count"] + 1,
            "generation":   generation,
            "is_new":       False,
            "ttp_fingerprint": fp,
            "all_matches":  matches[:3],
            "attribution_note": (
                f"Confidence {best['confidence']:.1f}% — "
                f"likely related to {best['name']} "
                f"(similarity {best['similarity']:.2f})"
            ),
        }
    else:
        # Create new campaign
        campaign = create_campaign(payload, payload_type, fp, risk_score, scan_id, conn)
        campaign["attributed"] = True
        campaign["ttp_fingerprint"] = fp
        campaign["attribution_note"] = (
            f"New campaign identified: {campaign['name']} "
            f"(threat level: {campaign['threat_level']})"
        )
        return campaign


# ─── Campaign Query Functions ──────────────────────────────────────────────────

def get_campaign_list(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    """Return all campaigns sorted by threat level and recency."""
    rows = conn.execute(
        """SELECT campaign_id, name, threat_level, first_seen, last_seen,
                  member_count, active, ttp_fingerprint
           FROM campaigns ORDER BY
                CASE threat_level WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
                last_seen DESC
           LIMIT ?""",
        (limit,)
    ).fetchall()

    result = []
    for row in rows:
        try:
            fp = json.loads(row["ttp_fingerprint"] or "{}")
        except Exception:
            fp = {}
        result.append({
            "campaign_id":   row["campaign_id"],
            "name":          row["name"],
            "threat_level":  row["threat_level"],
            "first_seen":    row["first_seen"],
            "last_seen":     row["last_seen"],
            "member_count":  row["member_count"],
            "active":        bool(row["active"]),
            "ttp_summary": {
                "keywords":      fp.get("keywords", [])[:5],
                "tlds":          fp.get("tlds", []),
                "payload_type":  fp.get("payload_type", ""),
                "has_ip":        fp.get("has_ip", False),
                "shortener":     fp.get("shortener_used", False),
            },
        })
    return result


def get_campaign_detail(campaign_id: str, conn: sqlite3.Connection) -> Optional[dict]:
    """Return full campaign detail including evolution chain and members."""
    row = conn.execute(
        "SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)
    ).fetchone()
    if not row:
        return None

    members = conn.execute(
        """SELECT cm.scan_id, cm.similarity_score, cm.joined_at, cm.generation,
                  s.payload, s.status, s.risk_score, s.payload_type
           FROM campaign_members cm
           JOIN scans s ON s.id = cm.scan_id
           WHERE cm.campaign_id=? ORDER BY cm.joined_at""",
        (campaign_id,)
    ).fetchall()

    try:
        evolution = json.loads(row["evolution_chain_json"] or "[]")
        fp        = json.loads(row["ttp_fingerprint"] or "{}")
        metadata  = json.loads(row["metadata_json"] or "{}")
    except Exception:
        evolution, fp, metadata = [], {}, {}

    return {
        "campaign_id":    row["campaign_id"],
        "name":           row["name"],
        "threat_level":   row["threat_level"],
        "first_seen":     row["first_seen"],
        "last_seen":      row["last_seen"],
        "member_count":   row["member_count"],
        "active":         bool(row["active"]),
        "ttp_fingerprint": fp,
        "evolution_chain": evolution,
        "metadata":        metadata,
        "members": [
            {
                "scan_id":        m["scan_id"],
                "payload":        m["payload"][:80],
                "status":         m["status"],
                "risk_score":     m["risk_score"],
                "similarity":     m["similarity_score"],
                "generation":     m["generation"],
                "joined_at":      m["joined_at"],
            }
            for m in members
        ],
    }
