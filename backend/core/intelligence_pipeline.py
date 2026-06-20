"""
intelligence_pipeline.py  —  Central Orchestrator
==================================================
Called AFTER risk scoring and BEFORE storing the final scan result.

New scan pipeline:
  Scan → Risk Analysis → [Intelligence Enrichment] → Trust Graph → Campaign Attribution → Store Result

Each module runs independently — a failure in one does NOT abort the others.
All results are stored in their respective tables and returned inline.
"""

import os
import json
import sqlite3
import traceback

from core.trust_scorer    import compute_trust_score
from core.behavior_graph  import update_from_scan
from core.campaign_tracker import assign_to_campaign
from core.relationship_engine import discover_related_threats


def _safe_run(fn, label: str, *args, **kwargs):
    """Run a function with full exception isolation. Returns (result, error)."""
    try:
        return fn(*args, **kwargs), None
    except Exception as e:
        return None, f"[{label}] {str(e)}"


# ─── DB Persistence ───────────────────────────────────────────────────────────

def _save_trust_score(scan_id: int, trust_result: dict, conn: sqlite3.Connection):
    if not trust_result:
        return
    dims = trust_result.get("dimensions", {})
    conn.execute(
        """INSERT OR REPLACE INTO trust_scores
           (scan_id, lexical_score, structural_score, protocol_score,
            historical_score, entropy_score, composite_score, trust_label,
            dimensions_json, explanations_json)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            scan_id,
            dims.get("lexical",    {}).get("score", 0),
            dims.get("structural", {}).get("score", 0),
            dims.get("protocol",   {}).get("score", 0),
            dims.get("historical", {}).get("score", 0),
            dims.get("entropy",    {}).get("score", 0),
            trust_result.get("composite", 0),
            trust_result.get("trust_label", "UNKNOWN"),
            json.dumps(dims),
            json.dumps(trust_result.get("explanations", [])),
        )
    )


def _save_visual_phishing(scan_id: int, url: str, phishing_result: dict,
                          conn: sqlite3.Connection):
    if not phishing_result:
        return
    conn.execute(
        """INSERT OR REPLACE INTO visual_phishing
           (scan_id, url, http_status, brand_detected, brand_confidence,
            impersonation_score, impersonation_label, signals_json,
            page_title, favicon_url)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            scan_id, url,
            phishing_result.get("http_status"),
            phishing_result.get("brand_detected"),
            phishing_result.get("brand_confidence", 0),
            phishing_result.get("impersonation_score", 0),
            phishing_result.get("impersonation_label", "CLEAN"),
            json.dumps(phishing_result.get("signals", {})),
            phishing_result.get("page_title"),
            phishing_result.get("favicon_url"),
        )
    )


# ─── Main Enrichment Entry Point ───────────────────────────────────────────────

def enrich_scan(
    scan_id: int,
    payload: str,
    payload_type: str,
    risk_data: dict,
    conn: sqlite3.Connection,
) -> dict:
    """
    Orchestrate all intelligence modules for a scan.

    Args:
        scan_id:      DB row ID of the scan (already stored in `scans` table).
        payload:      The raw QR payload string.
        payload_type: Payload type classification (URL, UPI, TEXT, etc.).
        risk_data:    Output from risk_engine.calculate_risk().
        conn:         SQLite connection (same transaction as scan storage).

    Returns:
        enrichment dict containing results from all modules.
    """
    enrichment = {
        "scan_id":      scan_id,
        "trust":        None,
        "graph":        None,
        "campaign":     None,
        "visual_phishing": None,
        "errors":       [],
    }

    # ── Module 1: Trust Score ─────────────────────────────────────────────────
    trust_result, err = _safe_run(
        compute_trust_score, "TrustScorer",
        payload, payload_type, risk_data, conn
    )
    if trust_result:
        _save_trust_score(scan_id, trust_result, conn)
        enrichment["trust"] = {
            "composite":   trust_result["composite"],
            "trust_label": trust_result["trust_label"],
            "dimensions":  {
                k: {"score": v["score"]}
                for k, v in trust_result["dimensions"].items()
            },
            "top_concerns": [
                e["factor"] for e in trust_result.get("explanations", [])
                if e.get("dimension_score", 100) < 50
            ][:3],
        }
    elif err:
        enrichment["errors"].append(err)

    # ── Module 2: Visual Phishing (URL only, optional — requires network) ─────
    if payload_type == "URL" and os.environ.get("QRIntel_VISUAL_PHISHING") == "1":
        from core.visual_phishing import analyze_url_content
        phishing_result, err = _safe_run(analyze_url_content, "VisualPhishing", payload)
        if phishing_result:
            _save_visual_phishing(scan_id, payload, phishing_result, conn)
            enrichment["visual_phishing"] = {
                "impersonation_score": phishing_result["impersonation_score"],
                "impersonation_label": phishing_result["impersonation_label"],
                "brand_detected":      phishing_result.get("brand_detected"),
                "triggered_signals":   len(phishing_result.get("triggered_signals", [])),
            }
        elif err:
            enrichment["errors"].append(err)

    # ── Module 3: Behavior Graph update ──────────────────────────────────────
    graph_result, err = _safe_run(
        update_from_scan, "BehaviorGraph",
        scan_id, payload, payload_type, risk_data.get("score", 0), conn
    )
    if graph_result:
        enrichment["graph"] = graph_result
        # If existing connected nodes had propagated risk, surface it
        if graph_result.get("new_node_anomaly_score", 0) > 30:
            enrichment["graph"]["alert"] = (
                f"New payload connects to high-risk graph cluster "
                f"(propagated risk: {graph_result['new_node_anomaly_score']:.1f})"
            )
    elif err:
        enrichment["errors"].append(err)

    # ── Module 4: Campaign Attribution ────────────────────────────────────────
    campaign_result, err = _safe_run(
        assign_to_campaign, "CampaignTracker",
        scan_id, payload, payload_type, risk_data.get("score", 0), conn
    )
    if campaign_result:
        enrichment["campaign"] = campaign_result
    elif err:
        enrichment["errors"].append(err)
        
    # ── Module 5: Related Threats Discovery ────────────────────────────────────
    if payload_type == "URL":
        related_result, err = _safe_run(
            discover_related_threats, "RelationshipEngine",
            payload
        )
        if related_result:
            enrichment["related_threats"] = related_result
        elif err:
            enrichment["errors"].append(err)

    conn.commit()
    return enrichment
