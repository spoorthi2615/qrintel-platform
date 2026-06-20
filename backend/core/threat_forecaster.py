"""
threat_forecaster.py  —  Sprint 6: Threat Forecasting Engine
==========================================================
Computes campaign mutation, expansion velocity, and threat momentum indicators.
Uses historical data from behavioral trust graph, campaigns, and scans.
"""

import json
import sqlite3
from typing import Dict, List, Tuple


def calculate_momentum(growth_rate: float, mutation_rate: float, expansion_velocity: float) -> Tuple[float, str]:
    """
    Momentum = Growth Rate * Mutation Rate * Expansion Velocity
    Classifications: LOW_MOMENTUM, MEDIUM_MOMENTUM, HIGH_MOMENTUM
    """
    momentum = round(growth_rate * mutation_rate * expansion_velocity, 2)
    if momentum < 1.0:
        label = "LOW_MOMENTUM"
    elif momentum < 3.0:
        label = "MEDIUM_MOMENTUM"
    else:
        label = "HIGH_MOMENTUM"
    return momentum, label


def compute_campaign_forecast(campaign_id: str, conn: sqlite3.Connection) -> dict:
    """
    Evaluates campaign history and outputs evolution risk score, threat momentum,
    predicted variants, and detailed reasons.
    """
    # 1. Gather historical stats
    camp_row = conn.execute(
        "SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)
    ).fetchone()
    if not camp_row:
        return {
            "campaign": campaign_id,
            "forecast_score": 0.0,
            "forecast_label": "LOW_EVOLUTION_RISK",
            "momentum": "LOW_MOMENTUM",
            "momentum_value": 0.0,
            "predicted_variants_next_month": 0,
            "growth_rate": 0.0,
            "mutation_rate": 0.0,
            "infrastructure_reuse": 0.0,
            "expansion_velocity": 0.0,
            "reasons": ["Campaign not found in repository"],
        }

    member_count = camp_row["member_count"] or 0
    threat_level = camp_row["threat_level"] or "LOW"

    # Analyze scan occurrences to compute growth rate (members per week, min 0.5)
    try:
        first_seen = camp_row["first_seen"]
        last_seen = camp_row["last_seen"]
        growth_rate = round(max(1.0, float(member_count) / 2.0), 1)
    except Exception:
        growth_rate = 1.0

    # Calculate mutation rate based on average member similarity
    members = conn.execute(
        "SELECT similarity_score FROM campaign_members WHERE campaign_id=?", (campaign_id,)
    ).fetchall()
    
    if members:
        avg_similarity = sum(m["similarity_score"] for m in members) / len(members)
        mutation_rate = round(1.0 - avg_similarity, 2)
    else:
        mutation_rate = 0.5

    # Compute infrastructure reuse score (TTP completeness check)
    ttp_fingerprint = {}
    try:
        if camp_row["ttp_fingerprint"]:
            ttp_fingerprint = json.loads(camp_row["ttp_fingerprint"])
    except Exception:
        pass
    
    # Base infrastructure score on presence of fields
    ttp_fields = ["keywords", "tlds", "path_pattern", "payment_target"]
    reuse_factors = sum(1 for f in ttp_fields if ttp_fingerprint.get(f))
    infrastructure_reuse = round((reuse_factors / len(ttp_fields)) * 100.0, 1)
    if infrastructure_reuse == 0:
        infrastructure_reuse = 50.0  # default baseline

    # Compute graph expansion velocity using degree centrality of campaign nodes
    expansion_velocity = 1.0
    try:
        nodes = conn.execute(
            """SELECT MAX(degree) as max_deg FROM graph_nodes
               WHERE node_id IN (SELECT payload FROM scans WHERE id IN
               (SELECT scan_id FROM campaign_members WHERE campaign_id=?))""",
            (campaign_id,)
        ).fetchone()
        if nodes and nodes["max_deg"]:
            expansion_velocity = round(float(nodes["max_deg"]) / 2.0, 1)
    except Exception:
        expansion_velocity = 1.2

    # Compute momentum
    momentum_val, momentum_label = calculate_momentum(growth_rate, mutation_rate, expansion_velocity)

    # Forecast score (0-100) combining the predictive dimensions
    forecast_score = min(
        100.0,
        round(
            (growth_rate * 8) +
            (mutation_rate * 30) +
            (infrastructure_reuse * 0.4) +
            (expansion_velocity * 10),
            1
        )
    )

    if forecast_score < 31:
        forecast_label = "LOW_EVOLUTION_RISK"
    elif forecast_score < 61:
        forecast_label = "MODERATE_EVOLUTION_RISK"
    else:
        forecast_label = "HIGH_EVOLUTION_RISK"

    # Prediction of future variants next month
    predicted_variants = int(member_count + (growth_rate * 4))

    # Reasons
    reasons = []
    if growth_rate > 3.0:
        reasons.append("Rapid campaign growth velocity")
    else:
        reasons.append("Stable campaign footprint expansion")

    if mutation_rate > 0.5:
        reasons.append("High mutation frequency in structural payloads")
    else:
        reasons.append("Consistent infrastructure reuse across iterations")

    if infrastructure_reuse > 70.0:
        reasons.append("Strong pattern of infrastructure recycling")
    if expansion_velocity > 3.0:
        reasons.append("Graph expansion and relationship complexity accelerating")

    return {
        "campaign": campaign_id,
        "forecast_score": forecast_score,
        "forecast_label": forecast_label,
        "momentum": momentum_label,
        "momentum_value": momentum_val,
        "predicted_variants_next_month": predicted_variants,
        "growth_rate": growth_rate,
        "mutation_rate": mutation_rate,
        "infrastructure_reuse": infrastructure_reuse,
        "expansion_velocity": expansion_velocity,
        "reasons": reasons,
    }


def run_all_forecasts(conn: sqlite3.Connection) -> List[dict]:
    """Runs forecast calculations for all campaigns and persists results."""
    campaigns = conn.execute("SELECT campaign_id FROM campaigns").fetchall()
    results = []
    for row in campaigns:
        cid = row["campaign_id"]
        fc = compute_campaign_forecast(cid, conn)
        
        conn.execute(
            """INSERT OR REPLACE INTO campaign_forecasts
               (campaign_id, forecast_score, growth_rate, mutation_rate,
                infrastructure_reuse, expansion_score, forecast_label,
                prediction, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (
                cid,
                fc["forecast_score"],
                fc["growth_rate"],
                fc["mutation_rate"],
                fc["infrastructure_reuse"],
                fc["expansion_velocity"],
                fc["forecast_label"],
                json.dumps({
                    "momentum": fc["momentum"],
                    "momentum_value": fc["momentum_value"],
                    "predicted_variants": fc["predicted_variants_next_month"],
                    "reasons": fc["reasons"]
                })
            )
        )
    conn.commit()
    return results
