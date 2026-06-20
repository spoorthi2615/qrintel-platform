import os
import sqlite3
from flask import Blueprint, jsonify

from core.graph_analytics import compute_campaign_influence, compute_connected_components, compute_pagerank

intelligence_bp = Blueprint('intelligence', __name__)

THREATS_DB = os.path.join(os.path.dirname(__file__), '..', 'database', 'historical_threats.db')
HISTORY_DB = os.path.join(os.path.dirname(__file__), '..', 'database', 'history.db')

@intelligence_bp.route('/top-campaigns', methods=['GET'])
def top_campaigns():
    influence_scores = compute_campaign_influence()
    influence_map = {c["campaign_id"]: c["influence_score"] for c in influence_scores}
    
    conn = sqlite3.connect(THREATS_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT campaign_id, member_count FROM campaigns ORDER BY member_count DESC LIMIT 20")
    
    results = []
    for row in cursor.fetchall():
        cid = row["campaign_id"]
        inf_score = influence_map.get(cid, 0)
        
        # Determine risk level
        if inf_score <= 25: risk = "LOW"
        elif inf_score <= 50: risk = "MODERATE"
        elif inf_score <= 75: risk = "HIGH"
        else: risk = "CRITICAL"
        
        results.append({
            "campaign_id": cid,
            "member_count": row["member_count"],
            "influence_score": inf_score,
            "risk_level": risk
        })
        
    # Sort by influence score descending
    results.sort(key=lambda x: x["influence_score"], reverse=True)
    conn.close()
    
    return jsonify(results[:10])

@intelligence_bp.route('/graph/stats', methods=['GET'])
def graph_stats():
    conn = sqlite3.connect(HISTORY_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if tables exist
    try:
        nodes = cursor.execute("SELECT COUNT(*) as c FROM graph_nodes").fetchone()["c"]
        edges = cursor.execute("SELECT COUNT(*) as c FROM graph_edges").fetchone()["c"]
    except sqlite3.OperationalError:
        nodes = 0
        edges = 0
        
    conn.close()
    
    components = compute_connected_components()
    connected_count = len(components)
    largest_comp = max([c["nodes"] for c in components]) if components else 0
    
    pr = compute_pagerank()
    highest_pr = max(pr, key=lambda x: x["pagerank"]) if pr else {}
    
    influence = compute_campaign_influence()
    highest_risk = max(influence, key=lambda x: x["influence_score"]) if influence else {}
    
    avg_deg = (2 * edges) / nodes if nodes > 0 else 0
    
    return jsonify({
        "total_nodes": nodes,
        "total_edges": edges,
        "connected_components": connected_count,
        "largest_component": largest_comp,
        "average_degree": round(avg_deg, 2),
        "highest_pagerank_campaign": highest_pr,
        "highest_risk_campaign": highest_risk
    })

@intelligence_bp.route('/attribution/<campaign_id>', methods=['GET'])
def campaign_attribution(campaign_id):
    conn = sqlite3.connect(THREATS_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,))
    campaign = cursor.fetchone()
    if not campaign:
        conn.close()
        return jsonify({"error": "Campaign not found"}), 404
        
    cursor.execute("SELECT url FROM campaign_members WHERE campaign_id=?", (campaign_id,))
    members = [row["url"] for row in cursor.fetchall()]
    
    conn.close()
    
    influence_scores = compute_campaign_influence()
    inf_score = next((c["influence_score"] for c in influence_scores if c["campaign_id"] == campaign_id), 0)
    
    if inf_score <= 25: risk = "LOW"
    elif inf_score <= 50: risk = "MODERATE"
    elif inf_score <= 75: risk = "HIGH"
    else: risk = "CRITICAL"
    
    return jsonify({
        "campaign": dict(campaign),
        "members": members,
        "related_campaigns": [], # simplified
        "risk_level": risk,
        "influence_score": inf_score
    })
