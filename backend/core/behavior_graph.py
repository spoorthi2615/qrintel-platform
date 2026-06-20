"""
behavior_graph.py  —  Sprint 4: Behavioral Trust Graph
=======================================================
Models relationships between domains, VPAs, and URL patterns as a directed graph.
Enables risk propagation: if node A is malicious and connected to node B,
B's trust is penalized even without direct heuristic evidence.

Graph stored entirely in SQLite (no external graph library).

Algorithms:
  - BFS risk propagation (malice spreads through connected components)
  - Union-Find cluster detection
  - Degree centrality for influence scoring
  - Anomaly scoring for new nodes connecting to high-risk clusters
"""

import re
import json
import math
import sqlite3
import hashlib
import urllib.parse
from datetime import datetime
from typing import Optional


# ─── Node extraction ──────────────────────────────────────────────────────────

def extract_nodes_from_scan(payload: str, payload_type: str) -> list[dict]:
    """
    Extract graph nodes from a QR payload.

    Returns list of {node_id, node_type, metadata} dicts.
    """
    nodes = []

    if payload_type == "URL":
        try:
            parsed = urllib.parse.urlparse(payload)
            domain = parsed.netloc.lower().split(":")[0]
            if domain:
                nodes.append({
                    "node_id":   f"domain:{domain}",
                    "node_type": "domain",
                    "metadata":  {"domain": domain, "tld": domain.split(".")[-1] if "." in domain else ""},
                })

            # Extract domain root (e.g., "google" from "www.google.com")
            parts = domain.split(".")
            if len(parts) >= 2:
                root = parts[-2]
                nodes.append({
                    "node_id":   f"domain_root:{root}",
                    "node_type": "domain_root",
                    "metadata":  {"root": root},
                })

            # IP address node
            ip_match = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain)
            if ip_match:
                ip_prefix = ".".join(domain.split(".")[:3])
                nodes.append({
                    "node_id":   f"ip_prefix:{ip_prefix}",
                    "node_type": "ip_prefix",
                    "metadata":  {"ip_prefix": ip_prefix},
                })

            # URL path pattern node (generalized)
            path = parsed.path
            if path and path != "/":
                # Generalize: replace UUIDs and numbers with placeholders
                pattern = re.sub(r'[0-9a-f]{8,}', '<token>', path, flags=re.IGNORECASE)
                pattern = re.sub(r'/\d+', '/<id>', pattern)
                nodes.append({
                    "node_id":   f"path_pattern:{pattern[:80]}",
                    "node_type": "path_pattern",
                    "metadata":  {"pattern": pattern[:80], "original": path[:80]},
                })

        except Exception:
            pass

    elif payload_type == "UPI":
        match = re.search(r"pa=([^&]+)", payload, re.IGNORECASE)
        if match:
            vpa = match.group(1).lower()
            nodes.append({
                "node_id":   f"vpa:{vpa}",
                "node_type": "upi_vpa",
                "metadata":  {"vpa": vpa, "provider": vpa.split("@")[-1] if "@" in vpa else ""},
            })
            # VPA provider node
            if "@" in vpa:
                provider = vpa.split("@")[1]
                nodes.append({
                    "node_id":   f"upi_provider:{provider}",
                    "node_type": "upi_provider",
                    "metadata":  {"provider": provider},
                })

    elif payload_type == "EMAIL":
        match = re.search(r"mailto:([^\?]+)", payload, re.IGNORECASE)
        if match:
            email = match.group(1).lower()
            nodes.append({
                "node_id":   f"email:{email}",
                "node_type": "email",
                "metadata":  {"email": email, "domain": email.split("@")[-1] if "@" in email else ""},
            })

    return nodes


def extract_edges_from_nodes(nodes: list[dict], scan_id: int, risk_score: float) -> list[dict]:
    """
    Create co-occurrence edges between all nodes extracted from the same scan.
    """
    edges = []
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            edges.append({
                "source_node": nodes[i]["node_id"],
                "target_node": nodes[j]["node_id"],
                "edge_type":   "co_occurrence",
                "weight":      max(0.1, risk_score / 100),
                "evidence":    {"scan_id": scan_id, "risk_score": risk_score},
            })
    return edges


# ─── Graph DB Operations ───────────────────────────────────────────────────────

def upsert_node(node_id: str, node_type: str, metadata: dict,
                risk_score: float, conn: sqlite3.Connection):
    """Insert or update a node, incrementing scan count and updating risk."""
    now = datetime.utcnow().isoformat()
    existing = conn.execute(
        "SELECT id, risk_score, scan_count FROM graph_nodes WHERE node_id = ?",
        (node_id,)
    ).fetchone()

    if existing:
        # Rolling average of risk score
        old_score = existing["risk_score"] or 0
        old_count = existing["scan_count"] or 1
        new_score  = (old_score * old_count + risk_score) / (old_count + 1)
        conn.execute(
            """UPDATE graph_nodes SET last_seen=?, risk_score=?,
               scan_count=scan_count+1, metadata_json=?
               WHERE node_id=?""",
            (now, round(new_score, 2), json.dumps(metadata), node_id)
        )
    else:
        conn.execute(
            """INSERT INTO graph_nodes
               (node_id, node_type, first_seen, last_seen, scan_count,
                risk_score, propagated_risk, degree, metadata_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (node_id, node_type, now, now, 1, risk_score, 0, 0, json.dumps(metadata))
        )


def upsert_edge(source: str, target: str, edge_type: str,
                weight: float, evidence: dict, conn: sqlite3.Connection):
    """Insert or update an edge, reinforcing weight on re-occurrence."""
    existing = conn.execute(
        "SELECT id, weight FROM graph_edges WHERE source_node=? AND target_node=? AND edge_type=?",
        (source, target, edge_type)
    ).fetchone()

    if existing:
        # Increase edge weight on re-occurrence (capped at 1.0)
        new_weight = min(1.0, existing["weight"] + weight * 0.1)
        conn.execute(
            "UPDATE graph_edges SET weight=?, evidence_json=? WHERE id=?",
            (round(new_weight, 3), json.dumps(evidence), existing["id"])
        )
    else:
        conn.execute(
            """INSERT INTO graph_edges
               (source_node, target_node, edge_type, weight, evidence_json)
               VALUES (?,?,?,?,?)""",
            (source, target, edge_type, round(weight, 3), json.dumps(evidence))
        )

    # Update degree for both nodes
    conn.execute(
        "UPDATE graph_nodes SET degree=degree+1 WHERE node_id=? OR node_id=?",
        (source, target)
    )


# ─── BFS Risk Propagation ─────────────────────────────────────────────────────

def propagate_risk(start_node_id: str, conn: sqlite3.Connection,
                   max_hops: int = 3, decay: float = 0.5):
    """
    BFS from a node, spreading its risk to neighbors with exponential decay.

    Args:
        start_node_id: Node to start propagation from.
        conn:          SQLite connection.
        max_hops:      Maximum BFS depth.
        decay:         Risk decay per hop (0.5 = halved each hop).
    """
    start = conn.execute(
        "SELECT risk_score FROM graph_nodes WHERE node_id=?", (start_node_id,)
    ).fetchone()
    if not start:
        return

    initial_risk = start["risk_score"] or 0
    if initial_risk < 30:
        return  # Only propagate from risky nodes

    visited = {start_node_id}
    queue   = [(start_node_id, initial_risk, 0)]  # (node_id, risk, hop)

    while queue:
        node_id, risk, hop = queue.pop(0)
        if hop >= max_hops:
            continue

        propagated = risk * (decay ** hop)
        if propagated < 5:
            continue

        # Find neighbors
        neighbors = conn.execute(
            """SELECT target_node as neighbor, weight FROM graph_edges WHERE source_node=?
               UNION
               SELECT source_node as neighbor, weight FROM graph_edges WHERE target_node=?""",
            (node_id, node_id)
        ).fetchall()

        for row in neighbors:
            neighbor_id = row["neighbor"]
            if neighbor_id in visited:
                continue
            visited.add(neighbor_id)

            edge_weight = row["weight"] or 0.5
            neighbor_risk = propagated * edge_weight

            # Update propagated_risk (take max)
            existing = conn.execute(
                "SELECT propagated_risk FROM graph_nodes WHERE node_id=?",
                (neighbor_id,)
            ).fetchone()
            if existing:
                curr_prop = existing["propagated_risk"] or 0
                new_prop  = max(curr_prop, round(neighbor_risk, 2))
                conn.execute(
                    "UPDATE graph_nodes SET propagated_risk=? WHERE node_id=?",
                    (new_prop, neighbor_id)
                )

            queue.append((neighbor_id, neighbor_risk, hop + 1))

    conn.commit()


# ─── Union-Find Cluster Detection ─────────────────────────────────────────────

def _find_clusters(conn: sqlite3.Connection) -> dict[str, str]:
    """
    Union-Find to detect connected components (clusters).
    Returns {node_id: cluster_representative}.
    """
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(x, y):
        parent[find(x)] = find(y)

    edges = conn.execute("SELECT source_node, target_node FROM graph_edges").fetchall()
    nodes = conn.execute("SELECT node_id FROM graph_nodes").fetchall()

    for row in nodes:
        find(row["node_id"])
    for row in edges:
        union(row["source_node"], row["target_node"])

    return {n: find(n) for n in parent}


# ─── Main Update Function ──────────────────────────────────────────────────────

def update_from_scan(
    scan_id: int,
    payload: str,
    payload_type: str,
    risk_score: float,
    conn: sqlite3.Connection,
) -> dict:
    """
    Update the behavior graph with data from a new scan.
    Called automatically in the intelligence pipeline for every scan.

    Returns: dict with nodes_added, edges_added, propagation_triggered,
             new_node_anomaly_score.
    """
    nodes = extract_nodes_from_scan(payload, payload_type)
    edges = extract_edges_from_nodes(nodes, scan_id, risk_score)

    # Check if any new nodes connect to high-risk existing nodes before inserting
    anomaly_score = 0.0
    anomaly_reasons = []

    for node in nodes:
        existing = conn.execute(
            "SELECT propagated_risk, risk_score, scan_count FROM graph_nodes WHERE node_id=?",
            (node["node_id"],)
        ).fetchone()
        if not existing:
            # New node — check if any of its future edges lead to high-risk nodes
            pass
        else:
            prop_risk = existing["propagated_risk"] or 0
            own_risk  = existing["risk_score"] or 0
            combined  = max(prop_risk, own_risk)
            if combined > 60:
                anomaly_score = max(anomaly_score, combined * 0.7)
                anomaly_reasons.append(
                    f"Node '{node['node_id']}' has historical propagated risk {combined:.1f}"
                )

    # Upsert all nodes
    for node in nodes:
        upsert_node(node["node_id"], node["node_type"], node["metadata"], risk_score, conn)

    # Upsert all edges
    for edge in edges:
        upsert_edge(edge["source_node"], edge["target_node"],
                    edge["edge_type"], edge["weight"], edge["evidence"], conn)

    # Trigger BFS propagation if scan is risky
    propagation_triggered = False
    if risk_score >= 50 and nodes:
        primary_node = nodes[0]["node_id"]
        propagate_risk(primary_node, conn)
        propagation_triggered = True

    conn.commit()

    return {
        "nodes_added":              len(nodes),
        "edges_added":              len(edges),
        "propagation_triggered":    propagation_triggered,
        "new_node_anomaly_score":   round(anomaly_score, 2),
        "anomaly_reasons":          anomaly_reasons,
        "node_ids":                 [n["node_id"] for n in nodes],
    }


# ─── Graph Query Functions ─────────────────────────────────────────────────────

def get_graph_snapshot(conn: sqlite3.Connection, limit_nodes: int = 200) -> dict:
    """Return all nodes and edges for dashboard visualization."""
    nodes = conn.execute(
        """SELECT node_id, node_type, risk_score, propagated_risk, degree,
                  scan_count, first_seen, last_seen, metadata_json
           FROM graph_nodes ORDER BY risk_score DESC LIMIT ?""",
        (limit_nodes,)
    ).fetchall()

    node_ids = {r["node_id"] for r in nodes}

    edges = conn.execute(
        """SELECT source_node, target_node, edge_type, weight
           FROM graph_edges
           WHERE source_node IN ({}) OR target_node IN ({})
           LIMIT 500""".format(
            ",".join("?" * len(node_ids)),
            ",".join("?" * len(node_ids)),
        ),
        list(node_ids) + list(node_ids)
    ).fetchall() if node_ids else []

    return {
        "nodes": [
            {
                "id":              r["node_id"],
                "type":            r["node_type"],
                "risk_score":      round(r["risk_score"] or 0, 1),
                "propagated_risk": round(r["propagated_risk"] or 0, 1),
                "degree":          r["degree"] or 0,
                "scan_count":      r["scan_count"] or 0,
                "first_seen":      r["first_seen"],
                "last_seen":       r["last_seen"],
                "metadata":        json.loads(r["metadata_json"] or "{}"),
            }
            for r in nodes
        ],
        "edges": [
            {
                "source": r["source_node"],
                "target": r["target_node"],
                "type":   r["edge_type"],
                "weight": round(r["weight"] or 0, 3),
            }
            for r in edges
        ],
        "stats": {
            "total_nodes": conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0],
            "total_edges": conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0],
            "high_risk_nodes": conn.execute(
                "SELECT COUNT(*) FROM graph_nodes WHERE risk_score > 60"
            ).fetchone()[0],
        },
    }


def get_node_neighborhood(node_id: str, conn: sqlite3.Connection, hops: int = 2) -> dict:
    """Return a node's neighborhood up to N hops."""
    visited = {node_id}
    frontier = {node_id}
    all_nodes = []
    all_edges = []

    for _ in range(hops):
        new_frontier = set()
        for nid in frontier:
            edges = conn.execute(
                """SELECT source_node, target_node, edge_type, weight FROM graph_edges
                   WHERE source_node=? OR target_node=?""",
                (nid, nid)
            ).fetchall()
            for e in edges:
                neighbor = e["target_node"] if e["source_node"] == nid else e["source_node"]
                if neighbor not in visited:
                    new_frontier.add(neighbor)
                    visited.add(neighbor)
                all_edges.append({
                    "source": e["source_node"], "target": e["target_node"],
                    "type": e["edge_type"], "weight": e["weight"],
                })
        frontier = new_frontier
        if not frontier:
            break

    for nid in visited:
        row = conn.execute(
            "SELECT * FROM graph_nodes WHERE node_id=?", (nid,)
        ).fetchone()
        if row:
            all_nodes.append({
                "id":              row["node_id"],
                "type":            row["node_type"],
                "risk_score":      round(row["risk_score"] or 0, 1),
                "propagated_risk": round(row["propagated_risk"] or 0, 1),
                "degree":          row["degree"] or 0,
                "metadata":        json.loads(row["metadata_json"] or "{}"),
            })

    # Deduplicate edges
    seen_edges = set()
    unique_edges = []
    for e in all_edges:
        key = tuple(sorted([e["source"], e["target"]]) + [e["type"]])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    return {
        "center_node": node_id,
        "nodes": all_nodes,
        "edges": unique_edges,
    }
