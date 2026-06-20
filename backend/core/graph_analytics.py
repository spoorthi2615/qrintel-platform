import os
import sqlite3
import networkx as nx

HISTORY_DB = os.path.join(os.path.dirname(__file__), '..', 'database', 'history.db')
THREATS_DB = os.path.join(os.path.dirname(__file__), '..', 'database', 'historical_threats.db')

def _build_graph():
    G = nx.Graph()
    if not os.path.exists(HISTORY_DB):
        return G
        
    conn = sqlite3.connect(HISTORY_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Add Nodes
    cursor.execute("SELECT node_id, node_type, risk_score FROM graph_nodes")
    for row in cursor.fetchall():
        G.add_node(row["node_id"], type=row["node_type"], risk=row["risk_score"] or 0)
        
    # Add Edges
    cursor.execute("SELECT source_node, target_node, weight FROM graph_edges")
    for row in cursor.fetchall():
        G.add_edge(row["source_node"], row["target_node"], weight=row["weight"] or 0.1)
        
    conn.close()
    return G

def compute_degree_centrality():
    G = _build_graph()
    if len(G.nodes) == 0:
        return []
        
    centrality = nx.degree_centrality(G)
    results = []
    for node, score in centrality.items():
        # Scale to degree integer for return value
        degree = G.degree(node)
        results.append({
            "node_id": node,
            "degree": degree,
            "centrality": round(score, 4)
        })
    return results

def compute_pagerank():
    G = _build_graph()
    if len(G.nodes) == 0:
        return []
        
    pr = nx.pagerank(G, weight='weight')
    
    # Map node PageRank to campaigns by reading from historical threats
    conn = sqlite3.connect(THREATS_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT campaign_id, url FROM campaign_members")
    members = cursor.fetchall()
    
    # Map url -> campaign_id
    url_to_campaign = {}
    for m in members:
        url_to_campaign[m["url"]] = m["campaign_id"]
        
    campaign_pr = {}
    for node, rank in pr.items():
        if node.startswith("domain:"):
            # try to find URL that has this domain
            domain = node.split(":", 1)[1]
            for url, cid in url_to_campaign.items():
                if domain in url:
                    campaign_pr[cid] = campaign_pr.get(cid, 0) + rank
                    
    conn.close()
    
    results = []
    for cid, rank in campaign_pr.items():
        results.append({
            "campaign_id": cid,
            "pagerank": round(rank, 4)
        })
    return results

def compute_connected_components():
    G = _build_graph()
    components = list(nx.connected_components(G))
    results = []
    for i, comp in enumerate(components):
        results.append({
            "component_id": i + 1,
            "nodes": len(comp)
        })
    return results

def compute_campaign_influence():
    # Campaign Influence = (0.4 * Pagerank) + (0.3 * Member Count) + (0.3 * Connected Nodes)
    # Normalize 0-100
    pr_scores = {p["campaign_id"]: p["pagerank"] for p in compute_pagerank()}
    
    conn = sqlite3.connect(THREATS_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT campaign_id, member_count FROM campaigns")
    campaigns = cursor.fetchall()
    conn.close()
    
    if not campaigns:
        return []
        
    max_pr = max(list(pr_scores.values()) + [0.001])
    max_members = max([c["member_count"] for c in campaigns] + [1])
    # Assume connected nodes is roughly proportional to member count for simplicity in disconnected DBs
    max_connected = max_members * 2
    
    results = []
    for c in campaigns:
        cid = c["campaign_id"]
        pr = pr_scores.get(cid, 0)
        members = c["member_count"]
        connected = members * 1.5 # Proxy for connected nodes
        
        pr_norm = min(1.0, pr / max_pr)
        mem_norm = min(1.0, members / max_members)
        conn_norm = min(1.0, connected / max_connected)
        
        influence = (0.4 * pr_norm) + (0.3 * mem_norm) + (0.3 * conn_norm)
        influence_score = min(100, int(influence * 100))
        
        results.append({
            "campaign_id": cid,
            "influence_score": influence_score
        })
        
    return results

def compute_brand_influence():
    # Placeholder for brand influence based on nodes
    pass

def compute_tld_influence():
    # Placeholder for tld influence based on nodes
    pass
