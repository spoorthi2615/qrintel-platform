import os
import sqlite3

HISTORY_DB = os.path.join(os.path.dirname(__file__), '..', 'database', 'history.db')

def propagate_trust(start_node_id: str, max_hops: int = 3):
    if not os.path.exists(HISTORY_DB):
        return []
        
    conn = sqlite3.connect(HISTORY_DB)
    conn.row_factory = sqlite3.Row
    
    start = conn.execute(
        "SELECT risk_score FROM graph_nodes WHERE node_id=?", (start_node_id,)
    ).fetchone()
    
    if not start:
        conn.close()
        return []
        
    initial_risk = start["risk_score"] or 0
    if initial_risk == 0:
        conn.close()
        return []

    visited = {start_node_id}
    queue = [(start_node_id, initial_risk, 0)]
    propagations = []

    while queue:
        node_id, risk, hop = queue.pop(0)
        if hop >= max_hops:
            continue

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
            propagated_risk = risk * edge_weight
            
            if propagated_risk > 0:
                conn.execute(
                    """UPDATE graph_nodes 
                       SET propagated_risk = MAX(propagated_risk, ?) 
                       WHERE node_id = ?""",
                    (propagated_risk, neighbor_id)
                )
                propagations.append({
                    "node_id": neighbor_id,
                    "propagated_risk": round(propagated_risk, 2)
                })
                
                queue.append((neighbor_id, propagated_risk, hop + 1))

    conn.commit()
    conn.close()
    return propagations
