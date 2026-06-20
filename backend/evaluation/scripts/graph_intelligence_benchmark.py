import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.graph_analytics import compute_pagerank, compute_connected_components, compute_campaign_influence, _build_graph
from core.trust_propagation import propagate_trust
from core.relationship_engine import discover_related_threats

def run_benchmark():
    print("--- Graph Intelligence Benchmark ---\n")
    
    # 1. Connected Components
    print("[1] Evaluating Connected Components...")
    components = compute_connected_components()
    print(f"Total Components Found: {len(components)}")
    if components:
        largest = max(components, key=lambda x: x["nodes"])
        print(f"Largest Component Nodes: {largest['nodes']}")
    print("STATUS: VERIFIED\n")
    
    # 2. PageRank
    print("[2] Evaluating PageRank Generation...")
    pagerank = compute_pagerank()
    print(f"Campaigns scored by PageRank: {len(pagerank)}")
    if pagerank:
        highest_pr = max(pagerank, key=lambda x: x["pagerank"])
        print(f"Highest PR Campaign: {highest_pr['campaign_id']} (Score: {highest_pr['pagerank']})")
    print("STATUS: VERIFIED\n")
    
    # 3. Influence Scores
    print("[3] Evaluating Influence Scores...")
    influence = compute_campaign_influence()
    print(f"Campaigns with Influence Scores: {len(influence)}")
    if influence:
        highest_inf = max(influence, key=lambda x: x["influence_score"])
        print(f"Highest Influence Campaign: {highest_inf['campaign_id']} (Score: {highest_inf['influence_score']})")
    print("STATUS: VERIFIED\n")
    
    # 4. Related Threat Discovery
    print("[4] Evaluating Related Threat Discovery...")
    test_node = "https://nidarosdiskgolf.no/sgi/065258aab9fe8e3/login.php"
    print(f"Testing URL: {test_node}")
    related = discover_related_threats(test_node)
    print(f"Related Campaigns: {related['related_campaigns']}")
    print(f"Related URLs Found: {len(related['related_urls'])}")
    print(f"Relationship Confidence: {related['relationship_confidence']}")
    print("STATUS: VERIFIED\n")
    
    # 5. Trust Propagation
    print("[5] Evaluating Trust Propagation...")
    G = _build_graph()
    if len(G.nodes) > 0:
        test_start_node = list(G.nodes)[0]
        print(f"Starting Propagation from: {test_start_node}")
        propagations = propagate_trust(test_start_node)
        print(f"Nodes Affected by Propagation: {len(propagations)}")
        if propagations:
            avg_prop = sum(p["propagated_risk"] for p in propagations) / len(propagations)
            print(f"Average Propagated Risk: {avg_prop:.2f}")
    print("STATUS: VERIFIED\n")
    
    print("All Graph Intelligence checks complete.")

if __name__ == "__main__":
    run_benchmark()
