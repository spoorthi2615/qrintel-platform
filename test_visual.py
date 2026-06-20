import os
import sys

sys.path.append(os.path.abspath('backend'))
from core.visual_similarity import analyze_visual_similarity
from core.risk_engine import calculate_risk

def test_visual_similarity():
    # 1. Test pure similarity calculation against a genuine github screenshot
    # We use the modified clone screenshot as the "target"
    target_path = 'backend/assets/evil_github.png'
    print(f"Testing visual similarity for {target_path}...")
    res = analyze_visual_similarity(target_path)
    print("Similarity Result:", res)
    
    # 2. Test risk engine override with deceptive domain
    analysis_results = {
        'url': {'score': 10, 'domain': 'github-login-security-check.net'},
        'visual_intel': res
    }
    
    risk = calculate_risk('https://github-login-security-check.net', 'URL', analysis_results)
    print("\nRisk Engine Result:")
    print("Score:", risk['score'])
    print("Status:", risk['status'])
    print("Reasons:", risk['final_reasons'])
    print("Breakdown:", risk['breakdown'])

if __name__ == "__main__":
    test_visual_similarity()
