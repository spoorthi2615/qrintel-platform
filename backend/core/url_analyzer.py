"""
url_analyzer.py
Orchestrates URL risk analysis by combining Shannon entropy and heuristic checks
into a single weighted result dict.
"""

from core.entropy import calculate_shannon_entropy, evaluate_entropy_risk
from core.heuristics import check_url_heuristics


def analyze_url(url: str) -> dict:
    """
    Run the full URL intelligence pipeline.

    Weights:
      Entropy score   : 20%
      Heuristic score : 80%

    Args:
        url: The URL string to analyze.

    Returns:
        Dict with: score, status, entropy, entropy_label, entropy_score,
                   heuristic_score, reasons, details.
    """
    # --- Entropy Analysis ---
    entropy_val = calculate_shannon_entropy(url)
    entropy_result = evaluate_entropy_risk(entropy_val, 'URL')
    entropy_score = entropy_result['score']
    entropy_label = entropy_result['label']
    entropy_reasons = []
    if entropy_score > 0:
        entropy_reasons.append(entropy_result['explanation'])

    # --- Heuristic Analysis ---
    heuristic_result = check_url_heuristics(url)
    heuristic_score = heuristic_result['score']
    heuristic_reasons = heuristic_result['reasons']
    threat_breakdown = heuristic_result.get('breakdown', {})

    # Incorporate entropy into breakdown
    if entropy_score > 0:
        threat_breakdown['Content Entropy'] = round(entropy_score * 0.20, 1)

    # --- Weighted Final Score ---
    raw_score = (entropy_score * 0.20) + (heuristic_score * 0.80)
    final_score = round(min(raw_score, 100), 2)

    # --- Status ---
    if final_score <= 30:
        status = 'SAFE'
    elif final_score <= 60:
        status = 'SUSPICIOUS'
    else:
        status = 'MALICIOUS'

    all_reasons = heuristic_reasons + entropy_reasons

    return {
        'score': final_score,
        'status': status,
        'entropy': round(entropy_val, 3),
        'entropy_label': entropy_label,
        'entropy_score': entropy_score,
        'heuristic_score': heuristic_score,
        'reasons': all_reasons,
        'breakdown': threat_breakdown,
        'details': {
            'entropy_result': entropy_result,
            'heuristic_result': heuristic_result,
        },
    }
