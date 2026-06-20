"""
entropy.py
Shannon entropy analysis for QR payloads.
Detects obfuscation, encoded strings, and suspicious randomness.
"""

import math
from collections import Counter


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    Higher values indicate more randomness / potential obfuscation.
    Typical readable English text: ~4.0 bits
    Random Base64 / URLs with tokens: ~5.5+ bits

    Args:
        data: Input string.

    Returns:
        Entropy value in bits (float).
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def evaluate_entropy_risk(entropy: float, payload_type: str) -> dict:
    """
    Evaluate the entropy value into a risk score with a human-readable label.

    Args:
        entropy:      Shannon entropy value.
        payload_type: Payload classification type (e.g. 'URL', 'UPI', 'TEXT').

    Returns:
        Dict with keys: score (0-100), label (str), explanation (str).
    """
    # Base thresholds vary slightly by type
    if payload_type == "URL":
        if entropy > 5.5:
            return {
                "score": 80,
                "label": "Very High",
                "explanation": (
                    f"Entropy {entropy:.2f} bits — extremely high randomness suggests "
                    "obfuscated tokens, encoded data, or malicious payload."
                ),
            }
        elif entropy > 4.8:
            return {
                "score": 40,
                "label": "High",
                "explanation": (
                    f"Entropy {entropy:.2f} bits — elevated randomness may indicate "
                    "tracking parameters or encoded strings."
                ),
            }
        elif entropy > 4.0:
            return {
                "score": 15,
                "label": "Moderate",
                "explanation": (
                    f"Entropy {entropy:.2f} bits — moderate randomness, typical of "
                    "legitimate URLs with query parameters."
                ),
            }
        else:
            return {
                "score": 0,
                "label": "Low",
                "explanation": (
                    f"Entropy {entropy:.2f} bits — low randomness consistent with "
                    "clean, readable URLs."
                ),
            }

    elif payload_type == "UPI":
        if entropy > 5.0:
            return {
                "score": 50,
                "label": "High",
                "explanation": (
                    f"Entropy {entropy:.2f} bits — UPI strings should be low-entropy. "
                    "This value indicates possible obfuscation."
                ),
            }
        return {
            "score": 0,
            "label": "Normal",
            "explanation": f"Entropy {entropy:.2f} bits — normal for UPI strings.",
        }

    else:
        # Generic text, vCard, etc.
        if entropy > 5.5:
            return {
                "score": 30,
                "label": "High",
                "explanation": (
                    f"Entropy {entropy:.2f} bits — unusually random for plain text."
                ),
            }
        return {
            "score": 0,
            "label": "Normal",
            "explanation": f"Entropy {entropy:.2f} bits — within expected range.",
        }
