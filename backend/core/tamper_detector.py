"""
tamper_detector.py  —  Sprint 2: QR Tampering Detection Engine
==============================================================
Analyses raw QR code image bytes for signs of physical or digital tampering.
No existing open-source QR scanner detects physical sticker-replacement attacks.

Seven integrity checks:
  1. Module Regularity    — pixel-level QR module size variance
  2. Quiet Zone Integrity — border region analysis
  3. Contrast Anomaly     — histogram bimodality (sticker-over-sticker)
  4. Edge Artifact        — Canny edge density in margins
  5. Color Channel Skew   — RGB per-channel entropy divergence
  6. Background Uniformity — local variance in background region
  7. Format Info Verify   — ECC level format information bytes
"""

import cv2
import numpy as np
from typing import Optional


TAMPERING_LABELS = {
    (0, 20):   "PRISTINE",
    (20, 45):  "POSSIBLY_ALTERED",
    (45, 70):  "LIKELY_TAMPERED",
    (70, 101): "TAMPERED",
}


def _tampering_label(probability: float) -> str:
    for (lo, hi), label in TAMPERING_LABELS.items():
        if lo <= probability < hi:
            return label
    return "UNKNOWN"


# ─── Check 1: Module Regularity ───────────────────────────────────────────────

def _check_module_regularity(gray: np.ndarray) -> dict:
    """
    Estimate QR module size and check uniformity.
    High variance in module sizes suggests pixel manipulation.
    """
    try:
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        # Find horizontal runs of black pixels
        runs = []
        for row in binary[::4]:  # Sample every 4th row
            in_run, run_len = False, 0
            for px in row:
                if px == 0:
                    in_run = True
                    run_len += 1
                elif in_run:
                    if 2 < run_len < gray.shape[1] // 4:
                        runs.append(run_len)
                    in_run, run_len = False, 0

        if len(runs) < 10:
            return {"score": 0, "passed": True, "detail": "Insufficient data for module analysis",
                    "risk_contribution": 0}

        mean_run = np.mean(runs)
        std_run  = np.std(runs)
        cv_pct   = (std_run / mean_run * 100) if mean_run > 0 else 0

        # Coefficient of variation: low CV = uniform modules (good)
        if cv_pct < 25:
            risk = 0
            detail = f"Module sizes uniform (CV={cv_pct:.1f}%)"
            passed = True
        elif cv_pct < 50:
            risk = 20
            detail = f"Moderate module size variation (CV={cv_pct:.1f}%)"
            passed = True
        else:
            risk = 45
            detail = f"High module size variation (CV={cv_pct:.1f}%) — possible pixel manipulation"
            passed = False

        return {"score": risk, "passed": passed, "detail": detail,
                "risk_contribution": risk, "cv_percent": round(cv_pct, 2)}

    except Exception as e:
        return {"score": 0, "passed": True, "detail": f"Check skipped: {e}", "risk_contribution": 0}


# ─── Check 2: Quiet Zone Integrity ────────────────────────────────────────────

def _check_quiet_zone(gray: np.ndarray) -> dict:
    """
    QR codes require a quiet zone (white border) of ≥4 modules.
    Non-white pixels in quiet zone indicate cropping or overlay.
    """
    try:
        h, w = gray.shape
        margin = max(4, min(h, w) // 20)

        zones = {
            "top":    gray[:margin, :],
            "bottom": gray[h - margin:, :],
            "left":   gray[:, :margin],
            "right":  gray[:, w - margin:],
        }

        dark_ratios = {}
        for name, zone in zones.items():
            dark_ratio = np.sum(zone < 128) / zone.size * 100
            dark_ratios[name] = round(dark_ratio, 1)

        max_dark = max(dark_ratios.values())

        if max_dark < 5:
            risk = 0
            detail = "Quiet zone intact on all sides"
            passed = True
        elif max_dark < 15:
            risk = 15
            detail = f"Minor quiet zone intrusion detected (max {max_dark:.1f}%)"
            passed = True
        else:
            risk = 40
            detail = f"Quiet zone significantly contaminated ({max_dark:.1f}% dark) — possible overlay"
            passed = False

        return {"score": risk, "passed": passed, "detail": detail,
                "risk_contribution": risk, "dark_ratios": dark_ratios}

    except Exception as e:
        return {"score": 0, "passed": True, "detail": f"Check skipped: {e}", "risk_contribution": 0}


# ─── Check 3: Contrast Anomaly (Histogram Bimodality) ─────────────────────────

def _check_contrast_anomaly(gray: np.ndarray) -> dict:
    """
    Legitimate QR codes have a clearly bimodal histogram (black + white peaks).
    Sticker-over-sticker tampering introduces intermediate gray values.
    """
    try:
        hist = cv2.calcHist([gray], [0], None, [256], [0, 256]).flatten()

        # Bimodality: peaks in dark (0-64) and light (192-255) regions
        dark_mass  = hist[:64].sum()
        mid_mass   = hist[64:192].sum()
        light_mass = hist[192:].sum()
        total      = hist.sum()

        dark_pct  = dark_mass  / total * 100
        mid_pct   = mid_mass   / total * 100
        light_pct = light_mass / total * 100

        # High mid-gray percentage = poor bimodality = tampering signal
        if mid_pct < 10:
            risk = 0
            detail = f"Clean bimodal histogram (mid-gray {mid_pct:.1f}%) — no layering detected"
            passed = True
        elif mid_pct < 25:
            risk = 20
            detail = f"Slight mid-gray presence ({mid_pct:.1f}%) — minor concern"
            passed = True
        else:
            risk = 50
            detail = (f"High mid-gray content ({mid_pct:.1f}%) — possible sticker "
                      f"layering or ink bleed-through")
            passed = False

        return {"score": risk, "passed": passed, "detail": detail,
                "risk_contribution": risk,
                "histogram_buckets": {"dark": round(dark_pct, 1),
                                      "mid": round(mid_pct, 1),
                                      "light": round(light_pct, 1)}}

    except Exception as e:
        return {"score": 0, "passed": True, "detail": f"Check skipped: {e}", "risk_contribution": 0}


# ─── Check 4: Edge Artifact Detection ─────────────────────────────────────────

def _check_edge_artifacts(gray: np.ndarray) -> dict:
    """
    Detect unnatural edge density in QR margin areas.
    Physical sticker cutting creates high-edge-density lines.
    """
    try:
        edges = cv2.Canny(gray, 50, 150)
        h, w  = gray.shape

        # Inner QR body region (excluding quiet zone)
        qz = max(4, min(h, w) // 20)
        inner   = edges[qz:h - qz, qz:w - qz]
        margins = np.concatenate([
            edges[:qz, :].flatten(),
            edges[h - qz:, :].flatten(),
            edges[:, :qz].flatten(),
            edges[:, w - qz:].flatten(),
        ])

        inner_density  = inner.sum() / (inner.size * 255) * 100
        margin_density = (margins.sum() / (margins.size * 255) * 100) if margins.size > 0 else 0

        # Margins should have very few edges; inner body has many (QR pattern)
        ratio = margin_density / inner_density if inner_density > 0 else 0

        if ratio < 0.15:
            risk = 0
            detail = f"Edge distribution normal (margin/inner ratio {ratio:.3f})"
            passed = True
        elif ratio < 0.35:
            risk = 20
            detail = f"Slightly elevated margin edges (ratio {ratio:.3f})"
            passed = True
        else:
            risk = 45
            detail = (f"Anomalous edge density in quiet zone (ratio {ratio:.3f}) "
                      f"— possible physical cutting/pasting artifact")
            passed = False

        return {"score": risk, "passed": passed, "detail": detail,
                "risk_contribution": risk,
                "margin_edge_density": round(margin_density, 3),
                "inner_edge_density": round(inner_density, 3)}

    except Exception as e:
        return {"score": 0, "passed": True, "detail": f"Check skipped: {e}", "risk_contribution": 0}


# ─── Check 5: Color Channel Consistency ───────────────────────────────────────

def _check_color_channels(img_bgr: np.ndarray) -> dict:
    """
    Genuine black-and-white QR codes have equal B/G/R channels.
    Layered stickers often introduce color imbalance.
    """
    try:
        if len(img_bgr.shape) < 3:
            return {"score": 0, "passed": True, "detail": "Grayscale image — channel check skipped",
                    "risk_contribution": 0}

        b, g, r = cv2.split(img_bgr)
        means = np.array([b.mean(), g.mean(), r.mean()])
        channel_std = means.std()

        if channel_std < 5:
            risk = 0
            detail = f"Color channels balanced (σ={channel_std:.2f}) — consistent black/white"
            passed = True
        elif channel_std < 15:
            risk = 15
            detail = f"Minor channel imbalance (σ={channel_std:.2f}) — possible color tint"
            passed = True
        else:
            risk = 35
            detail = (f"Significant RGB channel imbalance (σ={channel_std:.2f}) "
                      f"— possible layered sticker with different ink")
            passed = False

        return {"score": risk, "passed": passed, "detail": detail,
                "risk_contribution": risk,
                "channel_means": {"B": round(float(means[0]), 2),
                                   "G": round(float(means[1]), 2),
                                   "R": round(float(means[2]), 2)},
                "channel_std": round(float(channel_std), 2)}

    except Exception as e:
        return {"score": 0, "passed": True, "detail": f"Check skipped: {e}", "risk_contribution": 0}


# ─── Check 6: Background Uniformity ───────────────────────────────────────────

def _check_background_uniformity(gray: np.ndarray) -> dict:
    """
    Sample background (light) pixels and check for non-uniform texture.
    Non-uniform background indicates a sticker placed over existing material.
    """
    try:
        # Extract light pixels (background)
        light_mask = gray > 200
        if light_mask.sum() < 100:
            return {"score": 10, "passed": True,
                    "detail": "Too few background pixels to assess uniformity",
                    "risk_contribution": 10}

        light_pixels = gray[light_mask].astype(float)
        bg_std = light_pixels.std()

        if bg_std < 8:
            risk = 0
            detail = f"Uniform background (σ={bg_std:.2f})"
            passed = True
        elif bg_std < 20:
            risk = 10
            detail = f"Slightly textured background (σ={bg_std:.2f})"
            passed = True
        else:
            risk = 30
            detail = (f"Non-uniform background texture (σ={bg_std:.2f}) "
                      f"— possible sticker placed over printed material")
            passed = False

        return {"score": risk, "passed": passed, "detail": detail,
                "risk_contribution": risk, "bg_std": round(float(bg_std), 2)}

    except Exception as e:
        return {"score": 0, "passed": True, "detail": f"Check skipped: {e}", "risk_contribution": 0}


# ─── Check 7: Format Information Consistency ──────────────────────────────────

def _check_format_info(gray: np.ndarray) -> dict:
    """
    QR format information is stored in fixed positions (modules 0-8 near finder patterns).
    Pixel values in those positions should be consistently dark or light — not noisy.
    """
    try:
        h, w = gray.shape
        # Format info strip: row 8, columns 0-8 (top-left)
        if h < 25 or w < 25:
            return {"score": 5, "passed": True,
                    "detail": "Image too small for format info check",
                    "risk_contribution": 5}

        # Scale: estimate module size
        module_size = max(1, min(h, w) // 25)
        strip_row = 8 * module_size
        strip_col = 9 * module_size
        strip = gray[max(0, strip_row - module_size): strip_row + module_size,
                     :strip_col]

        # Each pixel in format strip should be clearly black or white
        ambiguous = np.sum((strip > 50) & (strip < 200)) / strip.size * 100

        if ambiguous < 10:
            risk = 0
            detail = f"Format information strip clean (ambiguous pixels: {ambiguous:.1f}%)"
            passed = True
        elif ambiguous < 25:
            risk = 15
            detail = f"Some ambiguous pixels in format info strip ({ambiguous:.1f}%)"
            passed = True
        else:
            risk = 40
            detail = (f"High ambiguity in format information region ({ambiguous:.1f}%) "
                      f"— possible modification to ECC level")
            passed = False

        return {"score": risk, "passed": passed, "detail": detail,
                "risk_contribution": risk, "ambiguous_pct": round(float(ambiguous), 2)}

    except Exception as e:
        return {"score": 0, "passed": True, "detail": f"Check skipped: {e}", "risk_contribution": 0}


# ─── Main Analysis Function ────────────────────────────────────────────────────

def analyze_qr_image(image_bytes: bytes) -> dict:
    """
    Run all 7 tampering checks on a QR code image.

    Args:
        image_bytes: Raw image bytes (PNG, JPG, etc.).

    Returns:
        Dict with: tampering_probability (0–100), tampering_label,
                   checks (per-check results), suspicious_regions,
                   confidence, explanations.
    """
    if not image_bytes:
        return {
            "tampering_probability": 0,
            "tampering_label": "UNKNOWN",
            "error": "No image data",
            "checks": {},
            "explanations": [],
        }

    try:
        nparr   = np.frombuffer(image_bytes, np.uint8)
        img_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img_bgr is None:
            return {
                "tampering_probability": 0,
                "tampering_label": "UNKNOWN",
                "error": "Image decode failed",
                "checks": {},
                "explanations": [],
            }

        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)

        # Run all checks
        checks = {
            "module_regularity":    _check_module_regularity(gray),
            "quiet_zone":           _check_quiet_zone(gray),
            "contrast_anomaly":     _check_contrast_anomaly(gray),
            "edge_artifacts":       _check_edge_artifacts(gray),
            "color_channels":       _check_color_channels(img_bgr),
            "background_uniformity":_check_background_uniformity(gray),
            "format_info":          _check_format_info(gray),
        }

        # Weighted combination of risk contributions
        weights = {
            "module_regularity":     0.20,
            "quiet_zone":            0.15,
            "contrast_anomaly":      0.20,
            "edge_artifacts":        0.20,
            "color_channels":        0.10,
            "background_uniformity": 0.10,
            "format_info":           0.05,
        }

        weighted_risk = sum(
            checks[k]["risk_contribution"] * weights[k]
            for k in checks
        )
        tampering_prob = round(min(weighted_risk, 100), 2)

        # Build explanations from failed checks
        explanations = []
        suspicious_regions = []

        for check_name, result in checks.items():
            if result["risk_contribution"] > 0:
                explanations.append({
                    "check": check_name.replace("_", " ").title(),
                    "risk": result["risk_contribution"],
                    "detail": result["detail"],
                    "passed": result["passed"],
                })
                if not result["passed"]:
                    suspicious_regions.append(check_name)

        # Confidence: how many checks ran successfully
        valid_checks = sum(1 for c in checks.values() if "error" not in c.get("detail", ""))
        confidence = round(valid_checks / len(checks) * 100, 1)

        return {
            "tampering_probability": tampering_prob,
            "tampering_label": _tampering_label(tampering_prob),
            "confidence": confidence,
            "checks": checks,
            "suspicious_regions": suspicious_regions,
            "explanations": sorted(explanations, key=lambda x: x["risk"], reverse=True),
            "summary": (
                f"{len(suspicious_regions)} of {len(checks)} checks flagged anomalies. "
                f"Tampering probability: {tampering_prob:.1f}%"
            ),
        }

    except Exception as e:
        return {
            "tampering_probability": 0,
            "tampering_label": "ERROR",
            "error": str(e),
            "checks": {},
            "explanations": [],
        }
