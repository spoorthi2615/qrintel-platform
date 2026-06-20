import json
import sqlite3
import os

from flask import Blueprint, request, jsonify

from core.payload_classifier import classify_payload
from core.entropy import calculate_shannon_entropy, evaluate_entropy_risk
from core.url_analyzer import analyze_url
from core.upi_validator import validate_upi_payload
from core.risk_engine import calculate_risk
from core.screenshot import capture_screenshot
from core.visual_similarity import analyze_visual_similarity
from core.visual_similarity import analyze_visual_similarity
from core.qr_decoder import decode_qr_image
from core.tamper_detector import analyze_qr_image
from core.intelligence_pipeline import enrich_scan
from core.threat_lookup import lookup_threat
from core.content_intelligence import analyze_content as new_analyze_content
from core.redirect_intelligence import analyze_redirects
from core.threat_feed_manager import lookup_threat
from core.feed_sync_scheduler import check_cache
from core.brand_intelligence import analyze_brand_intelligence
from core.dns_intelligence import analyze_dns
from core.ocr_intelligence import analyze_ocr
from core.logo_detection import analyze_logos
from core.infrastructure_intel import analyze_infrastructure

scan_bp = Blueprint('scan', __name__)

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'history.db')


# ─── Helpers ────────────────────────────────────────────────────────────────

def _get_db():
    """Return a SQLite connection to the history database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _save_scan(
    payload, payload_type, payload_display,
    score, status, confidence,
    entropy, entropy_label,
    reasons, breakdown,
    screenshot_b64, signature_status, scan_method,
    conn
) -> int:
    """Persist a scan record and return the new row id using the provided connection."""
    cursor = conn.cursor()
    cursor.execute(
        '''
        INSERT INTO scans
            (payload, payload_type, payload_display,
             risk_score, status, confidence,
             entropy, entropy_label,
             reasons, breakdown,
             screenshot_path, signature_status, scan_method)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            payload, payload_type, payload_display,
            score, status, confidence,
            entropy, entropy_label,
            json.dumps(reasons), json.dumps(breakdown),
            screenshot_b64, signature_status, scan_method,
        ),
    )
    return cursor.lastrowid


def _save_tamper_analysis(scan_id: int, tamper_result: dict, conn) -> None:
    """Persist QR code tampering analysis to the database."""
    if not tamper_result or "error" in tamper_result:
        return
    cursor = conn.cursor()
    cursor.execute(
        '''
        INSERT INTO tamper_analysis
            (scan_id, image_hash, tampering_probability, tampering_label,
             checks_json, suspicious_regions_json, annotated_image_b64)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            scan_id,
            None, # Image hash can be added if needed, otherwise null
            tamper_result.get("tampering_probability", 0),
            tamper_result.get("tampering_label", "UNKNOWN"),
            json.dumps(tamper_result.get("checks", {})),
            json.dumps(tamper_result.get("suspicious_regions", [])),
            None # Optional base64 annotated image
        )
    )


def _analyze_payload(payload: str, scan_method: str = 'manual', image_bytes: bytes = None) -> dict:
    """
    Core analysis pipeline:
      1. Classify payload type
      2. Shannon entropy analysis
      3. URL or UPI analysis (type-specific)
      4. Weighted risk scoring
      5. Screenshot (for URLs, non-blocking)
      6. Persist core scan
      7. Run QR tampering detection (if image_bytes is provided)
      8. Run trust scoring, behavior graph, and campaign attribution pipeline
    """
    # --- 1. Classify ---
    classification = classify_payload(payload)
    payload_type    = classification['type']
    payload_display = classification['display']
    if 'normalized' in classification:
        payload = classification['normalized']

    # --- 2. Entropy ---
    entropy_val    = calculate_shannon_entropy(payload)
    entropy_result = evaluate_entropy_risk(entropy_val, payload_type)

    # --- 3. Type-specific analysis ---
    url_result = {}
    content_result = {}
    visual_result = {}
    threat_result = {}
    infra_result = {}
    dns_result = {}
    upi_result = {}
    brand_result = {}
    redirect_result = {}

    if payload_type == 'URL':
        # 3a. Heuristics & Entropy
        url_result = analyze_url(payload)
        
        # 3b. Redirect Intelligence
        redirect_result = analyze_redirects(payload)
        
        # 3c. Content Intelligence
        final_domain = redirect_result.get("final_domain")
        final_url = redirect_result.get("final_url", payload)
        
        # 3d. Threat Intel (Live Feeds & Premium Cache)
        import urllib.parse
        initial_domain = urllib.parse.urlparse(payload).netloc.split(':')[0]
        
        # Check standard feeds (OpenPhish, URLHaus)
        threat_result = lookup_threat(payload, initial_domain)
        if not threat_result["found"] and final_domain and final_domain != initial_domain:
            threat_result = lookup_threat(final_url, final_domain)
            
        # Check premium cache (VT, GSB, OTX, AbuseIPDB)
        if not threat_result["found"]:
            cache_result = check_cache(payload)
            if not cache_result["found"] and final_url != payload:
                cache_result = check_cache(final_url)
                
            if cache_result["found"]:
                threat_result = {
                    "found": True,
                    "source": ", ".join(cache_result["sources"]),
                    "first_seen": "cache",
                    "confidence": cache_result["risk_score"]
                }
        
        content_result = new_analyze_content(final_url, final_domain)
        
        # 3e. Brand Intelligence
        brand_result = analyze_brand_intelligence(final_url)
        
        # 3f. Infrastructure Intel
        infra_result = analyze_infrastructure(payload)
        
        # 3g. DNS Intel
        dns_result = analyze_dns(final_url) or {}
        
    elif payload_type == 'UPI':
        upi_result = validate_upi_payload(payload)

    # --- 4. Screenshot & Visual Intelligence (URL only) ---
    screenshot_b64 = None
    screenshot_path = None
    visual_result = {}
    
    if payload_type == 'URL' and os.environ.get('QRIntel_SCREENSHOT') != '0':
        try:
            shot_res = capture_screenshot(payload)
            screenshot_b64 = shot_res.get("screenshot_b64")
            screenshot_path = shot_res.get("screenshot_path")
            
            if screenshot_path and os.path.exists(screenshot_path):
                # 4a. Run visual similarity
                from core.visual_similarity import analyze_visual_similarity
                visual_result = analyze_visual_similarity(screenshot_path)
                
                # 4b. Run OCR & Logo Detection
                visual_brand_intel = {
                    "ocr": analyze_ocr(screenshot_path),
                    "logo": analyze_logos(screenshot_path)
                }
        except Exception as e:
            print(f"[scan] Screenshot/Visual error: {e}")
            
    else:
        visual_brand_intel = None

    # --- 5. Risk scoring ---
    analysis_results = {
        'entropy': entropy_result,
        'url':     url_result,
        'threat_intel': threat_result,
        'redirect_intel': redirect_result if payload_type == 'URL' else {},
        'content_intel': content_result if payload_type == 'URL' else {},
        'brand_intel': brand_result if payload_type == 'URL' else {},
        'visual_intel': visual_result if payload_type == 'URL' else {},
        'dns_intel': dns_result,
        'infra':   infra_result,
        'upi':     upi_result,
        'crypto':  {'score': 0, 'status': 'UNSIGNED'},
    }
    risk = calculate_risk(payload, payload_type, analysis_results)

    score      = risk['score']
    status     = risk['status']
    confidence = risk['confidence']
    breakdown  = risk['breakdown']
    reasons    = risk['final_reasons']

    # --- 6. Persist & Enrich within a single connection transaction ---
    conn = _get_db()
    try:
        scan_id = _save_scan(
            payload=payload,
            payload_type=payload_type,
            payload_display=payload_display,
            score=score,
            status=status,
            confidence=confidence,
            entropy=round(entropy_val, 3),
            entropy_label=entropy_result.get('label', 'Normal'),
            reasons=reasons,
            breakdown=breakdown,
            screenshot_b64=screenshot_b64,
            signature_status='UNSIGNED',
            scan_method=scan_method,
            conn=conn,
        )

        # --- 7. QR Tamper Analysis ---
        tamper_result = None
        if image_bytes:
            try:
                tamper_result = analyze_qr_image(image_bytes)
                _save_tamper_analysis(scan_id, tamper_result, conn)
            except Exception as e:
                print(f'[scan] Tamper analysis failed: {e}')

        # --- 8. Intelligence Pipeline Enrichment ---
        enrichment_result = {}
        try:
            enrichment_result = enrich_scan(
                scan_id=scan_id,
                payload=payload,
                payload_type=payload_type,
                risk_data={'score': score, 'status': status, 'reasons': reasons},
                conn=conn
            )
        except Exception as e:
            print(f'[scan] Enrichment failed: {e}')

        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

    return {
        'scan_id':          scan_id,
        'payload':          payload,
        'payload_type':     payload_type,
        'payload_display':  payload_display,
        'score':            score,
        'status':           status,
        'confidence':       confidence,
        'entropy':          round(entropy_val, 3),
        'entropy_label':    entropy_result.get('label', 'Normal'),
        'reasons':          reasons,
        'breakdown':        breakdown,
        'screenshot':       screenshot_b64,
        'signature_status': 'UNSIGNED',
        'upi_fields':       upi_result.get('fields', {}),
        'scan_method':      scan_method,
        'tamper_analysis':  tamper_result,
        'intelligence':     enrichment_result,
        'content_intel':    analysis_results.get('content_intel', {}),
        'redirect_intel':   analysis_results.get('redirect_intel', {}),
        'brand_intel':      analysis_results.get('brand_intel', {}),
        'dns_intel':        analysis_results.get('dns_intel', {}),
        'visual_intel':     analysis_results.get('visual_intel', {}),
        'visual_brand_intel': visual_brand_intel,
        'infra_intel':      analysis_results.get('infra', {}),
        'threat_intel':     analysis_results.get('threat_intel', {}),
    }


# ─── Endpoints ──────────────────────────────────────────────────────────────

@scan_bp.route('/manual', methods=['POST'])
def scan_manual():
    """Scan a manually entered payload (URL, UPI, text, etc.)."""
    data = request.get_json(silent=True) or {}
    payload = (data.get('payload') or '').strip()

    if not payload:
        return jsonify({'error': 'No payload provided'}), 400

    try:
        result = _analyze_payload(payload, scan_method='manual')
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@scan_bp.route('/upload', methods=['POST'])
def scan_upload():
    """Decode a QR code image using OpenCV, then analyze the payload & tampering."""
    if 'image' not in request.files:
        return jsonify({'error': 'No image file in request'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    image_bytes = file.read()
    if not image_bytes:
        return jsonify({'error': 'Image file is empty'}), 400

    decode_result = decode_qr_image(image_bytes)

    if not decode_result.get('success'):
        return jsonify({'error': decode_result.get('error', 'QR code not found')}), 422

    payload = decode_result['payload']

    try:
        result = _analyze_payload(payload, scan_method='upload', image_bytes=image_bytes)
        result['decode_method'] = decode_result.get('method', 'unknown')
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@scan_bp.route('/live', methods=['POST'])
def scan_live():
    """Analyze a payload decoded by the browser camera (html5-qrcode)."""
    data = request.get_json(silent=True) or {}
    payload = (data.get('payload') or '').strip()

    if not payload:
        return jsonify({'error': 'No payload provided'}), 400

    try:
        result = _analyze_payload(payload, scan_method='live')
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

