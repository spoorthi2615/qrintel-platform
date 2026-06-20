"""
qr_decoder.py
Robust OpenCV-based QR code decoder with 5 fallback strategies.
Handles blurry, low-contrast, and small QR code images.
"""

import cv2
import numpy as np


def _decode_with_detector(img: np.ndarray, method_name: str) -> dict:
    """Attempt QR decoding on a single image array."""
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)
    if bbox is not None and data:
        return {
            'success': True,
            'payload': data.strip(),
            'method': method_name,
            'confidence': 1.0,
        }
    return None


def decode_qr_image(image_bytes: bytes) -> dict:
    """
    Attempt to decode a QR code from raw image bytes using multiple strategies.

    Strategies (in order):
      1. Original image (color)
      2. Grayscale conversion
      3. CLAHE contrast enhancement
      4. Adaptive thresholding
      5. 2× upscaled image

    Args:
        image_bytes: Raw bytes of the image file (PNG, JPG, etc.).

    Returns:
        Dict with: success (bool), payload (str), method (str), confidence (float),
                   and optionally error (str).
    """
    if not image_bytes:
        return {'success': False, 'error': 'No image data provided'}

    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            return {'success': False, 'error': 'Could not decode image — unsupported format'}

        # --- Strategy 1: Original color image ---
        result = _decode_with_detector(img, 'original')
        if result:
            return result

        # --- Strategy 2: Grayscale ---
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        result = _decode_with_detector(gray, 'grayscale')
        if result:
            return result

        # --- Strategy 3: CLAHE contrast enhancement ---
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        result = _decode_with_detector(enhanced, 'clahe_enhanced')
        if result:
            return result

        # --- Strategy 4: Adaptive thresholding ---
        thresh = cv2.adaptiveThreshold(
            gray, 255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            11, 2
        )
        result = _decode_with_detector(thresh, 'adaptive_threshold')
        if result:
            return result

        # --- Strategy 5: 2× upscale ---
        h, w = img.shape[:2]
        upscaled = cv2.resize(img, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
        result = _decode_with_detector(upscaled, 'upscaled_2x')
        if result:
            return result

        # --- Strategy 6: Histogram Equalization ---
        equalized = cv2.equalizeHist(gray)
        result = _decode_with_detector(equalized, 'histogram_equalized')
        if result:
            return result

        # --- Strategy 7: Sharpening Filter ---
        sharpen_kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
        sharpened = cv2.filter2D(gray, -1, sharpen_kernel)
        result = _decode_with_detector(sharpened, 'sharpened')
        if result:
            return result

        # --- Strategy 8: Otsu Thresholding ---
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        result = _decode_with_detector(otsu, 'otsu_threshold')
        if result:
            return result

        return {
            'success': False,
            'error': 'No QR code detected in image after 8 decoding strategies',
        }

    except Exception as e:
        return {'success': False, 'error': f'QR decoding exception: {str(e)}'}
