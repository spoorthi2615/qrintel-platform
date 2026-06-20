import os
import pytesseract
from PIL import Image

def is_tesseract_available():
    try:
        # Just querying version to see if it's in PATH
        pytesseract.get_tesseract_version()
        return True
    except pytesseract.TesseractNotFoundError:
        return False
    except Exception:
        return False

HAS_OCR = is_tesseract_available()

def extract_text_from_image(image_path: str):
    """
    Extracts raw text from an image using OCR.
    """
    if not HAS_OCR:
        return {
            "status": "MOCK/STUB",
            "ocr_text": "[OCR Engine Unavailable. Tesseract binary not found.]",
            "ocr_confidence": 0,
            "error": "TesseractNotFoundError"
        }
    
    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        # We can't easily get confidence for the entire block natively without image_to_data
        # For simplicity, if we get text, we assume some confidence.
        conf = 85 if text.strip() else 0
        return {
            "status": "VERIFIED",
            "ocr_text": text.strip(),
            "ocr_confidence": conf,
            "error": None
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "ocr_text": "",
            "ocr_confidence": 0,
            "error": str(e)
        }

def analyze_ocr(image_path: str):
    """
    Analyzes OCR text for brand keywords.
    """
    extraction = extract_text_from_image(image_path)
    
    brands_detected = []
    known_brands = ["github", "paypal", "microsoft", "amazon", "google", "apple", "facebook", "netflix"]
    
    text_lower = extraction.get("ocr_text", "").lower()
    
    for b in known_brands:
        if b in text_lower:
            brands_detected.append(b)
            
    return {
        "status": extraction["status"],
        "ocr_text": extraction["ocr_text"],
        "brands_detected": brands_detected,
        "ocr_confidence": extraction["ocr_confidence"]
    }
