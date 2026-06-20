import os
import cv2
import numpy as np
import glob

def check_model_availability():
    """
    Checks if reference logos exist.
    """
    reference_dir = os.path.join(os.path.dirname(__file__), '..', 'assets', 'reference_logos')
    if not os.path.exists(reference_dir):
        return False
    return len(glob.glob(os.path.join(reference_dir, '*.png'))) > 0

HAS_MODEL = check_model_availability()

def detect_logos(image_path: str):
    """
    Implementation of lightweight logo detection using ORB Feature Matching.
    """
    if not HAS_MODEL:
        return {
            "status": "MOCK/STUB",
            "logos_detected": [],
            "confidence": 0,
            "error": "No reference logos available"
        }
        
    try:
        # Load screenshot
        screenshot = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if screenshot is None:
            raise ValueError("Could not read image")
            
        orb = cv2.ORB_create(nfeatures=500)
        kp1, des1 = orb.detectAndCompute(screenshot, None)
        
        if des1 is None:
            return {"status": "VERIFIED", "logos_detected": [], "confidence": 0, "error": None}
            
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        
        reference_dir = os.path.join(os.path.dirname(__file__), '..', 'assets', 'reference_logos')
        logos_detected = []
        highest_conf = 0
        
        for ref_path in glob.glob(os.path.join(reference_dir, '*.png')):
            brand = os.path.basename(ref_path).replace('.png', '')
            ref_img = cv2.imread(ref_path, cv2.IMREAD_GRAYSCALE)
            
            if ref_img is None:
                continue
                
            kp2, des2 = orb.detectAndCompute(ref_img, None)
            
            if des2 is None:
                continue
                
            matches = bf.match(des1, des2)
            matches = sorted(matches, key=lambda x: x.distance)
            
            # Simple confidence metric based on good matches
            good_matches = [m for m in matches if m.distance < 50]
            
            # Threshold to consider a logo detected (varies by logo size, let's use 10 for ORB)
            if len(good_matches) > 10:
                conf = min(int((len(good_matches) / 30) * 100), 100)
                if conf > 50:
                    logos_detected.append(brand)
                    if conf > highest_conf:
                        highest_conf = conf
                        
        return {
            "status": "VERIFIED",
            "logos_detected": logos_detected,
            "confidence": highest_conf,
            "error": None
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "logos_detected": [],
            "confidence": 0,
            "error": str(e)
        }

def analyze_logos(image_path: str):
    """
    Wrapper for logo detection.
    """
    return detect_logos(image_path)
