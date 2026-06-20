import os
import cv2
import json
import imagehash
from PIL import Image
from skimage.metrics import structural_similarity as ssim

REFERENCES_DIR = os.path.join(os.path.dirname(__file__), '..', 'assets', 'reference_logins')

def analyze_visual_similarity(screenshot_path: str) -> dict:
    """
    Compare the provided screenshot against known reference login pages.
    Returns the target_brand and various similarity metrics (0-100%).
    """
    best_match = {
        "target_brand": None,
        "phash_similarity": 0.0,
        "dhash_similarity": 0.0,
        "ssim_similarity": 0.0,
        "final_similarity": 0.0
    }
    
    if not screenshot_path or not os.path.exists(screenshot_path):
        return best_match
        
    try:
        target_img = Image.open(screenshot_path)
        target_phash = imagehash.phash(target_img)
        target_dhash = imagehash.dhash(target_img)
        
        target_cv = cv2.imread(screenshot_path)
        if target_cv is None:
            return best_match
            
        target_cv_gray = cv2.cvtColor(target_cv, cv2.COLOR_BGR2GRAY)
        # Resize to fixed size for SSIM to handle different screen resolutions
        target_cv_gray = cv2.resize(target_cv_gray, (800, 600))
        
        if not os.path.exists(REFERENCES_DIR):
            return best_match

        for ref_file in os.listdir(REFERENCES_DIR):
            if not ref_file.endswith(('.png', '.jpg', '.jpeg')):
                continue
                
            brand_name = os.path.splitext(ref_file)[0]
            ref_path = os.path.join(REFERENCES_DIR, ref_file)
            
            # Hash comparison
            ref_img = Image.open(ref_path)
            ref_phash = imagehash.phash(ref_img)
            ref_dhash = imagehash.dhash(ref_img)
            
            # Hash difference (0 means identical, max is 64 bits)
            # Convert to percentage
            phash_sim = max(0, (1 - (target_phash - ref_phash) / 64.0)) * 100
            dhash_sim = max(0, (1 - (target_dhash - ref_dhash) / 64.0)) * 100
            
            # SSIM Comparison
            ref_cv = cv2.imread(ref_path)
            if ref_cv is not None:
                ref_cv_gray = cv2.cvtColor(ref_cv, cv2.COLOR_BGR2GRAY)
                ref_cv_gray = cv2.resize(ref_cv_gray, (800, 600))
                
                # compute SSIM
                s, _ = ssim(target_cv_gray, ref_cv_gray, full=True)
                ssim_sim = max(0, s) * 100
            else:
                ssim_sim = 0.0
                
            # Weighted Final Similarity (Hashes are more robust to minor UI changes than pure SSIM)
            final_sim = (phash_sim * 0.4) + (dhash_sim * 0.4) + (ssim_sim * 0.2)
            
            if final_sim > best_match["final_similarity"]:
                best_match = {
                    "target_brand": brand_name,
                    "phash_similarity": round(phash_sim, 2),
                    "dhash_similarity": round(dhash_sim, 2),
                    "ssim_similarity": round(ssim_sim, 2),
                    "final_similarity": round(final_sim, 2)
                }

    except Exception as e:
        print(f"Visual Similarity Error: {e}")
        
    return best_match
