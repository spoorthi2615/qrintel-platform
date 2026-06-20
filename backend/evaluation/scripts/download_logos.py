import os
import requests
import cv2
import numpy as np

def download_logos():
    logos = {
        "github": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
        "google": "https://upload.wikimedia.org/wikipedia/commons/thumb/c/c1/Google_%22G%22_logo.svg/512px-Google_%22G%22_logo.svg.png",
        "microsoft": "https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/512px-Microsoft_logo.svg.png",
        "amazon": "https://upload.wikimedia.org/wikipedia/commons/thumb/a/a9/Amazon_logo.svg/512px-Amazon_logo.svg.png",
        "paypal": "https://upload.wikimedia.org/wikipedia/commons/thumb/b/b5/PayPal.svg/512px-PayPal.svg.png"
    }

    target_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'assets', 'reference_logos')
    os.makedirs(target_dir, exist_ok=True)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    for brand, url in logos.items():
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                with open(os.path.join(target_dir, f"{brand}.png"), 'wb') as f:
                    f.write(resp.content)
                print(f"Downloaded {brand}.png")
            else:
                print(f"Failed to download {brand}: {resp.status_code}")
                # Create a mock logo using OpenCV
                img = np.zeros((100, 300, 3), dtype=np.uint8)
                cv2.putText(img, brand.upper(), (20, 60), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                cv2.imwrite(os.path.join(target_dir, f"{brand}.png"), img)
        except Exception as e:
            print(f"Error downloading {brand}: {e}")

if __name__ == "__main__":
    download_logos()
