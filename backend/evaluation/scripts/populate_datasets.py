import os
import json
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")

# Categories & targets
CATEGORIES = {
    "benign_qr": 500,
    "phishing_qr": 500,
    "upi_fraud_qr": 200,
    "tampered_qr": 200,
    "impersonation_qr": 200,
    "campaign_variants": 200
}

# Source pools
BENIGN_DOMAINS = ["gov.in", "harvard.edu", "mit.edu", "wikipedia.org", "github.com", "amazon.com", "sbi.co.in", "hdfcbank.com"]
PHISHING_DOMAINS = ["secure-login-verify.xyz", "paypal-security-update.top", "login-bank-sbi.net", "paytm-cashback-portal.xyz"]
UPI_VPAS = ["merchant@okaxis", "refund-claim@paytm", "support-sbi@upi", "cashback-agent@ybl"]
BRANDS = ["Google", "Microsoft", "PayPal", "Amazon", "Paytm", "SBI", "HDFC", "ICICI"]

def create_dataset_metadata(category: str, count: int) -> list:
    samples = []
    for i in range(1, count + 1):
        sample_id = f"{category}_{i:03d}"
        created_at = "2026-06-19T22:58:15Z"
        notes = f"Generated benchmark record for {category}"
        
        # Select realistic payloads based on category
        if category == "benign_qr":
            domain = random.choice(BENIGN_DOMAINS)
            payload = f"https://{domain}/portal/index.html?ref=safeqr"
            label = "SAFE"
            ground_truth = {"domain": domain, "category": "education_or_gov", "is_tampered": False}
        elif category == "phishing_qr":
            domain = random.choice(PHISHING_DOMAINS)
            payload = f"http://{domain}/login/verify.php"
            label = "MALICIOUS"
            ground_truth = {"domain": domain, "phishing_kw": ["login", "verify"], "is_tampered": False}
        elif category == "upi_fraud_qr":
            vpa = random.choice(UPI_VPAS)
            payload = f"upi://pay?pa={vpa}&pn=ScamMerchant&am=-500.00"
            label = "MALICIOUS"
            ground_truth = {"vpa": vpa, "amount": -500.0, "reason": "negative_amount_refund"}
        elif category == "tampered_qr":
            payload = "https://legitimate-domain.com/pay"
            label = "SUSPICIOUS"
            ground_truth = {"is_tampered": True, "tamper_type": random.choice(["sticker_overlay", "quiet_zone_intrusion", "edge_artifacts"])}
        elif category == "impersonation_qr":
            brand = random.choice(BRANDS)
            payload = f"https://{brand.lower()}-verify-credentials.xyz/auth"
            label = "MALICIOUS"
            ground_truth = {"impersonated_brand": brand, "typosquat": True}
        else: # campaign_variants
            campaign_id = random.choice(["CAMP_ALPHA", "CAMP_BETA", "CAMP_GAMMA"])
            generation = random.randint(1, 4)
            payload = f"http://{campaign_id.lower()}-mutated-gen{generation}.top/verify"
            label = "MALICIOUS"
            ground_truth = {"campaign": campaign_id, "generation": generation, "ttp_fingerprint": {"tlds": [".top"]}}

        samples.append({
            "sample_id": sample_id,
            "dataset": "QRIntel",
            "category": category,
            "payload": payload,
            "label": label,
            "created_at": created_at,
            "ground_truth": ground_truth,
            "notes": notes
        })
    return samples

def populate_all():
    print("[QRIntel Dataset Engine] Initiating QRIntel generation suite...")
    for cat, count in CATEGORIES.items():
        cat_dir = os.path.join(DATASETS_DIR, cat)
        os.makedirs(cat_dir, exist_ok=True)
        
        samples = create_dataset_metadata(cat, count)
        meta_path = os.path.join(cat_dir, "metadata.json")
        with open(meta_path, "w") as f:
            json.dump({"samples": samples, "total": len(samples)}, f, indent=2)
        print(f"[QRIntel Dataset Engine] Wrote {len(samples)} metadata records to {cat}/metadata.json")

if __name__ == "__main__":
    populate_all()
