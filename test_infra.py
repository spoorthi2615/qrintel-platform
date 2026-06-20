import os
import sys
import json
import time

sys.path.append(os.path.abspath('backend'))
from core.infrastructure_intel import analyze_infrastructure

def test_infra():
    print("Testing benign domain: google.com (First Run - should hit network)")
    start = time.time()
    res_benign = analyze_infrastructure("https://google.com")
    print(f"Time: {time.time() - start:.2f}s")
    
    print("\nTesting benign domain: google.com (Second Run - should hit cache)")
    start = time.time()
    res_benign_cached = analyze_infrastructure("https://google.com")
    print(f"Time: {time.time() - start:.2f}s")
    
    # Just to verify output structure is identical
    assert res_benign == res_benign_cached

if __name__ == "__main__":
    test_infra()
