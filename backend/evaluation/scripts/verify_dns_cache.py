import sys
import os
import time
import sqlite3

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from core.dns_intelligence import analyze_dns

def verify_cache():
    CACHE_DB = os.path.join(os.path.dirname(__file__), '..', '..', 'database', 'dns_cache.db')
    
    # 1. Clear existing cache for a clean benchmark
    if os.path.exists(CACHE_DB):
        conn = sqlite3.connect(CACHE_DB)
        conn.execute("DELETE FROM dns_cache")
        conn.commit()
        conn.close()

    test_domain = "https://netflix.com"
    
    # 2. First Lookup (Uncached)
    start = time.time()
    analyze_dns(test_domain)
    first_lookup_time = time.time() - start
    
    # 3. Second Lookup (Cached)
    start = time.time()
    analyze_dns(test_domain)
    cached_lookup_time = time.time() - start
    
    # 4. Verify DB state
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    schema = c.execute("PRAGMA table_info(dns_cache)").fetchall()
    count = c.execute("SELECT COUNT(*) FROM dns_cache").fetchone()[0]
    conn.close()
    
    print("--- DNS Cache Benchmark ---")
    print("Schema:")
    for col in schema:
        print(f"  {col[1]} ({col[2]})")
    
    print("\nTTL: 24 Hours (86400 seconds)")
    print(f"Cache Hit Rate Test Entries: {count}")
    
    print(f"\nFirst lookup latency (Uncached): {first_lookup_time * 1000:.2f} ms")
    print(f"Second lookup latency (Cached): {cached_lookup_time * 1000:.2f} ms")
    improvement = (first_lookup_time / (cached_lookup_time if cached_lookup_time > 0 else 0.0001))
    print(f"Performance Improvement: {improvement:.1f}x")

if __name__ == "__main__":
    verify_cache()
