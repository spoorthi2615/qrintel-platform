import os
import sqlite3
import json
import time
from datetime import datetime
from urllib.parse import urlparse

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'historical_threats.db')

def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    return conn

def _init_db(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historical_threats (
            url TEXT PRIMARY KEY,
            domain TEXT,
            first_seen REAL,
            last_seen REAL,
            feed_source TEXT,
            reputation TEXT,
            detection_date TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS campaigns (
            campaign_id TEXT PRIMARY KEY,
            name TEXT,
            threat_level TEXT,
            member_count INTEGER,
            first_seen TEXT,
            ttp_fingerprint TEXT,
            average_similarity REAL,
            confidence_score REAL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS campaign_members (
            campaign_id TEXT,
            url TEXT,
            PRIMARY KEY (campaign_id, url),
            FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id),
            FOREIGN KEY(url) REFERENCES historical_threats(url)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS forecast_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT,
            forecast_score REAL,
            predicted_variants INTEGER,
            forecast_label TEXT,
            created_at TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS forecast_validation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT,
            forecast_id INTEGER,
            predicted_variants INTEGER,
            observed_variants INTEGER,
            accuracy_score REAL,
            mape REAL,
            prediction_error REAL,
            evaluated_at TEXT,
            FOREIGN KEY(forecast_id) REFERENCES forecast_history(id)
        )
    ''')
    conn.commit()

def log_historical_threat(url: str, feed_source: str, reputation: str):
    conn = _get_db()
    cursor = conn.cursor()
    
    try:
        domain = urlparse(url).netloc
    except Exception:
        domain = ""

    now = time.time()
    now_str = datetime.utcnow().isoformat() + "Z"

    cursor.execute("SELECT * FROM historical_threats WHERE url = ?", (url,))
    row = cursor.fetchone()

    if row:
        cursor.execute('''
            UPDATE historical_threats 
            SET last_seen = ?, reputation = ?, detection_date = ?
            WHERE url = ?
        ''', (now, reputation, now_str, url))
    else:
        cursor.execute('''
            INSERT INTO historical_threats (url, domain, first_seen, last_seen, feed_source, reputation, detection_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (url, domain, now, now, feed_source, reputation, now_str))
    
    conn.commit()
    conn.close()

def retroactively_populate_from_metadata(metadata_path: str):
    if not os.path.exists(metadata_path):
        print(f"Metadata file not found: {metadata_path}")
        return
    
    with open(metadata_path, 'r') as f:
        data = json.load(f)
    
    samples = data.get("samples", [])
    for sample in samples:
        url = sample.get("payload")
        prov = sample.get("provenance", {})
        source = prov.get("source", "OpenPhish Active Links")
        log_historical_threat(url, source, "MALICIOUS")
    
    print(f"Populated {len(samples)} threats into historical database.")

if __name__ == '__main__':
    # Script to run standalone and populate
    meta_path = os.path.join(os.path.dirname(__file__), '..', 'evaluation', 'datasets', 'phishing_qr', 'metadata.json')
    retroactively_populate_from_metadata(meta_path)
