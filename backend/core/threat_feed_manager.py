import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'threat_feed.db')

def get_feed_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_feed_db():
    conn = get_feed_db()
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS feeds(
            url TEXT PRIMARY KEY,
            domain TEXT,
            source TEXT,
            first_seen TEXT,
            last_seen TEXT,
            confidence INTEGER
        )
    ''')
    
    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_feeds_domain ON feeds(domain)
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS feed_sync_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            sync_time TEXT,
            records_added INTEGER,
            records_updated INTEGER,
            status TEXT,
            error TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_feed_db()
    print("Threat feed DB initialized.")
