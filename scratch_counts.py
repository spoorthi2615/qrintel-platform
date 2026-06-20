import sqlite3

def count_table(db, table):
    try:
        conn = sqlite3.connect(f'backend/database/{db}')
        c = conn.cursor()
        c.execute(f"SELECT COUNT(*) FROM {table}")
        count = c.fetchone()[0]
        print(f'{db} - {table}: {count}')
    except Exception as e:
        print(f'{db} - {table}: Error {e}')

history_tables = ['scans', 'trust_scores', 'tamper_analysis', 'visual_phishing', 'graph_nodes', 'graph_edges', 'campaigns', 'campaign_members', 'campaign_forecasts']
historical_tables = ['historical_threats', 'campaigns', 'campaign_members', 'forecast_history', 'forecast_validation']
threat_tables = ['reputation_cache', 'feed_metadata']

for t in history_tables: count_table('history.db', t)
for t in historical_tables: count_table('historical_threats.db', t)
for t in threat_tables: count_table('threat_intel.db', t)
