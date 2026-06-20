import sqlite3

def list_tables(db):
    try:
        conn = sqlite3.connect(f'backend/database/{db}')
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in c.fetchall()]
        print(f'{db} tables: {tables}')
    except Exception as e:
        print(f'{db} error: {str(e)}')

list_tables('history.db')
list_tables('historical_threats.db')
list_tables('threat_intel.db')
