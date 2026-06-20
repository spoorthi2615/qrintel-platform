"""
app.py
QRIntel 2.0 — Flask application entry point.
Initialises the database, registers blueprints, and starts the dev server.
"""

import os
import sqlite3

from flask import Flask, jsonify
from flask_cors import CORS

from routes.scan         import scan_bp
from routes.history      import history_bp
from routes.crypto       import crypto_bp
from routes.intelligence import intelligence_bp

# ─── App factory ────────────────────────────────────────────────────────────

FRONTEND_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'dist')
app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path='')
CORS(app, resources={r'/api/*': {'origins': '*'}})

app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'database', 'history.db')

# Register blueprints
app.register_blueprint(scan_bp,          url_prefix='/api/scan')
app.register_blueprint(history_bp,       url_prefix='/api/history')
app.register_blueprint(crypto_bp,        url_prefix='/api')
app.register_blueprint(intelligence_bp,  url_prefix='/api/intelligence')

# ─── Database initialisation ─────────────────────────────────────────────────

DB_DIR  = os.path.join(os.path.dirname(__file__), 'database')
DB_PATH = os.path.join(DB_DIR, 'history.db')

SCHEMA = '''
-- ── Core scan table (unchanged) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
    payload          TEXT NOT NULL,
    payload_type     TEXT,
    payload_display  TEXT,
    risk_score       REAL    DEFAULT 0,
    status           TEXT    DEFAULT 'SAFE',
    confidence       REAL    DEFAULT 0,
    entropy          REAL    DEFAULT 0,
    entropy_label    TEXT,
    reasons          TEXT,
    breakdown        TEXT,
    screenshot_path  TEXT,
    signature_status TEXT    DEFAULT 'UNSIGNED',
    scan_method      TEXT    DEFAULT 'manual'
);

-- ── Sprint 1: Trust Score Framework ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trust_scores (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
    lexical_score    REAL,
    structural_score REAL,
    protocol_score   REAL,
    historical_score REAL,
    entropy_score    REAL,
    composite_score  REAL,
    trust_label      TEXT,
    dimensions_json    TEXT,
    explanations_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_trust_scan ON trust_scores(scan_id);

-- ── Sprint 2: QR Tampering Detection ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tamper_analysis (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id                INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    timestamp              DATETIME DEFAULT CURRENT_TIMESTAMP,
    image_hash             TEXT,
    tampering_probability  REAL,
    tampering_label        TEXT,
    checks_json            TEXT,
    suspicious_regions_json TEXT,
    annotated_image_b64    TEXT
);
CREATE INDEX IF NOT EXISTS idx_tamper_scan ON tamper_analysis(scan_id);

-- ── Sprint 3: Visual Phishing Detection ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS visual_phishing (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id              INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    timestamp            DATETIME DEFAULT CURRENT_TIMESTAMP,
    url                  TEXT,
    http_status          INTEGER,
    brand_detected       TEXT,
    brand_confidence     REAL,
    impersonation_score  REAL,
    impersonation_label  TEXT,
    signals_json         TEXT,
    page_title           TEXT,
    favicon_url          TEXT
);
CREATE INDEX IF NOT EXISTS idx_phishing_scan ON visual_phishing(scan_id);

-- ── Sprint 4: Behavioral Trust Graph ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS graph_nodes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id        TEXT UNIQUE,
    node_type      TEXT,
    first_seen     DATETIME,
    last_seen      DATETIME,
    scan_count     INTEGER DEFAULT 1,
    risk_score     REAL    DEFAULT 0,
    propagated_risk REAL   DEFAULT 0,
    degree         INTEGER DEFAULT 0,
    metadata_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_risk ON graph_nodes(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node  TEXT,
    target_node  TEXT,
    edge_type    TEXT,
    weight       REAL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    evidence_json TEXT,
    UNIQUE(source_node, target_node, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(source_node);
CREATE INDEX IF NOT EXISTS idx_graph_edges_tgt ON graph_edges(target_node);

-- ── Sprint 5: Campaign Evolution Tracking ───────────────────────────────────
CREATE TABLE IF NOT EXISTS campaigns (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id          TEXT UNIQUE,
    name                 TEXT,
    threat_level         TEXT,
    first_seen           DATETIME,
    last_seen            DATETIME,
    member_count         INTEGER DEFAULT 0,
    active               INTEGER DEFAULT 1,
    ttp_fingerprint      TEXT,
    evolution_chain_json TEXT,
    metadata_json        TEXT
);
CREATE INDEX IF NOT EXISTS idx_campaigns_threat ON campaigns(threat_level, last_seen DESC);

CREATE TABLE IF NOT EXISTS campaign_members (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id      TEXT REFERENCES campaigns(campaign_id),
    scan_id          INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    member_fingerprint TEXT,
    similarity_score   REAL,
    joined_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    generation         INTEGER  DEFAULT 1
);
CREATE TABLE IF NOT EXISTS campaign_forecasts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id          TEXT REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
    forecast_score       REAL,
    growth_rate          REAL,
    mutation_rate        REAL,
    infrastructure_reuse REAL,
    expansion_score      REAL,
    forecast_label       TEXT,
    prediction           TEXT,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_forecast_campaign ON campaign_forecasts(campaign_id);
CREATE INDEX IF NOT EXISTS idx_members_campaign ON campaign_members(campaign_id);
CREATE INDEX IF NOT EXISTS idx_members_scan     ON campaign_members(scan_id);
'''


def init_db():
    """Create the database directory and all tables (original + intelligence)."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f'[db] Initialised database at {DB_PATH}')


# ─── Global error handlers ───────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found', 'status': 404}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed', 'status': 405}), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error', 'status': 500}), 500

@app.route('/api/forecast/validation', methods=['GET'])
def get_forecast_validation():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        
        # Get overall accuracy
        metrics_query = """
            SELECT 
                COUNT(*) as count,
                AVG(absolute_error) as mae,
                AVG(percentage_error) as mape,
                SUM((predicted_value - actual_value)*(predicted_value - actual_value)) as sq_error_sum
            FROM forecast_validation
        """
        metrics = conn.execute(metrics_query).fetchone()
        
        count = metrics['count'] or 0
        mae = metrics['mae'] or 0.0
        mape = metrics['mape'] or 0.0
        rmse = 0.0
        if count > 0 and metrics['sq_error_sum']:
            import math
            rmse = math.sqrt(metrics['sq_error_sum'] / count)
            
        # Get recent records
        records = conn.execute("SELECT * FROM forecast_validation ORDER BY validation_date DESC LIMIT 50").fetchall()
        
        conn.close()
        return jsonify({
            'status': 'success',
            'metrics': {
                'mae': round(mae, 2),
                'mape': round(mape, 2),
                'rmse': round(rmse, 2)
            },
            'records': [dict(r) for r in records]
        })
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500


# ─── Health check ───────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status':   'ok',
        'service':  'QRIntel 2.0 Backend',
        'version':  '3.0.0',
        'modules':  ['trust_score', 'tamper_detection', 'visual_phishing',
                     'behavior_graph', 'campaign_tracking'],
    })


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ─── SPA Frontend catch-all ──────────────────────────────────────────────────

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path.startswith('api'):
        return jsonify({'error': 'Not found'}), 404
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return app.send_static_file(path)
    else:
        return app.send_static_file('index.html')


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print('[QRIntel] Backend starting on http://localhost:5000')
    app.run(debug=True, host='0.0.0.0', port=5000)
