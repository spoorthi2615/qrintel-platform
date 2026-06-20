"""
history.py
Flask Blueprint for scan history and analytics endpoints.
GET  /api/history       — paginated scan history
GET  /api/analytics     — aggregate stats + chart data
DELETE /api/history/<id> — delete one record
"""

import json
import sqlite3
import os
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify

history_bp = Blueprint('history', __name__)

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'history.db')


def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row) -> dict:
    d = dict(row)
    for key in ('reasons', 'breakdown'):
        if d.get(key) and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except Exception:
                d[key] = []
    return d


@history_bp.route('/', methods=['GET'])
def get_history():
    """Return paginated scan history (most recent first)."""
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(100, max(1, int(request.args.get('limit', 20))))
        offset = (page - 1) * limit

        conn = _get_db()
        total = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        rows  = conn.execute(
            '''SELECT id, timestamp, payload, payload_type, payload_display,
                      risk_score, status, confidence, entropy, entropy_label,
                      reasons, breakdown, signature_status, scan_method
               FROM scans
               ORDER BY id DESC
               LIMIT ? OFFSET ?''',
            (limit, offset),
        ).fetchall()
        conn.close()

        items = [_row_to_dict(r) for r in rows]
        total_pages = max(1, (total + limit - 1) // limit)

        return jsonify({
            'items':       items,
            'total':       total,
            'page':        page,
            'limit':       limit,
            'total_pages': total_pages,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@history_bp.route('/<int:scan_id>', methods=['DELETE'])
def delete_history(scan_id: int):
    """Delete a single scan record by ID."""
    try:
        conn = _get_db()
        conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': f'Scan {scan_id} deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@history_bp.route('/analytics', methods=['GET'])
def get_analytics():
    """Return aggregate statistics and chart-ready data for the dashboard."""
    try:
        conn = _get_db()

        # ── Totals ──────────────────────────────────────────────────────────
        total = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        safe_count       = conn.execute("SELECT COUNT(*) FROM scans WHERE status='SAFE'").fetchone()[0]
        suspicious_count = conn.execute("SELECT COUNT(*) FROM scans WHERE status='SUSPICIOUS'").fetchone()[0]
        malicious_count  = conn.execute("SELECT COUNT(*) FROM scans WHERE status='MALICIOUS'").fetchone()[0]

        # ── Threat Trends — last 7 days ─────────────────────────────────────
        trends = []
        today = datetime.utcnow().date()
        for i in range(6, -1, -1):
            day = today - timedelta(days=i)
            day_str = day.strftime('%Y-%m-%d')
            label   = day.strftime('%b %d')
            s = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE DATE(timestamp)=? AND status='SAFE'",
                (day_str,)
            ).fetchone()[0]
            su = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE DATE(timestamp)=? AND status='SUSPICIOUS'",
                (day_str,)
            ).fetchone()[0]
            m = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE DATE(timestamp)=? AND status='MALICIOUS'",
                (day_str,)
            ).fetchone()[0]
            trends.append({'date': label, 'safe': s, 'suspicious': su, 'malicious': m})

        # ── Top Threat Categories (payload types with non-zero risk) ─────────
        threat_rows = conn.execute(
            '''SELECT payload_type, COUNT(*) as cnt
               FROM scans
               WHERE status != 'SAFE'
               GROUP BY payload_type
               ORDER BY cnt DESC
               LIMIT 6'''
        ).fetchall()
        top_threats = [{'type': r['payload_type'], 'count': r['cnt']} for r in threat_rows]

        # ── Risk Distribution (histogram buckets) ────────────────────────────
        buckets = []
        for i in range(0, 100, 10):
            cnt = conn.execute(
                'SELECT COUNT(*) FROM scans WHERE risk_score >= ? AND risk_score < ?',
                (i, i + 10)
            ).fetchone()[0]
            buckets.append({'range': f'{i}-{i+10}', 'count': cnt})
        # Include 100 exactly in last bucket
        exact_100 = conn.execute(
            'SELECT COUNT(*) FROM scans WHERE risk_score = 100'
        ).fetchone()[0]
        if exact_100:
            buckets[-1]['count'] += exact_100

        # ── Payload Type Distribution ────────────────────────────────────────
        type_rows = conn.execute(
            '''SELECT payload_type, COUNT(*) as cnt FROM scans
               GROUP BY payload_type ORDER BY cnt DESC'''
        ).fetchall()
        type_dist = [{'type': r['payload_type'], 'count': r['cnt']} for r in type_rows]

        conn.close()

        return jsonify({
            'total_scans':       total,
            'safe_count':        safe_count,
            'suspicious_count':  suspicious_count,
            'malicious_count':   malicious_count,
            'threat_trends':     trends,
            'top_threats':       top_threats,
            'risk_distribution': buckets,
            'type_distribution': type_dist,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
