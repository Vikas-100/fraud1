import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "suspicious_messages.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes tables for scan history, reported scams, and threat statistics."""
    conn = get_connection()
    cursor = conn.cursor()

    # Table 1: Analysis history for all processed messages
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_text TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER NOT NULL,
            warnings_json TEXT NOT NULL,
            advice TEXT NOT NULL,
            client_ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table 2: Community & User reported fraud messages
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fraud_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_info TEXT,
            message_text TEXT NOT NULL,
            category TEXT NOT NULL,
            reported_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

def log_scan(message_text, status, score, warnings, advice, client_ip="127.0.0.1"):
    """Saves a scanned message and its evaluation into the database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history (message_text, status, score, warnings_json, advice, client_ip)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        message_text,
        status,
        score,
        json.dumps(warnings),
        advice,
        client_ip
    ))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_recent_scans(limit=10):
    """Retrieves recent scans for audit history and telemetry."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, message_text, status, score, warnings_json, advice, created_at
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "message_text": row["message_text"],
            "status": row["status"],
            "score": row["score"],
            "warnings": json.loads(row["warnings_json"]) if row["warnings_json"] else [],
            "advice": row["advice"],
            "created_at": row["created_at"]
        })
    conn.close()
    return results

def add_fraud_report(message_text, category, sender_info="Unknown", reported_by="Anonymous"):
    """Stores user submitted fraud reports."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO fraud_reports (sender_info, message_text, category, reported_by)
        VALUES (?, ?, ?, ?)
    """, (sender_info, message_text, category, reported_by))
    conn.commit()
    report_id = cursor.lastrowid
    conn.close()
    return report_id

def get_recent_reports(limit=10):
    """Retrieves user reported scam messages."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, sender_info, message_text, category, reported_by, created_at
        FROM fraud_reports
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    reports = [dict(row) for row in rows]
    conn.close()
    return reports

def get_telemetry_stats():
    """Computes threat telemetry and scan metrics."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM scan_history")
    total_scans = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM scan_history WHERE status = 'FRAUD'")
    fraud_count = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM scan_history WHERE status = 'SUSPICIOUS'")
    suspicious_count = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM scan_history WHERE status = 'SAFE'")
    safe_count = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM fraud_reports")
    reports_count = cursor.fetchone()["total"]

    conn.close()
    return {
        "total_scanned": total_scans,
        "fraud_detected": fraud_count,
        "suspicious_detected": suspicious_count,
        "safe_messages": safe_count,
        "community_reports": reports_count,
        "threat_ratio": round(((fraud_count + suspicious_count) / max(total_scans, 1)) * 100, 1)
    }
