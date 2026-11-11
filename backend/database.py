import sqlite3
import json
import os
from datetime import datetime

def _get_db_path():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Vercel sets VERCEL=1 and has a read-only filesystem except /tmp
    if os.environ.get("VERCEL"):
        return os.path.join("/tmp", "suspicious_messages.db")
    return os.path.join(project_root, "suspicious_messages.db")

def get_connection():
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes tables for scan history, reported scams, and threat statistics."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
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
    finally:
        conn.close()

def log_scan(message_text, status, score, warnings, advice, client_ip="127.0.0.1"):
    """Saves a scanned message and its evaluation into the database."""
    init_db()  # Self-healing: ensure tables exist in current process/container
    conn = get_connection()
    try:
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
        return cursor.lastrowid
    except Exception as e:
        print(f"[Warning] Failed to log scan to database: {e}")
        return None
    finally:
        conn.close()

def get_recent_scans(limit=10):
    """Retrieves recent scans for audit history and telemetry."""
    init_db()
    conn = get_connection()
    try:
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
        return results
    except Exception as e:
        print(f"[Warning] Failed to retrieve scans: {e}")
        return []
    finally:
        conn.close()

def add_fraud_report(message_text, category, sender_info="Unknown", reported_by="Anonymous"):
    """Stores user submitted fraud reports."""
    init_db()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO fraud_reports (sender_info, message_text, category, reported_by)
            VALUES (?, ?, ?, ?)
        """, (sender_info, message_text, category, reported_by))
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        print(f"[Warning] Failed to save fraud report: {e}")
        return None
    finally:
        conn.close()

def get_recent_reports(limit=10):
    """Retrieves user reported scam messages."""
    init_db()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, sender_info, message_text, category, reported_by, created_at
            FROM fraud_reports
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"[Warning] Failed to retrieve reports: {e}")
        return []
    finally:
        conn.close()

def get_telemetry_stats():
    """Computes threat telemetry and scan metrics."""
    init_db()
    conn = get_connection()
    try:
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

        return {
            "total_scanned": total_scans,
            "fraud_detected": fraud_count,
            "suspicious_detected": suspicious_count,
            "safe_messages": safe_count,
            "community_reports": reports_count,
            "threat_ratio": round(((fraud_count + suspicious_count) / max(total_scans, 1)) * 100, 1)
        }
    except Exception as e:
        print(f"[Warning] Failed to get telemetry stats: {e}")
        return {
            "total_scanned": 0,
            "fraud_detected": 0,
            "suspicious_detected": 0,
            "safe_messages": 0,
            "community_reports": 0,
            "threat_ratio": 0.0
        }
    finally:
        conn.close()
