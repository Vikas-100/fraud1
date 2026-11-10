from flask import Blueprint, request, jsonify
from backend.classifier import analyze_message_content
from backend.database import (
    log_scan,
    get_recent_scans,
    add_fraud_report,
    get_recent_reports,
    get_telemetry_stats
)

api_bp = Blueprint("api", __name__, url_prefix="/api")

@api_bp.route("/check", methods=["POST"])
def check_message_api():
    """Classifies incoming message and logs audit trail."""
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify({"error": "Message content cannot be empty."}), 400

    client_ip = request.remote_addr or "127.0.0.1"
    analysis = analyze_message_content(message)

    # Persist scan in SQLite database
    scan_id = log_scan(
        message_text=message,
        status=analysis["status"],
        score=analysis["score"],
        warnings=analysis["warnings"],
        advice=analysis["advice"],
        client_ip=client_ip
    )

    analysis["scan_id"] = scan_id
    return jsonify(analysis)

@api_bp.route("/history", methods=["GET"])
def get_history_api():
    """Returns recent message classification logs."""
    limit = request.args.get("limit", default=10, type=int)
    limit = max(1, min(limit, 50))
    scans = get_recent_scans(limit=limit)
    return jsonify({"history": scans, "count": len(scans)})

@api_bp.route("/report", methods=["POST"])
def report_fraud_api():
    """Allows users to submit confirmed or suspected fraud messages to database."""
    data = request.get_json(silent=True) or {}
    message_text = str(data.get("message", "")).strip()
    category = str(data.get("category", "General Phishing")).strip()
    sender_info = str(data.get("sender_info", "Unknown")).strip()
    reported_by = str(data.get("reported_by", "User")).strip()

    if not message_text:
        return jsonify({"error": "Report message text cannot be empty."}), 400

    report_id = add_fraud_report(
        message_text=message_text,
        category=category,
        sender_info=sender_info,
        reported_by=reported_by
    )

    return jsonify({
        "success": True,
        "message": "Fraud report submitted successfully to threat database.",
        "report_id": report_id
    }), 201

@api_bp.route("/reports", methods=["GET"])
def get_reports_api():
    """Returns recently reported scam messages."""
    limit = request.args.get("limit", default=10, type=int)
    limit = max(1, min(limit, 50))
    reports = get_recent_reports(limit=limit)
    return jsonify({"reports": reports, "count": len(reports)})

@api_bp.route("/stats", methods=["GET"])
def get_stats_api():
    """Returns live threat telemetry metrics."""
    stats = get_telemetry_stats()
    return jsonify(stats)

@api_bp.route("/health", methods=["GET"])
def health_check():
    """API health indicator."""
    return jsonify({
        "status": "healthy",
        "service": "Suspicious Message Classification Backend",
        "version": "2.0.0"
    })
