import os
from flask import Flask, render_template, request, jsonify
from backend.database import init_db, log_scan
from backend.classifier import analyze_message_content
from backend.routes import api_bp

app = Flask(__name__)

# Register REST API blueprint
app.register_blueprint(api_bp)

# Initialize database tables on server start
with app.app_context():
    init_db()

@app.route("/")
def home():
    """Renders the Suspicious Message Classification UI."""
    return render_template("index.html")

# Backward-compatible endpoint for existing client calls
@app.route("/check", methods=["POST"])
def check_message_legacy():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify({"error": "Please enter a message to check."}), 400

    client_ip = request.remote_addr or "127.0.0.1"
    analysis = analyze_message_content(message)

    # Save to database
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

if __name__ == "__main__":
    # Ensure database is created before starting server
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Suspicious Message Classification Server on port {port}...")
    app.run(host="127.0.0.1", port=port, debug=True)
