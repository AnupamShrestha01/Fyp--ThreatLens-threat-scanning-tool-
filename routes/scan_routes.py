"""
backend/routes/scan_routes.py
POST /api/scan/file      — scan uploaded file
POST /api/scan/history   — save scan to DB  (called internally)
GET  /api/scan/history/<user_id> — get user scan history
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

import json
from flask import Blueprint, request, jsonify
from database.db import get_db

scan_bp = Blueprint("scan", __name__)

# ── File Scan ──────────────────────────────────────────────────────────────
@scan_bp.route("/file", methods=["POST"])
def scan_file():
    from backend.services.file_service import scan_file as do_scan_file

    file = request.files.get("file")
    if not file:
        return jsonify({"success": False, "message": "No file uploaded."}), 400

    filename = file.filename or "unknown"
    file_data = file.read()

    if len(file_data) > 32 * 1024 * 1024:  # 32MB limit
        return jsonify({"success": False, "message": "File too large (max 32MB)."}), 413

    try:
        result = do_scan_file(file_data, filename)
    except Exception as e:
        return jsonify({"success": False, "message": f"Scan error: {str(e)}"}), 500

    # Save to DB if user_id provided
    user_id = request.form.get("user_id")
    if user_id:
        try:
            db = get_db()
            db.execute(
                """INSERT INTO scan_history
                   (user_id, scan_type, target, filename, file_size, verdict, risk_level, threat_score, sha256, md5, result_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    int(user_id), "file",
                    result.get("filename"),
                    result.get("filename"),
                    result.get("file_size"),
                    result.get("verdict"),
                    result.get("risk"),
                    result.get("threat_score"),
                    result.get("hashes", {}).get("sha256"),
                    result.get("hashes", {}).get("md5"),
                    json.dumps(result)
                )
            )
            db.commit()
            db.close()
        except Exception:
            pass  # Don't fail scan if DB save fails

    return jsonify({"success": True, "result": result})


# ── URL / Domain / IP Scan (stub — returns placeholder for now) ────────────
@scan_bp.route("/url", methods=["POST"])
def scan_url():
    value = (request.form.get("value") or request.json.get("value", "") if request.is_json else "").strip()
    if not value:
        return jsonify({"success": False, "message": "No URL/domain/IP provided."}), 400
    # Placeholder — backend not yet implemented for this phase
    return jsonify({
        "success": False,
        "message": "URL/Domain scanning will be available in the next phase. Stay tuned!"
    }), 501


# ── Hash Scan (stub) ───────────────────────────────────────────────────────
@scan_bp.route("/hash", methods=["POST"])
def scan_hash():
    return jsonify({
        "success": False,
        "message": "Hash scanning will be available in the next phase."
    }), 501


# ── Scan History ────────────────────────────────────────────────────────────
@scan_bp.route("/history/<int:user_id>", methods=["GET"])
def get_history(user_id):
    try:
        db = get_db()
        rows = db.execute(
            "SELECT id, scan_type, filename, target, verdict, risk_level, threat_score, sha256, scanned_at FROM scan_history WHERE user_id = ? ORDER BY scanned_at DESC LIMIT 50",
            (user_id,)
        ).fetchall()
        db.close()
        history = [dict(r) for r in rows]
        return jsonify({"success": True, "history": history})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
