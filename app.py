# app.py
import os
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from modules.eml_parser_module import parse_eml, extract_attachments
from modules.attachment_scanner import scan_attachment
from modules import vt_client
from modules.storage import store_json
from modules.nlu_module import classify_text

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

LAST_RESULT = {}  # in-memory last result for /api/last_result

app = Flask(__name__, template_folder="templates", static_folder="static")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/results")
def results_page():
    return render_template("results.html")

@app.route("/api/last_result")
def api_last_result():
    return jsonify(LAST_RESULT or {"message": "no results yet"})

# -----------------------
# /parse/eml
# Accepts multipart form with key 'file'
# -----------------------
@app.route("/parse/eml", methods=["POST"])
def parse_eml_route():
    global LAST_RESULT
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400
    f = request.files["file"]
    save_path = UPLOAD_DIR / f.filename
    f.save(save_path)
    parsed = parse_eml(str(save_path))
    # extract attachments (metadata) and save attachments if present
    attachments = extract_attachments(str(save_path))
    res = {"parsed_eml": parsed, "attachments_saved": attachments}
    LAST_RESULT = res
    return jsonify(res), 200

# -----------------------
# /scan/attachment
# Accepts multipart with 'file'
# -----------------------
@app.route("/scan/attachment", methods=["POST"])
def scan_attachment_route():
    global LAST_RESULT
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400
    f = request.files["file"]
    save_path = UPLOAD_DIR / f.filename
    f.save(save_path)
    res = scan_attachment(str(save_path))
    LAST_RESULT = res
    return jsonify(res), 200

# -----------------------
# /analyze/url
# Accepts JSON {"ip": "1.2.3.4"} or {"url": "..."} (URL path checking uses vt_ip_report for IPs)
# -----------------------
@app.route("/analyze/url", methods=["POST"])
def analyze_url_route():
    global LAST_RESULT
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "no json provided"}), 400
    if "ip" in data:
        ip = data["ip"]
        res = vt_client.vt_ip_report(ip)
        LAST_RESULT = res
        return jsonify(res), 200
    # for urls: we'll do a simple check - extract hostname and call vt_ip_report if it's an IP
    if "url" in data:
        url = data["url"].strip()
        # crude IP extraction
        host = url.split("//")[-1].split("/")[0]
        if all(c.isdigit() or c=='.' for c in host):
            res = vt_client.vt_ip_report(host)
            LAST_RESULT = res
            return jsonify(res), 200
        else:
            return jsonify({"message": "URL host is not an IP. URL analysis via VT not implemented in this minimal version.", "host": host}), 200
    return jsonify({"error": "provide ip or url field"}), 400

# -----------------------
# /store/json
# Accepts JSON payload for email/sms content and saves it to disk.
# -----------------------
@app.route("/store/json", methods=["POST"])
def store_json_route():
    global LAST_RESULT
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "no json provided"}), 400
    name = data.get("name", "content")
    path = store_json(data, name=name)
    res = {"stored_path": path}
    LAST_RESULT = res
    return jsonify(res), 200

# -----------------------
# /analyze/nlu
# Accepts JSON {"text": "..."} and returns NLU classification
# -----------------------
@app.route("/analyze/nlu", methods=["POST"])
def analyze_nlu_route():
    global LAST_RESULT
    data = request.get_json(force=True)
    if not data or "text" not in data:
        return jsonify({"error": "provide text field"}), 400
    text = data["text"]
    res = classify_text(text)
    LAST_RESULT = res
    return jsonify(res), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)
