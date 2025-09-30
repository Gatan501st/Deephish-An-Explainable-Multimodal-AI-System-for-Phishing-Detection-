from flask import Flask, render_template, request, jsonify
from pathlib import Path
import os
from API import (
    hash_it, vt_get_data, vt_post_files, vt_get_analyses,
    vt_get_upload_url, parse_response
)

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Existing route for rendering HTML
@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

# New API route for your frontend fetch
@app.route("/ingest/email", methods=["POST"])
def ingest_email():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    filepath = Path(UPLOAD_FOLDER) / file.filename
    file.save(filepath)

    f_hash = hash_it(filepath, "sha256")
    response = vt_get_data(f_hash)

    if response.status_code == 404:
        if filepath.stat().st_size > 32000000:
            response = vt_get_data(vt_get_analyses(vt_post_files(filepath, vt_get_upload_url())))
        else:
            response = vt_get_data(vt_get_analyses(vt_post_files(filepath)))

    if response.status_code == 200:
        parsed = parse_response(response)
        return jsonify(parsed)

    return jsonify({"error": f"VirusTotal returned {response.status_code}"}), response.status_code
@app.route("/results")
def results():
    return render_template("results.html")

if __name__ == "__main__":
    app.run(debug=True)
