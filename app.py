# app.py
import os
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime
from modules.eml_parser_module import parse_eml, extract_attachments
from modules.attachment_scanner import scan_attachment
from modules import vt_client
from modules.storage import store_json
from modules.nlu_module import (
    classify_text,
    comprehensive_analysis,
    analyze_email_content,
)
from modules.dnn_module import predict_url, analyze_urls
from modules.auth import require_auth, optional_auth, get_supabase
from modules.database import (
    save_analysis_history,
    get_analysis_history,
    get_analysis_by_id,
    get_user_statistics,
    create_feedback_report,
    get_or_create_user_profile,
    update_user_preferences,
    get_threat_rules,
    create_threat_rule,
    delete_threat_rule,
)
import socket

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

LAST_RESULT = {}  # in-memory last result for /api/last_result

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-in-production")

# Enable CORS for all routes to allow extension requests
CORS(app, origins=["chrome-extension://*", "moz-extension://*", "http://localhost:*"], supports_credentials=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/signup")
def signup_page():
    return render_template("signup.html")


@app.route("/education")
def education_page():
    return render_template("education.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


@app.route("/results")
def results_page():
    """
    Display comprehensive analysis results page
    Results are passed via session or API call
    """
    return render_template("results.html")


@app.route("/dashboard")
def dashboard_page():
    """
    Display analytics dashboard with statistics and charts
    """
    return render_template("dashboard.html")


@app.route("/api/last_result")
@optional_auth
def api_last_result():
    return jsonify(LAST_RESULT or {"message": "no results yet"})


# Authentication endpoints
@app.route("/api/auth/signup", methods=["POST"])
def api_signup():
    """Sign up a new user"""
    data = request.get_json()
    if not data or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Email and password required"}), 400
    
    supabase = get_supabase()
    if not supabase:
        return jsonify({"error": "Authentication service unavailable"}), 503
    
    try:
        response = supabase.auth.sign_up({
            "email": data["email"],
            "password": data["password"]
        })
        
        if response.user:
            return jsonify({
                "message": "Sign up successful. Please check your email to verify your account.",
                "user": {
                    "id": response.user.id,
                    "email": response.user.email
                }
            }), 201
        else:
            return jsonify({"error": "Sign up failed"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """Login and get access token"""
    data = request.get_json()
    if not data or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Email and password required"}), 400
    
    supabase = get_supabase()
    if not supabase:
        return jsonify({"error": "Authentication service unavailable"}), 503
    
    try:
        response = supabase.auth.sign_in_with_password({
            "email": data["email"],
            "password": data["password"]
        })
        
        if response.user and response.session:
            return jsonify({
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
                "user": {
                    "id": response.user.id,
                    "email": response.user.email
                }
            }), 200
        else:
            return jsonify({"error": "Login failed"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route("/api/auth/verify", methods=["POST"])
def api_verify():
    """Verify access token"""
    data = request.get_json()
    if not data or not data.get("token"):
        return jsonify({"error": "Token required"}), 400
    
    from modules.auth import verify_token
    user = verify_token(data["token"])
    
    if user:
        return jsonify({"valid": True, "user": user}), 200
    else:
        return jsonify({"valid": False, "error": "Invalid token"}), 401


# -----------------------
# Helper function to extract email text for NLU analysis
# -----------------------
def extract_email_text(parsed_eml):
    """
    Extract combined text from parsed email (subject + body) for NLU analysis
    """
    text_parts = []

    # Get subject
    if parsed_eml.get("header") and parsed_eml["header"].get("subject"):
        text_parts.append(f"Subject: {parsed_eml['header']['subject']}")

    # Get body content
    body = parsed_eml.get("body")
    if isinstance(body, list):
        for part in body:
            if isinstance(part, dict):
                content = part.get("content")
                if isinstance(content, str):
                    text_parts.append(content)
    elif isinstance(body, str):
        text_parts.append(body)
    elif isinstance(body, dict):
        # Handle nested body structure
        for key in ["text", "html", "content"]:
            if key in body:
                text_parts.append(str(body[key]))

    return "\n\n".join(text_parts)


# -----------------------
# /parse/eml
# Accepts multipart form with key 'file'
# Parses email and performs comprehensive analysis
# -----------------------
@app.route("/parse/eml", methods=["POST"])
@optional_auth  # Allow file uploads without auth (free tier)
def parse_eml_route():
    global LAST_RESULT
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400
    f = request.files["file"]
    save_path = UPLOAD_DIR / f.filename
    f.save(save_path)

    # Parse email
    parsed = parse_eml(str(save_path))
    attachments = extract_attachments(str(save_path))

    # Extract text for NLU analysis
    email_text = extract_email_text(parsed)

    # Perform NLU analysis on email content
    nlu_result = None
    if email_text.strip():
        nlu_result = analyze_email_content(email_text)

    # Combine results
    res = {
        "parsed_eml": parsed,
        "attachments_saved": attachments,
        "email_text_extracted": email_text[:500]
        + ("..." if len(email_text) > 500 else ""),
        "nlu_analysis": nlu_result,
        "analysis_timestamp": datetime.now().isoformat(),
    }

    LAST_RESULT = res
    return jsonify(res), 200


# -----------------------
# /scan/attachment
# Accepts multipart with 'file'
# -----------------------
@app.route("/scan/attachment", methods=["POST"])
@require_auth
def scan_attachment_route():
    global LAST_RESULT
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400
    f = request.files["file"]
    save_path = UPLOAD_DIR / f.filename
    f.save(save_path)
    res = scan_attachment(str(save_path))
    LAST_RESULT = res
    
    # Save to database if user is authenticated
    if hasattr(request, 'current_user') and request.current_user:
        save_analysis_history(
            user_id=request.current_user['id'],
            analysis_type='attachment',
            result_data=res,
            input_data={'filename': f.filename}
        )
    
    return jsonify(res), 200


# -----------------------
# /analyze/url
# Accepts JSON {"ip": "1.2.3.4"} or {"url": "..."} (URL path checking uses vt_ip_report for IPs)
# -----------------------
@app.route("/analyze/url", methods=["POST"])
@require_auth
def analyze_url_route():
    global LAST_RESULT
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "no json provided"}), 400

    result = {
        "analysis_timestamp": datetime.now().isoformat(),
        "url": None,
        "ip": None,
        "dnn_analysis": None,
        "vt_analysis": None,
    }

    # Handle IP address
    if "ip" in data:
        ip = data["ip"].strip()
        result["ip"] = ip

        # Convert IP to URL format for DNN analysis
        ip_url = f"http://{ip}"
        result["url"] = ip_url

        # DNN Analysis for IP
        try:
            dnn_result = predict_url(ip_url)
            result["dnn_analysis"] = dnn_result
        except Exception as e:
            result["dnn_analysis"] = {"error": str(e)}

        # VirusTotal analysis for IP
        try:
            vt_result = vt_client.vt_ip_report(ip)
            result["vt_analysis"] = vt_result
        except Exception as e:
            result["vt_analysis"] = {"error": str(e)}

        LAST_RESULT = result
        
        # Save to database if user is authenticated
        if hasattr(request, 'current_user') and request.current_user:
            save_analysis_history(
                user_id=request.current_user['id'],
                analysis_type='url',
                result_data=result,
                input_data={'ip': ip, 'url': ip_url}
            )
        
        return jsonify(result), 200

    # Handle URL
    if "url" in data:
        url = data["url"].strip()
        # Ensure URL has protocol
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        result["url"] = url

        # Extract hostname
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split("/")[0]
        result["host"] = host

        # DNN Analysis - ALWAYS analyze URLs with DNN
        try:
            dnn_result = predict_url(url)
            result["dnn_analysis"] = dnn_result
        except Exception as e:
            result["dnn_analysis"] = {"error": str(e), "url": url}

        # Check if host is an IP address for VirusTotal
        try:
            # Try to parse as IP
            socket.inet_aton(host.split(":")[0])
            # It's an IP, use VirusTotal
            try:
                vt_result = vt_client.vt_ip_report(host.split(":")[0])
                result["vt_analysis"] = vt_result
                result["ip"] = host.split(":")[0]
            except Exception as e:
                result["vt_analysis"] = {"error": f"VT IP check failed: {str(e)}"}
        except (socket.error, ValueError):
            # Not an IP address - DNN analysis is still performed above
            result["vt_analysis"] = {
                "message": "Domain-based URL. VirusTotal domain analysis not implemented. DNN analysis completed.",
                "dnn_used": True,
            }

        LAST_RESULT = result
        
        # Save to database if user is authenticated
        if hasattr(request, 'current_user') and request.current_user:
            save_analysis_history(
                user_id=request.current_user['id'],
                analysis_type='url',
                result_data=result,
                input_data={'url': url, 'host': host}
            )
        
        return jsonify(result), 200

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
@require_auth
def analyze_nlu_route():
    global LAST_RESULT
    data = request.get_json(force=True)
    if not data or "text" not in data:
        return jsonify({"error": "provide text field"}), 400
    text = data["text"]

    # Use analyze_email_content for consistent format
    nlu_analysis = analyze_email_content(text)

    # Format result to match results page expectations
    res = {
        "analysis_timestamp": datetime.now().isoformat(),
        "nlu_analysis": nlu_analysis,
        "input_text": text[:500] + ("..." if len(text) > 500 else ""),
        "risk_assessment": (
            {
                "risk_level": (
                    "HIGH"
                    if (
                        nlu_analysis.get("is_phishing")
                        and nlu_analysis.get("confidence", 0) > 0.8
                    )
                    else ("MEDIUM" if nlu_analysis.get("is_phishing") else "LOW")
                ),
                "risk_score": (
                    nlu_analysis.get("confidence", 0)
                    if nlu_analysis.get("is_phishing")
                    else (1 - nlu_analysis.get("confidence", 0))
                ),
                "risk_factors": (
                    [
                        f"NLU classified as {nlu_analysis.get('prediction', 'UNKNOWN')} (confidence: {nlu_analysis.get('confidence', 0):.2%})"
                    ]
                    if not nlu_analysis.get("error")
                    else []
                ),
                "recommendation": (
                    "Do not interact with this content. Report to security team immediately."
                    if nlu_analysis.get("is_phishing")
                    and nlu_analysis.get("confidence", 0) > 0.8
                    else (
                        "Use caution. Verify sender and links before taking any action."
                        if nlu_analysis.get("is_phishing")
                        else "Content appears safe, but review carefully."
                    )
                ),
            }
            if not nlu_analysis.get("error")
            else None
        ),
    }

    LAST_RESULT = res
    return jsonify(res), 200


# -----------------------
# /analyze/comprehensive
# Accepts JSON {"email_text": "...", "comment_text": "..."}
# Performs comprehensive analysis combining email and comment
# -----------------------
@app.route("/analyze/comprehensive", methods=["POST"])
def analyze_comprehensive_route():
    global LAST_RESULT
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "no json provided"}), 400

    email_text = data.get("email_text")
    comment_text = data.get("comment_text")

    if not email_text and not comment_text:
        return jsonify({"error": "provide at least email_text or comment_text"}), 400

    # Add timestamp to results
    results = comprehensive_analysis(email_text=email_text, comment_text=comment_text)
    results["analysis_timestamp"] = datetime.now().isoformat()

    LAST_RESULT = results
    return jsonify(results), 200


# -----------------------
# /analyze/full
# Accepts multipart form with key 'file' (EML file)
# Performs full analysis: parsing + NLU + URL extraction + attachments
# -----------------------
@app.route("/analyze/full", methods=["POST"])
@require_auth
def analyze_full_route():
    """
    Complete analysis pipeline: Parse email, extract URLs/IPs, analyze with NLU,
    check external threats, and provide comprehensive results
    """
    global LAST_RESULT
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    f = request.files["file"]
    save_path = UPLOAD_DIR / f.filename
    f.save(save_path)

    # Step 1: Parse email
    parsed = parse_eml(str(save_path))
    attachments = extract_attachments(str(save_path))

    # Step 2: Extract text for NLU
    email_text = extract_email_text(parsed)

    # Step 3: Perform NLU analysis
    nlu_analysis = None
    if email_text.strip():
        nlu_analysis = analyze_email_content(email_text)

    # Step 4: Extract URLs and IPs from email content
    import re

    url_regex = r"https?://[^\s>]+"
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    urls = re.findall(url_regex, email_text)
    ips = re.findall(ip_regex, email_text)
    urls = list(set(urls))
    ips = list(set(ips))

    # Step 5: Analyze URLs/IPs with DNN model
    dnn_analyses = []
    for url in urls[:5]:  # Analyze up to 5 URLs
        try:
            dnn_result = predict_url(url)
            dnn_analyses.append(dnn_result)
        except Exception as e:
            dnn_analyses.append({"url": url, "error": str(e)})

    # Also analyze IPs converted to URLs
    for ip in ips[:3]:
        try:
            ip_url = f"http://{ip}"
            dnn_result = predict_url(ip_url)
            dnn_analyses.append(dnn_result)
        except Exception as e:
            dnn_analyses.append({"url": ip_url, "error": str(e)})

    # Step 6: Check URLs/IPs with VirusTotal (limit to first 3 to avoid rate limits)
    url_reports = []
    ip_reports = []
    for url in urls[:3]:
        try:
            # Extract hostname for IP check if possible
            host = url.split("//")[-1].split("/")[0]
            if all(c.isdigit() or c == "." for c in host):
                report = vt_client.vt_ip_report(host)
                ip_reports.append({"url": url, "ip": host, "report": report})
        except Exception as e:
            url_reports.append({"url": url, "error": str(e)})

    for ip in ips[:3]:
        try:
            report = vt_client.vt_ip_report(ip)
            ip_reports.append({"ip": ip, "report": report})
        except Exception as e:
            ip_reports.append({"ip": ip, "error": str(e)})

    # Step 7: Comprehensive risk assessment
    risk_score = 0.0
    risk_factors = []

    if nlu_analysis and not nlu_analysis.get("error"):
        if nlu_analysis.get("is_phishing"):
            risk_score += 0.6
            confidence = nlu_analysis.get("confidence", 0)
            risk_factors.append(
                f"NLU classified as phishing (confidence: {confidence:.2%})"
            )

    if urls:
        risk_score += 0.1
        risk_factors.append(f"Found {len(urls)} URL(s) in email")

    # Add DNN analysis to risk score
    if dnn_analyses:
        phishing_urls = [
            r
            for r in dnn_analyses
            if not r.get("error") and r.get("is_phishing", False)
        ]
        if phishing_urls:
            avg_confidence = sum(r.get("confidence", 0) for r in phishing_urls) / len(
                phishing_urls
            )
            risk_score += 0.25 * avg_confidence
            risk_factors.append(
                f"DNN detected {len(phishing_urls)} phishing URL(s) (avg confidence: {avg_confidence:.2%})"
            )

    if ip_reports:
        malicious_ips = [
            r
            for r in ip_reports
            if isinstance(r.get("report"), dict)
            and r.get("report", {})
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0)
            > 0
        ]
        if malicious_ips:
            risk_score += 0.3
            risk_factors.append(
                f"VirusTotal flagged {len(malicious_ips)} IP(s) as malicious"
            )

    risk_level = (
        "HIGH" if risk_score >= 0.7 else ("MEDIUM" if risk_score >= 0.4 else "LOW")
    )

    # Compile final results
    results = {
        "analysis_timestamp": datetime.now().isoformat(),
        "email_parsing": {
            "headers": parsed.get("header", {}),
            "attachments_count": len(attachments),
            "attachments": attachments,
            "email_preview": email_text[:500]
            + ("..." if len(email_text) > 500 else ""),
        },
        "nlu_analysis": nlu_analysis,
        "url_extraction": {
            "urls_found": urls,
            "ips_found": ips,
            "url_count": len(urls),
            "ip_count": len(ips),
        },
        "dnn_analysis": {
            "urls_analyzed": len(dnn_analyses),
            "phishing_detected": sum(
                1
                for r in dnn_analyses
                if not r.get("error") and r.get("is_phishing", False)
            ),
            "detailed_results": dnn_analyses,
        },
        "external_checks": {"url_reports": url_reports, "ip_reports": ip_reports},
        "risk_assessment": {
            "risk_level": risk_level,
            "risk_score": round(risk_score, 2),
            "risk_factors": risk_factors,
            "recommendation": (
                "Do not interact with this email. Report to security team immediately."
                if risk_level == "HIGH"
                else (
                    "Use caution. Verify sender and links before taking any action."
                    if risk_level == "MEDIUM"
                    else "Email appears relatively safe, but review carefully."
                )
            ),
        },
        "file_info": {"filename": f.filename, "saved_path": str(save_path)},
    }

    LAST_RESULT = results
    
    # Save to database if user is authenticated
    if hasattr(request, 'current_user') and request.current_user:
        save_analysis_history(
            user_id=request.current_user['id'],
            analysis_type='full',
            result_data=results,
            input_data={'filename': f.filename if 'file' in request.files else None}
        )
    
    return jsonify(results), 200


# -----------------------
# Analysis History API Endpoints
# -----------------------
@app.route("/api/history", methods=["GET"])
@require_auth
def get_history_route():
    """Get analysis history for authenticated user"""
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    analysis_type = request.args.get("type")
    is_phishing = request.args.get("is_phishing")
    is_phishing = bool(is_phishing) if is_phishing is not None else None
    
    history = get_analysis_history(
        user_id=request.current_user['id'],
        limit=limit,
        offset=offset,
        analysis_type=analysis_type,
        is_phishing=is_phishing,
    )
    
    return jsonify({"history": history, "count": len(history)}), 200


@app.route("/api/history/<analysis_id>", methods=["GET"])
@require_auth
def get_history_item_route(analysis_id):
    """Get a specific analysis by ID"""
    analysis = get_analysis_by_id(analysis_id, request.current_user['id'])
    
    if not analysis:
        return jsonify({"error": "Analysis not found"}), 404
    
    return jsonify(analysis), 200


@app.route("/api/statistics", methods=["GET"])
@require_auth
def get_statistics_route():
    """Get user statistics"""
    days = request.args.get("days", 30, type=int)
    stats = get_user_statistics(request.current_user['id'], days=days)
    return jsonify(stats), 200


@app.route("/api/feedback", methods=["POST"])
@require_auth
def create_feedback_route():
    """Create a false positive/negative feedback report"""
    data = request.get_json(force=True)
    
    if not data or not data.get("analysis_id") or not data.get("feedback_type"):
        return jsonify({"error": "analysis_id and feedback_type required"}), 400
    
    feedback_id = create_feedback_report(
        analysis_id=data["analysis_id"],
        user_id=request.current_user['id'],
        feedback_type=data["feedback_type"],
        original_prediction=data.get("original_prediction", ""),
        user_correction=data.get("user_correction"),
        comments=data.get("comments"),
    )
    
    if feedback_id:
        return jsonify({"id": feedback_id, "message": "Feedback submitted"}), 201
    else:
        return jsonify({"error": "Failed to create feedback"}), 500


@app.route("/api/profile", methods=["GET", "PUT"])
@require_auth
def profile_route():
    """Get or update user profile"""
    if request.method == "GET":
        profile = get_or_create_user_profile(
            request.current_user['id'],
            request.current_user.get('email', '')
        )
        return jsonify(profile), 200
    else:  # PUT
        data = request.get_json(force=True)
        if data.get("preferences"):
            update_user_preferences(request.current_user['id'], data["preferences"])
        return jsonify({"message": "Profile updated"}), 200


@app.route("/api/threat-rules", methods=["GET", "POST"])
@require_auth
def threat_rules_route():
    """Get or create threat rules"""
    if request.method == "GET":
        rules = get_threat_rules(request.current_user['id'])
        return jsonify({"rules": rules}), 200
    else:  # POST
        data = request.get_json(force=True)
        rule_id = create_threat_rule(
            user_id=request.current_user['id'],
            rule_type=data.get("rule_type"),
            rule_category=data.get("rule_category"),
            rule_value=data.get("rule_value"),
            description=data.get("description"),
        )
        if rule_id:
            return jsonify({"id": rule_id, "message": "Rule created"}), 201
        else:
            return jsonify({"error": "Failed to create rule"}), 500


@app.route("/api/threat-rules/<rule_id>", methods=["DELETE"])
@require_auth
def delete_threat_rule_route(rule_id):
    """Delete a threat rule"""
    success = delete_threat_rule(rule_id, request.current_user['id'])
    if success:
        return jsonify({"message": "Rule deleted"}), 200
    else:
        return jsonify({"error": "Failed to delete rule"}), 500


@app.route("/api/export/<analysis_id>", methods=["GET"])
@require_auth
def export_analysis_route(analysis_id):
    """Export analysis as JSON (for now, PDF/CSV can be added later)"""
    analysis = get_analysis_by_id(analysis_id, request.current_user['id'])
    
    if not analysis:
        return jsonify({"error": "Analysis not found"}), 404
    
    # Return as downloadable JSON
    from flask import Response
    return Response(
        jsonify(analysis).data,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=analysis_{analysis_id}.json'}
    )


@app.route("/history")
@require_auth
def history_page():
    """Analysis history page"""
    return render_template("history.html")


@app.route("/settings")
@require_auth
def settings_page():
    """User settings page"""
    return render_template("settings.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
