from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os

from backend.detector import detect_sensitive_data
from backend.masker import mask_data
from backend.risk_analyzer import analyze_risk
from backend.injection_detector import detect_prompt_injection
from backend.suggestions import generate_suggestions
from backend.decision_engine import make_security_decision

from backend.database import (
    initialize_database,
    save_scan,
    get_scans
)


# ==========================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()

API_KEY = os.getenv("PROMPTGUARD_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "PROMPTGUARD_API_KEY is not configured"
    )


# ==========================================
# FLASK APPLICATION
# ==========================================

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)


# ==========================================
# RATE LIMITING
# ==========================================

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


# ==========================================
# SECURITY HEADERS
# ==========================================

@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    return response


# ==========================================
# GLOBAL ERROR HANDLERS
# ==========================================

@app.errorhandler(400)
def handle_bad_request(error):

    return jsonify({
        "error": "Bad request."
    }), 400


@app.errorhandler(404)
def handle_not_found(error):

    return jsonify({
        "error": "Endpoint not found."
    }), 404


@app.errorhandler(405)
def handle_method_not_allowed(error):

    return jsonify({
        "error": "HTTP method not allowed."
    }), 405


@app.errorhandler(413)
def handle_payload_too_large(error):

    return jsonify({
        "error": "Request payload is too large."
    }), 413


@app.errorhandler(500)
def handle_internal_error(error):

    return jsonify({
        "error": "Internal server error."
    }), 500


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

initialize_database()


# ==========================================
# CONFIGURATION
# ==========================================

MAX_PROMPT_LENGTH = 10000


# ==========================================
# API AUTHENTICATION
# ==========================================

def authenticate_request():

    provided_key = request.headers.get("X-API-Key")

    if not provided_key:
        return False

    if provided_key != API_KEY:
        return False

    return True


# ==========================================
# PROMPT ANALYSIS PIPELINE
# ==========================================

def analyze_prompt(prompt):

    # ==========================================
    # 1. DETECT SENSITIVE INFORMATION
    # ==========================================

    detected = detect_sensitive_data(prompt)

    # ==========================================
    # 2. MASK SENSITIVE INFORMATION
    # ==========================================

    masked = mask_data(prompt)

    # ==========================================
    # 3. DETECT PROMPT INJECTION
    # ==========================================

    injection = detect_prompt_injection(prompt)

    injection_categories = injection.get(
        "categories",
        []
    )

    # ==========================================
    # 4. CALCULATE RISK
    # ==========================================

    risk = analyze_risk(
        detected,
        injection_categories
    )

    # ==========================================
    # 5. MAKE SECURITY DECISION
    # ==========================================

    decision = make_security_decision(risk)

    # ==========================================
    # 6. GENERATE RECOMMENDATIONS
    # ==========================================

    suggestions = generate_suggestions(
        detected,
        injection.get("detected", False)
    )

    # ==========================================
    # 7. CREATE PRIVACY-SAFE DETECTION RESULT
    # ==========================================

    safe_detected = []

    for item in detected:

        safe_detected.append({
            "type": item["type"],
            "confidence": item["confidence"]
        })

    # ==========================================
    # 8. REMOVE RAW VALUES FROM RISK DETAILS
    # ==========================================

    safe_detected_details = []

    for item in risk.get("detected_details", []):

        safe_detected_details.append({
            "type": item["type"],
            "severity": item["severity"]
        })

    # ==========================================
    # 9. CREATE SAFE RISK OBJECT
    # ==========================================

    safe_risk = risk.copy()

    safe_risk["detected_details"] = (
        safe_detected_details
    )

    # ==========================================
    # 10. RETURN RESULT
    # ==========================================

    return {
        # Needed by the web dashboard
        "original": prompt,

        "masked": masked,

        "detected": safe_detected,

        "injection": injection,

        "risk": safe_risk,

        "decision": decision,

        "suggestions": suggestions
    }


# ==========================================
# MAIN WEB PAGE
# ==========================================

@app.route("/", methods=["GET", "POST"])
def index():

    # ==========================================
    # DEFAULT VALUES
    # ==========================================

    result = {

        "original": "",

        "masked": "",

        "detected": [],

        "injection": {
            "detected": False,
            "categories": [],
            "matches": []
        },

        "risk": {
            "privacy_score": 0,
            "privacy_level": "LOW",

            "security_score": 0,
            "security_level": "LOW",

            "overall_score": 0,
            "overall_level": "LOW",

            "detected_details": [],
            "injection_details": []
        },

        "decision": {
            "action": "ALLOW",
            "reason": (
                "Enter a prompt to perform "
                "a security analysis."
            )
        },

        "suggestions": []
    }

    # ==========================================
    # PROCESS SUBMITTED PROMPT
    # ==========================================

    if request.method == "POST":

        prompt = request.form.get(
            "prompt",
            ""
        ).strip()

        # ==========================================
        # EMPTY PROMPT
        # ==========================================

        if not prompt:

            return render_template(
                "index.html",
                **result
            )

        # ==========================================
        # PROMPT LENGTH VALIDATION
        # ==========================================

        if len(prompt) > MAX_PROMPT_LENGTH:

            result["original"] = prompt

            result["decision"] = {
                "action": "BLOCK",
                "reason": (
                    f"Prompt is too long. "
                    f"Maximum length is "
                    f"{MAX_PROMPT_LENGTH} characters."
                )
            }

            result["suggestions"] = [
                "Reduce the prompt length and try again."
            ]

            return render_template(
                "index.html",
                **result
            )

        # ==========================================
        # ANALYZE SUBMITTED PROMPT
        # ==========================================

        result = analyze_prompt(prompt)

        # ==========================================
        # SAVE SCAN
        # ==========================================

        save_scan(
            result["masked"],
            result["risk"],
            result["injection"]["detected"]
        )

    # ==========================================
    # RENDER WEB PAGE
    # ==========================================

    return render_template(
        "index.html",
        **result
    )


# ==========================================
# REST API
# ==========================================

@app.route(
    "/api/analyze",
    methods=["POST"]
)
@limiter.limit("30 per minute")
def api_analyze():

    # ==========================================
    # API AUTHENTICATION
    # ==========================================

    if not authenticate_request():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    # ==========================================
    # READ JSON REQUEST
    # ==========================================

    if not request.is_json:

        return jsonify({
            "error": "Request must contain JSON."
        }), 400

    data = request.get_json(
        silent=True
    )

    # ==========================================
    # INVALID JSON
    # ==========================================

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON body."
        }), 400

    # ==========================================
    # MISSING PROMPT
    # ==========================================

    if "prompt" not in data:

        return jsonify({
            "error": (
                "Request must contain "
                "a 'prompt' field."
            )
        }), 400

    prompt = data["prompt"]

    # ==========================================
    # PROMPT MUST BE A STRING
    # ==========================================

    if not isinstance(prompt, str):

        return jsonify({
            "error": "Prompt must be a string."
        }), 400

    prompt = prompt.strip()

    # ==========================================
    # EMPTY PROMPT
    # ==========================================

    if not prompt:

        return jsonify({
            "error": "Prompt cannot be empty."
        }), 400

    # ==========================================
    # MAXIMUM PROMPT LENGTH
    # ==========================================

    if len(prompt) > MAX_PROMPT_LENGTH:

        return jsonify({
            "error": (
                f"Prompt is too long. "
                f"Maximum length is "
                f"{MAX_PROMPT_LENGTH} characters."
            )
        }), 413

    # ==========================================
    # ANALYZE PROMPT
    # ==========================================

    result = analyze_prompt(prompt)

    # ==========================================
    # SAVE SCAN
    # ==========================================

    save_scan(
        result["masked"],
        result["risk"],
        result["injection"]["detected"]
    )

    # ==========================================
    # REMOVE ORIGINAL PROMPT FROM API RESPONSE
    # ==========================================

    api_result = result.copy()

    api_result.pop(
        "original",
        None
    )

    # ==========================================
    # RETURN PRIVACY-SAFE API RESULT
    # ==========================================

    return jsonify(api_result)


# ==========================================
# HEALTH CHECK
# ==========================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    return jsonify({
        "status": "healthy",
        "service": "PromptGuard AI"
    })


# ==========================================
# SCAN HISTORY WEB PAGE
# ==========================================

@app.route("/history")
def history():

    scans = get_scans()

    return render_template(
        "history.html",
        scans=scans
    )


# ==========================================
# SCAN HISTORY REST API
# ==========================================

@app.route(
    "/api/history",
    methods=["GET"]
)
def api_history():

    scans = get_scans()

    history_data = []

    for scan in scans:

        history_data.append({

            "id": scan["id"],

            "masked_prompt": (
                scan["masked_prompt"]
            ),

            "privacy_score": (
                scan["privacy_score"]
            ),

            "security_score": (
                scan["security_score"]
            ),

            "overall_score": (
                scan["overall_score"]
            ),

            "overall_level": (
                scan["overall_level"]
            ),

            "injection_detected": bool(
                scan["injection_detected"]
            ),

            "created_at": (
                scan["created_at"]
            )
        })

    return jsonify({

        "count": len(history_data),

        "scans": history_data
    })


# ==========================================
# APPLICATION START
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                5000
            )
        ),
        debug=False
    )