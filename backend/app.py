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

    provided_key = request.headers.get(
        "X-API-Key"
    )

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

    detected = detect_sensitive_data(
        prompt
    )


    # ==========================================
    # 2. MASK SENSITIVE INFORMATION
    # ==========================================

    masked = mask_data(
        prompt
    )


    # ==========================================
    # 3. DETECT PROMPT INJECTION
    # ==========================================

    injection = detect_prompt_injection(
        prompt
    )

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

    decision = make_security_decision(
        risk
    )


    # ==========================================
    # 6. GENERATE RECOMMENDATIONS
    # ==========================================

    suggestions = generate_suggestions(
        detected,
        injection["detected"]
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

    for item in risk["detected_details"]:

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
    # 10. RETURN PRIVACY-SAFE RESULT
    # ==========================================

    return {
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
                "Enter a prompt to perform a security analysis."
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

        result = analyze_prompt(
            prompt
        )


        # ==========================================
        # SAVE SCAN
        # ==========================================

        save_scan(
            result["masked"],
            result["risk"],
            result["injection"]["detected"]
        )


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

    data = request.get_json(
        silent=True
    )


    # ==========================================
    # MISSING JSON OR PROMPT
    # ==========================================

    if not data or "prompt" not in data:

        return jsonify({
            "error": (
                "Request must contain a 'prompt' field."
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

    result = analyze_prompt(
        prompt
    )


    # ==========================================
    # SAVE SCAN
    # ==========================================

    save_scan(
        result["masked"],
        result["risk"],
        result["injection"]["detected"]
    )


    # ==========================================
    # RETURN PRIVACY-SAFE RESULT
    # ==========================================

    return jsonify(
        result
    )


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
        debug=False
    )

