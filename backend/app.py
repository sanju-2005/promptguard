from flask import Flask, render_template, request, jsonify

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


app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)


# Initialize database when application starts
initialize_database()


def analyze_prompt(prompt):

    # 1. Detect sensitive information
    detected = detect_sensitive_data(prompt)

    # 2. Mask sensitive information
    masked = mask_data(prompt)

    # 3. Detect prompt injection
    injection = detect_prompt_injection(prompt)

    injection_categories = injection.get(
        "categories",
        []
    )

    # 4. Calculate risk
    risk = analyze_risk(
        detected,
        injection_categories
    )

    # 5. Make security decision
    decision = make_security_decision(
        risk
    )

    # 6. Generate recommendations
    suggestions = generate_suggestions(
        detected,
        injection["detected"]
    )

    return {
        "original": prompt,
        "masked": masked,
        "detected": detected,
        "injection": injection,
        "risk": risk,
        "decision": decision,
        "suggestions": suggestions
    }


# ==========================================
# MAIN WEB PAGE
# ==========================================

@app.route("/", methods=["GET", "POST"])
def index():

    # Default values for first page load
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

        # IMPORTANT:
        # This prevents Jinja from saying
        # "decision is undefined"
        "decision": {
            "action": "ALLOW",
            "reason": "Enter a prompt to perform a security analysis."
        },

        "suggestions": []
    }


    # If user submitted a prompt
    if request.method == "POST":

        prompt = request.form.get(
            "prompt",
            ""
        ).strip()


        if prompt:

            result = analyze_prompt(
                prompt
            )


            # Save scan to database
            save_scan(
                result["original"],
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

@app.route("/api/analyze", methods=["POST"])
def api_analyze():

    data = request.get_json(
        silent=True
    )


    # Missing JSON or prompt
    if not data or "prompt" not in data:

        return jsonify({
            "error": "Request must contain a 'prompt' field."
        }), 400


    prompt = data["prompt"]


    # Prompt must be a string
    if not isinstance(prompt, str):

        return jsonify({
            "error": "Prompt must be a string."
        }), 400


    prompt = prompt.strip()


    # Empty prompt
    if not prompt:

        return jsonify({
            "error": "Prompt cannot be empty."
        }), 400


    # Analyze prompt
    result = analyze_prompt(
        prompt
    )


    # Save scan
    save_scan(
        result["original"],
        result["masked"],
        result["risk"],
        result["injection"]["detected"]
    )


    return jsonify(
        result
    )
# ==========================================
# HEALTH CHECK
# ==========================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "healthy",
        "service": "PromptGuard AI"
    })

# ==========================================
# SCAN HISTORY
# ==========================================



@app.route("/history")
def history():

    scans = get_scans()

    return render_template(
        "history.html",
        scans=scans
    )


# ==========================================
# APPLICATION START
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )