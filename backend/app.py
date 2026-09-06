from flask import Flask, render_template, request, jsonify
from backend.detector import detect_sensitive_data
from backend.masker import mask_data
from backend.risk_analyzer import analyze_risk
from backend.injection_detector import detect_prompt_injection
from backend.suggestions import generate_suggestions

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


# Initialize SQLite database when application starts
initialize_database()


def analyze_prompt(prompt):

    # Detect sensitive information
    detected = detect_sensitive_data(prompt)

    # Mask sensitive information
    masked = mask_data(prompt)

    # Detect prompt injection
    injection = detect_prompt_injection(prompt)

    # Get injection categories
    injection_categories = injection.get(
        "categories",
        []
    )

    # Calculate privacy/security/overall risk
    risk = analyze_risk(
        detected,
        injection_categories
    )

    # Generate recommendations
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
        "suggestions": suggestions
    }


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def index():

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
            "overall_level": "LOW"
        },

        "suggestions": []
    }


    if request.method == "POST":

        prompt = request.form.get(
            "prompt",
            ""
        ).strip()


        if prompt:

            result = analyze_prompt(prompt)


            # Save scan to SQLite database
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


# --------------------------------------------------
# REST API
# --------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def api_analyze():

    data = request.get_json(
        silent=True
    )


    if not data or "prompt" not in data:

        return jsonify({
            "error": "Request must contain a 'prompt' field."
        }), 400


    prompt = data["prompt"]


    if not isinstance(prompt, str):

        return jsonify({
            "error": "Prompt must be a string."
        }), 400


    prompt = prompt.strip()


    if not prompt:

        return jsonify({
            "error": "Prompt cannot be empty."
        }), 400


    result = analyze_prompt(prompt)


    # Save API scan to database
    save_scan(
        result["original"],
        result["masked"],
        result["risk"],
        result["injection"]["detected"]
    )


    return jsonify(result)


# --------------------------------------------------
# SCAN HISTORY
# --------------------------------------------------

@app.route("/history")
def history():

    scans = get_scans()

    return render_template(
        "history.html",
        scans=scans
    )


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=True
    )