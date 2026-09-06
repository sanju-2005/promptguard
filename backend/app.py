from flask import Flask, render_template, request

from detector import detect_sensitive_data
from masker import mask_data
from risk_analyzer import analyze_risk
from injection_detector import detect_prompt_injection
from suggestions import generate_suggestions


app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)


@app.route("/", methods=["GET", "POST"])
def index():

    original = ""

    masked = ""

    detected = []

    injection = {
        "detected": False,
        "categories": [],
        "matches": []
    }

    risk = {
        "privacy_score": 0,
        "privacy_level": "LOW",
        "security_score": 0,
        "security_level": "LOW",
        "overall_score": 0,
        "overall_level": "LOW"
    }

    suggestions = []


    if request.method == "POST":

        original = request.form.get(
            "prompt",
            ""
        ).strip()


        if original:

            # Detect sensitive information
            detected = detect_sensitive_data(
                original
            )


            # Mask sensitive information
            masked = mask_data(
                original
            )


            # Detect prompt injection
            injection = detect_prompt_injection(
                original
            )


            # Extract attack categories
            injection_categories = injection.get(
                "categories",
                []
            )


            # Calculate risk
            risk = analyze_risk(
                detected,
                injection_categories
            )


            # Generate recommendations
            suggestions = generate_suggestions(
                detected,
                injection["detected"]
            )

    return render_template(
        "index.html",

        original=original,

        masked=masked,

        detected=detected,

        injection=injection,

        risk=risk,

        suggestions=suggestions
    )


if __name__ == "__main__":

    app.run(
        debug=True
    )