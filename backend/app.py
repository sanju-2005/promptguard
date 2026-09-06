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
        "matches": []
    }
    risk = {
        "score": 0,
        "level": "LOW"
    }
    suggestions = []

    if request.method == "POST":

        original = request.form.get("prompt", "")

        detected = detect_sensitive_data(original)

        masked = mask_data(original)

        injection = detect_prompt_injection(original)

        risk = analyze_risk(
            detected,
            injection["detected"]
        )

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
    app.run(debug=True)