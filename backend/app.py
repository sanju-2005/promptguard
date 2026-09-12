from flask import Flask, render_template, request, jsonify, session
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

from backend.llm_router import LLMRouter
from backend.prompt_optimizer import optimize_prompt
from backend.token_analyzer import analyze_tokens

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

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "promptguard-development-secret"
)


# ==========================================
# RATE LIMITING
# ==========================================

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[
        "200 per day",
        "50 per hour"
    ],
    storage_uri="memory://"
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
# ERROR HANDLERS
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
# LLM ROUTER
# ==========================================

llm_router = LLMRouter()


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
    decision = make_security_decision(risk)

    # 6. Generate recommendations
    suggestions = generate_suggestions(
        detected,
        injection.get("detected", False)
    )

    # 7. Privacy-safe detection results
    safe_detected = []

    for item in detected:

        safe_detected.append({
            "type": item["type"],
            "confidence": item["confidence"]
        })

    # 8. Privacy-safe risk details
    safe_detected_details = []

    for item in risk.get(
        "detected_details",
        []
    ):

        safe_detected_details.append({
            "type": item["type"],
            "severity": item["severity"]
        })

    safe_risk = risk.copy()

    safe_risk["detected_details"] = (
        safe_detected_details
    )

    return {
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

    if request.method == "POST":

        prompt = request.form.get(
            "prompt",
            ""
        ).strip()

        if not prompt:

            return render_template(
                "index.html",
                **result
            )

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

        result = analyze_prompt(prompt)

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
# REST API - ANALYZE PROMPT
# ==========================================

@app.route(
    "/api/analyze",
    methods=["POST"]
)
@limiter.limit("30 per minute")
def api_analyze():

    if not authenticate_request():

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not request.is_json:

        return jsonify({
            "error": "Request must contain JSON."
        }), 400

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON body."
        }), 400

    if "prompt" not in data:

        return jsonify({
            "error": (
                "Request must contain "
                "a 'prompt' field."
            )
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

    if len(prompt) > MAX_PROMPT_LENGTH:

        return jsonify({
            "error": (
                f"Prompt is too long. "
                f"Maximum length is "
                f"{MAX_PROMPT_LENGTH} characters."
            )
        }), 413

    result = analyze_prompt(prompt)

    save_scan(
        result["masked"],
        result["risk"],
        result["injection"]["detected"]
    )

    api_result = result.copy()

    api_result.pop(
        "original",
        None
    )

    return jsonify(api_result)


# ==========================================
# AVAILABLE LLM PROVIDERS
# ==========================================

@app.route(
    "/api/providers",
    methods=["GET"]
)
def api_providers():

    return jsonify({
        "providers": llm_router.available_providers()
    })


# ==========================================
# GENERATE AI RESPONSE
# ==========================================

@app.route(
    "/api/generate",
    methods=["POST"]
)
@limiter.limit("10 per minute")
def api_generate():

    # ==========================================
    # FRONTEND REQUEST
    # ==========================================
    #
    # This endpoint is called by our own
    # frontend. The frontend must NOT receive
    # the PromptGuard API key.
    #
    # External clients should use /api/analyze
    # with X-API-Key authentication.
    #

    # ==========================================
    # JSON VALIDATION
    # ==========================================

    if not request.is_json:

        return jsonify({
            "error": "Request must contain JSON."
        }), 400

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON body."
        }), 400

    # ==========================================
    # GET PROMPT
    # ==========================================

    prompt = data.get("prompt")

    if not isinstance(prompt, str):

        return jsonify({
            "error": "Prompt must be a string."
        }), 400

    prompt = prompt.strip()

    if not prompt:

        return jsonify({
            "error": "Prompt cannot be empty."
        }), 400

    if len(prompt) > MAX_PROMPT_LENGTH:

        return jsonify({
            "error": (
                f"Prompt is too long. "
                f"Maximum length is "
                f"{MAX_PROMPT_LENGTH} characters."
            )
        }), 413

    # ==========================================
    # SELECT PROVIDER
    # ==========================================

    provider = data.get(
        "provider",
        "groq"
    )

    if not isinstance(provider, str):

        return jsonify({
            "error": "Provider must be a string."
        }), 400

    provider = provider.lower().strip()

    if provider not in llm_router.SUPPORTED_PROVIDERS:

        return jsonify({
            "error": (
                f"Unsupported provider: {provider}. "
                f"Supported providers: "
                f"{', '.join(llm_router.SUPPORTED_PROVIDERS.keys())}"
            )
        }), 400

    # ==========================================
    # SECURITY ANALYSIS
    # ==========================================

    analysis = analyze_prompt(prompt)

    # ==========================================
    # SECURITY DECISION
    # ==========================================

    decision = analysis["decision"]

    if decision.get("action", "").upper() == "BLOCK":

        return jsonify({
            "error": "Prompt blocked by PromptGuard.",
            "decision": decision,
            "risk": analysis["risk"],
            "injection": {
                "detected": analysis[
                    "injection"
                ].get("detected", False),
                "categories": analysis[
                    "injection"
                ].get("categories", [])
            },
            "suggestions": analysis[
                "suggestions"
            ]
        }), 403

    # ==========================================
    # USE MASKED PROMPT
    # ==========================================

    masked_prompt = analysis["masked"]

    # ==========================================
    # OPTIMIZE MASKED PROMPT
    # ==========================================

    optimized = optimize_prompt(
        masked_prompt
    )

    optimized_prompt = optimized[
        "optimized_prompt"
    ]

    # ==========================================
    # TOKEN ANALYSIS
    # ==========================================

    token_analysis = analyze_tokens(
        optimized_prompt,
        provider=provider,
        estimated_output_tokens=1000
    )

    # ==========================================
    # CONTEXT LIMIT CHECK
    # ==========================================

    if token_analysis["status"] == "EXCEEDED":

        return jsonify({
            "error": (
                "Prompt blocked because the "
                "estimated token usage exceeds "
                "the selected model context limit."
            ),
            "token_analysis": token_analysis
        }), 413

    # ==========================================
    # CALL LLM
    # ==========================================

    try:

        llm_result = llm_router.generate(
            provider=provider,
            prompt=optimized_prompt,
            temperature=0.2,
            max_tokens=1000
        )

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 400

    except Exception:

        return jsonify({
            "error": (
                "LLM provider request failed."
            )
        }), 502

    # ==========================================
    # SAVE SECURITY SCAN
    # ==========================================

    save_scan(
        masked_prompt,
        analysis["risk"],
        analysis["injection"]["detected"]
    )

    # ==========================================
    # RETURN RESPONSE
    # ==========================================

    return jsonify({

        "provider": llm_result.get(
            "provider"
        ),

        "model": llm_result.get(
            "model"
        ),

        "response": llm_result.get(
            "response"
        ),

        "usage": llm_result.get(
            "usage",
            {}
        ),

        "security": {
            "risk": analysis["risk"],

            "decision": analysis["decision"],

            "injection": {
                "detected": analysis[
                    "injection"
                ].get("detected", False),

                "categories": analysis[
                    "injection"
                ].get("categories", [])
            }
        },

        "prompt": {
            "masked": masked_prompt,

            "optimized": optimized_prompt,

            "task_type": optimized[
                "task_type"
            ]
        },

        "token_analysis": token_analysis
    })


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
# HISTORY PAGE
# ==========================================

@app.route("/history")
def history():

    scans = get_scans()

    return render_template(
        "history.html",
        scans=scans
    )


# ==========================================
# HISTORY API
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

    from waitress import serve

    serve(
        app,
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                5000
            )
        )
    )