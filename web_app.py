"""Flask web interface for ScamLens AI."""

from flask import Flask, jsonify, render_template, request

from src.analyzer import analyze


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    return response


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/healthz")
def health():
    return jsonify(status="ok")


@app.post("/api/analyze")
def analyze_input():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Send a JSON object with content and scan_type."), 400

    content = payload.get("content")
    scan_type = payload.get("scan_type")
    if not isinstance(content, str) or not content.strip():
        return jsonify(error="Paste a message or URL to analyze."), 400
    if len(content) > 5000:
        return jsonify(error="Please keep the input under 5,000 characters."), 413
    if not isinstance(scan_type, str) or scan_type not in {"message", "url"}:
        return jsonify(error="Choose either message or URL analysis."), 400

    result = analyze(content.strip(), scan_type)
    return jsonify(
        score=result.score,
        label=result.label,
        summary=result.summary,
        advice=result.advice,
        signals=[{"title": item.title, "detail": item.detail} for item in result.signals],
        spam_model_score=result.spam_model_score,
        spam_model_clues=result.spam_model_clues,
        url_model_score=result.url_model_score,
        url_model_clues=result.url_model_clues,
    )


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="Please keep the input under 5,000 characters."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
