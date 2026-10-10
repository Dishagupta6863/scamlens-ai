"""Production WSGI entry point used by the Render deployment manifest."""

import os

from waitress import serve

from web_app import app


if __name__ == "__main__":
    serve(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000")),
        threads=8,
        max_request_body_size=12 * 1024,
    )
