"""Explainable baseline analyzer for suspicious messages and URLs."""

from dataclasses import dataclass, field
import re
from urllib.parse import urlparse


@dataclass(frozen=True)
class Signal:
    title: str
    detail: str
    weight: int


@dataclass(frozen=True)
class Analysis:
    score: int
    label: str
    summary: str
    signals: list[Signal]
    advice: str
    spam_model_score: float | None = None
    spam_model_clues: list[str] = field(default_factory=list)
    url_model_score: float | None = None
    url_model_clues: list[str] = field(default_factory=list)


URGENCY = ("urgent", "immediately", "act now", "within 24 hours", "limited time", "final warning")
THREATS = ("account will be suspended", "account is locked", "legal action", "warrant", "deactivated")
CREDENTIALS = ("password", "one-time password", "otp", "verification code", "login details", "pin")
PAYMENT = ("gift card", "crypto", "cryptocurrency", "wire transfer", "bank transfer", "processing fee")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "ow.ly"}


def _message_signals(text: str) -> list[Signal]:
    lowered = text.lower()
    signals: list[Signal] = []
    checks = [
        (URGENCY, "Pressure to act quickly", "Urgency can make it harder to verify a request.", 18),
        (THREATS, "Threatening account or legal language", "The message uses a threat to push the recipient into action.", 22),
        (CREDENTIALS, "Sensitive login information requested", "Legitimate organizations should not ask you to share passwords or one-time codes in a message.", 30),
        (PAYMENT, "Unusual payment method mentioned", "Gift cards, cryptocurrency, or urgent transfers are common scam payment demands.", 28),
    ]
    for phrases, title, detail, weight in checks:
        matches = [phrase for phrase in phrases if phrase in lowered]
        if matches:
            signals.append(Signal(title, f"Matched wording: {', '.join(matches[:3])}. {detail}", weight))

    if re.search(r"\b(prize|winner|won|claim your reward)\b", lowered):
        signals.append(Signal("Unexpected prize or reward", "Unexpected prizes may be used to collect personal details or fees.", 16))
    if re.search(r"https?://|www\.", lowered):
        signals.append(Signal("Link included", "Check the destination independently instead of following an unexpected link.", 8))
        # Inspect the visible URL structure as well as the surrounding message.
        # Limit this to three links so a long message cannot inflate the score
        # simply by repeating the same URL many times.
        urls = re.findall(r"(?:https?://|www\.)[^\s<>]+", text, flags=re.IGNORECASE)
        for raw_url in urls[:3]:
            url = raw_url.rstrip(".,;:!?)\"]}")
            for signal in _url_signals(url):
                if signal.weight > 0:
                    signals.append(
                        Signal(
                            f"Link check: {signal.title}",
                            f"Visible URL {url[:100]} — {signal.detail}",
                            signal.weight,
                        )
                    )
    return signals


def _url_signals(value: str) -> list[Signal]:
    candidate = value.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    signals: list[Signal] = []
    if parsed.scheme != "https":
        signals.append(Signal("No HTTPS", "The URL does not use an encrypted HTTPS connection.", 15))
    if not host:
        signals.append(Signal("URL could not be parsed", "Enter a complete domain or URL so it can be inspected.", 10))
    if host in SHORTENERS:
        signals.append(Signal("Shortened link", "The final destination is hidden behind a URL shortener.", 25))
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        signals.append(Signal("IP address used as host", "A raw IP address can make it harder to verify who operates the site.", 25))
    if "@" in parsed.netloc:
        signals.append(Signal("Misleading @ symbol", "Text before @ in a URL can mislead readers about the actual host.", 25))
    if host.count("-") >= 3:
        signals.append(Signal("Unusual number of hyphens", "Multiple hyphens can be used in deceptive lookalike domains.", 12))
    if len(host.split(".")) >= 5:
        signals.append(Signal("Many subdomain levels", "A long chain of subdomains can obscure the registered domain.", 12))
    if len(candidate) > 180:
        signals.append(Signal("Unusually long URL", "Long URLs may hide tracking or confusing destination paths.", 8))
    if parsed.scheme == "https" and host and not signals:
        signals.append(Signal("Basic URL checks passed", "No configured URL warning pattern was detected; this does not establish trustworthiness.", 0))
    return signals


def analyze(content: str, scan_type: str = "message") -> Analysis:
    """Analyze text with transparent rules and return a bounded risk score."""
    signals = _url_signals(content) if scan_type == "url" else _message_signals(content)
    score = min(100, sum(signal.weight for signal in signals))
    if score >= 60:
        label, summary = "High risk", "Several strong warning signs were detected."
        advice = "Do not click, reply, pay, or share codes. Contact the organization using a number or website you find independently."
    elif score >= 30:
        label, summary = "Caution", "Some warning signs were detected; verify the request independently."
        advice = "Pause and confirm the sender and request through an official channel you already trust."
    else:
        label, summary = "Lower risk signals", "Few configured warning signs were detected; this is not a safety guarantee."
        advice = "Stay cautious. Check the sender and destination independently before sharing information or money."
    # Load the optional trained model only after its dependencies and artifact
    # are available. The transparent rule engine still works without it.
    model_score = None
    model_clues = []
    url_model_score = None
    url_model_clues = []
    if scan_type == "message":
        try:
            from .ml_model import model_clues as get_model_clues, spam_score

            model_score = spam_score(content)
            model_clues = get_model_clues(content)
        except ImportError:
            model_score = None
            model_clues = []
    elif scan_type == "url":
        try:
            from .url_model import model_clues as get_url_clues, phishing_score

            url_model_score = phishing_score(content)
            url_model_clues = get_url_clues(content)
        except ImportError:
            url_model_score = None
            url_model_clues = []
    return Analysis(
        score,
        label,
        summary,
        signals,
        advice,
        model_score,
        model_clues,
        url_model_score,
        url_model_clues,
    )
