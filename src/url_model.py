"""URL-only feature extraction and categorical Naive Bayes scoring."""

from collections import Counter
from functools import lru_cache
import json
import math
from pathlib import Path
import ipaddress
from urllib.parse import urlsplit


MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "phishing_url_model.json"
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "ow.ly"}
SUSPICIOUS_TERMS = {"account", "bank", "confirm", "login", "password", "secure", "signin", "update", "verify", "wallet"}

FEATURE_LABELS = {
    "length": "URL length",
    "scheme": "URL connection scheme",
    "ip_host": "IP address used as host",
    "subdomains": "Subdomain depth",
    "host_hyphens": "Hyphens in host name",
    "at_symbol": "@ symbol in URL authority",
    "shortener": "Known URL shortener host",
    "query": "Query string present",
    "path_depth": "Path depth",
    "suspicious_term": "Sensitive or sign-in term in URL",
    "digit_ratio": "Digits in URL",
    "encoded_chars": "Percent-encoded characters",
    "host_punycode": "Punycode host name",
}


def extract_features(value: str) -> dict[str, str]:
    """Extract only URL-text properties; never request the URL or page."""
    candidate = value.strip()
    has_scheme = "://" in candidate
    parsed = urlsplit(candidate if has_scheme else "//" + candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    host_parts = [part for part in host.split(".") if part]
    path_and_query = (parsed.path + "?" + parsed.query).lower()
    digits = sum(char.isdigit() for char in candidate)
    specials = sum(not char.isalnum() for char in candidate)

    try:
        ipaddress.ip_address(host)
        ip_host = "yes"
    except ValueError:
        ip_host = "no"

    length = len(candidate)
    digit_ratio = digits / max(1, len(candidate))
    path_parts = [part for part in parsed.path.split("/") if part]
    features = {
        "length": "short" if length < 55 else "medium" if length < 100 else "long",
        "scheme": parsed.scheme.lower() if has_scheme else "missing",
        "ip_host": ip_host,
        "subdomains": "low" if len(host_parts) <= 2 else "medium" if len(host_parts) == 3 else "high",
        "host_hyphens": "none" if "-" not in host else "one" if host.count("-") == 1 else "many",
        "at_symbol": "yes" if "@" in parsed.netloc or "@" in candidate else "no",
        "shortener": "yes" if host in SHORTENERS else "no",
        "query": "yes" if parsed.query else "no",
        "path_depth": "shallow" if len(path_parts) <= 1 else "medium" if len(path_parts) <= 3 else "deep",
        "suspicious_term": "yes" if any(term in path_and_query or term in host for term in SUSPICIOUS_TERMS) else "no",
        "digit_ratio": "low" if digit_ratio < 0.1 else "medium" if digit_ratio < 0.25 else "high",
        "encoded_chars": "yes" if "%" in candidate else "no",
        "host_punycode": "yes" if "xn--" in host else "no",
    }
    # Keep `specials` useful as a coarse lexical shape without storing a numeric range.
    features["symbols"] = "low" if specials < 4 else "medium" if specials < 10 else "high"
    return features


def score_with_model(model: dict, url: str) -> float:
    """Return the model's phishing-class score for one URL."""
    features = extract_features(url)
    alpha = model["alpha"]
    counts = model["feature_counts"]
    totals = model["document_counts"]
    score_by_class = {}
    for label in (0, 1):
        key = str(label)
        score = math.log(totals[key] / sum(totals.values()))
        for name, value in features.items():
            categories = model["categories"][name]
            count = counts[key][name].get(value, 0)
            probability = (count + alpha) / (totals[key] + alpha * len(categories))
            score += math.log(probability)
        score_by_class[label] = score

    difference = score_by_class[1] - score_by_class[0]
    if difference >= 0:
        return 1 / (1 + math.exp(-difference))
    exp_difference = math.exp(difference)
    return exp_difference / (1 + exp_difference)


@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_PATH.exists():
        return None
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def phishing_score(url: str) -> float | None:
    model = _load_model()
    if model is None:
        return None
    return score_with_model(model, url)


def model_clues(url: str, limit: int = 3) -> list[str]:
    """Describe URL features that leaned toward the phishing class."""
    model = _load_model()
    if model is None:
        return []
    features = extract_features(url)
    counts = model["feature_counts"]
    totals = model["document_counts"]
    alpha = model["alpha"]
    contributions = []
    for name, value in features.items():
        categories = model["categories"][name]
        phish_probability = (counts["1"][name].get(value, 0) + alpha) / (totals["1"] + alpha * len(categories))
        legitimate_probability = (counts["0"][name].get(value, 0) + alpha) / (totals["0"] + alpha * len(categories))
        contribution = math.log(phish_probability / legitimate_probability)
        if contribution > 0:
            label = FEATURE_LABELS.get(name, name.replace("_", " ").capitalize())
            contributions.append((contribution, label, value))
    contributions.sort(reverse=True)
    return [
        f"{label}: “{value}” was more common in phishing URLs in the training data."
        for _, label, value in contributions[:limit]
    ]
