"""Pure-Python text features and Naive Bayes prediction."""

from collections import Counter
from functools import lru_cache
import json
import math
from pathlib import Path
import re


MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "sms_spam_model.json"
TOKEN_PATTERN = re.compile(r"[a-z0-9]+(?:'[a-z0-9]+)?")


def tokenize(text: str) -> list[str]:
    """Return lowercase word tokens plus adjacent word bigrams."""
    words = TOKEN_PATTERN.findall(text.lower())
    bigrams = [f"bigram:{first}_{second}" for first, second in zip(words, words[1:])]
    return words + bigrams


def score_with_model(model: dict, text: str) -> float:
    """Compute a smoothed Naive Bayes score for the spam class."""
    vocabulary = set(model["vocabulary"])
    vocabulary_size = max(1, len(vocabulary))
    alpha = model["alpha"]
    total_documents = sum(model["document_counts"].values())
    message_counts = Counter(token for token in tokenize(text) if token in vocabulary)
    log_scores = {}

    for label in (0, 1):
        key = str(label)
        class_documents = model["document_counts"][key]
        token_total = model["token_totals"][key]
        counts = model["token_counts"][key]
        score = math.log(class_documents / total_documents)
        for token, repetitions in message_counts.items():
            probability = (counts.get(token, 0) + alpha) / (token_total + alpha * vocabulary_size)
            score += repetitions * math.log(probability)
        log_scores[label] = score

    difference = log_scores[1] - log_scores[0]
    if difference >= 0:
        return 1 / (1 + math.exp(-difference))
    exp_difference = math.exp(difference)
    return exp_difference / (1 + exp_difference)


@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_PATH.exists():
        return None
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def spam_score(text: str) -> float | None:
    """Return the trained model's spam-class score, or None until trained."""
    model = _load_model()
    if model is None:
        return None
    return score_with_model(model, text)


def model_clues(text: str, limit: int = 3) -> list[str]:
    """Return the strongest spam-associated words found in this message."""
    model = _load_model()
    if model is None:
        return []

    vocabulary = set(model["vocabulary"])
    alpha = model["alpha"]
    vocabulary_size = max(1, len(vocabulary))
    token_counts = Counter(token for token in tokenize(text) if token in vocabulary)
    ham_total = model["token_totals"]["0"]
    spam_total = model["token_totals"]["1"]
    ham_counts = model["token_counts"]["0"]
    spam_counts = model["token_counts"]["1"]
    contributions = []

    for token, repetitions in token_counts.items():
        ham_rate = (ham_counts.get(token, 0) + alpha) / (ham_total + alpha * vocabulary_size)
        spam_rate = (spam_counts.get(token, 0) + alpha) / (spam_total + alpha * vocabulary_size)
        contribution = repetitions * math.log(spam_rate / ham_rate)
        if contribution > 0:
            display_token = token.removeprefix("bigram:").replace("_", " ")
            contributions.append((contribution, display_token))

    contributions.sort(reverse=True)
    return [
        f"“{token}” is more associated with spam than legitimate messages in the training data."
        for _, token in contributions[:limit]
    ]
