"""Train and evaluate a pure-Python Naive Bayes SMS spam baseline."""

from collections import Counter, defaultdict
import json
import random
from pathlib import Path
from urllib.request import urlretrieve
from zipfile import ZipFile

from src.ml_model import score_with_model, tokenize


ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "raw" / "smsspamcollection.zip"
MODEL_PATH = ROOT / "models" / "sms_spam_model.json"
METRICS_PATH = ROOT / "reports" / "sms_spam_metrics.json"
DATASET_URL = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"
RANDOM_STATE = 42


def load_messages() -> list[tuple[str, int]]:
    """Download the UCI archive once and read its tab-separated messages."""
    if not DATA_PATH.exists():
        DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        print("Downloading the UCI SMS Spam Collection...")
        urlretrieve(DATASET_URL, DATA_PATH)

    with ZipFile(DATA_PATH) as archive:
        data_file = next(name for name in archive.namelist() if name.lower().endswith("smsspamcollection"))
        raw = archive.read(data_file).decode("utf-8", errors="replace")

    records = []
    for line in raw.splitlines():
        label, separator, text = line.partition("\t")
        label = label.strip().lower()
        text = text.strip()
        if separator and text and label in {"ham", "spam"}:
            records.append((text, int(label == "spam")))

    unique: dict[str, tuple[str, int]] = {}
    for text, label in records:
        unique.setdefault(text.casefold(), (text, label))
    return list(unique.values())


def stratified_split(records: list[tuple[str, int]]) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Make a repeatable 80/20 split while retaining both classes."""
    groups: dict[int, list[tuple[str, int]]] = defaultdict(list)
    for record in records:
        groups[record[1]].append(record)

    rng = random.Random(RANDOM_STATE)
    training, testing = [], []
    for group in groups.values():
        rng.shuffle(group)
        split_at = max(1, round(len(group) * 0.20))
        testing.extend(group[:split_at])
        training.extend(group[split_at:])
    rng.shuffle(training)
    rng.shuffle(testing)
    return training, testing


def train_naive_bayes(training: list[tuple[str, int]]) -> dict:
    document_counts = Counter(label for _, label in training)
    document_frequency: Counter[str] = Counter()
    for text, _ in training:
        document_frequency.update(set(tokenize(text)))

    vocabulary = sorted(token for token, count in document_frequency.items() if count >= 2)
    vocabulary_set = set(vocabulary)
    token_counts = {0: Counter(), 1: Counter()}
    for text, label in training:
        token_counts[label].update(token for token in tokenize(text) if token in vocabulary_set)

    return {
        "vocabulary": vocabulary,
        "document_counts": {str(label): document_counts[label] for label in (0, 1)},
        "token_counts": {str(label): dict(token_counts[label]) for label in (0, 1)},
        "token_totals": {str(label): sum(token_counts[label].values()) for label in (0, 1)},
        "alpha": 1.0,
    }


def evaluate(model: dict, testing: list[tuple[str, int]]) -> dict:
    predictions = [int(score_with_model(model, text) >= 0.5) for text, _ in testing]
    actual = [label for _, label in testing]
    tn = sum(y == 0 and p == 0 for y, p in zip(actual, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(actual, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(actual, predictions))
    tp = sum(y == 1 and p == 1 for y, p in zip(actual, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tn + tp) / len(actual) if actual else 0.0
    return {
        "accuracy": round(accuracy, 4),
        "spam_precision": round(precision, 4),
        "spam_recall": round(recall, 4),
        "spam_f1": round(f1, 4),
        "confusion_matrix_labels": ["ham", "spam"],
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def main() -> None:
    records = load_messages()
    training, testing = stratified_split(records)
    model = train_naive_bayes(training)
    metrics = {
        "dataset": "UCI SMS Spam Collection",
        "dataset_url": "https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
        "dataset_license": "CC BY 4.0",
        "scope_note": "English SMS spam classification; this is a baseline proxy, not a general scam detector.",
        "deduplicated_examples": len(records),
        "train_examples": len(training),
        "test_examples": len(testing),
        "random_state": RANDOM_STATE,
        "split": "stratified 80/20 holdout after case-insensitive exact-text deduplication",
        "feature_method": "word unigrams and adjacent bigrams; tokens seen in at least two training messages",
        "classifier": "multinomial Naive Bayes with Laplace smoothing (alpha=1)",
        **evaluate(model, testing),
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.write_text(json.dumps(model), encoding="utf-8")
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("Training complete.")
    print(f"Unique messages: {len(records)} (train {len(training)}, test {len(testing)})")
    print(f"Accuracy:       {metrics['accuracy']:.1%}")
    print(f"Spam precision: {metrics['spam_precision']:.1%}")
    print(f"Spam recall:    {metrics['spam_recall']:.1%}")
    print(f"Spam F1:        {metrics['spam_f1']:.1%}")
    print(f"Metrics saved:  {METRICS_PATH}")
    print(f"Model saved:    {MODEL_PATH}")
    print("Reminder: these holdout results measure SMS spam classification, not all scam types.")


if __name__ == "__main__":
    main()
