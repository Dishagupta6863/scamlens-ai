"""Train a URL-only categorical Naive Bayes phishing baseline."""

from collections import Counter, defaultdict
import csv
import json
import random
from pathlib import Path
import time
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
from zipfile import ZipFile

from src.url_model import extract_features, score_with_model


ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "raw" / "phiusiil_dataset.zip"
MODEL_PATH = ROOT / "models" / "phishing_url_model.json"
METRICS_PATH = ROOT / "reports" / "phishing_url_metrics.json"
ERROR_REPORT_PATH = ROOT / "reports" / "phishing_url_error_analysis.md"
DATASET_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
RANDOM_STATE = 42


def ensure_dataset_downloaded() -> None:
    """Download to a temporary file and retry interrupted transfers."""
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DATA_PATH.exists():
        try:
            with ZipFile(DATA_PATH) as archive:
                if archive.testzip() is None:
                    return
        except Exception:
            DATA_PATH.unlink(missing_ok=True)

    partial_path = DATA_PATH.with_suffix(".zip.part")
    request = Request(DATASET_URL, headers={"User-Agent": "ScamLens-AI/1.0"})
    for attempt in range(1, 5):
        partial_path.unlink(missing_ok=True)
        try:
            print(f"Downloading the UCI PhiUSIIL URL dataset (about 15 MB), attempt {attempt}/4...")
            with urlopen(request, timeout=120) as response, partial_path.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)

            with ZipFile(partial_path) as archive:
                if archive.testzip() is not None:
                    raise ValueError("The downloaded ZIP failed its integrity check.")
            partial_path.replace(DATA_PATH)
            return
        except Exception as error:
            partial_path.unlink(missing_ok=True)
            if attempt == 4:
                raise RuntimeError(
                    "The UCI download did not complete after four attempts. "
                    "Check your internet connection and rerun the training command."
                ) from error
            time.sleep(attempt * 2)


def load_urls() -> list[tuple[str, int]]:
    """Download the UCI archive once and read URL strings plus labels only."""
    ensure_dataset_downloaded()

    with ZipFile(DATA_PATH) as archive:
        data_file = next(name for name in archive.namelist() if name.lower().endswith(".csv"))
        with archive.open(data_file) as csv_file:
            reader = csv.DictReader((line.decode("utf-8-sig", errors="replace") for line in csv_file))
            fields = {name.lower(): name for name in (reader.fieldnames or [])}
            url_key = fields.get("url")
            label_key = fields.get("label")
            if not url_key or not label_key:
                raise ValueError("The downloaded CSV did not contain URL and Label columns.")

            unique: dict[str, tuple[str, int]] = {}
            for row in reader:
                url = (row.get(url_key) or "").strip()
                label = (row.get(label_key) or "").strip()
                if url and label in {"0", "1"}:
                    # Positive class: 1 = phishing; 0 = legitimate.
                    unique.setdefault(url.casefold(), (url, int(label == "0")))
    return list(unique.values())


def host_group(url: str) -> str:
    """Return a normalized host key so URLs on one host stay in one split."""
    candidate = url.strip()
    parsed = urlsplit(candidate if "://" in candidate else "//" + candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or candidate.casefold()


def host_group_split(
    records: list[tuple[str, int]],
    fractions: tuple[float, float, float] = (0.70, 0.15, 0.15),
) -> tuple[list[list[tuple[str, int]]], list[set[str]]]:
    """Create deterministic, approximately class-balanced host-disjoint splits."""
    by_host: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for record in records:
        by_host[host_group(record[0])].append(record)

    host_items = list(by_host.items())
    random.Random(RANDOM_STATE).shuffle(host_items)
    totals = [sum(label == cls for _, label in records) for cls in (0, 1)]
    targets = [[count * fraction for count in totals] for fraction in fractions]
    counts = [[0, 0] for _ in fractions]
    split_hosts: list[set[str]] = [set() for _ in fractions]

    # Assign each whole host to the split that most reduces normalized class-count
    # error. A single pass avoids quadratic behavior on large URL collections.
    for host, rows in host_items:
        host_counts = [sum(label == cls for _, label in rows) for cls in (0, 1)]
        costs = []
        for split_index in range(len(fractions)):
            cost = 0.0
            for i in range(len(fractions)):
                for cls in (0, 1):
                    proposed = counts[i][cls] + (host_counts[cls] if i == split_index else 0)
                    target = max(1.0, targets[i][cls])
                    cost += ((proposed - targets[i][cls]) / target) ** 2
            costs.append(cost)
        chosen = min(range(len(costs)), key=costs.__getitem__)
        split_hosts[chosen].add(host)
        for cls in (0, 1):
            counts[chosen][cls] += host_counts[cls]

    splits = [
        [row for host in hosts for row in by_host[host]]
        for hosts in split_hosts
    ]
    return splits, split_hosts


def train_model(training: list[tuple[str, int]]) -> dict:
    document_counts = Counter(label for _, label in training)
    feature_counts = {0: defaultdict(Counter), 1: defaultdict(Counter)}
    categories: dict[str, set[str]] = defaultdict(set)

    for url, label in training:
        for feature, value in extract_features(url).items():
            feature_counts[label][feature][value] += 1
            categories[feature].add(value)

    return {
        "document_counts": {str(label): document_counts[label] for label in (0, 1)},
        "feature_counts": {
            str(label): {name: dict(values) for name, values in feature_counts[label].items()}
            for label in (0, 1)
        },
        "categories": {name: sorted(values) for name, values in categories.items()},
        "alpha": 1.0,
    }


def evaluate(model: dict, testing: list[tuple[str, int]], threshold: float = 0.5) -> dict:
    predictions = [int(score_with_model(model, url) >= threshold) for url, _ in testing]
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
        "phishing_precision": round(precision, 4),
        "phishing_recall": round(recall, 4),
        "phishing_f1": round(f1, 4),
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def select_threshold(model: dict, validation: list[tuple[str, int]]) -> tuple[float, dict]:
    """Choose the validation threshold with best F1; tie-break by recall, then precision."""
    scored = sorted(
        ((score_with_model(model, url), label) for url, label in validation),
        key=lambda item: item[0],
        reverse=True,
    )
    positives = sum(label == 1 for _, label in scored)
    true_positives = false_positives = 0
    best_threshold = 0.5
    baseline = evaluate(model, validation, best_threshold)
    best_key = (baseline["phishing_f1"], baseline["phishing_recall"], baseline["phishing_precision"])

    index = 0
    while index < len(scored):
        threshold = scored[index][0]
        while index < len(scored) and scored[index][0] == threshold:
            if scored[index][1] == 1:
                true_positives += 1
            else:
                false_positives += 1
            index += 1
        precision = true_positives / max(1, true_positives + false_positives)
        recall = true_positives / max(1, positives)
        f1 = 2 * precision * recall / max(1e-12, precision + recall)
        candidate_key = (f1, recall, precision)
        if candidate_key > best_key:
            best_key = candidate_key
            best_threshold = threshold
    return best_threshold, evaluate(model, validation, best_threshold)


def defang_url(url: str) -> str:
    """Return a non-clickable, path-redacted example for reports."""
    candidate = url.strip()
    parsed = urlsplit(candidate if "://" in candidate else "//" + candidate)
    host = (parsed.hostname or "unparsed-host").lower().rstrip(".")
    safe_host = host.replace(".", "[.]" ).replace(":", "[:]")
    scheme = "hxxps" if parsed.scheme.lower() == "https" else "hxxp"
    return f"{scheme}://{safe_host}/<path-redacted>"


def build_error_report(
    model: dict, testing: list[tuple[str, int]], metrics: dict, threshold: float,
) -> str:
    """Summarize false negatives and false positives with defanged examples."""
    errors = {"missed_phishing": [], "false_alarms": []}
    for url, actual in testing:
        score = score_with_model(model, url)
        predicted = int(score >= threshold)
        if actual == 1 and predicted == 0:
            errors["missed_phishing"].append((score, url))
        elif actual == 0 and predicted == 1:
            errors["false_alarms"].append((score, url))

    phishing_count = sum(label == 1 for _, label in testing)
    legitimate_count = len(testing) - phishing_count
    missed_count = len(errors["missed_phishing"])
    false_alarm_count = len(errors["false_alarms"])
    lines = [
        "# URL model error analysis",
        "",
        f"Generated from the host-disjoint test set using the validation-selected threshold ({threshold:.6f}).",
        "Examples are defanged and paths are redacted so they are not usable links.",
        "Scores below are raw, uncalibrated Naive Bayes class scores.",
        "",
        "## Error counts",
        "",
        f"- Missed phishing URLs (false negatives): **{missed_count:,} / {phishing_count:,}** phishing examples ({missed_count / max(1, phishing_count):.1%}).",
        f"- Legitimate URLs flagged as phishing (false positives): **{false_alarm_count:,} / {legitimate_count:,}** legitimate examples ({false_alarm_count / max(1, legitimate_count):.1%}).",
        f"- Overall holdout accuracy: **{metrics['accuracy']:.1%}**; phishing precision: **{metrics['phishing_precision']:.1%}**; phishing recall: **{metrics['phishing_recall']:.1%}**.",
        "",
        "## Most confident missed phishing examples",
        "",
        "These are false negatives with the lowest phishing scores. Their patterns are useful candidates for improving features, but do not change the threshold based on this final holdout.",
        "",
    ]
    missed = sorted(errors["missed_phishing"], key=lambda item: item[0])[:10]
    if missed:
        for score, url in missed:
            features = extract_features(url)
            shape = ", ".join(f"{name}={value}" for name, value in features.items())
            lines.append(f"- `{defang_url(url)}` — raw phishing score {score:.3f}; {shape}.")
    else:
        lines.append("- None in this holdout.")

    lines += ["", "## Most confident false alarms", "", "These are legitimate URLs with the highest phishing scores.", ""]
    false_alarms = sorted(errors["false_alarms"], key=lambda item: item[0], reverse=True)[:10]
    if false_alarms:
        for score, url in false_alarms:
            features = extract_features(url)
            shape = ", ".join(f"{name}={value}" for name, value in features.items())
            lines.append(f"- `{defang_url(url)}` — raw phishing score {score:.3f}; {shape}.")
    else:
        lines.append("- None in this holdout.")

    lines += [
        "",
        "## Interpretation",
        "",
        "Review these errors to identify missing URL patterns and benign patterns that trigger warnings. Any feature or threshold changes should be selected using a separate validation split; keep this host-held-out test set unchanged for the final reported result.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    records = load_urls()
    splits, split_hosts = host_group_split(records)
    training, validation, testing = splits
    train_hosts, validation_hosts, test_hosts = split_hosts
    if (train_hosts & validation_hosts) or (train_hosts & test_hosts) or (validation_hosts & test_hosts):
        raise RuntimeError("Host leakage detected between train, validation, and test splits.")
    model = train_model(training)
    threshold, validation_metrics = select_threshold(model, validation)
    metrics = {
        "dataset": "UCI PhiUSIIL Phishing URL (Website)",
        "dataset_url": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset",
        "dataset_license": "CC BY 4.0",
        "scope_note": "Uses URL-text features only; the source dataset also contains webpage-derived fields that this model does not use.",
        "unique_urls": len(records),
        "train_examples": len(training),
        "validation_examples": len(validation),
        "test_examples": len(testing),
        "train_hosts": len(train_hosts),
        "validation_hosts": len(validation_hosts),
        "test_hosts": len(test_hosts),
        "host_overlap": len((train_hosts & validation_hosts) | (train_hosts & test_hosts) | (validation_hosts & test_hosts)),
        "random_state": RANDOM_STATE,
        "split": "deterministic approximately 70/15/15 host-grouped train/validation/test split after case-insensitive URL deduplication; www-prefixed hosts are normalized together",
        "threshold_selection": "maximize phishing F1 on validation; ties broken by recall then precision",
        "decision_threshold": round(threshold, 6),
        "validation_metrics_at_selected_threshold": validation_metrics,
        "split_limitation": "Grouping uses normalized hostnames, not a complete public-suffix list; sibling subdomains may remain in different groups. The dataset has no collection timestamp, so temporal evaluation is unavailable.",
        "features": "URL length, scheme, IP host, subdomain depth, hyphens, @ symbol, shortener, query, path depth, sensitive terms, digits, encoding, symbols, and punycode",
        "classifier": "categorical Naive Bayes with Laplace smoothing (alpha=1)",
        **evaluate(model, testing, threshold),
    }
    error_report = build_error_report(model, testing, metrics, threshold)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.write_text(json.dumps(model), encoding="utf-8")
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    ERROR_REPORT_PATH.write_text(error_report, encoding="utf-8")

    print("URL model training complete.")
    print(
        f"Unique URLs: {len(records)} (train {len(training)}, "
        f"validation {len(validation)}, test {len(testing)})"
    )
    print(f"Accuracy:          {metrics['accuracy']:.1%}")
    print(f"Phishing precision:{metrics['phishing_precision']:.1%}")
    print(f"Phishing recall:   {metrics['phishing_recall']:.1%}")
    print(f"Phishing F1:       {metrics['phishing_f1']:.1%}")
    print(f"Validation-selected threshold: {threshold:.6f} (validation F1 {validation_metrics['phishing_f1']:.1%})")
    print(f"Host-disjoint split: {metrics['train_hosts']} train, {metrics['validation_hosts']} validation, {metrics['test_hosts']} test hosts; {metrics['host_overlap']} overlap")
    print(f"Metrics saved: {METRICS_PATH}")
    print(f"Error analysis saved: {ERROR_REPORT_PATH}")
    print(f"Model saved:   {MODEL_PATH}")
    print("Reminder: holdout scores are dataset results, not a guarantee for current live URLs.")


if __name__ == "__main__":
    main()
