import json
from pathlib import Path

import streamlit as st

from src.analyzer import analyze


st.set_page_config(page_title="ScamLens AI", page_icon="🛡️", layout="centered")
METRICS_PATH = Path(__file__).parent / "reports" / "sms_spam_metrics.json"
URL_METRICS_PATH = Path(__file__).parent / "reports" / "phishing_url_metrics.json"
URL_ERROR_REPORT_PATH = Path(__file__).parent / "reports" / "phishing_url_error_analysis.md"

st.title("🛡️ ScamLens AI")
st.caption("A transparent first-pass scam risk check for messages and links.")

with st.container(border=True):
    scan_type = st.radio("What would you like to check?", ["Message", "URL"], horizontal=True)
    content = st.text_area(
        "Paste suspicious content",
        height=170,
        placeholder="Example: Your account is locked. Verify now at https://example.com",
    )
    submitted = st.button("Analyze risk", type="primary", use_container_width=True)

if submitted:
    if not content.strip():
        st.warning("Paste a message or URL to analyze.")
    else:
        result = analyze(content, scan_type.lower())
        st.subheader("Risk assessment")
        col1, col2 = st.columns([1, 2])
        col1.metric("Rule-based risk score", f"{result.score}/100")
        col2.markdown(f"### {result.label}\n{result.summary}")
        if result.spam_model_score is not None:
            st.metric("SMS spam score (uncalibrated)", f"{result.spam_model_score:.0%}")
            st.caption(
                "This raw Naive Bayes class score is not calibrated confidence and is not "
                "the probability that this message is fraudulent."
            )
            if result.spam_model_clues:
                st.markdown("#### Model clues")
                for clue in result.spam_model_clues:
                    st.markdown(f"- {clue}")
        if result.url_model_score is not None:
            st.metric("Phishing URL score (uncalibrated)", f"{result.url_model_score:.0%}")
            st.caption(
                "This URL-only model score is uncalibrated and does not prove whether a link is safe."
            )
            if result.url_model_clues:
                st.markdown("#### URL model clues")
                for clue in result.url_model_clues:
                    st.markdown(f"- {clue}")

        if result.signals:
            st.markdown("#### Rule-based signals")
            for signal in result.signals:
                st.markdown(f"- **{signal.title}** — {signal.detail}")
        else:
            st.info("No configured warning signals were found. That does not prove the content is safe.")

        st.markdown("#### Suggested next step")
        st.write(result.advice)

if METRICS_PATH.exists():
    with st.expander("Model evaluation"):
        metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        st.caption(
            f"Held-out evaluation on {metrics['test_examples']:,} messages from the "
            f"{metrics['dataset']} dataset. This measures SMS spam classification only."
        )
        metric_cols = st.columns(4)
        metric_cols[0].metric("Accuracy", f"{metrics['accuracy']:.1%}")
        metric_cols[1].metric("Spam precision", f"{metrics['spam_precision']:.1%}")
        metric_cols[2].metric("Spam recall", f"{metrics['spam_recall']:.1%}")
        metric_cols[3].metric("Spam F1", f"{metrics['spam_f1']:.1%}")
        st.caption("Confusion matrix rows = actual (ham, spam); columns = predicted (ham, spam).")
        st.code(json.dumps(metrics["confusion_matrix"], indent=2), language="json")

if URL_METRICS_PATH.exists():
    with st.expander("URL model evaluation"):
        metrics = json.loads(URL_METRICS_PATH.read_text(encoding="utf-8"))
        st.caption(
            f"Held-out evaluation on {metrics['test_examples']:,} URLs from the "
            f"{metrics['dataset']} dataset. Hosts are separated across "
            f"{metrics.get('train_hosts', 0):,} train, {metrics.get('validation_hosts', 0):,} validation, "
            f"and {metrics.get('test_hosts', 0):,} test groups, with {metrics.get('host_overlap', 0)} overlap. "
            f"Threshold {metrics.get('decision_threshold', 0.5):.3f} was selected on validation data. "
            "Only URL-text features are used."
        )
        metric_cols = st.columns(4)
        metric_cols[0].metric("Accuracy", f"{metrics['accuracy']:.1%}")
        metric_cols[1].metric("Phishing precision", f"{metrics['phishing_precision']:.1%}")
        metric_cols[2].metric("Phishing recall", f"{metrics['phishing_recall']:.1%}")
        metric_cols[3].metric("Phishing F1", f"{metrics['phishing_f1']:.1%}")
        st.caption("Confusion matrix rows = actual (legitimate, phishing); columns = predicted (legitimate, phishing).")
        st.code(json.dumps(metrics["confusion_matrix"], indent=2), language="json")
        if metrics.get("split_limitation"):
            st.caption(metrics["split_limitation"])
        if URL_ERROR_REPORT_PATH.exists():
            st.download_button(
                "Download URL error analysis",
                data=URL_ERROR_REPORT_PATH.read_bytes(),
                file_name="phishing_url_error_analysis.md",
                mime="text/markdown",
            )

st.divider()
st.caption(
    "ScamLens combines transparent warning rules with separate SMS spam and phishing URL models. "
    "The rule-based risk score and model scores are separate signals. Neither "
    "proves content is safe or detects every kind of scam."
)
