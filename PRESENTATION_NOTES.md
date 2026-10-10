# ScamLens AI — presentation notes

## 30-second introduction

ScamLens AI is a responsive website for first-pass screening of suspicious messages and URLs. It combines transparent warning rules with two lightweight Naive Bayes baselines, explains which signals influenced its analysis, and recommends safer verification steps. It is an educational prototype for decision support, not a guarantee that a message or link is safe.

## Suggested 3-minute demo

1. Start the local website and open `http://127.0.0.1:5000`.
2. On the **Message** tab, click **Try a sample**. Point out the rule score, matched warning signals, separate SMS spam score, and model clues.
3. Explain that the SMS model detects patterns from an English SMS spam dataset; it does not detect every kind of scam.
4. Switch to **Link / URL**, click **Try a sample**, and run the check. Note that `.example` is reserved for documentation and that ScamLens inspects the URL text without opening it.
5. Explain that scores are separate and model scores are uncalibrated. Show the evaluation numbers in the README and discuss the false negatives in the error-analysis report.

Do not demonstrate with real private messages, credentials, or live suspicious links.

## Results to present

- **SMS spam baseline:** 98.8% accuracy, 96.8% precision, 93.8% recall, and 95.2% F1 on a stratified holdout of 1,031 English SMS messages.
- **Phishing URL baseline:** 93.1% accuracy, 97.2% precision, 86.4% recall, and 91.5% F1 on 35,305 host-held-out URLs.
- **URL evaluation design:** 70/15/15 host-disjoint train/validation/test splits; decision threshold 0.607903 selected on validation F1; zero normalized-host overlap.

These are dataset results, not live-world guarantees. URL host grouping uses normalized hostnames rather than a complete public-suffix list, and the dataset has no timestamps for temporal evaluation.

## Likely questions

**Does the score mean the message is definitely a scam?**
No. The rule score is a transparent heuristic score, and model values are uncalibrated class scores. ScamLens should prompt independent verification, not make a definitive decision.

**Does ScamLens open a link or send the text to an AI service?**
No. The URL model uses only the pasted URL text, and inference uses local model files without an external AI API. A hosted demo still receives the submitted content on its server, so do not enter private information.

**Why use simple Naive Bayes models?**
They are lightweight, reproducible baselines. Future work could compare stronger models and independently sourced, time-aware data while preserving careful evaluation splits.

**What is the biggest current limitation?**
Dataset coverage and generalization. The SMS model is limited to English SMS spam, and the URL benchmark cannot measure performance on future URLs or every scam type.

## Resume bullet

Built ScamLens AI, a responsive Flask app combining explainable scam-warning rules with pure-Python Naive Bayes baselines; evaluated phishing detection using host-disjoint train/validation/test splits, reaching 93.1% accuracy and 97.2% precision on a held-out UCI URL test set.
