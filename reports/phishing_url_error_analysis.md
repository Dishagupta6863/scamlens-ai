# URL model error analysis

Generated from the host-disjoint test set using the validation-selected threshold (0.607903).
Examples are defanged and paths are redacted so they are not usable links.
Scores below are raw, uncalibrated Naive Bayes class scores.

## Error counts

- Missed phishing URLs (false negatives): **2,053 / 15,078** phishing examples (13.6%).
- Legitimate URLs flagged as phishing (false positives): **375 / 20,227** legitimate examples (1.9%).
- Overall holdout accuracy: **93.1%**; phishing precision: **97.2%**; phishing recall: **86.4%**.

## Most confident missed phishing examples

These are false negatives with the lowest phishing scores. Their patterns are useful candidates for improving features, but do not change the threshold based on this final holdout.

- `hxxps://fpostlecers[.]firebaseapp[.]com/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://maildinshaakckjnw639[.]web[.]app/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://dpomstlms[.]web[.]app/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://xyuh1j[.]webwave[.]dev/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://ovhdjdjdjjdjdjd[.]firebaseapp[.]com/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://maildinshaakckjnw37[.]web[.]app/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://www[.]auraschoolpmna[.]com/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://eqofuh[.]webwave[.]dev/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://yeqk42t[.]square[.]site/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://maildinshaakckjnw232[.]web[.]app/<path-redacted>` — raw phishing score 0.065; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=none, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.

## Most confident false alarms

These are legitimate URLs with the highest phishing scores.

- `hxxps://www[.]non-man-entry-tank-cleaning-oil-recovery[.]com/<path-redacted>` — raw phishing score 1.000; length=medium, scheme=https, ip_host=no, subdomains=medium, host_hyphens=many, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=high.
- `hxxps://www[.]collectors-club-of-great-britain[.]co[.]uk/<path-redacted>` — raw phishing score 1.000; length=short, scheme=https, ip_host=no, subdomains=high, host_hyphens=many, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=high.
- `hxxps://www[.]220-380v[.]by/<path-redacted>` — raw phishing score 0.996; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=one, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=high, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://www[.]talent-databank[.]co[.]jp/<path-redacted>` — raw phishing score 0.918; length=short, scheme=https, ip_host=no, subdomains=high, host_hyphens=one, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=yes, digit_ratio=low, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://www[.]2-10[.]com/<path-redacted>` — raw phishing score 0.895; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=one, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=medium, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://www[.]1-54[.]com/<path-redacted>` — raw phishing score 0.895; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=one, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=medium, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://www[.]l-36[.]com/<path-redacted>` — raw phishing score 0.895; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=one, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=medium, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://www[.]exodus-314[.]com/<path-redacted>` — raw phishing score 0.895; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=one, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=medium, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://www[.]1001-lampaszalon[.]hu/<path-redacted>` — raw phishing score 0.895; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=one, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=medium, encoded_chars=no, host_punycode=no, symbols=medium.
- `hxxps://www[.]medizin-2000[.]de/<path-redacted>` — raw phishing score 0.895; length=short, scheme=https, ip_host=no, subdomains=medium, host_hyphens=one, at_symbol=no, shortener=no, query=no, path_depth=shallow, suspicious_term=no, digit_ratio=medium, encoded_chars=no, host_punycode=no, symbols=medium.

## Interpretation

Review these errors to identify missing URL patterns and benign patterns that trigger warnings. Any feature or threshold changes should be selected using a separate validation split; keep this host-held-out test set unchanged for the final reported result.
