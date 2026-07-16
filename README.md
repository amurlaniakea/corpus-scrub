# corpus-scrub

Detect and redact **PII** (personally identifiable information: email, phone, IBAN,
credit card, person names) and **secrets** (API keys, tokens) in ML training corpora
**before training**. Local-first, CLI, AGPL-3.0-or-later.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

## Why

Training data scraped from the web routinely contains personal data and secrets. Models
memorize and leak them (see *References*), and GDPR / EU AI Act art. 10 prohibit
unstructured personal data in training sets without consent. `corpus-scrub` cleans the
corpus before training.

## Scope (MVP)

- **PII detection**: Presidio (NER via spaCy `en_core_web_lg` for `PERSON`, regex for
  EMAIL/IBAN/CARD/PHONE) — **English only** in MVP.
- **Secret detection**: regex based on gitleaks `generic-api-key` rule (MIT),
  multi-language by nature.
- **Redaction**: `mask` (`<TYPE>`), `hash` (sha256 truncated), `drop`.
- **Report**: JSON audit with counts per type + locations.
- **Out of scope (MVP)**: NER for ES/DE/FR (Fase 2, requires per-language spaCy models
  ~400 MB each). See `KNOWN_ISSUES` in the SDD spec.
- **Recall guarantee (MVP)**: AC-1 guarantees ≥0.95 recall for EMAIL_ADDRESS, PERSON and
  CREDIT_CARD. **PHONE_NUMBER and IBAN_CODE are NOT guaranteed** in MVP — Presidio scores
  phone below the 0.85 NER threshold (silently dropped) and the IBAN recognizer misses some
  formats in EN. Documented as KI-4; see `test_ac1_phone_iban_below_threshold`.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
# first run downloads spaCy en_core_web_lg (~400 MB) automatically
```

## Usage

```bash
# Scan a corpus (jsonl/txt/parquet), mask findings, write redacted corpus + audit report
corpus-scrub scan --input corpus.jsonl --policy mask --out redacted.jsonl --report report.json

# Hash instead of mask
corpus-scrub scan --input ./corpus_dir --policy hash --out redacted.jsonl

# Only English NER is supported in MVP; other languages error explicitly
corpus-scrub scan --input corpus.jsonl --lang en
```

## Tests

```bash
pytest -m "not slow"   # fast suite (no model download)
pytest -m slow         # requires spaCy en_core_web_lg download
pytest                 # full suite + coverage
```

Current coverage: **82%** (measured via `pytest --cov`, see CI).

## License

AGPL-3.0-or-later. Dependencies (Presidio, spaCy, gitleaks regex) are MIT and compatible.

## References

- When T2I Synthetic Data Backfires: Amplified Privacy Risks in Real-Synthetic Mix Training — arXiv 2607.13541
- Unintended Memorization of Sensitive Information in Fine-Tuned Language Models — arXiv 2601.17480
- Discovering Universal Activation Directions for PII Leakage (UniLeak) — arXiv 2602.16980
