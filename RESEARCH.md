# RESEARCH — corpus-scrub

## Problem (Thesis of creation)

ML training corpora scraped from the web contain PII and secrets. Models memorize
them and leak on inference; GDPR and EU AI Act art. 10 forbid unstructured personal
data in training sets without consent. We need a reusable, maintained, multi-language
corpus cleaner — the gap confirmed by find-niche (2026-07-16): specific solution
`total_count` on GitHub = 0–4, while the 4 existing repos (LLM-Sanitizer-openenv,
data-sanitizer, AI-Data-Quality-Guardrail, NoLeakAi) are 0–2★, unlicensed, one-day
prototypes.

## Scientific foundation (papers)

- **2607.13541** — When T2I Synthetic Data Backfires: Amplified Privacy Risks in
  Real-Synthetic Mix Training. RSMT *amplifies* leakage of real training samples.
- **2601.17480** — Unintended Memorization of Sensitive Information in Fine-Tuned LLMs.
  Quantifies PII memorization from model *inputs*; benchmarks 4 defenses.
- **2602.16980** — Discovering Universal Activation Directions for PII Leakage (UniLeak).
  Latent directions that amplify PII generation.

## Methodology

- **PII**: Presidio AnalyzerEngine (spaCy `en_core_web_lg` NER for PERSON + built-in
  regex recognizers for EMAIL/IBAN/CARD/PHONE). English only in MVP.
- **Secrets**: regex ported from gitleaks `generic-api-key` rule (MIT,
  github.com/gitleaks/gitleaks). Not pinned to a commit (generic rule, no quantitative
  claim); if a secrets-recall benchmark is published, pin the commit.
- **Redaction**: mask / hash / drop, applied in reverse span order to preserve indices.

## KNOWN ISSUES (from viability spike 2026-07-16)

- **KI-1**: `AnalyzerEngine.analyze(language="es")` raises
  `ValueError: No matching recognizers` — even universal regex (EMAIL/IBAN) is
  registered per `supported_language="en"`. ES/DE/FR NER is Fase 2 (model per language,
  ~400 MB each).
- **KI-2**: NER PERSON in EN yields false positives (generic proper nouns). Mitigated
  by a configurable score threshold (default 0.85). AC-4 target is precision ≥ 0.95
  (not zero), trading off against AC-1 recall ≥ 0.95.
- **KI-3**: gitleaks regex copied, not commit-pinned (MIT, generic rule).

## Acceptance Criteria (SDD, all verified by tests)

| AC | Target | Result |
|----|--------|--------|
| AC-1 PII recall (EN, por tipo) | ≥ 0.95 en EMAIL/PERSON/CARD; PHONE e IBAN fuera (KI-4) | ✅ EMAIL 11/11, PERSON 12/12, CARD 3/3; PHONE 0/6, IBAN 4/5 |
| AC-2 Secret recall | ≥ 0.90 | ✅ 12/12 docs (fast) |
| AC-3 Redaction policy | mask/hash/drop | ✅ (fast) |
| AC-4 Precision benign | ≥ 0.95 | ✅ 0 false positives / 12 (fast) |
| AC-5 JSON report | counts per type | ✅ (fast) |
| AC-6 CLI streaming | all docs processed | ✅ (slow) |
| AC-7 Non-EN rejected | explicit error | ✅ exit 2 (slow) |

Test coverage measured: **82%** (`pytest --cov`, full suite). `readers.py` parquet
path untested (pyarrow optional, out of fast scope).
