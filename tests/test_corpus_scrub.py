"""Tests de corpus_scrub — AC-1..AC-7.

Volumen real: fixtures con 12 casos cada una (ver tests/data/fixtures/make_fixtures.py).
AC-1/AC-2/AC-6 son slow (descarga de modelo spaCy en_core_web_lg en runtime).
AC-3/AC-4/AC-5/AC-7 son fast (no requieren NER).

Sin @parametrize (evita el parser de marcadores de pytest 9.x con valores no-string).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from corpus_scrub.detectors.secrets import SecretDetector
from corpus_scrub.redact import redact_text
from corpus_scrub.report import build_report
from corpus_scrub.models import Finding

FIX = Path(__file__).parent / "data" / "fixtures"


def _load(name: str):
    docs = []
    for line in (FIX / name).read_text(encoding="utf-8").splitlines():
        if line.strip():
            obj = json.loads(line)
            docs.append(obj["text"])
    return docs


# AC-2: secretos (fast, regex gitleaks, sin NER)
def test_ac2_secret_recall():
    docs = _load("secrets_seed.jsonl")
    det = SecretDetector()
    for text in docs:
        findings = det.detect("doc", text)
        secrets = [f for f in findings if f.type == "SECRET"]
        assert len(secrets) >= 1, f"Esperado >=1 secreto en: {text[:60]}"


def test_ac2_secret_recall_aggregate():
    docs = _load("secrets_seed.jsonl")
    det = SecretDetector()
    total = sum(len([f for f in det.detect("doc", d) if f.type == "SECRET"]) for d in docs)
    assert total >= 12, f"Recall de secretos bajo: {total}/12 docs con secreto"


# AC-3: redacción por política
def test_ac3_mask():
    f = Finding("d1", "EMAIL_ADDRESS", 0, 20, "john@example.com", 1.0)
    out = redact_text("john@example.com", [f], policy="mask")
    assert out == "<EMAIL_ADDRESS>"


def test_ac3_hash():
    f = Finding("d1", "EMAIL_ADDRESS", 0, 20, "john@example.com", 1.0)
    out = redact_text("john@example.com", [f], policy="hash")
    assert out != "john@example.com" and len(out) == 12


def test_ac3_drop():
    f = Finding("d1", "EMAIL_ADDRESS", 0, 20, "john@example.com", 1.0)
    out = redact_text("john@example.com", [f], policy="drop")
    assert out == ""


def test_ac3_structure_preserved():
    text = "Contact john@example.com now"
    f = Finding("d1", "EMAIL_ADDRESS", 8, 24, "john@example.com", 1.0)
    out = redact_text(text, [f], policy="mask")
    assert out == "Contact <EMAIL_ADDRESS> now"


# AC-4: precisión >= 0.95 en benigno paritario (fast)
def test_ac4_benign_no_false_positives():
    docs = _load("benign.jsonl")
    det = SecretDetector()
    for text in docs:
        secrets = [f for f in det.detect("doc", text) if f.type == "SECRET"]
        assert len(secrets) == 0, f"Falso positivo en benigno: {text[:60]}"


def test_ac4_benign_precision_aggregate():
    docs = _load("benign.jsonl")
    det = SecretDetector()
    false_pos = sum(len([f for f in det.detect("doc", d) if f.type == "SECRET"]) for d in docs)
    assert false_pos == 0, f"{false_pos} falsos positivos en benigno (precision <1.0)"


# AC-5: reporte JSON con conteos por tipo
def test_ac5_report_structure():
    findings = [
        Finding("d1", "EMAIL_ADDRESS", 0, 5, "x@y.z", 1.0),
        Finding("d2", "SECRET", 0, 10, "sk-abc", 1.0),
    ]
    rep = build_report(findings)
    assert rep["total_findings"] == 2
    assert rep["counts_by_type"]["EMAIL_ADDRESS"] == 1
    assert rep["counts_by_type"]["SECRET"] == 1
    assert rep["findings"][0]["doc_id"] == "d1"


# AC-6: streaming CLI (slow, requiere NER)
@pytest.mark.slow
def test_ac6_cli_scan_end_to_end(tmp_path):
    from corpus_scrub.cli import main
    import subprocess, sys
    out_file = tmp_path / "redacted.jsonl"
    report_file = tmp_path / "report.json"
    r = subprocess.run(
        [sys.executable, "-m", "corpus_scrub.cli", "scan",
         "--input", str(FIX / "pii_seed.jsonl"),
         "--policy", "mask", "--out", str(out_file), "--report", str(report_file)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    lines = [json.loads(l) for l in out_file.read_text().splitlines() if l.strip()]
    assert len(lines) == 12, f"CLI no procesó todos los docs: {len(lines)}"
    rep = json.loads(report_file.read_text())
    assert rep["total_findings"] >= 12, "Reporte sin hallazgos PII"


# AC-7: idioma no soportado en MVP da error explícito, no silencioso
@pytest.mark.slow
def test_ac7_non_en_language_rejected():
    from corpus_scrub.cli import main
    import subprocess, sys
    r = subprocess.run(
        [sys.executable, "-m", "corpus_scrub.cli", "scan",
         "--input", str(FIX / "pii_seed.jsonl"), "--lang", "es"],
        capture_output=True, text=True,
    )
    assert r.returncode == 2, f"Esperado exit 2 para lang=es, got {r.returncode}"
    assert "no soportado en MVP" in r.stderr, "Error debe ser explícito (KI-1)"


# AC-1: recall PII en EN (slow, NER)
@pytest.mark.slow
def test_ac1_pii_recall_aggregate():
    from corpus_scrub.detectors.pii import PiiDetector
    docs = _load("pii_seed.jsonl")
    det = PiiDetector(language="en", ner_threshold=0.85)
    total_docs_with_pii = 0
    for d in docs:
        findings = det.detect("doc", d)
        if findings:
            total_docs_with_pii += 1
    recall = total_docs_with_pii / len(docs)
    assert recall >= 0.95, f"Recall PII = {recall:.2f} < 0.95"
