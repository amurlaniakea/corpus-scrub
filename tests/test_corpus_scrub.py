# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 Pedro Sordo Martínez
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program. If not, see
# <https://www.gnu.org/licenses/>.

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
from corpus_scrub.models import Finding
from corpus_scrub.redact import redact_text
from corpus_scrub.report import build_report

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


# AC-4 (NER): falsos positivos de PERSON en benigno endurecido (slow, requiere NER).
# KI-2 predice que el NER marcará marcas/empresas/tecnicismos como PERSON.
# Con 18 docs, precision >= 0.95 tolera hasta 1 falso positivo de PERSON.
@pytest.mark.slow
def test_ac4_ner_false_positives_benign():
    from corpus_scrub.detectors.pii import PiiDetector

    docs = _load("benign.jsonl")
    det = PiiDetector(language="en", ner_threshold=0.85)
    false_pos = 0
    for d in docs:
        findings = det.detect("doc", d)
        persons = [f for f in findings if f.type == "PERSON"]
        false_pos += len(persons)
    # Tolerancia KI-2: hasta 1 FP de PERSON en 18 docs => precision >= 0.94 ~ 0.95
    assert false_pos <= 1, f"{false_pos} falsos positivos PERSON en benigno endurecido (KI-2)"


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
    import subprocess
    import sys

    out_file = tmp_path / "redacted.jsonl"
    report_file = tmp_path / "report.json"
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "corpus_scrub.cli",
            "scan",
            "--input",
            str(FIX / "pii_seed.jsonl"),
            "--policy",
            "mask",
            "--out",
            str(out_file),
            "--report",
            str(report_file),
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    lines = [json.loads(line) for line in out_file.read_text().splitlines() if line.strip()]
    assert len(lines) == 13, f"CLI no procesó todos los docs: {len(lines)}"
    rep = json.loads(report_file.read_text())
    assert rep["total_findings"] >= 12, "Reporte sin hallazgos PII"


# AC-7: idioma no soportado en MVP da error explícito, no silencioso
@pytest.mark.slow
def test_ac7_non_en_language_rejected():
    import subprocess
    import sys

    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "corpus_scrub.cli",
            "scan",
            "--input",
            str(FIX / "pii_seed.jsonl"),
            "--lang",
            "es",
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2, f"Esperado exit 2 para lang=es, got {r.returncode}"
    assert "no soportado en MVP" in r.stderr, "Error debe ser explícito (KI-1)"


# AC-1: recall PII en EN, DESGLOSADO POR TIPO (slow, NER).
# No basta con "el doc tuvo algun hallazgo" (lo taparia el email regex score=1.0).
# Medimos por tipo: de los docs que siembran X, cuantos produjeron Finding(type=X).
# Mapa de PII sembrado por doc (ver pii_seed.jsonl).
_SEEDED = {
    "EMAIL_ADDRESS": [0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    "PERSON": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    "PHONE_NUMBER": [0, 3, 5, 7, 8, 10, 12],
    "IBAN_CODE": [1, 4, 7, 9, 11],
    "CREDIT_CARD": [2, 6, 9],
}

# Tipos donde AC-1 garantiza recall >= 0.95 tras Feature 004 (desacople universal).
# EMAIL/PERSON/CREDIT_CARD (regex/Luhn + NER en_core_web_lg) y ahora PHONE/IBAN
# (regex propios con mod-97 / formato intl). Ver spec/features/004-universal-detectors.
_AC1_GUARANTEED = {"EMAIL_ADDRESS", "PERSON", "CREDIT_CARD", "PHONE_NUMBER", "IBAN_CODE"}


@pytest.mark.slow
def test_ac1_pii_recall_by_type():
    from corpus_scrub.detectors.pii import PiiDetector

    docs = _load("pii_seed.jsonl")
    det = PiiDetector(language="en", ner_threshold=0.85)
    detected_types_per_doc = {}
    for i, d in enumerate(docs):
        detected_types_per_doc[i] = {f.type for f in det.detect("doc", d)}
    report_lines = []
    for pii_type, seeded_docs in _SEEDED.items():
        hits = sum(1 for i in seeded_docs if pii_type in detected_types_per_doc[i])
        recall = hits / len(seeded_docs)
        report_lines.append(f"  AC-1 {pii_type}: recall={recall:.2f} ({hits}/{len(seeded_docs)})")
        if pii_type in _AC1_GUARANTEED:
            assert recall >= 0.95, f"Recall {pii_type} = {recall:.2f} < 0.95\n" + "\n".join(
                report_lines
            )
    # Desglose impreso para auditoria
    print("\nAC-1 recall por tipo:\n" + "\n".join(report_lines))


# Feature 004: PHONE/IBAN ahora DEBEN dar recall >= 0.95 (fix de causa raíz con
# regex propio, no umbral global). Si cae < 0.95, el desacople falló.
@pytest.mark.slow
def test_ac4_phone_iban_now_guaranteed():
    from corpus_scrub.detectors.pii import PiiDetector

    docs = _load("pii_seed.jsonl")
    det = PiiDetector(language="en", ner_threshold=0.85)
    dt = {i: {f.type for f in det.detect("doc", d)} for i, d in enumerate(docs)}
    for pii_type in ("PHONE_NUMBER", "IBAN_CODE"):
        seeded = _SEEDED[pii_type]
        recall = sum(1 for i in seeded if pii_type in dt[i]) / len(seeded)
        assert recall >= 0.95, (
            f"{pii_type} recall={recall:.2f} < 0.95 tras Feature 004; "
            "revisar detectors/universal.py"
        )


# --- Feature 004: tests unitarios de detectores universales (fast, sin NER) ---


def test_004_iban_mod97_checksum():
    """Condición #1: IBAN valida checksum mod-97, no solo formato.
    FR15... (generado con mod-97==1) debe detectarse; un IBAN con checksum
    inválido (cambio último dígito) debe rechazarse."""
    from corpus_scrub.detectors import universal

    ok = universal.detect_iban("IBAN FR62 2004 1010 0505 0001 3003 412 end")
    assert len(ok) == 1 and ok[0].type == "IBAN_CODE"
    # checksum roto -> rechazado
    bad = universal.detect_iban("IBAN FR62 2004 1010 0505 0001 3003 413 end")
    assert bad == [], "IBAN con checksum inválido no debe detectarse"
    # DE89 válido
    assert len(universal.detect_iban("DE89 3704 0044 0532 0130 00")) == 1


def test_004_credit_card_luhn():
    """Condición #3: tarjeta valida Luhn, no solo longitud.
    4111 1111 1111 1111 (Visa test, Luhn OK) -> detectada;
    4111 1111 1111 1112 (Luhn roto) -> rechazada."""
    from corpus_scrub.detectors import universal

    ok = universal.detect_credit_card("card 4111 1111 1111 1111 charged")
    assert len(ok) == 1 and ok[0].type == "CREDIT_CARD"
    bad = universal.detect_credit_card("card 4111 1111 1111 1112 charged")
    assert bad == [], "Tarjeta sin Luhn válido no debe detectarse"


def test_004_phone_no_overlap_numeric():
    """Condición #2: el regex de PHONE NO debe confundir secuencias numéricas
    no telefónicas (versiones, IPs, códigos de producto)."""
    from corpus_scrub.detectors import universal

    texts = [
        "version v2.7.1.4092 fixed parser",
        "connect to 192.168.1.1 port 8080",
        "SKU-551200998877 batch 441209887766554433221100",
        "checksum 9821736450918237465 matched",
        "reference 1234567890123 and 998877665544332211",
    ]
    for t in texts:
        hits = universal.detect_phone(t)
        assert hits == [], f"PHONE falsamente detectó en: {t!r}"


def test_004_phone_international():
    """PHONE intl (+44 UK, +34 ES, +1 US) debe detectarse tras Feature 004."""
    from corpus_scrub.detectors import universal

    for txt in [
        "call +44 20 7946 0958 office",
        "teléfono +34 612 345 678 cuenta",
        "reach +1-202-555-0143 now",
    ]:
        hits = universal.detect_phone(txt)
        assert len(hits) == 1 and hits[0].type == "PHONE_NUMBER", f"fallo en {txt!r}"


# --- Feature 004: resolución de overlaps entre detectores independientes ---


def test_004_resolve_overlaps_keeps_longest():
    """IBAN [5:32] y PHONE [15:32] se solapan; el más largo (IBAN) gana."""
    from corpus_scrub.detectors import universal
    from corpus_scrub.redact import resolve_overlaps

    text = "IBAN GB82 WEST 1234 5698 7654 32 confirmed by phone +44 12 3456 7654."
    fs = universal.detect_iban(text) + universal.detect_phone(text)
    kept = resolve_overlaps(fs)
    types = {f.type for f in kept}
    assert "IBAN_CODE" in types, "IBAN debe ganar el overlap"
    assert "PHONE_NUMBER" not in {f.type for f in kept if f.start == 15}, (
        "PHONE solapado [15:32] debe descartarse"
    )
    # el PHONE no solapado (+44 12...) sí queda
    assert any(f.type == "PHONE_NUMBER" and f.start == 53 for f in kept)


def test_004_redact_no_corrupt_on_overlap():
    """Reproduce el bug de integración: IBAN+teléfono en mismo doc no corrompe
    el texto circundante (el 'co' de 'confirmed' no debe desaparecer)."""
    from corpus_scrub.detectors import universal
    from corpus_scrub.redact import redact_text

    text = "IBAN GB82 WEST 1234 5698 7654 32 confirmed by phone +44 12 3456 7654."
    fs = universal.detect_iban(text) + universal.detect_phone(text)
    out = redact_text(text, fs, policy="mask")
    assert "confirmed" in out, f"TEXTO CORRUPTO: {out!r}"
    assert out == "IBAN <IBAN_CODE> confirmed by phone +<PHONE_NUMBER>."


def test_004_no_overlap_combinations():
    """Busca solapamientos no deseados entre pares de detectores con combinaciones
    sintéticas (CARD vs PHONE con agrupaciones de 4, IBAN vs CARD, etc.). Ningún
    span de distinto tipo debe solaparse en estos casos controlados."""
    from corpus_scrub.detectors import universal

    cases = [
        # CARD (4111 1111 1111 1111) y PHONE juntos: no deben solaparse
        "card 4111 1111 1111 1111 and phone +1-202-555-0143",
        # IBAN y CARD juntos
        "IBAN DE89 3704 0044 0532 0130 00 paid with 5500 0000 0000 0004",
        # EMAIL y PHONE juntos
        "write john@example.com or call +44 20 7946 0958",
        # dos PHONE con agrupaciones de 4 dígitos cerca de CARD
        "call +1 202 555 0143 or card 4000 0000 0000 0002 here",
    ]
    for t in cases:
        # EMAIL + IBAN + CARD + PHONE juntos (todos los detectores)
        allf = (
            universal.detect_email(t)
            + universal.detect_iban(t)
            + universal.detect_credit_card(t)
            + universal.detect_phone(t)
        )
        # verificar que no hay solapamientos entre distintos tipos
        spans = sorted(allf, key=lambda f: f.start)
        for a, b in zip(spans, spans[1:], strict=False):
            assert not (a.start < b.end and b.start < a.end), (
                f"Overlap no resuelto en {t!r}: {a.type}{a.start}:{a.end} vs "
                f"{b.type}{b.start}:{b.end}"
            )


# --- Feature 005: secret ruleset (gitleaks port) ---


def test_005_secret_recall_by_type():
    """AC-005-1: recall >= 0.90 por tipo de secreto en fixtures sintéticos.

    TODOS los tokens se generan EN RUNTIME (ofuscados en el código fuente para no
    disparar GitHub Push Protection). El fixture solo contiene placeholders EXAMPLE;
    el test los sustituye por valores sintéticos válidos para las regex de gitleaks
    antes de llamar al detector. Así el repo nunca contiene un secreto realista.
    """
    import json
    from corpus_scrub.detectors.secrets import SecretDetector

    d = SecretDetector()
    # tokens ofuscados (concatenados) para no disparar escáneres de secretos externos
    tok = {
        "GITHUB_PAT_PLACEHOLDER": "ghp_" + "EXAMPLEtoken0000000000000000000000abcd",
        "GITHUB_OAUTH_PLACEHOLDER": "gho_" + "EXAMPLEtoken0000000000000000000000abcd",
        "SLACK_BOT_TOKEN_PLACEHOLDER": "xo" + "xb-123456789012-123456789012-AbCdEfGhIjKlMnOpQr",
        "SLACK_WEBHOOK_PLACEHOLDER": "https://hook" + "s.slack.com/services/T00000000/B00000000/" + "X" * 44,
        "STRIPE_TOKEN_PLACEHOLDER": "sk_live_" + "EXAMPLEtoken00000000000000000000abcd",
        "STRIPE_RESTRICTED_PLACEHOLDER": "rk_test_" + "EXAMPLEtoken00000000000000000000abcd",
        "GITLAB_PAT_PLACEHOLDER": "glpat-" + "EXAMPLEtoken0000000000000000000000abcd",
        "OPENAI_KEY_PLACEHOLDER": "sk-" + "B" * 20 + "T3BlbkFJ" + "C" * 20,
        "ANTHROPIC_KEY_PLACEHOLDER": "sk-ant-api03-" + "A" * 93 + "AA",
        "PYPI_TOKEN_PLACEHOLDER": "pypi-AgEIcH" + "D" * 10 + "vcmc" + "E" * 25,
        "GENERIC_API_KEY_PLACEHOLDER": "sk-" + "EXAMPLEtoken00000000000000000000abcd",
        "GENERIC_TOKEN_PLACEHOLDER": "EXAMPLEtoken00000000000000000000abcd",
    }

    total = 0
    detected = 0
    for line in open("tests/data/fixtures/secrets_typed.jsonl"):
        line = line.strip()
        if not line:
            continue
        doc = json.loads(line)
        text = doc["text"]
        for ph, val in tok.items():
            if ph in text:
                text = text.replace(ph, val)
        fs = d.detect(doc["doc_id"], text)
        total += 1
        if fs:  # al menos un secreto detectado en el doc sembrado
            detected += 1
    recall = detected / total
    assert recall >= 0.90, f"recall secretos={recall:.2f} < 0.90"
    assert detected == total, f"docs con secreto no detectado: {total - detected}"


def test_005_secret_precision_benign():
    """AC-005-2: 0 FP en corpus benigno paritario (logs, código, prose sin secretos)."""
    import json

    from corpus_scrub.detectors.secrets import SecretDetector

    d = SecretDetector()
    fp = 0
    for line in open("tests/data/fixtures/secrets_benign.jsonl"):
        line = line.strip()
        if not line:
            continue
        doc = json.loads(line)
        fs = d.detect(doc["doc_id"], doc["text"])
        # b4 contiene 'ghp_placeholder' y un hex largo de ejemplo -> es benigno
        # real (no es un token real); si el detector lo marca, es FP controlada.
        # El fixture está diseñado para NO contener secretos reales.
        fp += len(fs)
    assert fp == 0, f"secretos falsos positivos en benigno: {fp}"


def test_005_gitleaks_commit_cited():
    """KI-3: el ruleset cita el commit fijado de gitleaks."""
    from corpus_scrub.detectors.secrets import _GITLEAKS_COMMIT

    assert _GITLEAKS_COMMIT == "4c232b5014f7618360bd992b4c489cb055881c6b"
