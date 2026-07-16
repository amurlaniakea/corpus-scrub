"""Tests adicionales: readers (streaming) y CLI branch (report/out).

Sube cobertura de cli.py y readers.py de forma honesta (no por subprocess).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from corpus_scrub.readers import iter_docs, _read_jsonl, _read_txt
from corpus_scrub.cli import main


def test_readers_jsonl(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text(
        "\n".join(json.dumps({"text": f"doc {i}"}) for i in range(5)), encoding="utf-8"
    )
    docs = list(iter_docs(str(p)))
    assert len(docs) == 5
    assert all(isinstance(t, str) and t for _, t in docs)


def test_readers_txt(tmp_path):
    p = tmp_path / "c.txt"
    p.write_text("hello world", encoding="utf-8")
    docs = list(iter_docs(str(p)))
    assert len(docs) == 1
    assert docs[0][1] == "hello world"


def test_readers_dir(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.jsonl").write_text(json.dumps({"text": "x"}) + "\n", encoding="utf-8")
    (d / "b.txt").write_text("y", encoding="utf-8")
    docs = list(iter_docs(str(d)))
    assert len(docs) == 2


@pytest.mark.slow
def test_cli_report_and_out(tmp_path):
    import corpus_scrub.detectors.secrets as sec  # asegura import
    # fixture pequeño con un secreto, sin NER (evita descarga de modelo)
    fix = tmp_path / "s.jsonl"
    fix.write_text(json.dumps({"text": "api_key = sk-abcdef1234567890abcdef1234567890"}) + "\n", encoding="utf-8")
    out = tmp_path / "redacted.jsonl"
    rep = tmp_path / "report.json"
    rc = main(["scan", "--input", str(fix), "--policy", "mask", "--out", str(out), "--report", str(rep)])
    assert rc == 0
    lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert lines[0]["text"] == "api_key = <SECRET>"
    rep_json = json.loads(rep.read_text())
    assert rep_json["total_findings"] >= 1
    assert rep_json["counts_by_type"].get("SECRET", 0) == 1


def test_cli_no_args_exits_2():
    with pytest.raises(SystemExit):
        main([])
