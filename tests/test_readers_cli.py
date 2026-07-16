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

"""Tests adicionales: readers (streaming) y CLI branch (report/out).

Sube cobertura de cli.py y readers.py de forma honesta (no por subprocess).
"""

from __future__ import annotations

import json

import pytest

from corpus_scrub.cli import main
from corpus_scrub.readers import iter_docs


def test_readers_jsonl(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text("\n".join(json.dumps({"text": f"doc {i}"}) for i in range(5)), encoding="utf-8")
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
    # fixture pequeño con un secreto, sin NER (evita descarga de modelo)
    fix = tmp_path / "s.jsonl"
    fix.write_text(
        json.dumps({"text": "api_key = sk-abcdef1234567890abcdef1234567890"}) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "redacted.jsonl"
    rep = tmp_path / "report.json"
    rc = main(
        ["scan", "--input", str(fix), "--policy", "mask", "--out", str(out), "--report", str(rep)]
    )
    assert rc == 0
    lines = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    assert lines[0]["text"] == "<SECRET>"
    rep_json = json.loads(rep.read_text())
    assert rep_json["total_findings"] >= 1
    assert rep_json["counts_by_type"].get("SECRET", 0) == 1


def test_cli_no_args_exits_2():
    with pytest.raises(SystemExit):
        main([])
