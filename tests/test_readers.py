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

"""Tests de readers.py — cobertura de jsonl/txt/parquet/dir (Feature 003 soporte)."""

import pytest

from corpus_scrub.readers import iter_docs


def test_read_jsonl_text_field(tmp_path):
    f = tmp_path / "a.jsonl"
    f.write_text(
        '{"text": "hello world"}\n'
        '{"content": "alt field"}\n'
        '{"other": "ignored", "text": "via text"}\n',
        encoding="utf-8",
    )
    docs = list(iter_docs(str(f)))
    assert len(docs) == 3
    assert docs[0] == ("a.jsonl:0", "hello world")
    assert docs[1] == ("a.jsonl:1", "alt field")
    assert docs[2] == ("a.jsonl:2", "via text")


def test_read_jsonl_plain_text_fallback(tmp_path):
    f = tmp_path / "b.jsonl"
    f.write_text('this is not json at all\n{"text": "valid json line"}\n', encoding="utf-8")
    docs = list(iter_docs(str(f)))
    # línea 0 no es JSON -> fallback a texto plano; línea 1 es JSON válido
    assert docs[0] == ("b.jsonl:0", "this is not json at all")
    assert docs[1] == ("b.jsonl:1", "valid json line")


def test_read_jsonl_non_dict_json(tmp_path):
    f = tmp_path / "c.jsonl"
    f.write_text('"just a string"\n42\n', encoding="utf-8")
    docs = list(iter_docs(str(f)))
    # JSON válido pero no dict -> str(obj)
    assert docs[0] == ("c.jsonl:0", "just a string")
    assert docs[1] == ("c.jsonl:1", "42")


def test_read_jsonl_skips_blank_lines(tmp_path):
    f = tmp_path / "d.jsonl"
    f.write_text('\n{"text": "x"}\n\n\n{"text": "y"}\n', encoding="utf-8")
    docs = list(iter_docs(str(f)))
    # líneas vacías se ignoran; solo 2 docs
    assert [d[1] for d in docs] == ["x", "y"]


def test_read_txt(tmp_path):
    f = tmp_path / "doc.txt"
    f.write_text("whole file is one doc\nwith two lines", encoding="utf-8")
    docs = list(iter_docs(str(f)))
    assert len(docs) == 1
    assert docs[0][0] == "doc.txt"
    assert "whole file is one doc" in docs[0][1]


def test_read_parquet(tmp_path):
    pq = pytest.importorskip("pyarrow.parquet")
    import pyarrow as pa

    f = tmp_path / "data.parquet"
    table = pa.table({"text": ["row one", "row two"], "meta": [1, 2]})
    pq.write_table(table, f)
    docs = list(iter_docs(str(f)))
    assert len(docs) == 2
    assert docs[0] == ("data.parquet:0", "row one")
    assert docs[1] == ("data.parquet:1", "row two")


def test_read_parquet_single_column(tmp_path):
    pq = pytest.importorskip("pyarrow.parquet")
    import pyarrow as pa

    f = tmp_path / "single.parquet"
    table = pa.table({"document": ["only col"]})
    pq.write_table(table, f)
    docs = list(iter_docs(str(f)))
    assert docs[0] == ("single.parquet:0", "only col")


def test_read_parquet_no_text_column_raises(tmp_path):
    pq = pytest.importorskip("pyarrow.parquet")
    import pyarrow as pa

    f = tmp_path / "multi.parquet"
    table = pa.table({"col_a": ["x"], "col_b": ["y"]})
    pq.write_table(table, f)
    with pytest.raises(RuntimeError, match="no tiene columna"):
        list(iter_docs(str(f)))


def test_iter_docs_directory_mixed(tmp_path):
    (tmp_path / "a.jsonl").write_text('{"text": "from jsonl"}\n', encoding="utf-8")
    (tmp_path / "b.txt").write_text("from txt", encoding="utf-8")
    (tmp_path / "ignore.bin").write_text("binary", encoding="utf-8")
    docs = list(iter_docs(str(tmp_path)))
    texts = sorted(d[1] for d in docs)
    assert texts == ["from jsonl", "from txt"]
    # .bin no es formato soportado -> ignorado silenciosamente


def test_iter_docs_empty_dir(tmp_path):
    docs = list(iter_docs(str(tmp_path)))
    assert docs == []
