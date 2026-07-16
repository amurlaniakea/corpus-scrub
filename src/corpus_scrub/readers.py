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

"""corpus_scrub.readers — iterador streaming de documentos (jsonl/txt/parquet).

No carga todo en RAM: yield doc a doc. Para jsonl, una línea = un doc (texto plano
o JSON con campo "text"/"content"). Para txt, un archivo = un doc. Para parquet,
itera fila a fila usando pyarrow si está disponible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, List, Tuple


def _read_jsonl(path: Path) -> Iterator[Tuple[str, str]]:
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            doc_id = f"{path.name}:{i}"
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    text = obj.get("text") or obj.get("content") or ""
                else:
                    text = str(obj)
            except json.JSONDecodeError:
                text = line
            yield doc_id, str(text)


def _read_txt(path: Path) -> Iterator[Tuple[str, str]]:
    text = path.read_text(encoding="utf-8")
    yield path.name, text


def _read_parquet(path: Path) -> Iterator[Tuple[str, str]]:
    try:
        import pyarrow.parquet as pq  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            "Lectura parquet requiere pyarrow (opcional). Instala con: pip install pyarrow"
        ) from e
    table = pq.read_table(path)
    text_col = None
    for cand in ("text", "content", "document"):
        if cand in table.column_names:
            text_col = cand
            break
    if text_col is None:
        if table.num_columns == 1:
            text_col = table.column_names[0]
        else:
            raise RuntimeError(
                f"Parquet {path.name} no tiene columna 'text'/'content' "
                f"y tiene {table.num_columns} columnas"
            )
    col = table.column(text_col).to_pylist()
    for i, val in enumerate(col):
        yield f"{path.name}:{i}", "" if val is None else str(val)


def iter_docs(input_path: str) -> Iterator[Tuple[str, str]]:
    """Yield (doc_id, text) en streaming desde un archivo o directorio."""
    p = Path(input_path)
    files: List[Path]
    if p.is_dir():
        files = sorted(p.rglob("*"))
    else:
        files = [p]
    for f in files:
        if not f.is_file():
            continue
        suffix = f.suffix.lower()
        if suffix == ".jsonl":
            yield from _read_jsonl(f)
        elif suffix == ".txt":
            yield from _read_txt(f)
        elif suffix == ".parquet":
            yield from _read_parquet(f)
        # otros formatos: ignorados silenciosamente (extensibles en Fase 3)
