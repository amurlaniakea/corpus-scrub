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

"""corpus_scrub.models — dataclass Finding: fuente de verdad única.

Todos los módulos (detectors, redact, report, cli) importan esta clase.
Evita duplicación de contrato de datos entre módulos (lección de auditoría externa).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass
class Finding:
    doc_id: str
    type: str  # PERSON|EMAIL_ADDRESS|IBAN_CODE|CREDIT_CARD|PHONE_NUMBER|SECRET
    start: int
    end: int
    text: str  # valor redactado (mask/hash/drop)
    score: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
