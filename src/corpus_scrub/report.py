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

"""corpus_scrub.report — agrega Findings en reporte JSON de auditoría.

Conteos por tipo + lista de hallazgos con ubicación.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import List

from corpus_scrub.models import Finding


def build_report(findings: List[Finding]) -> dict:
    counts = Counter(f.type for f in findings)
    return {
        "total_findings": len(findings),
        "counts_by_type": dict(counts),
        "findings": [f.to_dict() for f in findings],
    }


def write_report(findings: List[Finding], report_path: str) -> None:
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(build_report(findings), fh, ensure_ascii=False, indent=2)
