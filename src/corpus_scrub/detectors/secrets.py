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

"""corpus_scrub.detectors.secrets — regex tipo gitleaks (MIT).

Fuente de la regla: github.com/gitleaks/gitleaks, regla `generic-api-key` (MIT).
Trazabilidad citada: no fijado a commit exacto (regla genérica, no claim cuantitativo;
si se anuncia benchmark de recall de secretos, fijar commit — ver KI-3 en spec.md).

Cubre asignaciones  key=/api=/token=/secret=/... <valor 10-64 chars, con o sin comillas,
para valores tipo sk-..., ghp_, AKIA..., bearer_..., etc. Multi-idioma (regex, no NER).
"""

from __future__ import annotations

import re
from typing import List

from corpus_scrub.models import Finding

# Basado en gitleaks generic-api-key (MIT). Permite comillas y '_' en la clave.
GITLEAKS_GENERIC = re.compile(
    r"(?i)(?:key|api|token|secret|client|passwd|password|auth|access)"
    r"(?:[0-9a-z_\-.\t ]{0,20})"
    r"(?:=|>|:=|\|\|:|<=|=>|:)"
    r"(?:[\s'\"]*)"  # consume espacios y comillas de apertura
    r"([0-9a-z_\-.:=]{9,63})"  # valor 10-64 chars (sin comillas de cierre)
)


class SecretDetector:
    def detect(self, doc_id: str, text: str) -> List[Finding]:
        findings: List[Finding] = []
        for m in GITLEAKS_GENERIC.finditer(text):
            secret = m.group(1)
            findings.append(
                Finding(
                    doc_id=doc_id,
                    type="SECRET",
                    start=m.start(1),
                    end=m.end(1),
                    text=secret,
                    score=1.0,
                )
            )
        return findings
