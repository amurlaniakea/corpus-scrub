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

"""corpus_scrub.redact — aplica política mask/hash/drop sobre spans.

Feature 004: los detectores son independientes (EMAIL/IBAN/CARD/PHONE + PERSON),
así que pueden producir spans que SE SOLAPAN (ej. IBAN y PHONE comparten el tramo
final). Antes de redactar, `resolve_overlaps` deja un solo span por tramo
conflictivo (el más largo, o el de mayor prioridad de tipo en empate) para no
corromper el texto al reemplazar índices ya desplazados.
"""

from __future__ import annotations

import hashlib
from typing import List

from corpus_scrub.models import Finding

# Prioridad de tipo para desempate de overlaps (mayor = gana si misma longitud).
# SECRET es lo más específico (regex dedicado), luego IBAN/CARD (checksum),
# EMAIL, PHONE, PERSON (NER, más propenso a FP).
_TYPE_PRIORITY = {
    "SECRET": 6,
    "IBAN_CODE": 5,
    "CREDIT_CARD": 5,
    "EMAIL_ADDRESS": 4,
    "PHONE_NUMBER": 3,
    "PERSON": 2,
}


def _overlaps(a: Finding, b: Finding) -> bool:
    return a.start < b.end and b.start < a.end


def resolve_overlaps(findings: List[Finding]) -> List[Finding]:
    """Devuelve findings sin spans solapados.

    Criterio: de dos findings que se solapan, se queda el de MAYOR prioridad de
    tipo (SECRET > IBAN/CARD > EMAIL > PHONE > PERSON); en empate, el de mayor
    longitud (end-start). El perdedor se descarta.

    El orden de evaluación es por PRIORIDAD GLOBAL (y longitud), NO por posición de
    inicio: si un finding de menor prioridad empieza antes pero uno de mayor
    prioridad lo solapa, el de mayor prioridad gana y no se pierde silenciosamente.
    Esto evita la fuga de datos que ocurría antes (ver bug de prioridad Feature 004 /
    auditoría post-#7): el algoritmo antiguo ordenaba por `start` y solo desempataba
    por prioridad entre findings con el MISMO inicio, descartando así el de mayor
    prioridad cuando empezaba más tarde.
    """
    # orden: prioridad desc, luego longitud desc, luego start asc (determinista)
    ordered = sorted(
        findings,
        key=lambda f: (-_TYPE_PRIORITY.get(f.type, 0), -(f.end - f.start), f.start),
    )
    kept: List[Finding] = []
    for f in ordered:
        if not any(_overlaps(f, k) for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def redact_text(text: str, findings: List[Finding], policy: str = "mask") -> str:
    """Devuelve el texto con las spans sustituidas según política.

    policy:
      - mask: reemplaza por <TYPE>
      - hash: reemplaza por sha256(truncado 12 hex) del fragmento original
      - drop: elimina el fragmento (deja vacío)
    Actualiza finding.text al valor resultante para el reporte.

    Los spans deben ser DISJUNTOS: usar `resolve_overlaps` antes si los
    detectores pueden producir solapamientos.
    """
    if not findings:
        return text
    # resolver overlaps antes de redactar (no durante)
    findings = resolve_overlaps(findings)
    # orden inverso para no desplazar índices
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        original = text[f.start : f.end]
        if policy == "mask":
            replacement = f"<{f.type}>"
        elif policy == "hash":
            replacement = hashlib.sha256(original.encode()).hexdigest()[:12]
        elif policy == "drop":
            replacement = ""
        else:
            raise ValueError(f"Política desconocida: {policy}")
        text = text[: f.start] + replacement + text[f.end :]
        f.text = replacement
    return text
