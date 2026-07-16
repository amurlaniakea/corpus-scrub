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

"""corpus_scrub.detectors.pii — orquesta detectores universales + NER PERSON.

Feature 004: EMAIL/IBAN/CREDIT_CARD/PHONE se resuelven con regex propios
(`detectors.universal`) que NO dependen de Presidio ni de modelo spaCy, así
funcionan en cualquier idioma. Presidio (AnalyzerEngine + spaCy) queda
reservado SOLO para PERSON (NER de nombres), que sí necesita modelo por idioma.

Umbral de score solo aplica a PERSON (NER, default 0.85). Los universales
devuelven score 1.0 porque ya validan checksum (mod-97 / Luhn). AC-4 intacto.
"""

from __future__ import annotations

from typing import List

from presidio_analyzer import AnalyzerEngine

from corpus_scrub.detectors import universal
from corpus_scrub.models import Finding

# Solo PERSON va por NER (Presidio). El resto es universal.
_NER_TYPES = {"PERSON"}


class PiiDetector:
    def __init__(self, language: str = "en", ner_threshold: float = 0.85):
        self.language = language
        self.ner_threshold = ner_threshold
        try:
            self._engine = AnalyzerEngine()
        except Exception as e:
            # Falla duro, no silenciosamente (KI-1): sin modelo NER no hay PERSON.
            raise RuntimeError(
                f"No se pudo instanciar AnalyzerEngine "
                f"(¿faltan modelos spaCy para '{language}'?): {e}"
            ) from e

    def detect(self, doc_id: str, text: str) -> List[Finding]:
        findings: List[Finding] = []
        # 1) Detectores universales (sin modelo, cualquier idioma)
        findings += universal.detect_email(text, doc_id)
        findings += universal.detect_iban(text, doc_id)
        findings += universal.detect_credit_card(text, doc_id)
        findings += universal.detect_phone(text, doc_id)
        # 2) NER PERSON (Presidio + spaCy, umbral configurable)
        results = self._engine.analyze(text=text, language=self.language, entities=list(_NER_TYPES))
        for r in results:
            if r.score < self.ner_threshold:
                continue
            findings.append(
                Finding(
                    doc_id=doc_id,
                    type=r.entity_type,
                    start=r.start,
                    end=r.end,
                    text=text[r.start : r.end],
                    score=round(r.score, 3),
                )
            )
        return findings
