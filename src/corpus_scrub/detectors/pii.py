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

"""corpus_scrub.detectors.pii — wrapper de Presidio AnalyzerEngine.

MVP: solo inglés (language="en"). El motor NER (spaCy en_core_web_lg) y los
recognizers regex (EMAIL/IBAN/CARD/PHONE) se cargan por defecto para "en".
Para ES/DE/FR ver KI-1 en spec.md (Fase 2, requiere modelo por idioma).

Umbral de score configurable (default 0.85 del spike). Trade-off con AC-4
documentado en spec.md.
"""

from __future__ import annotations

from typing import List

from presidio_analyzer import AnalyzerEngine

from corpus_scrub.models import Finding

# Tipos de entidad que Presidio puede devolver y que mapeamos a Finding.type
_PII_TYPES = {
    "PERSON",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "CREDIT_CARD",
    "PHONE_NUMBER",
    "URL",
}


class PiiDetector:
    def __init__(self, language: str = "en", ner_threshold: float = 0.85):
        self.language = language
        self.ner_threshold = ner_threshold
        try:
            self._engine = AnalyzerEngine()
        except Exception as e:
            # Falla duro, no silenciosamente (KI-1): sin modelo NER no hay recognizers.
            raise RuntimeError(
                f"No se pudo instanciar AnalyzerEngine "
                f"(¿faltan modelos spaCy para '{language}'?): {e}"
            ) from e

    def detect(self, doc_id: str, text: str) -> List[Finding]:
        results = self._engine.analyze(text=text, language=self.language)
        findings: List[Finding] = []
        for r in results:
            # El umbral solo aplica a entidades basadas en NER (score < 1.0).
            # Regex (score 1.0) siempre pasa; NER (score < 1.0) requiere >= umbral.
            if r.score < 1.0 and r.score < self.ner_threshold:
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
