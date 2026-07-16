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
                f"No se pudo instanciar AnalyzerEngine (¿faltan modelos spaCy para '{language}'?): {e}"
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
