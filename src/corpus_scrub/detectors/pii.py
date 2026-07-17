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
funcionan en cualquier idioma.

Feature 006: PERSON (NER) soporta EN (Presidio + en_core_web_lg) y ES/DE/FR
(spaCy directo, modelo del idioma cargado bajo demanda, fallback xx_ent_wiki_sm
multilingüe si no hay modelo dedicado).

Umbral de score solo aplica a PERSON en EN (Presidio, default 0.85). En
multilingüe spaCy no da score 0-1 por entidad -> score 1.0 (spaCy ya decidió);
el filtro de precisión es el corpus benigno por idioma (AC-4), no numérico.
"""

from __future__ import annotations

import threading
from typing import Dict, List

from presidio_analyzer import AnalyzerEngine

from corpus_scrub.detectors import universal
from corpus_scrub.models import Finding

# Solo PERSON va por NER. El resto es universal.
_NER_TYPES = {"PERSON"}

# Idiomas con modelo spaCy dedicado (se descargan bajo demanda en producción).
_SPACY_LANG_MODELS = {
    "es": "es_core_news_lg",
    "de": "de_core_news_lg",
    "fr": "fr_core_news_lg",
}
_MULTILINGUAL_FALLBACK = "xx_ent_wiki_sm"

# Cache de pipelines spaCy por modelo (carga única, thread-safe).
_nlp_cache: Dict[str, object] = {}
_nlp_lock = threading.Lock()


def _load_spacy(model_name: str):
    """Carga un pipeline spaCy bajo demanda (cacheado). Falla duro si no existe."""
    with _nlp_lock:
        if model_name not in _nlp_cache:
            import spacy

            _nlp_cache[model_name] = spacy.load(model_name)
    return _nlp_cache[model_name]


class PiiDetector:
    def __init__(self, language: str = "en", ner_threshold: float = 0.85):
        self.language = language
        self.ner_threshold = ner_threshold
        # EN usa Presidio (como MVP/004). ES/DE/FR usan spaCy directo.
        self._engine = None
        self._nlp = None
        if language == "en":
            try:
                self._engine = AnalyzerEngine()
            except Exception as e:
                raise RuntimeError(
                    f"No se pudo instanciar AnalyzerEngine (¿faltan modelos spaCy EN?): {e}"
                ) from e
            self._nlp = None
            self._model_loaded = None
            self._using_fallback = False
        elif language in _SPACY_LANG_MODELS:
            model = _SPACY_LANG_MODELS[language]
            try:
                self._nlp = _load_spacy(model)
            except Exception:
                # Fallback multilingüe si no está el modelo dedicado
                self._nlp = _load_spacy(_MULTILINGUAL_FALLBACK)
                self._using_fallback = True
            else:
                self._using_fallback = False
            self._model_loaded = getattr(self._nlp, "meta", {}).get("name")
        else:
            # Idioma no soportado: fallback multilingüe (no crashear, KI-1 honesto)
            self._nlp = _load_spacy(_MULTILINGUAL_FALLBACK)
            self._using_fallback = True
            self._model_loaded = getattr(self._nlp, "meta", {}).get("name")

    @property
    def model_loaded(self) -> str | None:
        """Nombre del modelo spaCy realmente cargado (p.ej. ``es_core_news_lg``).

        Útil para auditoría: distingue si el detector usa el modelo dedicado del
        idioma o cayó al fallback multilingüe ``xx_ent_wiki_sm``.
        """
        return self._model_loaded

    @property
    def using_fallback(self) -> bool:
        """``True`` si el detector NER usa el fallback multilingüe en vez del modelo dedicado.

        Los AC-006-1/AC-006-2 solo son válidos con el modelo dedicado instalado;
        si esto es ``True`` para es/de/fr, los resultados de precisión/recall no
        representan la garantía documentada y deben fallar explícitamente.
        """
        return self._using_fallback

    def _detect_person_spacy(self, doc_id: str, text: str) -> List[Finding]:
        findings: List[Finding] = []
        doc = self._nlp(text)
        for ent in doc.ents:
            if ent.label_ == "PER":
                findings.append(
                    Finding(
                        doc_id=doc_id,
                        type="PERSON",
                        start=ent.start_char,
                        end=ent.end_char,
                        text=ent.text,
                        score=1.0,
                    )
                )
        return findings

    def detect(self, doc_id: str, text: str) -> List[Finding]:
        findings: List[Finding] = []
        # 1) Detectores universales (sin modelo, cualquier idioma)
        findings += universal.detect_email(text, doc_id)
        findings += universal.detect_iban(text, doc_id)
        findings += universal.detect_credit_card(text, doc_id)
        findings += universal.detect_phone(text, doc_id)
        # 2) NER PERSON
        if self._engine is not None:
            # EN: Presidio + umbral
            results = self._engine.analyze(
                text=text, language=self.language, entities=list(_NER_TYPES)
            )
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
        elif self._nlp is not None:
            # ES/DE/FR (o fallback): spaCy directo
            findings += self._detect_person_spacy(doc_id, text)
        return findings
