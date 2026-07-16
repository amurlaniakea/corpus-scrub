"""corpus_scrub.models — dataclass Finding: fuente de verdad única.

Todos los módulos (detectors, redact, report, cli) importan esta clase.
Evita duplicación de contrato de datos entre módulos (lección de auditoría externa).
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Any


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
