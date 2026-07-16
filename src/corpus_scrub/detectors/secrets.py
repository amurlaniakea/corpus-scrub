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
