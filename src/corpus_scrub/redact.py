"""corpus_scrub.redact — aplica política mask/hash/drop sobre spans.

Se aplica en orden inverso de posiciones para no desplazar índices.
"""
from __future__ import annotations

import hashlib
from typing import List

from corpus_scrub.models import Finding


def redact_text(text: str, findings: List[Finding], policy: str = "mask") -> str:
    """Devuelve el texto con las spans sustituidas según política.

    policy:
      - mask: reemplaza por <TYPE>
      - hash: reemplaza por sha256(truncado 12 hex) del fragmento original
      - drop: elimina el fragmento (deja vacío)
    Actualiza finding.text al valor resultante para el reporte.
    """
    if not findings:
        return text
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
