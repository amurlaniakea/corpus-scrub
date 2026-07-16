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
