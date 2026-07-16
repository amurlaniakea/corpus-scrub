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

"""corpus_scrub.cli — entrypoint argparse.

Uso:
  corpus-scrub scan --input <dir|file> --lang en --policy mask --report out.json
  corpus-scrub scan --input corpus.jsonl --policy hash --out redacted.jsonl
"""

from __future__ import annotations

import argparse
import sys
from typing import List

from corpus_scrub.detectors.pii import PiiDetector
from corpus_scrub.detectors.secrets import SecretDetector
from corpus_scrub.models import Finding
from corpus_scrub.readers import iter_docs
from corpus_scrub.redact import redact_text
from corpus_scrub.report import build_report, write_report


def _scan(input_path: str, lang: str, policy: str, ner_threshold: float):
    pii = PiiDetector(language=lang, ner_threshold=ner_threshold)
    secrets = SecretDetector()
    all_findings: List[Finding] = []
    redacted_docs = []
    for doc_id, text in iter_docs(input_path):
        findings: List[Finding] = []
        findings.extend(pii.detect(doc_id, text))
        findings.extend(secrets.detect(doc_id, text))
        redacted = redact_text(text, findings, policy=policy)
        all_findings.extend(findings)
        redacted_docs.append({"doc_id": doc_id, "text": redacted})
    return all_findings, redacted_docs


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="corpus-scrub",
        description="Detect and redact PII + secrets in ML training corpora.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a corpus and redact findings")
    scan.add_argument("--input", required=True, help="file or directory (jsonl/txt/parquet)")
    scan.add_argument("--lang", default="en", help="NER language (MVP: en only)")
    scan.add_argument(
        "--policy",
        default="mask",
        choices=["mask", "hash", "drop"],
        help="redaction policy",
    )
    scan.add_argument(
        "--ner-threshold", type=float, default=0.85, help="min NER score to keep (default 0.85)"
    )
    scan.add_argument("--report", default=None, help="path to write JSON audit report")
    scan.add_argument("--out", default=None, help="path to write redacted jsonl")

    args = parser.parse_args(argv)

    if args.command == "scan":
        # KI-1 resuelto en Feature 006: EN (Presidio), ES/DE/FR (spaCy dedicado),
        # resto -> fallback multilingüe xx_ent_wiki_sm (no crashea, advertido).
        supported = {"en", "es", "de", "fr"}
        if args.lang not in supported:
            print(
                f"AVISO: language '{args.lang}' sin modelo dedicado; usando fallback "
                f"multilingüe (xx_ent_wiki_sm). Soporte garantizado: en/es/de/fr.",
                file=sys.stderr,
            )
        findings, redacted_docs = _scan(args.input, args.lang, args.policy, args.ner_threshold)
        if args.report:
            write_report(findings, args.report)
            print(f"Reporte escrito: {args.report}", file=sys.stderr)
        if args.out:
            import json

            with open(args.out, "w", encoding="utf-8") as fh:
                for d in redacted_docs:
                    fh.write(json.dumps(d, ensure_ascii=False) + "\n")
            print(f"Corpus redactado escrito: {args.out}", file=sys.stderr)
        summary = build_report(findings)
        print(
            f"Documentos: {len(redacted_docs)} | Hallazgos: {summary['total_findings']} "
            f"| Por tipo: {summary['counts_by_type']}",
            file=sys.stderr,
        )
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
