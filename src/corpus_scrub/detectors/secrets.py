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

"""corpus_scrub.detectors.secrets — ruleset de secretos portado de gitleaks (MIT).

Feature 005: se amplia la cobertura de la unica regla `generic-api-key` del MVP a
un ruleset curado de reglas reales de gitleaks, portadas a regex Python.

Fuente fijada (KI-3: se anuncia recall de secretos -> commit fijado):
  github.com/gitleaks/gitleaks @ 4c232b5014f7618360bd992b4c489cb055881c6b
  (config/gitleaks.toml, 222 reglas). Cada regla porta su `id` y `regex` originales;
  NO se inventa ninguna regex. Verificado automáticamente por
  test_005_rules_verbatim_vs_gitleaks contra el gitleaks.toml embebido como fixture.
  Multi-idioma (regex, no depende de NER).

Score fijo 1.0: son regex exactas, no probabilísticas. El filtrado de FP se hace
en la regex misma (keywords/prefijos), no bajando umbral.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from corpus_scrub.models import Finding

# Tupla (tipo_secreto, regex) portada de gitleaks commit 4c232b5.
# El `type` del Finding es "SECRET" (como en MVP) pero el `text`/reporte puede
# distinguir vía el prefijo. Para redactar usamos group(0) (span completo).
_GITLEAKS_COMMIT = "4c232b5014f7618360bd992b4c489cb055881c6b"

# Secret rules ported verbatim from gitleaks config/gitleaks.toml @ 4c232b5.
# Source fixed (KI-3): github.com/gitleaks/gitleaks @ 4c232b5014f7618360bd992b4c489cb055881c6b
_SECRET_RULES: List[Tuple[str, re.Pattern]] = [
    # generic-api-key (gitleaks real, commit 4c232b5 — más estricta que la del MVP)
    (
        "generic-api-key",
        re.compile(
            r"(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|"
            r"secret|token)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)"
            r"[\x60'\"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})"
            r"(?:[\x60'\"\s;]|\\[nr]|$)"
        ),
    ),
    # aws-access-token
    ("aws-access-token", re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b")),
    # private-key (BEGIN ... PRIVATE KEY ...)
    (
        "private-key",
        re.compile(
            r"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S-]{64,}?KEY(?: BLOCK)?-----"
        ),
    ),
    # slack-bot-token / slack-webhook-url
    ("slack-bot-token", re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*")),
    (
        "slack-webhook-url",
        re.compile(
            r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"
        ),
    ),
    # stripe-access-token
    (
        "stripe-access-token",
        re.compile(
            r"\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})"
            r"(?:[\x60'\"\s;]|\\[nr]|$)"
        ),
    ),
    # github-pat / github-oauth / github-app-token / github-fine-grained-pat
    ("github-pat", re.compile(r"ghp_[0-9a-zA-Z]{36}")),
    ("github-oauth", re.compile(r"gho_[0-9a-zA-Z]{36}")),
    ("github-app-token", re.compile(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}")),
    ("github-fine-grained-pat", re.compile(r"github_pat_\w{82}")),
    # gitlab-pat / gitlab-ptt
    ("gitlab-pat", re.compile(r"glpat-[\w-]{20}")),
    ("gitlab-ptt", re.compile(r"glptt-[0-9a-f]{40}")),
    # openai-api-key
    (
        "openai-api-key",
        re.compile(
            r"\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})"
            r"T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|"
            r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})"
        ),
    ),
    # anthropic-api-key
    (
        "anthropic-api-key",
        re.compile(r"\b(sk-ant-api03-[a-zA-Z0-9_-]{93}AA)(?:[\x60'\"\s;]|\\[nr]|$)"),
    ),
    # pypi-upload-token (gitleaks real @4c232b5: prefijo fijo 'pypi-AgEIcHlwaS5vcmc' + 50-1000)
    ("pypi-upload-token", re.compile(r"pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}")),
    # cloudflare-api-key
    (
        "cloudflare-api-key",
        re.compile(
            r"(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'\"]{0,3}"
            r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}"
            r"([a-z0-9_-]{40})(?:[\x60'\"\s;]|\\[nr]|$)"
        ),
    ),
]


class SecretDetector:
    def detect(self, doc_id: str, text: str) -> List[Finding]:
        """Detecta secretos con el ruleset gitleaks (commit fijado).

        Devuelve Findings de type="SECRET" con score 1.0. El `text` incluye el
        prefijo del secreto para trazabilidad en el reporte.
        """
        findings: List[Finding] = []
        for rule_id, pattern in _SECRET_RULES:
            for m in pattern.finditer(text):
                # group(0) = span completo; para reglas con grupo de captura de
                # valor, preferimos group(0) para redactar todo el tramo.
                secret = m.group(0)
                # trazabilidad: prefijar el rule_id de gitleaks en el reporte
                findings.append(
                    Finding(
                        doc_id=doc_id,
                        type="SECRET",
                        start=m.start(),
                        end=m.end(),
                        text=f"{rule_id}:{secret}",
                        score=1.0,
                    )
                )
        return findings
