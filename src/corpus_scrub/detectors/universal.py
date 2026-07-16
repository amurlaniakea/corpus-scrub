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
"""Detectores universales desacoplados de Presidio.

EMAIL / IBAN / CREDIT_CARD / PHONE funcionan con regex + validación de checksum
propia (mod-97 para IBAN, Luhn para tarjeta). No dependen de modelo spaCy ni de
Presidio, así que detectan en CUALQUIER idioma. Presidio queda reservado solo para
PERSON (NER de nombres). Ver spec 004.
"""

from __future__ import annotations

import re

from corpus_scrub.models import Finding

# --- EMAIL: formato RFC 5322 simplificado (suficiente para corpus) ---
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# --- IBAN: ISO 13616. 2 letras país + 2 dígitos check + hasta 30 alfanum.
# Permitimos espacios de agrupación en el texto; los quitamos antes de validar.
_IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}\b")

# --- CREDIT_CARD: 13-19 dígitos, agrupados de 4 (con/sin separador).
# Validamos formato Y Luhn. Prefijos conocidos reducen FP (Visa 4, MC 5[1-5],
# Amex 34/37, Discover 6).
_CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
    r"|6(?:011|5[0-9]{2})[0-9]{12}|(?:[0-9]{4}[ \-]?){3,4}[0-9]{1,4})\b"
)

# --- PHONE: formato con agrupaciones o prefijo +CC. NO captura blobs de dígitos
# pegados (versiones, SKUs, IPs) — requiere separadores o '+'. E.164 máx 15 dígitos.
_PHONE_RE = re.compile(r"\b(?:\+\d{1,3}[\-\.\s]?)?(?:\(?\d{2,4}\)?[\-\.\s]?){2,5}\d{2,4}\b")
# Para descartar blobs numéricos largos sin separadores (ej. SKU-551200998877),
# el patrón anterior aún podría atrapar 12 dígitos seguidos. Filtro extra en código:
# exigir que haya AL MENOS un separador (espacio/guion/punto) o prefijo '+', y que no
# sea una secuencia de solo dígitos de longitud >=10 sin separador.

_IBAN_LENGTHS = {
    "AD": 24,
    "AE": 23,
    "AL": 28,
    "AT": 20,
    "AZ": 28,
    "BA": 20,
    "BE": 16,
    "BG": 22,
    "BH": 22,
    "BR": 29,
    "CH": 21,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "DO": 28,
    "EE": 20,
    "ES": 24,
    "FI": 18,
    "FO": 18,
    "FR": 27,
    "GB": 22,
    "GE": 22,
    "GI": 23,
    "GL": 18,
    "GR": 27,
    "GT": 28,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IL": 23,
    "IS": 26,
    "IT": 27,
    "KW": 30,
    "KZ": 20,
    "LB": 28,
    "LC": 32,
    "LI": 21,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "MC": 27,
    "MD": 24,
    "ME": 22,
    "MK": 19,
    "MR": 27,
    "MT": 31,
    "MU": 30,
    "NL": 18,
    "NO": 15,
    "PK": 24,
    "PL": 28,
    "PT": 25,
    "RO": 24,
    "RS": 22,
    "SA": 24,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "SM": 27,
    "TN": 24,
    "TR": 26,
    "VG": 24,
    "XK": 20,
}


def _iban_valid_mod97(iban: str) -> bool:
    """ISO 13616: mover 4 primeros chars al final, letras->A=10..Z=35, mod 97 == 1."""
    s = iban[4:] + iban[:4]
    digits = ""
    for ch in s:
        digits += str(ord(ch) - 55) if ch.isalpha() else ch
    # mod 97 por bloques para evitar overflow
    rem = 0
    for d in digits:
        rem = (rem * 10 + int(d)) % 97
    return rem == 1


def _luhn_valid(number: str) -> bool:
    """Algoritmo de Luhn: duplicar cada 2º dígito de derecha a izquierda."""
    total = 0
    rev = number[::-1]
    for i, ch in enumerate(rev):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_email(text: str, doc_id: str = "doc") -> list[Finding]:
    out = []
    for m in _EMAIL_RE.finditer(text):
        out.append(
            Finding(
                doc_id=doc_id,
                type="EMAIL_ADDRESS",
                start=m.start(),
                end=m.end(),
                score=1.0,
                text=m.group(0),
            )
        )
    return out


def detect_iban(text: str, doc_id: str = "doc") -> list[Finding]:
    out = []
    for m in _IBAN_RE.finditer(text):
        iban = m.group(0).replace(" ", "")
        # ISO 13616: 2 letras país + 2 dígitos check + 11-30 alfanum (total 15-34).
        if not (15 <= len(iban) <= 34):
            continue
        if not _iban_valid_mod97(iban):
            continue
        out.append(
            Finding(
                doc_id=doc_id,
                type="IBAN_CODE",
                start=m.start(),
                end=m.end(),
                score=1.0,
                text=m.group(0),
            )
        )
    return out


def detect_credit_card(text: str, doc_id: str = "doc") -> list[Finding]:
    out = []
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) < 13 or len(digits) > 19:
            continue
        if not _luhn_valid(digits):
            continue
        out.append(
            Finding(
                doc_id=doc_id,
                type="CREDIT_CARD",
                start=m.start(),
                end=m.end(),
                score=1.0,
                text=m.group(0),
            )
        )
    return out


def detect_phone(text: str, doc_id: str = "doc") -> list[Finding]:
    out = []
    for m in _PHONE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        # filtro básico: un teléfono real tiene 7-15 dígitos (E.164 máx 15)
        if not (7 <= len(digits) <= 15):
            continue
        # Rechazar blobs de solo dígitos sin separador ni prefijo '+' (versiones,
        # SKUs, IDs). Un teléfono real lleva '+' o agrupaciones con separadores.
        if "+" not in raw and "-" not in raw and "." not in raw and " " not in raw:
            # solo dígitos pegados: solo aceptar si es un patrón tipo (NNN)NNN... corto
            if len(digits) >= 10:
                continue
        out.append(
            Finding(
                doc_id=doc_id,
                type="PHONE_NUMBER",
                start=m.start(),
                end=m.end(),
                score=1.0,
                text=raw,
            )
        )
    return out
