import re


def _load_gitleaks_rules(path: str) -> dict:
    """Extrae reglas de un gitleaks.toml leyendo como TEXTO (no via tomllib).

    gitleaks usa comillas simples ''' para las regex; en TOML comillas simples
    los backslashes son LITERALES, asi que el contenido entre '''...''' ES la
    regex real que usa gitleaks (p.ej. \b es word boundary, no backspace).
    tomllib procesaria los escapes y romperia \b, por eso parseamos como texto.
    """
    text = open(path, encoding="utf-8").read()
    rules = {}
    # coincidir bloques [[rules]] con id = "..." y regex = '''...'''
    blocks = re.split(r"\[\[rules\]\]", text)
    for block in blocks[1:]:
        m_id = re.search(r'^\s*id\s*=\s*"([^"]+)"', block, re.M)
        m_rx = re.search(r"regex\s*=\s*'''(.*?)'''", block, re.S)
        if m_id and m_rx:
            rules[m_id.group(1)] = m_rx.group(1)
    return rules
