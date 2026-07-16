"""Fixtures deterministas con VOLUMEN REAL (no un ejemplo).

Cada fixture tiene N>=10 casos para que recall/precisión >=0.95 tengan sentido
estadístico (un solo fallo en 10 casos = 0.90, detectable; en 1 caso sería ruido).

Semilla fija para reproducibilidad. PII sembrada se conocen de antemano para
calcular recall en AC-1.
"""

import json
from pathlib import Path

HERE = Path(__file__).parent

# AC-1: PII sembrada en EN. Cada doc tiene PII conocida.
PII_DOCS = [
    "Contact John Smith at john.smith@example.com or call +1-202-555-0143.",
    "Maria Garcia reached me at maria.garcia@company.org about IBAN GB82 WEST 1234 5698 7654 32.",
    "His card 4111 1111 1111 1111 was charged and he is David Lee.",
    "Email alice.wong@university.edu, phone +44 20 7946 0958, name Robert Brown.",
    "Jane Doe lives at jane.doe@mail.com; her IBAN is DE89 3704 0044 0532 0130 00.",
    "Call William Chen on +1-415-555-2671 or write william.chen@startup.io.",
    "Michael Johnson, card 5500 0000 0000 0004, email michael.j@corp.com.",
    "Sarah Wilson: sarah.wilson@gov.us, IBAN FR14 2004 1010 0505 0001 3003, "
    "phone +33 1 70 18 00 00.",
    "Thomas Miller contacted us at thomas.miller@web.net; his number +1-312-555-0987.",
    "Elizabeth Taylor, elizabeth.taylor@film.com, card 4000 0000 0000 0002, "
    "IBAN ES91 2100 0418 4502 0005 1332.",
    "James Anderson james.anderson@news.com phone +1-646-555-7712 name James Anderson.",
    "Patricia Martin patricia.martin@shop.es IBAN IT60 X054 2811 1010 0000 0123 456.",
]

# AC-2: secretos sintéticos (api_key=sk-..., ghp_..., token=...)
SECRET_DOCS = [
    "config: api_key = sk-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
    "auth token = 'ghp_1234567890abcdefABCDEF1234567890ab'",
    "secret = 'AKIA1234567890ABCDEF' and access_token: bearer_abc123def456",
    "password = 'supersecretvalue12345' client_secret = cs_99887766554433221100",
    "apikey: sk_live_abcdef1234567890abcdef1234567890",
    "token = 'ya29.a0AfH6SMBbCdEfGhIjKlMnOpQrStUvWxYz0123456789'",
    "DB_PASSWORD=myDbP@ssw0rdLongEnough12345 and key=abc123def456ghi789",
    "ghp_aAbBcCdDeEfF00112233445566778899 and api_key = ZmFrZV9rZXlfdmFsdWUxMjM0NQ==",
    "client_secret: 'abcd1234efgh5678ijkl9012mnop3456' auth_token = 'xyz789abc123def456'",
    "access = sk-proj-1111222233334444555566667777888899990000aaaabbbb",
    "secret_key = 'longenoughsecretvalue00000000000000000099' password = pwd_verylongvalue99887766",
    "token: 'tkn_aaabbbcccdddeeefffggghhhiiiijjkkllmmnnooppqq'",
]

# AC-4: corpus benigno paritario (mismo largo/idioma, 0 PII intencional).
# Texto natural sin emails/teléfanos/IBAN/tarjetas/nombres-propios-como-PII.
BENIGN_DOCS = [
    "The quick brown fox jumps over the lazy dog near the river bank.",
    "Machine learning models require large amounts of text for training.",
    "We observed that weather patterns shift slowly across the northern hemisphere.",
    "A report on renewable energy showed gains in solar and wind deployment.",
    "The library book was returned on time and placed back on the shelf.",
    "Cooking requires patience and a clear understanding of the ingredients used.",
    "Local communities organized a festival to celebrate the harvest season.",
    "The committee reviewed the proposal and suggested several minor revisions.",
    "Students practiced the exercises until they felt confident about the topic.",
    "The bridge was repaired after the inspection found minor structural issues.",
    "Gardens benefit from regular watering and exposure to direct sunlight.",
    "The museum displayed artifacts describing daily life in past centuries.",
    # --- Casos adversariales (KI-2): el NER PERSON tiende a confundir estos con PERSON ---
    "Apple released a new version of macOS that improves battery life on the MacBook.",
    "Our team deployed the service using Kubernetes and PostgreSQL running on Linux servers.",
    "Google and Microsoft announced a partnership to develop TensorFlow-based tools.",
    "The Amazon warehouse in Seattle uses robots built by Boston Dynamics.",
    "We evaluated the model on the Stanford dataset and compared it against BERT and RoBERTa.",
    "The river Thames flows through London and the Nile passes near Cairo and Khartoum.",
]


def _write(name: str, docs):
    out = [{"doc_id": f"{name}:{i}", "text": d} for i, d in enumerate(docs)]
    (HERE / name).write_text(
        "\n".join(json.dumps(o, ensure_ascii=False) for o in out), encoding="utf-8"
    )


if __name__ == "__main__":
    _write("pii_seed.jsonl", PII_DOCS)
    _write("secrets_seed.jsonl", SECRET_DOCS)
    _write("benign.jsonl", BENIGN_DOCS)
    print(
        f"Fixtures escritos: {len(PII_DOCS)} PII, {len(SECRET_DOCS)} secretos, "
        f"{len(BENIGN_DOCS)} benignos"
    )
