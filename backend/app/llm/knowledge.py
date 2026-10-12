"""Contextual search over ticket history (local TF-IDF, no external service).

The index covers title, category, description, diagnosis and solution. Text is analysed the same way
for tickets and queries: accents removed, Spanish stopwords and generic filler dropped ("problemas",
"habituales"...), plurals reduced to singular and support synonyms expanded to a shared term
(printer/imprimir -> impresora, wifi/internet -> red, outlook/email -> correo...). Results are always
filtered by what the requesting user may see:
* ADMIN / JEFE_TI: every ticket.
* TECNICO: resolved tickets as a shared knowledge base (no requester data) plus their own.
* USUARIO: only their own tickets.
"""
from __future__ import annotations

import re
import threading

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ml.dataset import normalize_text
from app.models import Category, Priority, Ticket, TicketState
from app.synthetic.catalog import SYNTHETIC_TICKET_PREFIX

RESOLVED_STATES = {"RESUELTO", "CERRADO"}
# Function words plus filler that says nothing about the technical problem ("¿qué problemas son habituales?").
STOPWORDS = set("""
a al ante con contra de del desde durante en entre hacia hasta mediante para por segun sin sobre tras
el la lo los las un una uno unos unas y e o u ni pero si que cual cuales quien como cuando donde
es son ser fue era esta estan estoy este esta esto estos estas ese esa eso esos esas aquel
mi mis tu tus su sus se me te le les nos os ya muy mas menos tambien hay ha han he
problema inconveniente habitual frecuente frecuencia comun tipico suele suelen general
resolver solucionar arreglar ayuda favor hola quisiera necesito
""".split())
# Variant -> shared term. Both the original token and the shared term are indexed.
SYNONYMS = {
    **dict.fromkeys(["imprimir", "imprime", "imprimen", "imprimo", "impresion", "printer", "multifuncional", "plotter", "toner"], "impresora"),
    **dict.fromkeys(["scanner", "escanear", "escaneo", "digitalizar"], "escaner"),
    **dict.fromkeys(["internet", "wifi", "inalambrica", "inalambrico", "ethernet", "conectividad"], "red"),
    **dict.fromkeys(["email", "mail", "outlook", "gmail", "buzon"], "correo"),
    **dict.fromkeys(["clave", "password", "credencial"], "contrasena"),
    **dict.fromkeys(["bloqueada", "bloqueado", "bloquea", "bloquear"], "bloqueo"),
    **dict.fromkeys(["login", "logueo", "ingresar"], "sesion"),
    **dict.fromkeys(["computador", "ordenador", "pc", "laptop", "portatil", "notebook"], "computadora"),
    **dict.fromkeys(["videollamada", "zoom", "teams", "meet", "videoconferencia"], "video"),
    **dict.fromkeys(["webcam"], "camara"),
    **dict.fromkeys(["sonido"], "audio"),
    **dict.fromkeys(["raton"], "mouse"),
    **dict.fromkeys(["telefonia", "anexo", "celular", "movil", "smartphone"], "telefono"),
    **dict.fromkeys(["malware", "ransomware", "troyano", "antivirus"], "virus"),
    **dict.fromkeys(["phishing", "fraudulento", "extrano"], "sospechoso"),
    **dict.fromkeys(["instalacion", "instalo"], "instalar"),
    **dict.fromkeys(["software", "app"], "aplicacion"),
    **dict.fromkeys(["lentitud", "lenta"], "lento"),
    **dict.fromkeys(["sap"], "erp"),
}
_lock = threading.Lock()
_index: dict = {"key": None}


def _singular(word: str) -> str:
    """Light Spanish plural reduction: impresoras -> impresora, errores -> error, conexiones -> conexion."""
    if len(word) <= 3 or word.isdigit():
        return word
    if word.endswith("iones"):
        return word[:-2]
    if word.endswith("es") and len(word) > 4 and word[-3] in "rlndz" and not word.endswith("lles"):
        return word[:-2]
    if word.endswith("s") and word[-2] in "aeiou":
        return word[:-1]
    return word


def analyze(text: str) -> list[str]:
    """Terms indexed for a ticket or a query: singular unigrams, their synonym term and adjacent bigrams."""
    text = re.sub(r"\b(wi)[\s-]?(fi)\b|\be-mail\b", lambda m: "wifi" if m.group(1) else "email", normalize_text(text))
    words = [_singular(w) for w in re.findall(r"[a-z0-9]+", text)]
    words = [w for w in words if w not in STOPWORDS]
    shared = [SYNONYMS.get(w, w) for w in words]
    terms = words + [s for w, s in zip(words, shared) if s != w]
    # Bigrams over the original words and over the shared terms ("printer no" also counts as "impresora no").
    bigrams = {f"{a} {b}" for seq in (words, shared) for a, b in zip(seq, seq[1:])}
    return terms + sorted(bigrams)


def _signature(db: Session):
    return db.execute(select(func.count(Ticket.id), func.max(Ticket.updated_at))).one()


def _build(db: Session) -> dict:
    rows = db.execute(select(Ticket.id, Ticket.number, Ticket.title, Ticket.description, Ticket.diagnosis, Ticket.solution,
                             Ticket.requester_id, Ticket.technician_id, Category.name, Priority.code, TicketState.code, Ticket.created_at)
                      .join(Category, Category.id == Ticket.category_id).join(Priority, Priority.id == Ticket.priority_id)
                      .join(TicketState, TicketState.id == Ticket.state_id)).all()
    docs = [" ".join(filter(None, [r[2], r[2], r[8], r[3], r[4], r[5]])) for r in rows]
    meta = [{"id": r[0], "number": r[1], "title": r[2], "description": r[3], "diagnosis": r[4], "solution": r[5],
             "requester_id": r[6], "technician_id": r[7], "category": r[8], "priority": r[9], "state": r[10],
             "created_at": r[11], "synthetic": (r[1] or "").startswith(SYNTHETIC_TICKET_PREFIX)} for r in rows]
    if not docs:
        return {"vectorizer": None, "matrix": None, "meta": []}
    vectorizer = TfidfVectorizer(analyzer=analyze, min_df=1, max_features=40000, sublinear_tf=True)
    return {"vectorizer": vectorizer, "matrix": vectorizer.fit_transform(docs), "meta": meta}


def get_index(db: Session) -> dict:
    key = tuple(_signature(db))
    with _lock:
        if _index.get("key") != key:
            _index.update(_build(db))
            _index["key"] = key
        return dict(_index)


def _allowed(user, item: dict) -> bool:
    role = user.role.code
    if role in {"ADMIN", "JEFE_TI"}:
        return True
    if role == "TECNICO":
        own = user.technician and item["technician_id"] == user.technician.id
        return bool(own or item["state"] in RESOLVED_STATES)
    return item["requester_id"] == user.id


def search(db: Session, user, query: str, limit: int = 5, resolved_only: bool = False, exclude_id: str | None = None) -> list[dict]:
    query = (query or "").strip()
    if not analyze(query):
        return []
    index = get_index(db)
    if index["vectorizer"] is None:
        return []
    scores = linear_kernel(index["vectorizer"].transform([query]), index["matrix"]).ravel()
    results = []
    for i in scores.argsort()[::-1]:
        if scores[i] <= 0.02 or len(results) >= limit:
            break
        item = index["meta"][i]
        if item["id"] == exclude_id or not _allowed(user, item) or (resolved_only and item["state"] not in RESOLVED_STATES):
            continue
        results.append({"id": item["id"], "number": item["number"], "title": item["title"], "category": item["category"],
                        "priority": item["priority"], "state": item["state"], "diagnosis": item["diagnosis"],
                        "solution": item["solution"], "score": round(float(scores[i]), 3), "synthetic": item["synthetic"]})
    return results
