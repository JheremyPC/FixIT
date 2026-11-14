"""Evidence files: validated by content (not by the name or type sent by the client), stored under UPLOAD_DIR/auditoria with
a random name, outside the static web root, and served only through authorized API endpoints as attachments."""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from fastapi import HTTPException

from app.core.config import settings

# Declared type -> stored extension. HTML, SVG, scripts and office documents with macros are never accepted.
ALLOWED = {"application/pdf": ".pdf", "image/png": ".png", "image/jpeg": ".jpg", "text/plain": ".txt", "text/csv": ".csv",
           "application/json": ".json"}
MAGIC = {"application/pdf": (b"%PDF-",), "image/png": (b"\x89PNG\r\n\x1a\n",), "image/jpeg": (b"\xff\xd8\xff",)}
TEXT_TYPES = {"text/plain", "text/csv", "application/json"}
ACTIVE_MARKERS = (b"<script", b"<html", b"<svg", b"<!doctype html", b"<iframe", b"javascript:")
EXTENSION_TYPES = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".txt": "text/plain",
                   ".csv": "text/csv", ".json": "application/json", ".log": "text/plain"}


def evidence_dir() -> Path:
    path = settings.upload_path / "auditoria"
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_name(name: str | None) -> str:
    base = Path((name or "").replace("\\", "/")).name
    base = "".join(c for c in base if c.isprintable() and c not in '<>:"/\\|?*').strip(" .")
    return base[:200] or "evidencia"


def detect_type(declared: str | None, filename: str | None) -> str:
    content_type = (declared or "").split(";")[0].strip().lower()
    if content_type in ("application/octet-stream", "", "application/vnd.ms-excel", "text/x-log"):
        content_type = EXTENSION_TYPES.get(Path(filename or "").suffix.lower(), content_type)
    return content_type


def validate(raw: bytes, content_type: str, max_bytes: int) -> None:
    if not raw: raise HTTPException(422, "El archivo está vacío")
    if len(raw) > max_bytes: raise HTTPException(413, f"El archivo excede el máximo permitido ({max_bytes // 1_048_576} MB)")
    if content_type not in ALLOWED: raise HTTPException(415, "Tipo de archivo no permitido (PDF, PNG, JPEG, TXT, CSV o JSON)")
    if content_type in MAGIC:
        if not raw.startswith(MAGIC[content_type]): raise HTTPException(415, "El contenido del archivo no corresponde a su tipo")
        return
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(415, "Los archivos de texto deben estar codificados en UTF-8") from None
    if "\x00" in text: raise HTTPException(415, "El archivo de texto contiene caracteres no permitidos")
    head = raw[:4096].lower()
    if any(marker in head for marker in ACTIVE_MARKERS): raise HTTPException(415, "El archivo contiene contenido HTML o de script")
    if content_type == "application/json":
        try:
            json.loads(text)
        except ValueError:
            raise HTTPException(415, "El archivo JSON no es válido") from None


def store(raw: bytes, content_type: str) -> tuple[str, str]:
    """(stored file name, SHA-256 hex)."""
    stored = f"{uuid.uuid4()}{ALLOWED[content_type]}"
    (evidence_dir() / stored).write_bytes(raw)
    return stored, hashlib.sha256(raw).hexdigest()


def path_of(stored_name: str) -> Path:
    path = (evidence_dir() / stored_name).resolve()
    if path.parent != evidence_dir().resolve(): raise HTTPException(404, "Archivo no encontrado")
    return path
