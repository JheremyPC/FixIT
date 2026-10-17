"""Persistence of trained models (joblib) and their version metadata (JSON).

The database table ``ml_artifacts`` is the source of truth, so models survive restarts and
redeploys on hosts with an ephemeral disk. ``settings.ml_model_dir`` is only a local cache that
inference reads from; ``restore`` rebuilds it from the database at startup.

joblib/pickle executes code on load, so every artifact is signed with an HMAC derived from
``JWT_SECRET_KEY`` and only loaded when the signature matches: rows written by anyone without the
application's secret are rejected (and the models are retrained). Never place third-party .joblib
files in the cache folder either.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import threading
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import MLArtifact

log = logging.getLogger("fixit.ml")
TRAIN_LOCK = threading.Lock()
_cache: dict[str, tuple[float, object]] = {}
_cache_lock = threading.Lock()
MODEL_NAMES = ("resolution", "sla_risk", "priority", "forecast")
METADATA, HISTORY = "metadata", "training_history"
# Bump when features, pipelines or bundle layout change: stored models are then retrained at startup.
FORMAT_VERSION = 2  # 2: regression metrics include RMSE and R² in hours


def _dir() -> Path:
    return settings.ml_path


def _atomic_write(path: Path, writer) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    writer(tmp)
    os.replace(tmp, path)


def _sign(payload: bytes) -> str:
    key = hashlib.sha256(b"fixit-ml-artifacts:" + settings.jwt_secret_key.encode()).digest()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _dump(obj) -> bytes:
    buf = io.BytesIO()
    joblib.dump(obj, buf, compress=3)
    return buf.getvalue()


def _json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def _put(db: Session, name: str, version: str, payload: bytes) -> None:
    row = db.get(MLArtifact, name)
    if row is None:
        db.add(MLArtifact(name=name, version=version, payload=payload, signature=_sign(payload)))
    else:
        row.version, row.payload, row.signature = version, payload, _sign(payload)


def _verified(row: MLArtifact | None) -> bytes | None:
    if row is None or not hmac.compare_digest(row.signature, _sign(row.payload)):
        return None
    return row.payload


def compatible(meta: dict | None) -> bool:
    """Metadata produced by this code version and these library versions (pickles are not portable)."""
    libs = (meta or {}).get("libraries", {})
    return bool(meta) and meta.get("format") == FORMAT_VERSION and libs.get("scikit-learn") == sklearn.__version__ \
        and libs.get("numpy") == np.__version__


def _write_cache(files: dict[str, bytes | None]) -> None:
    for filename, payload in files.items():
        path = _dir() / filename
        if payload is None:
            path.unlink(missing_ok=True)
        else:
            _atomic_write(path, lambda p, data=payload: p.write_bytes(data))
    with _cache_lock:
        _cache.clear()


def persist(db: Session, bundles: dict[str, object | None], meta: dict) -> None:
    """Store a complete training run atomically (one transaction), then refresh the local cache.
    ``None`` bundles are removed: a stale model never stays next to new metadata."""
    history = load_history(db)
    entry = {"version": meta["version"], "trained_at": meta["trained_at"], "trained_by": meta.get("trained_by"),
             "data_source": meta["data"]["source"], "tickets": meta["data"]["tickets_used"],
             "models": {k: {"status": v.get("status"), "headline": v.get("headline")} for k, v in meta["models"].items()}}
    history = ([entry] + history)[:30]
    files: dict[str, bytes | None] = {}
    for name, obj in bundles.items():
        payload = _dump(obj) if obj is not None else None
        if payload is None:
            db.execute(delete(MLArtifact).where(MLArtifact.name == name))
        else:
            _put(db, name, meta["version"], payload)
        files[f"{name}.joblib"] = payload
    files["metadata.json"], files["training_history.json"] = _json(meta), _json(history)
    _put(db, METADATA, meta["version"], files["metadata.json"])
    _put(db, HISTORY, meta["version"], files["training_history.json"])
    db.commit()
    _write_cache(files)


def _discard_cache() -> None:
    _write_cache({f"{n}.joblib": None for n in MODEL_NAMES} | {"metadata.json": None})


def restore(db: Session) -> dict | None:
    """Rebuild the local cache from the database. Returns the metadata when every stored model is
    authentic, loadable and compatible with this version; ``None`` means the models must be retrained
    (the local cache is then emptied so an outdated model is never served)."""
    rows = {r.name: r for r in db.scalars(select(MLArtifact))}
    raw_meta = _verified(rows.get(METADATA))
    try:
        meta = json.loads(raw_meta) if raw_meta else None
    except ValueError:
        meta = None
    if not compatible(meta):
        _discard_cache()
        return None
    files: dict[str, bytes | None] = {"metadata.json": raw_meta, "training_history.json": _verified(rows.get(HISTORY))}
    for name in MODEL_NAMES:
        expected = meta["models"].get(name, {}).get("status") == "trained"
        row = rows.get(name)
        payload = _verified(row)
        if expected and (payload is None or row.version != meta["version"]):
            log.warning("Artefacto ML '%s' ausente, alterado o de otra versión", name)
            _discard_cache()
            return None
        if payload is not None:
            try:
                joblib.load(io.BytesIO(payload))
            except Exception:
                log.exception("Artefacto ML '%s' no se puede cargar", name)
                _discard_cache()
                return None
        files[f"{name}.joblib"] = payload if expected else None
    _write_cache(files)
    return meta


def load_bundle(name: str):
    path = _dir() / f"{name}.joblib"
    if not path.exists():
        return None
    mtime = path.stat().st_mtime
    with _cache_lock:
        cached = _cache.get(name)
        if cached and cached[0] == mtime:
            return cached[1]
        obj = joblib.load(path)
        _cache[name] = (mtime, obj)
        return obj


def load_metadata() -> dict | None:
    path = _dir() / "metadata.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def load_history(db: Session | None = None) -> list[dict]:
    try:
        if db is not None:
            raw = _verified(db.get(MLArtifact, HISTORY))
            return json.loads(raw) if raw else []
        path = _dir() / "training_history.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except ValueError:
        return []
