"""Persistence of trained models (joblib) and their version metadata (JSON).

Artifacts are written atomically to ``settings.ml_model_dir`` (outside Git). Only files
produced by this application are ever loaded: never place third-party .joblib files there,
because joblib/pickle executes code on load.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import joblib

from app.core.config import settings

TRAIN_LOCK = threading.Lock()
_cache: dict[str, tuple[float, object]] = {}
_cache_lock = threading.Lock()
MODEL_NAMES = ("resolution", "sla_risk", "priority", "forecast")


def _dir() -> Path:
    return settings.ml_path


def _atomic_write(path: Path, writer) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    writer(tmp)
    os.replace(tmp, path)


def save_bundle(name: str, obj) -> None:
    _atomic_write(_dir() / f"{name}.joblib", lambda p: joblib.dump(obj, p, compress=3))


def delete_bundle(name: str) -> None:
    path = _dir() / f"{name}.joblib"
    if path.exists():
        path.unlink()


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


def save_metadata(meta: dict) -> None:
    _atomic_write(_dir() / "metadata.json", lambda p: p.write_text(json.dumps(meta, ensure_ascii=False, indent=2, default=str), encoding="utf-8"))
    history_path = _dir() / "training_history.json"
    history = []
    if history_path.exists():
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except ValueError:
            history = []
    entry = {"version": meta["version"], "trained_at": meta["trained_at"], "trained_by": meta.get("trained_by"),
             "data_source": meta["data"]["source"], "tickets": meta["data"]["tickets_used"],
             "models": {k: {"status": v.get("status"), "headline": v.get("headline")} for k, v in meta["models"].items()}}
    history = ([entry] + history)[:30]
    _atomic_write(history_path, lambda p: p.write_text(json.dumps(history, ensure_ascii=False, indent=2, default=str), encoding="utf-8"))


def load_metadata() -> dict | None:
    path = _dir() / "metadata.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def load_history() -> list[dict]:
    path = _dir() / "training_history.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return []
