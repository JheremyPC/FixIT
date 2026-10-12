"""Configurable LLM provider. Credentials are read only on the backend from environment
variables and are never logged, returned to clients or embedded in the frontend.

LLM_PROVIDER=anthropic          -> official Anthropic SDK (LLM_API_KEY or ANTHROPIC_API_KEY)
LLM_PROVIDER=openai_compatible  -> any /chat/completions endpoint at LLM_BASE_URL (e.g. a local Ollama,
                                   or Gemini at https://generativelanguage.googleapis.com/v1beta/openai)
LLM_PROVIDER empty              -> not configured: callers must say so instead of simulating answers.
"""
from __future__ import annotations

import logging
import re
import time

import httpx

from app.core.config import settings

logger = logging.getLogger("fixit.llm")
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"
# Models that accept server-side refusal fallbacks ("default" routing).
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
GEMINI_HOST = "generativelanguage.googleapis.com"
GEMINI_EFFORTS = {"minimal", "low", "medium", "high"}  # reasoning_effort values Gemini 3 accepts
# Google (AIza...), OpenAI/Anthropic-style (sk-...) keys and bearer tokens echoed back in error bodies.
SECRET_PATTERN = re.compile(r"AIza[0-9A-Za-z_\-]{20,}|sk-[0-9A-Za-z_\-]{10,}|(?i:bearer)\s+\S+")
ERROR_DETAIL_MAX = 300
UNAVAILABLE = 503
RETRY_DELAYS_SECONDS = (1, 2, 4)  # waits before each of the 3 retries of an HTTP 503
_sleep = time.sleep  # indirection so tests do not actually wait


class LLMNotConfigured(RuntimeError):
    pass


class LLMError(RuntimeError):
    pass


def _api_key() -> str | None:
    for secret in (settings.llm_api_key, settings.anthropic_api_key if settings.llm_provider.strip().lower() == "anthropic" else None):
        if secret and secret.get_secret_value().strip():
            return secret.get_secret_value().strip()
    return None


def provider_status() -> dict:
    provider = settings.llm_provider.strip().lower()
    if provider == "anthropic":
        ok = bool(_api_key())
        return {"configured": ok, "provider": "anthropic", "model": settings.llm_model or DEFAULT_ANTHROPIC_MODEL,
                "message": None if ok else "Falta LLM_API_KEY (o ANTHROPIC_API_KEY) en el backend."}
    if provider == "openai_compatible":
        ok = bool(settings.llm_base_url and settings.llm_model)
        return {"configured": ok, "provider": "openai_compatible", "model": settings.llm_model or None,
                "message": None if ok else "Faltan LLM_BASE_URL y/o LLM_MODEL en el backend."}
    if provider:
        return {"configured": False, "provider": provider, "model": None, "message": f"Proveedor LLM desconocido: '{provider}'. Use anthropic u openai_compatible."}
    return {"configured": False, "provider": None, "model": None,
            "message": "El asistente LLM no está configurado. Defina LLM_PROVIDER y sus credenciales en las variables de entorno del backend."}


def complete(system: str, messages: list[dict]) -> dict:
    """Return {"text", "provider", "model"}; raise LLMNotConfigured / LLMError otherwise."""
    status = provider_status()
    if not status["configured"]:
        raise LLMNotConfigured(status["message"])
    if status["provider"] == "anthropic":
        return _anthropic(system, messages, status["model"])
    return _openai_compatible(system, messages, status["model"])


def _anthropic(system: str, messages: list[dict], model: str) -> dict:
    import anthropic

    client = anthropic.Anthropic(api_key=_api_key(), timeout=settings.llm_timeout_seconds, max_retries=2)
    params = {"model": model, "max_tokens": settings.llm_max_tokens, "system": system, "messages": messages}
    if settings.llm_effort in {"low", "medium", "high", "xhigh", "max"}:
        params["output_config"] = {"effort": settings.llm_effort}
    try:
        if settings.llm_anthropic_fallbacks == "default" and model in FALLBACK_MODELS:
            response = client.beta.messages.create(**params, betas=["server-side-fallback-2026-07-01"], fallbacks="default")
        else:
            response = client.messages.create(**params)
    except anthropic.AuthenticationError:
        raise LLMError("El proveedor LLM rechazó las credenciales configuradas.")
    except anthropic.PermissionDeniedError:
        raise LLMError("La credencial configurada no tiene permiso para usar este modelo.")
    except anthropic.NotFoundError:
        raise LLMError(f"Modelo LLM no encontrado: {model}.")
    except anthropic.RateLimitError:
        raise LLMError("El proveedor LLM limitó las solicitudes. Intente nuevamente en unos minutos.")
    except anthropic.APIStatusError as exc:
        logger.warning("Anthropic API status %s (request %s)", exc.status_code, getattr(exc, "request_id", None))
        raise LLMError("El proveedor LLM devolvió un error. Intente nuevamente.")
    except anthropic.APIConnectionError:
        raise LLMError("No se pudo conectar con el proveedor LLM.")
    if response.stop_reason == "refusal":
        raise LLMError("El modelo declinó responder esta solicitud.")
    text = "".join(block.text for block in response.content if block.type == "text").strip()
    if not text:
        raise LLMError("El proveedor LLM no devolvió texto.")
    return {"text": text, "provider": "anthropic", "model": getattr(response, "model", model),
            "truncated": response.stop_reason == "max_tokens"}


def _error_detail(response: httpx.Response, key: str | None) -> str:
    """Provider error message from an HTTP error body, safe to log and show: secrets redacted, length bounded.
    Handles OpenAI-style {"error": {...}} and Gemini's [{"error": {...}}]."""
    try:
        data = response.json()
        error = (data[0] if isinstance(data, list) and data else data).get("error", {})
        if isinstance(error, str):
            error = {"message": error}
        status = error.get("status") or error.get("type") or error.get("code")
        message = str(error.get("message") or "")
        text = f"{status}: {message}" if status and message else message or str(status or "")
    except (ValueError, AttributeError, IndexError, TypeError):
        text = response.text
    if key:
        text = text.replace(key, "[redactado]")
    text = SECRET_PATTERN.sub("[redactado]", text)
    text = " ".join(text.split())
    return text[:ERROR_DETAIL_MAX] + ("…" if len(text) > ERROR_DETAIL_MAX else "")


def _openai_compatible(system: str, messages: list[dict], model: str) -> dict:
    key = _api_key()
    gemini = GEMINI_HOST in settings.llm_base_url
    # The fallback model only makes sense on Gemini (its default is a Gemini model); other servers keep one model.
    fallback = settings.llm_fallback_model.strip() if gemini else ""
    candidates = [model] + ([fallback] if fallback and fallback != model else [])
    for current in candidates:
        response = _post_with_retries(system, messages, current, key, gemini)
        if response.status_code != UNAVAILABLE:
            if current != model:
                logger.warning("LLM fallback model %s answered after HTTP 503 from %s", current, model)
            return _handle_response(response, current, key, gemini)
    attempts = 1 + len(RETRY_DELAYS_SECONDS)
    tried = " ni con el alternativo ".join(candidates)
    raise LLMError(f"El proveedor LLM no está disponible temporalmente (HTTP 503) con el modelo {tried} "
                   f"tras {attempts} intentos por modelo. Intente nuevamente en unos minutos."
                   + (f" Detalle: {_error_detail(response, key)}" if response.content else ""))


def _post_with_retries(system: str, messages: list[dict], model: str, key: str | None, gemini: bool) -> httpx.Response:
    """POST /chat/completions; only HTTP 503 (temporarily unavailable) is retried, with progressive waits.
    Authentication, 400 and every other status are returned at once for _handle_response."""
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body = {"model": model, "max_tokens": settings.llm_max_tokens, "messages": [{"role": "system", "content": system}, *messages]}
    # Gemini counts reasoning tokens against max_tokens; LLM_EFFORT keeps that reasoning bounded.
    # Only sent to Gemini: other OpenAI-compatible servers (e.g. Ollama) may reject the field.
    if gemini and settings.llm_effort in GEMINI_EFFORTS:
        body["reasoning_effort"] = settings.llm_effort
    for attempt, delay in enumerate([*RETRY_DELAYS_SECONDS, None], start=1):
        try:
            response = httpx.post(settings.llm_base_url.rstrip("/") + "/chat/completions", json=body, headers=headers,
                                  timeout=settings.llm_timeout_seconds)
        except httpx.HTTPError:
            raise LLMError("No se pudo conectar con el proveedor LLM.")
        if response.status_code != UNAVAILABLE:
            return response
        logger.warning("LLM provider HTTP 503 (modelo %s, intento %s): %s", model, attempt, _error_detail(response, key))
        if delay is not None:
            _sleep(delay)
    return response


def _handle_response(response: httpx.Response, model: str, key: str | None, gemini: bool) -> dict:
    detail = _error_detail(response, key) if response.status_code >= 400 else ""
    if detail:
        logger.warning("LLM provider HTTP %s: %s", response.status_code, detail)
    # Gemini reports a missing or invalid API key as HTTP 400 instead of 401/403.
    if response.status_code in {401, 403} or (gemini and response.status_code == 400 and
                                              any(s in response.text for s in ("API key", "API_KEY", "Authorization header"))):
        raise LLMError("El proveedor LLM rechazó las credenciales configuradas.")
    if response.status_code == 404:
        raise LLMError(f"Modelo LLM no encontrado: {model}.")
    if response.status_code == 429:
        raise LLMError("El proveedor LLM limitó las solicitudes. Intente nuevamente en unos minutos.")
    if response.status_code >= 400:
        if not detail:
            logger.warning("LLM provider HTTP %s", response.status_code)
        raise LLMError(f"El proveedor LLM devolvió HTTP {response.status_code}" + (f": {detail}" if detail else "."))
    try:
        choice = response.json()["choices"][0]
        text = (choice["message"]["content"] or "").strip()
    except (ValueError, KeyError, IndexError, TypeError):
        raise LLMError("Respuesta del proveedor LLM con formato inesperado.")
    if not text and choice.get("finish_reason") == "length":
        raise LLMError("El modelo agotó LLM_MAX_TOKENS antes de responder (incluye el razonamiento interno). Aumente LLM_MAX_TOKENS.")
    if not text:
        raise LLMError("El proveedor LLM no devolvió texto.")
    return {"text": text, "provider": "openai_compatible", "model": model, "truncated": choice.get("finish_reason") == "length"}
