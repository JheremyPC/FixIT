"""Configurable LLM provider. Credentials are read only on the backend from environment
variables and are never logged, returned to clients or embedded in the frontend.

LLM_PROVIDER=anthropic          -> official Anthropic SDK (LLM_API_KEY or ANTHROPIC_API_KEY)
LLM_PROVIDER=openai_compatible  -> any /chat/completions endpoint at LLM_BASE_URL (e.g. a local Ollama,
                                   or Gemini at https://generativelanguage.googleapis.com/v1beta/openai)
LLM_PROVIDER empty              -> not configured: callers must say so instead of simulating answers.
"""
from __future__ import annotations

import logging
import math
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

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
RATE_LIMITED, UNAVAILABLE = 429, 503
RETRYABLE = {RATE_LIMITED, UNAVAILABLE}  # transient: retried, then the fallback model. Never 400/401/403/404.
RETRY_DELAYS_SECONDS = (1, 2, 4)  # waits before each of the 3 retries (Retry-After replaces them when present)
RETRY_WAIT_BUDGET_SECONDS = 10  # max total wait per model; a longer Retry-After goes straight to the fallback
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
    """Return {"text", "provider", "model"}; raise LLMNotConfigured / LLMError otherwise.
    Every call is recorded in llm_calls (metadata only, see app.llm.telemetry)."""
    from app.llm import telemetry

    status = provider_status()
    started = time.perf_counter()
    elapsed = lambda: int((time.perf_counter() - started) * 1000)
    if not status["configured"]:
        telemetry.record(status["provider"], status["model"], "NO_CONFIGURADO", 0, status["message"])
        raise LLMNotConfigured(status["message"])
    try:
        if status["provider"] == "anthropic":
            result = _anthropic(system, messages, status["model"])
        else:
            result = _openai_compatible(system, messages, status["model"])
    except LLMError as exc:
        telemetry.record(status["provider"], status["model"], "ERROR", elapsed(), str(exc))
        raise
    telemetry.record(result["provider"], result["model"], "OK", elapsed(),
                     fallback_used=result["provider"] == "openai_compatible" and result["model"] != status["model"])
    return result


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
    failures = []  # (model, final response, attempts) of every model that stayed 429/503
    for current in candidates:
        response, attempts = _post_with_retries(system, messages, current, key, gemini)
        if response.status_code not in RETRYABLE:
            if failures:
                logger.warning("LLM fallback model %s answered after HTTP %s from %s", current,
                               failures[0][1].status_code, model)
            return _handle_response(response, current, key, gemini)
        failures.append((current, response, attempts))
    raise LLMError(_exhausted_message(failures, key))


def _exhausted_message(failures: list[tuple[str, httpx.Response, int]], key: str | None) -> str:
    tried = " ni con el alternativo ".join(model for model, _, _ in failures)
    last = failures[-1][1]
    detail = f" Detalle: {_error_detail(last, key)}" if last.content else ""
    statuses = {response.status_code for _, response, _ in failures}
    if statuses == {UNAVAILABLE}:
        return (f"El proveedor LLM no está disponible temporalmente (HTTP 503) con el modelo {tried} "
                f"tras {1 + len(RETRY_DELAYS_SECONDS)} intentos por modelo. Intente nuevamente en unos minutos.{detail}")
    hints = [h for _, response, _ in failures if (h := _retry_after_seconds(response)) is not None]
    when = f"en unos {max(1, math.ceil(min(hints)))} segundos" if hints else "en unos minutos"
    if statuses == {RATE_LIMITED}:
        reason = f"limitó las solicitudes (HTTP 429: cuota o frecuencia excedida) con el modelo {tried}"
    else:
        reason = "no pudo atender la solicitud con ningún modelo (" + "; ".join(
            f"{model}: HTTP {response.status_code}" for model, response, _ in failures) + ")"
    attempts = ", ".join(str(n) for _, _, n in failures)
    return f"El proveedor LLM {reason} tras {attempts} intentos. Intente nuevamente {when}.{detail}"


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Wait requested by the provider: Retry-After (seconds or HTTP date) or Gemini's RetryInfo.retryDelay."""
    value = response.headers.get("retry-after", "").strip()
    if value:
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
            except (TypeError, ValueError):
                pass
    try:  # [{"error": {"details": [{"@type": ".../google.rpc.RetryInfo", "retryDelay": "17s"}]}}]
        data = response.json()
        error = (data[0] if isinstance(data, list) and data else data).get("error", {})
        for item in error.get("details") or []:
            match = re.fullmatch(r"(\d+(?:\.\d+)?)s", str(item.get("retryDelay", "")).strip())
            if match:
                return float(match[1])
    except (ValueError, AttributeError, IndexError, TypeError):
        pass
    return None


def _post_with_retries(system: str, messages: list[dict], model: str, key: str | None, gemini: bool) -> tuple[httpx.Response, int]:
    """POST /chat/completions -> (response, attempts). Only HTTP 429 and 503 are retried, with progressive waits
    or the provider's Retry-After, within RETRY_WAIT_BUDGET_SECONDS. Authentication, 400 and every other status
    are returned at once for _handle_response."""
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body = {"model": model, "max_tokens": settings.llm_max_tokens, "messages": [{"role": "system", "content": system}, *messages]}
    # Gemini counts reasoning tokens against max_tokens; LLM_EFFORT keeps that reasoning bounded.
    # Only sent to Gemini: other OpenAI-compatible servers (e.g. Ollama) may reject the field.
    if gemini and settings.llm_effort in GEMINI_EFFORTS:
        body["reasoning_effort"] = settings.llm_effort
    waited = 0.0
    for attempt, delay in enumerate([*RETRY_DELAYS_SECONDS, None], start=1):
        try:
            response = httpx.post(settings.llm_base_url.rstrip("/") + "/chat/completions", json=body, headers=headers,
                                  timeout=settings.llm_timeout_seconds)
        except httpx.HTTPError:
            raise LLMError("No se pudo conectar con el proveedor LLM.")
        if response.status_code not in RETRYABLE:
            return response, attempt
        logger.warning("LLM provider HTTP %s (modelo %s, intento %s): %s", response.status_code, model, attempt,
                       _error_detail(response, key))
        if delay is None:
            break
        hinted = _retry_after_seconds(response)
        if hinted is not None:
            delay = hinted
        if waited + delay > RETRY_WAIT_BUDGET_SECONDS:
            logger.warning("LLM provider pide esperar %.1f s (modelo %s): sin más reintentos con este modelo", delay, model)
            break
        _sleep(delay)
        waited += delay
    return response, attempt


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
