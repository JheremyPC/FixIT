"""Import of external evidence: database activity logs and security tool reports.

Database logs (kind ``LOGS_BD``): CSV or JSON exported from the Supabase Logs Explorer (fields such as ``timestamp`` and
``event_message``, optionally nested ``metadata``/``parsed``), or a PostgreSQL ``csvlog`` file. Lines produced by pgAudit
(``AUDIT: SESSION|OBJECT,...``) and connection/authentication events are kept; other lines are counted and discarded.
Every stored record keeps:
* ``record_hash``: SHA-256 of the line as received (duplicates are skipped, also across imports);
* ``original``: the received fields with control characters escaped, secrets redacted and pgAudit bind parameters removed
  (they are never stored, as ``pgaudit.log_parameter`` may contain personal data);
* parsed columns (time, role, class, command, object...), which are a transformation of ``original``.

Tool reports (``BANDIT``, ``PIP_AUDIT``, ``ZAP``, ``SARIF``) are reduced to a summary (counts and up to 300 items, with file
paths made relative). The raw file is never stored: only its name, size and SHA-256.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone

from fastapi import HTTPException

from app.auditing.redaction import redact_text, relative_source, secret_free, strip_paths

UTC = timezone.utc
KINDS = {"LOGS_BD": "Logs de base de datos (pgAudit / PostgreSQL / Supabase)", "BANDIT": "Bandit (JSON)",
         "PIP_AUDIT": "pip-audit (JSON)", "ZAP": "OWASP ZAP (JSON tradicional)", "SARIF": "SARIF 2.1.0"}
MAX_ITEMS = 300
PARAMS_REMOVED = "[PARAMETROS NO ALMACENADOS]"
CSVLOG = ["log_time", "user_name", "database_name", "process_id", "connection_from", "session_id", "session_line_num", "command_tag",
          "session_start_time", "virtual_transaction_id", "transaction_id", "error_severity", "sql_state_code", "message", "detail", "hint",
          "internal_query", "internal_query_pos", "context", "query", "query_pos", "location", "application_name", "backend_type"]
MESSAGE_KEYS = ("event_message", "message", "msg", "log_message")
TIME_KEYS = ("timestamp", "log_time", "time", "@timestamp", "created_at")
USER_KEYS = ("user_name", "usename", "db_user", "user")
DB_KEYS = ("database_name", "database", "datname", "db")
SESSION_KEYS = ("session_id", "sessionid", "session")


class ImportRejected(HTTPException):
    def __init__(self, detail: str):
        super().__init__(422, detail)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _text(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImportRejected("El archivo debe estar codificado en UTF-8") from None
    if "\x00" in text: raise ImportRejected("El archivo contiene caracteres NUL")
    return text


def _json(raw: bytes):
    try:
        return json.loads(_text(raw))
    except ValueError:
        raise ImportRejected("El archivo no es un JSON válido") from None


# --- Database logs --------------------------------------------------------------------------------------------------
def parse_time(value) -> datetime | None:
    if value in (None, ""): return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().lstrip("-").isdigit()):
            number = float(value)
            seconds = number / 1e6 if number > 1e15 else number / 1e3 if number > 1e12 else number
            return datetime.fromtimestamp(seconds, UTC)
        text = str(value).strip().replace(" UTC", "+00:00").replace("Z", "+00:00")
        if len(text) > 19 and text[10] == " ": text = text[:10] + "T" + text[11:]
        if text[-3:].lstrip("+-").isdigit() and text[-3] in "+-": text += ":00"   # "+00" -> "+00:00" (csvlog)
        moment = datetime.fromisoformat(text)
        return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    except (ValueError, OverflowError, OSError):
        return None


def _find(record, keys: tuple[str, ...], depth: int = 0):
    if not isinstance(record, dict) or depth > 3: return None
    for key in keys:
        value = record.get(key)
        if value not in (None, "", []) and not isinstance(value, (dict, list)): return value
    for value in record.values():
        if isinstance(value, list) and value and isinstance(value[0], dict): value = value[0]
        if isinstance(value, dict):
            found = _find(value, keys, depth + 1)
            if found not in (None, ""): return found
    return None


def parse_pgaudit(message: str) -> dict | None:
    """Fields of a pgAudit line ``AUDIT: <type>,<stmt>,<substmt>,<class>,<command>,<object_type>,<object>,<statement>[,<params>]``."""
    index = message.find("AUDIT:")
    if index < 0: return None
    body = message[index + 6:].strip()
    try:
        fields = next(csv.reader([body]))
    except (csv.Error, StopIteration):
        return None
    if len(fields) < 8 or fields[0] not in ("SESSION", "OBJECT"): return None
    params = fields[8] if len(fields) > 8 else None
    has_params = params not in (None, "", "<not logged>", "<none>")
    return {"audit_type": fields[0], "statement_class": fields[3][:30], "command": fields[4][:60], "object_type": fields[5][:40] or None,
            "object_name": fields[6][:200] or None, "statement": fields[7], "had_params": has_params,
            "clean_message": message[:index] + "AUDIT: " + ",".join(_csv_quote(f) for f in fields[:8]) + (f",{PARAMS_REMOVED}" if has_params else "")}


def _csv_quote(value: str) -> str:
    out = io.StringIO()
    csv.writer(out, lineterminator="").writerow([value])
    return out.getvalue()


def classify_connection(message: str) -> tuple[str, str] | None:
    lower = message.lower()
    if "password authentication failed" in lower or "authentication failed" in lower: return "AUTENTICACION_FALLIDA", "AUTH"
    if lower.startswith("connection authorized") or "connection authenticated" in lower: return "CONEXION", "CONNECT"
    if lower.startswith("disconnection"): return "CONEXION", "DISCONNECT"
    if "permission denied" in lower: return "PERMISO_DENEGADO", "ERROR"
    return None


def _rows_from(raw: bytes) -> tuple[list[dict], str]:
    """Records of a log export, and the detected format."""
    text = _text(raw)
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        data = _json(raw)
        if isinstance(data, dict):
            data = next((data[k] for k in ("result", "results", "rows", "data", "logs") if isinstance(data.get(k), list)), [data])
        if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
            raise ImportRejected("El JSON debe ser una lista de registros (objetos)")
        return data, "JSON"
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        raise ImportRejected("El archivo CSV está vacío") from None
    except csv.Error:
        raise ImportRejected("El archivo CSV no es válido") from None
    names = [h.strip().lower() for h in header]
    try:
        if any(k in names for k in MESSAGE_KEYS):
            return [dict(zip(names, row, strict=False)) for row in reader if row], "CSV"
        if len(header) >= 14 and parse_time(header[0]):  # csvlog has no header row
            rows = [header] + [row for row in reader if row]
            return [dict(zip(CSVLOG, row, strict=False)) for row in rows], "CSVLOG"
    except csv.Error:
        raise ImportRejected("El archivo CSV no es válido") from None
    raise ImportRejected("Formato no reconocido: se esperaba una columna event_message/message (exportación de Supabase) o un csvlog de PostgreSQL")


def _original(record: dict, message_key: str | None, clean_message: str | None) -> tuple[dict, bool]:
    out, redacted = {}, False
    for key, value in list(record.items())[:40]:
        if isinstance(value, (dict, list)): value = json.dumps(value, ensure_ascii=False, default=str)
        if key == message_key and clean_message is not None: value = clean_message
        text, changed = redact_text(value, 2000)
        out[str(key)[:60]] = text
        redacted = redacted or changed
    return out, redacted


def parse_db_logs(raw: bytes, max_rows: int) -> dict:
    rows, fmt = _rows_from(raw)
    if len(rows) > max_rows: raise ImportRejected(f"El archivo tiene {len(rows)} registros; el máximo por importación es {max_rows}")
    records, discarded, rejected, errors = [], 0, 0, []
    for number, record in enumerate(rows, start=1):
        message_key = next((k for k in MESSAGE_KEYS if isinstance(record.get(k), str)), None)
        message = record.get(message_key) if message_key else _find(record, MESSAGE_KEYS)
        if not isinstance(message, str) or not message.strip():
            rejected += 1
            if len(errors) < 20: errors.append(f"Registro {number}: sin mensaje")
            continue
        raw_line = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
        audit = parse_pgaudit(message)
        connection = None if audit else classify_connection(message)
        if not audit and not connection:
            discarded += 1
            continue
        original, redacted = _original(record, message_key, audit["clean_message"] if audit else None)
        statement, changed = redact_text(audit["statement"], 4000) if audit else redact_text(message, 1000)
        stamp = parse_time(_find(record, TIME_KEYS))
        records.append({
            "record_hash": sha256(raw_line.encode()), "source": "PGAUDIT" if audit else "POSTGRES", "log_time": stamp,
            "db_user": (secret_free(_find(record, USER_KEYS), 100) or None), "database": secret_free(_find(record, DB_KEYS), 100) or None,
            "session_id": secret_free(_find(record, SESSION_KEYS), 100) or None, "audit_type": audit["audit_type"] if audit else None,
            "statement_class": audit["statement_class"] if audit else connection[0], "command": audit["command"] if audit else connection[1],
            "object_type": audit["object_type"] if audit else None, "object_name": secret_free(audit["object_name"], 200) if audit else None,
            "statement": statement, "redacted": redacted or changed or bool(audit and audit["had_params"]), "original": original})
    return {"format": fmt, "total": len(rows), "records": records, "discarded": discarded, "rejected": rejected, "errors": errors}


# --- Tool reports ---------------------------------------------------------------------------------------------------
def _count(items: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for item in items: out[str(item.get(key))] = out.get(str(item.get(key)), 0) + 1
    return out


def parse_bandit(raw: bytes) -> dict:
    data = _json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ImportRejected("No es un informe JSON de Bandit (falta la lista «results»)")
    items = [{"test_id": r.get("test_id"), "test": r.get("test_name"), "severidad": str(r.get("issue_severity", "")).upper(),
              "confianza": str(r.get("issue_confidence", "")).upper(), "archivo": relative_source(r.get("filename")),
              "linea": r.get("line_number"), "texto": secret_free(r.get("issue_text"), 300)} for r in data["results"] if isinstance(r, dict)]
    totals = (data.get("metrics") or {}).get("_totals") or {}
    return {"tool": {"name": "bandit", "version": None, "generated_at": data.get("generated_at")},
            "summary": {"total": len(items), "por_severidad": _count(items, "severidad"), "por_confianza": _count(items, "confianza"),
                        "lineas_analizadas": totals.get("loc"), "errores_de_analisis": len(data.get("errors") or []),
                        "items": items[:MAX_ITEMS]}, "total": len(items)}


def parse_pip_audit(raw: bytes) -> dict:
    data = _json(raw)
    deps = data.get("dependencies") if isinstance(data, dict) else data
    if not isinstance(deps, list): raise ImportRejected("No es un informe JSON de pip-audit (falta «dependencies»)")
    items, vulnerable = [], 0
    for dep in deps:
        if not isinstance(dep, dict): continue
        vulns = dep.get("vulns") or []
        if vulns: vulnerable += 1
        for v in vulns:
            items.append({"paquete": dep.get("name"), "version": dep.get("version"), "id": v.get("id"), "alias": (v.get("aliases") or [])[:5],
                          "corregido_en": (v.get("fix_versions") or [])[:5], "descripcion": secret_free(v.get("description"), 300)})
    skipped = [d.get("name") for d in deps if isinstance(d, dict) and d.get("skip_reason")]
    return {"tool": {"name": "pip-audit", "version": None},
            "summary": {"dependencias": len(deps), "dependencias_vulnerables": vulnerable, "vulnerabilidades": len(items),
                        "sin_correccion": sum(1 for i in items if not i["corregido_en"]), "omitidas": skipped[:50], "items": items[:MAX_ITEMS]},
            "total": len(deps)}


ZAP_RISK = {"3": "ALTO", "2": "MEDIO", "1": "BAJO", "0": "INFORMATIVO"}


def parse_zap(raw: bytes) -> dict:
    data = _json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("site"), list): raise ImportRejected("No es un informe JSON tradicional de OWASP ZAP (falta «site»)")
    items, sites = [], []
    for site in data["site"]:
        if not isinstance(site, dict): continue
        sites.append(strip_paths(str(site.get("@name", "")))[:200])
        for alert in site.get("alerts") or []:
            items.append({"plugin": alert.get("pluginid"), "alerta": secret_free(alert.get("alert") or alert.get("name"), 200),
                          "riesgo": ZAP_RISK.get(str(alert.get("riskcode")), str(alert.get("riskcode"))),
                          "confianza": alert.get("confidence"), "instancias": int(alert.get("count") or len(alert.get("instances") or []) or 0),
                          "sitio": sites[-1]})
    return {"tool": {"name": "OWASP ZAP", "version": data.get("@version"), "generated_at": data.get("@generated")},
            "summary": {"sitios": sites[:20], "alertas": len(items), "por_riesgo": _count(items, "riesgo"), "items": items[:MAX_ITEMS]},
            "total": len(items)}


SARIF_LEVEL = {"error": "ALTO", "warning": "MEDIO", "note": "BAJO", "none": "INFORMATIVO"}


def parse_sarif(raw: bytes) -> dict:
    data = _json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list): raise ImportRejected("No es un archivo SARIF (falta «runs»)")
    items, tools = [], []
    for run in data["runs"]:
        driver = ((run or {}).get("tool") or {}).get("driver") or {}
        tools.append({"name": driver.get("name"), "version": driver.get("version") or driver.get("semanticVersion")})
        for result in run.get("results") or []:
            location = (((result.get("locations") or [{}])[0]).get("physicalLocation") or {})
            items.append({"regla": result.get("ruleId"), "nivel": SARIF_LEVEL.get(result.get("level") or "warning", "MEDIO"),
                          "mensaje": secret_free(((result.get("message") or {}).get("text")), 300),
                          "archivo": relative_source((location.get("artifactLocation") or {}).get("uri")),
                          "linea": (location.get("region") or {}).get("startLine"), "herramienta": driver.get("name")})
    first = tools[0] if tools else {"name": None, "version": None}
    return {"tool": {"name": first["name"] or "SARIF", "version": first["version"], "sarif": data.get("version"), "herramientas": tools[:10]},
            "summary": {"resultados": len(items), "por_nivel": _count(items, "nivel"), "items": items[:MAX_ITEMS]}, "total": len(items)}


PARSERS = {"BANDIT": parse_bandit, "PIP_AUDIT": parse_pip_audit, "ZAP": parse_zap, "SARIF": parse_sarif}
