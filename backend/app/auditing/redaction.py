"""Redaction used by every control, import and report: results never carry passwords, tokens, keys, connection strings,
full e-mail addresses, full IP addresses or absolute server paths."""
import re
from app.services.audit import REDACTED, clean_text, redact

# Secrets that may appear inside free text (SQL statements, error messages, tool reports).
SECRET_TEXT = [
    # key=value / key: value (connection strings, configuration dumps, JSON-like text). Plain prose is left untouched.
    (re.compile(r"(?i)\b(password|passwd|pwd|contrase(?:ñ|n)a)\b(\s*[=:]\s*)('[^']*'|\"[^\"]*\"|[^\s,;]+)"), r"\1\2" + REDACTED),
    # SQL: [ENCRYPTED] PASSWORD 'value'
    (re.compile(r"(?i)\b((?:encrypted\s+)?password)\s+'[^']*'"), r"\1 '" + REDACTED + "'"),
    (re.compile(r"(?i)\b(secret|token|api[_-]?key|apikey|authorization)\b(\s*[=:]\s*)('[^']*'|\"[^\"]*\"|[^\s,;]+)"), r"\1\2" + REDACTED),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/\-]{8,}=*"), r"\1 " + REDACTED),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), REDACTED),          # JWT
    (re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s@/]+@"), "postgresql://" + REDACTED + "@"),  # URL with credentials
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}|sk-[0-9A-Za-z_\-]{10,}|sb_secret_[0-9A-Za-z_\-]{10,}"), REDACTED),
    (re.compile(r"(?i)\bpgp_sym_(?:en|de)crypt\s*\([^)]*\)"), "pgp_sym_*(" + REDACTED + ")"),
]
EMAIL = re.compile(r"([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*([A-Za-z0-9_%+\-])@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
ABS_PATH = re.compile(r"(?:[A-Za-z]:\\|/)(?:[^\s\"'<>|:]+[\\/])+([^\s\"'<>|:\\/]+)")


def redact_text(value, limit: int | None = None) -> tuple[str | None, bool]:
    """(text with control characters escaped and secrets replaced, whether anything was redacted)."""
    if value is None: return None, False
    text = clean_text(value)
    changed = False
    for pattern, replacement in SECRET_TEXT:
        text, count = pattern.subn(replacement, text)
        changed = changed or bool(count)
    if limit and len(text) > limit: text = text[:limit] + "…"
    return text, changed


def secret_free(value, limit: int | None = None) -> str | None:
    return redact_text(value, limit)[0]


def mask_email(email: str | None) -> str | None:
    """juan.perez@fixit.org -> j***z@fixit.org (enough to recognise an account in a report, not to contact it)."""
    if not email or "@" not in email: return email
    local, domain = email.rsplit("@", 1)
    return f"{local[0]}***{local[-1] if len(local) > 1 else ''}@{domain}"


def mask_emails_in(text: str | None) -> str | None:
    return EMAIL.sub(lambda m: f"{m.group(1)}***{m.group(2)}@{m.group(3)}", text) if text else text


def mask_ip(ip: str | None) -> str | None:
    if not ip: return ip
    if ":" in ip and "." not in ip:  # IPv6: keep the first two groups
        return ":".join(ip.split(":")[:2]) + ":…"
    parts = ip.split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else "[IP]"


def strip_paths(text: str | None) -> str | None:
    """Absolute paths of the server or of the machine that produced a report keep only their last component."""
    return ABS_PATH.sub(lambda m: m.group(1), text) if text else text


def relative_source(path: str | None) -> str | None:
    """A source file reported by a tool, reduced to its path inside the project (app/..., migrations/..., tests/...)."""
    if not path: return path
    norm = path.replace("\\", "/")
    for anchor in ("/backend/", "backend/"):
        if anchor in norm:
            return norm.split(anchor, 1)[1]
    for root in ("app/", "migrations/", "tests/"):
        index = norm.find("/" + root)
        if index >= 0: return norm[index + 1:]
    return norm.rsplit("/", 1)[-1] if norm.startswith("/") or ":" in norm[:3] else norm


def safe_error(exc: BaseException, limit: int = 400) -> str:
    """Error text that can be stored and shown: type, message without secrets, e-mails or absolute paths."""
    text = f"{type(exc).__name__}: {exc}"
    text = strip_paths(mask_emails_in(secret_free(text)))
    return " ".join(text.split())[:limit]


def redact_details(value):
    """Structured evidence: sensitive keys redacted (same rule as audit_logs: any key containing pass, token, secret,
    clave, session, cookie, credential...) and secrets inside free text removed."""
    value = redact(value)
    if isinstance(value, dict): return {k: redact_details(v) for k, v in value.items()}
    if isinstance(value, list): return [redact_details(v) for v in value]
    if isinstance(value, str): return secret_free(value)
    return value
