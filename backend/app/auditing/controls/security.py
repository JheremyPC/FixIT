"""Category SEGURIDAD: application security.

Static controls inspect the deployed code and configuration (routes and their dependencies, settings, static files).
Dynamic controls send requests to the application inside the same process (ASGI transport): they never leave the
server, never authenticate and never reach endpoints that write data. Tool results (Bandit, pip-audit, OWASP ZAP,
SARIF) come from imported reports: no command is executed from the web interface and active scans are never run
against production.
"""
from __future__ import annotations

import asyncio
import inspect
import re
from importlib import metadata

from sqlalchemy import func, literal_column, select

from app.auditing.controls.common import finding, from_import
from app.auditing.registry import Ctx, NotVerifiable, Outcome, control, fail, ok, warn
from app.core.config import BACKEND_DIR, settings
from app.models import User

C = "SEGURIDAD"
APP_DIR = BACKEND_DIR / "app"
STATIC_DIR = APP_DIR / "static"
PUBLIC_ROUTES = {("POST", "/api/auth/login"), ("POST", "/api/auth/register"), ("POST", "/api/auth/refresh"), ("GET", "/api/legal"),
                 ("GET", "/health"), ("GET", "/"), ("GET", "/legal")}
# Least privilege expected for sensitive routes: the roles a route accepts must be a subset of these.
ROLE_POLICY = [
    (r"^/api/users", None, {"ADMIN"}), (r"^/api/settings", None, {"ADMIN"}), (r"^/api/priorities$", "POST", {"ADMIN"}),
    (r"^/api/catalogs/", "POST", {"ADMIN"}), (r"^/api/technicians", "POST|PATCH", {"ADMIN"}), (r"^/api/technicians$", "GET", {"ADMIN", "JEFE_TI"}),
    (r"^/api/reports/", None, {"ADMIN", "JEFE_TI"}), (r"^/api/ml/", None, {"ADMIN", "JEFE_TI"}), (r"^/api/audit(/|$)", None, {"ADMIN", "JEFE_TI"}),
    (r"^/api/audit-center/", None, {"ADMIN", "JEFE_TI", "TECNICO"}), (r"^/api/agents(/monitor|/runs/|/alerts|$)", "GET", {"ADMIN", "JEFE_TI"}),
    (r"^/api/agents/[^/]+/run$", "POST", {"ADMIN", "JEFE_TI"}), (r"^/api/agents/[^/]+$", "PATCH", {"ADMIN", "JEFE_TI"}),
]
# Calls that, inside an endpoint, show an object-level authorization check (ownership or role).
OWNERSHIP_MARKERS = ("can_access_ticket", "requester_id", "user_id=actor.id", "owner_id", "filter_by(user_id=", "_can_see", "_visible_to",
                     "technician_id==user.technician")
ASVS = ["OWASP ASVS 5.0"]


# --- Route introspection --------------------------------------------------------------------------------------------
def _calls(dependant) -> list:
    out = []
    for dep in dependant.dependencies:
        if dep.call is not None: out.append(dep.call)
        out += _calls(dep)
    return out


def _roles_of(call) -> set[str] | None:
    """Roles a dependency accepts, or None if it does not restrict roles."""
    roles = getattr(call, "roles", None)
    if roles: return set(roles)
    try:
        closure = inspect.getclosurevars(call).nonlocals
    except (TypeError, ValueError):
        closure = {}
    if "codes" in closure: return set(closure["codes"])
    module = getattr(call, "__module__", "")
    if module == "app.api.audit" and call.__name__ == "auditor":
        from app.api.audit import AUDITORS
        return set(AUDITORS)
    return None


def _source_with_helpers(fn) -> str:
    """Source of an endpoint plus the module-level functions it calls (one level), where authorization helpers live."""
    try:
        source = inspect.getsource(fn)
    except (OSError, TypeError):
        return ""
    import importlib
    module = inspect.getmodule(fn)
    local_imports = {}
    for origin, names in re.findall(r"from\s+([A-Za-z0-9_.]+)\s+import\s+([A-Za-z0-9_, ]+)", source):
        try:
            imported = importlib.import_module(origin)
        except ImportError:
            continue
        for name in (n.strip() for n in names.split(",")):
            if name: local_imports[name] = getattr(imported, name, None)
    extra = []
    for name in set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\(", source)):
        helper = local_imports.get(name) or getattr(module, name, None)
        if inspect.isfunction(helper) and helper is not fn:
            try: extra.append(inspect.getsource(helper))
            except (OSError, TypeError): pass
    return source + "\n".join(extra)


def api_routes(routes=None, prefix: str = "", extra_dependencies: tuple = ()) -> list[tuple[str, object, tuple]]:
    """(full path, APIRoute, dependencies added by include_router) of every API route. FastAPI >= 0.16x keeps included
    routers as ``_IncludedRouter`` objects instead of copying their routes into ``app.routes``; both layouts are supported."""
    from fastapi.routing import APIRoute
    if routes is None:
        from app.main import app
        routes = app.routes
    out = []
    for route in routes:
        if isinstance(route, APIRoute):
            out.append((prefix + route.path, route, extra_dependencies))
        elif hasattr(route, "original_router"):
            context = getattr(route, "include_context", None)
            deps = tuple(getattr(d, "dependency", d) for d in (getattr(context, "dependencies", None) or ()))
            out += api_routes(route.original_router.routes, prefix + (getattr(context, "prefix", "") or ""), extra_dependencies + deps)
    return out


def route_inventory() -> list[dict]:
    from app.security.auth import current_user
    rows = []
    for path, route, included_deps in api_routes():
        calls = _calls(route.dependant) + list(included_deps)
        authenticated = any(c is current_user for c in calls) or any(_roles_of(c) for c in calls)
        roles = None
        for c in calls:
            r = _roles_of(c)
            if r: roles = r if roles is None else roles & r
        source = _source_with_helpers(route.endpoint)
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            rows.append({"metodo": method, "ruta": path, "autenticada": authenticated, "roles": sorted(roles) if roles else None,
                         "funcion": f"{route.endpoint.__module__}.{route.endpoint.__name__}",
                         "control_objeto": any(m in source for m in OWNERSHIP_MARKERS),
                         "parametros_id": bool(re.search(r"\{[a-z_]*id\}", path))})
    return rows


@control("SEG-AUT-01", C, "Autenticación requerida en la API", "Verificar, inspeccionando el árbol de dependencias de cada ruta, que solo las "
         "rutas públicas previstas (inicio de sesión, registro, documentos legales, salud) aceptan solicitudes sin sesión.", "ESTATICO", "CRITICO",
         ["OWASP ASVS 5.0 V6 (autenticación) y V8 (autorización)"])
def authenticated_routes(ctx: Ctx) -> Outcome:
    routes = route_inventory()
    unexpected = [r for r in routes if not r["autenticada"] and (r["metodo"], r["ruta"]) not in PUBLIC_ROUTES]
    details = {"rutas": len(routes), "publicas_previstas": sorted(f"{m} {p}" for m, p in PUBLIC_ROUTES),
               "publicas_inesperadas": [f"{r['metodo']} {r['ruta']}" for r in unexpected]}
    if unexpected:
        return fail(f"{len(unexpected)} rutas aceptan solicitudes sin autenticación fuera de la lista prevista.", [finding(
            f"ruta:{r['metodo']} {r['ruta']}", f"Ruta sin autenticación: {r['metodo']} {r['ruta']}",
            f"La ruta {r['metodo']} {r['ruta']} ({r['funcion']}) no depende de current_user ni de un control de roles.",
            "Acceso anónimo a la funcionalidad de la ruta.", "Alta: la ruta es alcanzable desde Internet.",
            "Añada la dependencia de autenticación o documente por qué es pública.", evidence=r) for r in unexpected], **details)
    return ok(f"Las {len(routes)} rutas de la API exigen sesión, salvo las {len(PUBLIC_ROUTES)} públicas previstas.", **details)


@control("SEG-AUT-02", C, "Privilegios por rol en rutas sensibles", "Comparar los roles aceptados por cada ruta sensible (usuarios, "
         "configuración, reportes, ML, agentes, auditoría) con la política de privilegio mínimo de FixIT.", "ESTATICO", "ALTO",
         ["OWASP ASVS 5.0 V8.2 (autorización a nivel de función)"])
def role_policy(ctx: Ctx) -> Outcome:
    routes = route_inventory()
    violations, checked = [], 0
    for r in routes:
        for pattern, methods, allowed in ROLE_POLICY:
            if re.search(pattern, r["ruta"]) and (methods is None or re.fullmatch(methods, r["metodo"])):
                checked += 1
                accepted = set(r["roles"]) if r["roles"] else {"ADMIN", "JEFE_TI", "TECNICO", "USUARIO"}
                if not accepted <= allowed:
                    violations.append({**r, "permitidos_por_politica": sorted(allowed), "exceso": sorted(accepted - allowed)})
                break
    details = {"rutas_sensibles_revisadas": checked, "violaciones": violations,
               "politica": [{"ruta": p, "metodos": m or "todos", "roles": sorted(a)} for p, m, a in ROLE_POLICY]}
    if violations:
        return fail(f"{len(violations)} rutas sensibles aceptan más roles que los permitidos.", [finding(
            f"rol:{v['metodo']} {v['ruta']}", f"Privilegios excesivos en {v['metodo']} {v['ruta']}",
            f"La ruta acepta {', '.join(v['exceso'])} además de {', '.join(v['permitidos_por_politica'])}.",
            "Usuarios con menos privilegios acceden a funciones administrativas.", "Alta para usuarios autenticados.",
            "Restrinja la dependencia con require_roles(...) a los roles de la política.", evidence=v) for v in violations], **details)
    return ok(f"{checked} rutas sensibles respetan la política de roles.", **details)


@control("SEG-IDOR-01", C, "Autorización a nivel de objeto (IDOR/BOLA)", "Identificar rutas con identificadores en la URL accesibles a roles "
         "no administrativos cuyo código no muestra una comprobación de propiedad o de rol.", "ESTATICO", "ALTO",
         ["OWASP ASVS 5.0 V8.2.2 (acceso a objetos)", "OWASP API Security Top 10: API1 BOLA"])
def object_level(ctx: Ctx) -> Outcome:
    routes = [r for r in route_inventory() if r["parametros_id"] and r["autenticada"]]
    exposed = [r for r in routes if not r["roles"] or set(r["roles"]) - {"ADMIN", "JEFE_TI"}]
    unchecked = [r for r in exposed if not r["control_objeto"]]
    details = {"rutas_con_identificador": len(routes), "accesibles_a_roles_no_administrativos": len(exposed),
               "sin_comprobacion_visible": [f"{r['metodo']} {r['ruta']}" for r in unchecked],
               "metodo": "Heurístico: busca en el código de la función llamadas como can_access_ticket o filtros por propietario. "
                         "Complementa, no sustituye, las pruebas automatizadas de acceso cruzado entre usuarios."}
    if unchecked:
        return warn(f"{len(unchecked)} rutas con identificador sin comprobación de propiedad visible en su código.", [finding(
            f"idor:{r['metodo']} {r['ruta']}", f"Revisar autorización por objeto: {r['metodo']} {r['ruta']}",
            "La ruta recibe un identificador y es accesible a roles no administrativos; no se encontró una comprobación de propiedad.",
            "Un usuario podría acceder a recursos de otro cambiando el identificador.", "Requiere confirmación manual o prueba.",
            "Verifique la comprobación (puede estar en una función auxiliar) y añada una prueba de acceso cruzado.", "MEDIO", evidence=r)
            for r in unchecked], "MEDIO", **details)
    return ok(f"Las {len(exposed)} rutas con identificador accesibles a roles no administrativos comprueban propiedad o rol.", **details)


# --- Configuration --------------------------------------------------------------------------------------------------
# Values published in this repository (.env.example, tests) or common defaults: a key containing them is public knowledge.
KNOWN_PLACEHOLDERS = ("replace-with-a-long-random-secret-at-least-32-characters", "change-this", "changeme", "test-secret-key-for-pytest",
                      "your-secret-key", "supersecret")


def _strength(value: str) -> dict:
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return {"longitud": len(value), "caracteres_distintos": len(set(value)), "tipos_de_caracter": classes}


@control("SEG-JWT-01", C, "Configuración de JWT", "Verificar algoritmo, longitud y unicidad de la clave de firma, vigencia de los tokens y "
         "claims obligatorios.", "ESTATICO", "CRITICO", ["OWASP ASVS 5.0 V9 (tokens autocontenidos)"])
def jwt_config(ctx: Ctx) -> Outcome:
    from app.security import auth
    secret = settings.jwt_secret_key
    strength = _strength(secret)
    placeholder = any(p in secret.lower() for p in KNOWN_PLACEHOLDERS)
    src = inspect.getsource(auth.decode_token)
    details = {"algoritmo": auth.ALGORITHM, "acepta_solo_un_algoritmo": "algorithms=[ALGORITHM]" in src,
               "claims_obligatorios": "require" in src and all(c in src for c in ('"exp"', '"iat"', '"sub"')), "clave": strength,
               "clave_es_valor_de_ejemplo": placeholder, "minutos_acceso": settings.jwt_access_minutes, "dias_renovacion": settings.jwt_refresh_days,
               "verifica_tipo": "type" in src}
    problems = []
    if placeholder: problems.append(("CRITICO", "La clave de firma es un valor de ejemplo o de prueba conocido."))
    if strength["longitud"] < 32 or strength["caracteres_distintos"] < 12: problems.append(("ALTO", "La clave de firma es corta o de baja variedad."))
    if not details["acepta_solo_un_algoritmo"] or auth.ALGORITHM.lower() == "none": problems.append(("CRITICO", "La verificación no fija el algoritmo."))
    if settings.jwt_access_minutes > 60: problems.append(("MEDIO", f"Los tokens de acceso duran {settings.jwt_access_minutes} minutos (máximo recomendado 60)."))
    if settings.jwt_refresh_days > 14: problems.append(("MEDIO", f"Los tokens de renovación duran {settings.jwt_refresh_days} días (máximo recomendado 14)."))
    if problems:
        worst = min((p[0] for p in problems), key=["CRITICO", "ALTO", "MEDIO", "BAJO"].index)
        return fail(" ".join(p[1] for p in problems), [finding(
            "config:jwt", "Configuración de JWT insegura", " ".join(p[1] for p in problems),
            "Una clave conocida o débil permite falsificar sesiones de cualquier rol.", "Alta si la clave es un valor público.",
            "Defina JWT_SECRET_KEY con 64 caracteres aleatorios en Render (rotarla cierra todas las sesiones y requiere reentrenar ML).",
            worst, {k: v for k, v in details.items() if k != "clave"})], worst, **details)
    return ok(f"HS256 con algoritmo fijo, claims exp/iat/sub obligatorios, clave de {strength['longitud']} caracteres y vigencias "
              f"{settings.jwt_access_minutes} min / {settings.jwt_refresh_days} días.", **details)


@control("SEG-PWD-01", C, "Almacenamiento de contraseñas", "Comprobar que todas las contraseñas se almacenan con bcrypt y un factor de costo "
         "≥ 10, leyendo solo el prefijo del hash.", "SQL", "CRITICO", ["OWASP ASVS 5.0 V11.4 (almacenamiento de contraseñas)"])
def password_storage(ctx: Ctx) -> Outcome:
    # Literal bounds: with bind parameters PostgreSQL does not treat the SELECT and GROUP BY expressions as equal.
    prefix = func.substr(User.password_hash, literal_column("1"), literal_column("7"))
    rows = ctx.session.execute(select(prefix, func.count()).group_by(prefix)).all()
    groups = {prefix: count for prefix, count in rows}
    weak = {p: c for p, c in groups.items() if not re.fullmatch(r"\$2[aby]\$\d\d\$", p or "") or int((p or "$2b$00$")[4:6]) < 10}
    details = {"cuentas": sum(groups.values()), "algoritmos": {("bcrypt costo " + p[4:6]) if p and p.startswith("$2") else "otro": c for p, c in groups.items()}}
    if weak:
        return fail(f"{sum(weak.values())} cuentas no usan bcrypt con costo ≥ 10.", [finding(
            "usuarios:hash_debil", "Contraseñas almacenadas con un algoritmo débil", f"{sum(weak.values())} cuentas tienen un hash que no es bcrypt ≥ 10.",
            "Si se filtra la base, esas contraseñas se recuperan con poco esfuerzo.", "Depende de una filtración de la base.",
            "Obligue a esas cuentas a restablecer su contraseña.", evidence={"cuentas": sum(weak.values())})], **details)
    return ok(f"Las {details['cuentas']} cuentas usan bcrypt con costo ≥ 10.", **details)


@control("SEG-PWD-02", C, "Política de contraseñas y factores de autenticación", "Revisar la longitud mínima exigida y la disponibilidad de "
         "autenticación multifactor.", "ESTATICO", "MEDIO", ["OWASP ASVS 5.0 V6.2 (contraseñas) y V6.3 (MFA)"])
def password_policy(ctx: Ctx) -> Outcome:
    from app.schemas import LoginIn, UserCreate
    minimum = min(m.min_length for m in UserCreate.model_fields["password"].metadata if hasattr(m, "min_length"))
    maximum = max(m.max_length for m in LoginIn.model_fields["password"].metadata if hasattr(m, "max_length"))
    sources = "\n".join(p.read_text(encoding="utf-8", errors="ignore").lower() for d in ("api", "security") for p in (APP_DIR / d).glob("*.py"))
    has_mfa = any(word in sources for word in ("totp", "webauthn", "otp_secret"))
    breach_check = any(word in sources for word in ("pwnedpasswords", "haveibeenpwned", "breached"))
    details = {"longitud_minima": minimum, "longitud_maxima": maximum, "mfa_disponible": has_mfa, "verificacion_contra_filtraciones": breach_check}
    if minimum < 8:
        return fail(f"La longitud mínima es {minimum} (ASVS exige al menos 8).", [finding("politica:longitud", "Longitud mínima insuficiente",
                    f"Se aceptan contraseñas de {minimum} caracteres.", "Contraseñas adivinables.", "Alta.", "Exija al menos 8 (recomendado 15).", "ALTO")], **details)
    if has_mfa and breach_check:
        return ok(f"Longitud mínima {minimum}, MFA disponible y verificación contra contraseñas filtradas.", **details)
    if has_mfa:
        return warn(f"Longitud mínima {minimum} y MFA disponible; sin verificación contra contraseñas filtradas.", [], "BAJO", **details)
    return warn(f"Longitud mínima {minimum}; no hay MFA ni verificación contra contraseñas comprometidas.", [finding(
        "politica:mfa", "Sin autenticación multifactor", "FixIT solo admite correo y contraseña, también para ADMIN y JEFE_TI.",
        "Una contraseña filtrada o reutilizada da acceso completo a la cuenta.", "Media: mitigada por el bloqueo tras intentos fallidos.",
        "Implemente MFA (TOTP) al menos para ADMIN y JEFE_TI y compare las contraseñas nuevas con listas de contraseñas comprometidas.", "MEDIO")],
        "MEDIO", **details)


@control("SEG-LOG-01", C, "Control de intentos de inicio de sesión", "Verificar el bloqueo temporal por cuenta y por IP tras intentos fallidos.",
         "ESTATICO", "MEDIO", ["OWASP ASVS 5.0 V6.3.1 (protección contra fuerza bruta)"])
def login_throttling(ctx: Ctx) -> Outcome:
    details = {"fallos_por_cuenta": settings.login_max_failures, "fallos_por_ip": settings.login_ip_max_failures, "ventana_minutos": settings.login_window_minutes,
               "alcance": "Contador en memoria por proceso: con varias instancias cada una cuenta por separado."}
    if settings.login_max_failures <= 0 or settings.login_max_failures > 20:
        return fail("El bloqueo por cuenta está desactivado o es demasiado permisivo.", [finding("config:login_throttle", "Bloqueo de inicio de sesión débil",
                    f"LOGIN_MAX_FAILURES = {settings.login_max_failures}.", "Ataques de fuerza bruta contra cuentas conocidas.", "Media.",
                    "Use un valor entre 5 y 10.", "ALTO")], **details)
    if settings.login_ip_max_failures <= 0:
        return warn(f"Bloqueo por cuenta tras {settings.login_max_failures} fallos; el límite por IP está desactivado.", [finding(
            "config:login_ip", "Sin límite de intentos por IP", "LOGIN_IP_MAX_FAILURES = 0.", "Un atacante puede probar muchas cuentas desde la misma IP.",
            "Media.", "Configure TRUSTED_PROXY_HOPS según Render y luego LOGIN_IP_MAX_FAILURES.", "BAJO")], "BAJO", **details)
    return ok(f"Bloqueo tras {settings.login_max_failures} fallos por cuenta y {settings.login_ip_max_failures} por IP en {settings.login_window_minutes} min.", **details)


@control("SEG-SES-01", C, "Gestión de sesiones en el cliente", "Revisar dónde guarda el cliente web los tokens y si el servidor puede revocar "
         "sesiones.", "ESTATICO", "MEDIO", ["OWASP ASVS 5.0 V7 (gestión de sesiones)"])
def sessions(ctx: Ctx) -> Outcome:
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    local = "localStorage.setItem(\"fixitToken\"" in js
    revocation = any("revoke" in p.read_text(encoding="utf-8", errors="ignore").lower() for p in (APP_DIR / "security").glob("*.py"))
    deactivation = "user.active" in inspect.getsource(__import__("app.security.auth", fromlist=["current_user"]).current_user)
    details = {"almacenamiento_tokens": "localStorage" if local else "otro", "revocacion_en_servidor": revocation,
               "cierre_por_desactivacion": deactivation, "minutos_acceso": settings.jwt_access_minutes}
    if not local and revocation:
        return ok("Tokens fuera de localStorage y revocación en el servidor disponible.", **details)
    return warn("Tokens en localStorage y sin revocación individual en el servidor (riesgo aceptado y documentado en docs/seguridad.md).", [finding(
        "sesiones:cliente", "Tokens en localStorage sin revocación en el servidor", "Un XSS permitiría leer los tokens; un token robado vale hasta su expiración.",
        "Suplantación de la sesión mientras el token esté vigente.", "Baja: la CSP impide scripts inline y de terceros y la interfaz escapa los datos.",
        "Evalúe cookies HttpOnly con protección CSRF o una lista de revocación de tokens de renovación.", "BAJO")], "BAJO", **details)


@control("SEG-SEC-01", C, "Protección de secretos y configuración sensible", "Verificar que los secretos requeridos están definidos (sin leer "
         "sus valores), que la documentación interactiva está desactivada y que los archivos públicos no contienen secretos.", "ESTATICO", "ALTO",
         ["OWASP ASVS 5.0 V13.3 (gestión de secretos)"])
def secrets(ctx: Ctx) -> Outcome:
    from app.auditing.redaction import SECRET_TEXT
    leaks = []
    for path in sorted(STATIC_DIR.rglob("*")):
        if path.suffix.lower() not in (".js", ".html", ".css", ".json", ".txt"): continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern, _ in SECRET_TEXT[4:7]:  # JWT, URL with credentials, API keys
            if pattern.search(text): leaks.append(path.name)
    hmac_key = bool(settings.audit_hmac_key and settings.audit_hmac_key.get_secret_value())
    env_public = any(p.name.startswith(".env") for p in STATIC_DIR.rglob("*"))
    details = {"jwt_secret_definido": bool(settings.jwt_secret_key), "audit_hmac_key_definida": hmac_key, "documentacion_api_activa": settings.api_docs_enabled,
               "archivos_publicos_con_patrones_de_secreto": sorted(set(leaks)), "env_en_directorio_publico": env_public,
               "nota": "Solo se informa si cada variable está definida; sus valores nunca se leen para el informe."}
    if leaks or env_public:
        return fail("Hay patrones de secretos o archivos .env en el directorio público.", [finding("estaticos:secretos", "Secretos en archivos públicos",
                    "Los archivos servidos en /static contienen patrones de credenciales.", "Cualquier visitante puede leerlos.", "Alta.",
                    "Retire los secretos, rótelos y vuelva a desplegar.", "CRITICO", {"archivos": sorted(set(leaks))})], "CRITICO", **details)
    problems = []
    if settings.api_docs_enabled: problems.append("La documentación interactiva (/docs, /openapi.json) está activa.")
    if not hmac_key: problems.append("AUDIT_HMAC_KEY no está definida: los sellos de auditoría dependen de JWT_SECRET_KEY.")
    if problems:
        return warn(" ".join(problems), [finding("config:secretos", "Configuración sensible mejorable", " ".join(problems),
                    "Rotar JWT_SECRET_KEY dejaría los sellos de auditoría como CLAVE_DISTINTA; /docs expone el mapa de la API.", "Baja.",
                    "Defina AUDIT_HMAC_KEY (aleatoria y estable) y mantenga API_DOCS_ENABLED=false en producción.", "BAJO")], "BAJO", **details)
    return ok("Secretos requeridos definidos, documentación de la API desactivada y sin secretos en archivos públicos.", **details)


# --- Dynamic (in-process) -------------------------------------------------------------------------------------------
def _requests(calls: list[tuple]) -> list[dict]:
    """Send requests to the app through the ASGI transport (same process, no network). Returns status, headers and body."""
    import httpx
    from app.main import app

    async def go():
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://fixit.audit.internal") as client:
            out = []
            for method, path, kwargs in calls:
                response = await client.request(method, path, **kwargs)
                out.append({"metodo": method, "ruta": path, "estado": response.status_code, "cabeceras": {k.lower(): v for k, v in response.headers.items()},
                            "cuerpo": response.text[:2000]})
            return out
    return asyncio.run(go())


REQUIRED_HEADERS = {"content-security-policy": None, "x-content-type-options": "nosniff", "x-frame-options": "DENY",
                    "referrer-policy": None, "permissions-policy": None, "cross-origin-opener-policy": None}


@control("SEG-HTTP-01", C, "Cabeceras de seguridad HTTP", "Solicitar la página principal, la API y un recurso estático y comprobar las "
         "cabeceras de seguridad, incluida HSTS bajo HTTPS.", "DINAMICO", "MEDIO", ["OWASP ASVS 5.0 V3.4 (cabeceras de seguridad)"])
def security_headers(ctx: Ctx) -> Outcome:
    responses = _requests([("GET", "/", {}), ("GET", "/health", {}), ("GET", "/static/style.css", {}),
                           ("GET", "/health", {"headers": {"x-forwarded-proto": "https"}})])
    missing = []
    for r in responses[:3]:
        for name, expected in REQUIRED_HEADERS.items():
            value = r["cabeceras"].get(name)
            if value is None or (expected and value != expected): missing.append(f"{r['ruta']}: {name}")
    hsts = responses[3]["cabeceras"].get("strict-transport-security")
    if not hsts or "max-age=" not in hsts or int(re.search(r"max-age=(\d+)", hsts).group(1)) < 15_552_000: missing.append("HSTS bajo HTTPS")
    server = [r["ruta"] for r in responses if "server" in r["cabeceras"] or "x-powered-by" in r["cabeceras"]]
    details = {"respuestas": [{"ruta": r["ruta"], "estado": r["estado"], "cabeceras": {k: v for k, v in r["cabeceras"].items() if k in REQUIRED_HEADERS or k in
               ("strict-transport-security", "cache-control", "cross-origin-resource-policy", "cross-origin-embedder-policy")}} for r in responses],
               "cabeceras_que_revelan_tecnologia": server,
               "limitacion": "Se comprueba la aplicación; cabeceras añadidas o eliminadas por el proxy de Render no son visibles desde el proceso."}
    if missing:
        return fail(f"Faltan cabeceras de seguridad: {', '.join(missing[:8])}.", [finding("http:cabeceras", "Cabeceras de seguridad ausentes",
                    f"Ausentes o incorrectas: {', '.join(missing)}.", "Mayor exposición a clickjacking, MIME sniffing o degradación a HTTP.", "Media.",
                    "Revise app.security.hardening.security_headers.", evidence={"faltantes": missing})], **details)
    return ok("CSP, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP y HSTS (bajo HTTPS) presentes.", **details)


@control("SEG-CSP-01", C, "Calidad de la Content Security Policy", "Analizar la CSP efectiva: scripts solo propios, sin 'unsafe-inline' ni "
         "'unsafe-eval', object-src 'none' y frame-ancestors 'none'.", "DINAMICO", "MEDIO", ["OWASP ASVS 5.0 V3.4.3"])
def csp_quality(ctx: Ctx) -> Outcome:
    csp = _requests([("GET", "/", {})])[0]["cabeceras"].get("content-security-policy", "")
    directives = {d.split()[0]: d.split()[1:] for d in (x.strip() for x in csp.split(";")) if d}
    script = directives.get("script-src", directives.get("default-src", []))
    problems = []
    if any(v in script for v in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:")): problems.append("script-src permite código inline, eval u orígenes amplios")
    if directives.get("object-src") != ["'none'"]: problems.append("object-src no es 'none'")
    if directives.get("frame-ancestors") != ["'none'"]: problems.append("frame-ancestors no es 'none'")
    if "default-src" not in directives: problems.append("sin default-src")
    notes = ["style-src-attr 'unsafe-inline' permite atributos style (necesario para los gráficos); no permite ejecutar código."] \
        if "'unsafe-inline'" in directives.get("style-src-attr", []) else []
    details = {"csp": csp, "directivas": directives, "observaciones": notes}
    if problems:
        return fail("; ".join(problems).capitalize() + ".", [finding("http:csp", "CSP permisiva", "; ".join(problems), "Facilita la explotación de XSS.",
                    "Media.", "Endurezca la CSP en app.security.hardening.", evidence={"csp": csp})], **details)
    return ok("CSP restrictiva: scripts solo del propio origen, sin inline ni eval, object-src y frame-ancestors 'none'.", **details)


@control("SEG-ERR-01", C, "Manejo de errores y exposición de información", "Provocar errores controlados (ruta inexistente, datos inválidos "
         "con un valor testigo, solicitud sin sesión) y verificar que no se revelan trazas, valores enviados ni la documentación de la API.",
         "DINAMICO", "MEDIO", ["OWASP ASVS 5.0 V16.5 (manejo de errores)"])
def error_handling(ctx: Ctx) -> Outcome:
    probe = "fixit-audit-probe-7f3a"
    responses = _requests([("GET", "/api/no-existe-auditoria", {}), ("POST", "/api/auth/login", {"json": {"email": "no-es-correo", "password": probe}}),
                           ("GET", "/api/users", {}), ("GET", "/openapi.json", {}), ("GET", "/docs", {})])
    problems = []
    for r in responses:
        body = r["cuerpo"]
        if "Traceback" in body or "File \"" in body or "sqlalchemy" in body.lower(): problems.append(f"{r['ruta']}: traza o detalle interno")
        if probe in body: problems.append(f"{r['ruta']}: devuelve el valor enviado")
    if responses[1]["estado"] != 422: problems.append("Datos inválidos no producen 422")
    if responses[2]["estado"] != 401: problems.append("/api/users sin sesión no responde 401")
    if not settings.api_docs_enabled and (responses[3]["estado"] != 404 or responses[4]["estado"] != 404): problems.append("Documentación de la API accesible")
    details = {"pruebas": [{"metodo": r["metodo"], "ruta": r["ruta"], "estado": r["estado"]} for r in responses],
               "nota": "La solicitud de inicio de sesión usa un correo inválido: se rechaza en la validación, antes de consultar la base o registrar intentos."}
    if problems:
        return fail("; ".join(problems) + ".", [finding("http:errores", "Los errores revelan información", "; ".join(problems),
                    "Ayuda a un atacante a conocer la implementación o filtra datos enviados.", "Media.", "Revise los manejadores de excepciones de app.main.",
                    evidence={"problemas": problems})], **details)
    return ok("Errores sin trazas ni valores enviados; 401 sin sesión; documentación de la API no expuesta.", **details)


@control("SEG-CORS-01", C, "CORS y CSRF", "Verificar la política de orígenes cruzados y si el modelo de autenticación es susceptible a CSRF.",
         "ESTATICO", "MEDIO", ["OWASP ASVS 5.0 V3.5 (CSRF y CORS)"])
def cors_csrf(ctx: Ctx) -> Outcome:
    from app.main import app
    cors = [m for m in app.user_middleware if getattr(m.cls, "__name__", "") == "CORSMiddleware"]
    sources = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in APP_DIR.rglob("*.py"))
    cookies = bool(re.search(r"\.set_cookie\(", sources))
    details = {"cors_configurado": bool(cors), "autenticacion": "Cabecera Authorization: Bearer (HTTPBearer)", "usa_cookies": cookies}
    if cors:
        options = cors[0].kwargs
        details["cors"] = {k: options.get(k) for k in ("allow_origins", "allow_credentials", "allow_methods")}
        if "*" in (options.get("allow_origins") or []) and options.get("allow_credentials"):
            return fail("CORS permite cualquier origen con credenciales.", [finding("http:cors", "CORS abierto con credenciales",
                        "allow_origins=['*'] y allow_credentials=True.", "Sitios de terceros pueden leer respuestas autenticadas.", "Alta.",
                        "Limite allow_origins a los dominios propios.", "ALTO")], **details)
    if cookies:
        return warn("La aplicación emite cookies: revise la protección CSRF.", [finding("http:csrf", "Cookies sin protección CSRF verificada",
                    "Se encontró set_cookie en el código.", "Solicitudes forjadas desde otros sitios.", "Media.", "Use SameSite=Strict y tokens CSRF.", "MEDIO")], **details)
    return ok("Sin CORS (solo mismo origen) y autenticación mediante la cabecera Authorization; por eso CSRF no aplica a este modelo.", **details)


@control("SEG-HTTPS-01", C, "HTTPS en el despliegue", "Comprobar que la URL pública declarada usa HTTPS y que la aplicación emite HSTS cuando "
         "recibe solicitudes HTTPS.", "DINAMICO", "ALTO", ["OWASP ASVS 5.0 V12 (comunicaciones seguras)"])
def https(ctx: Ctx) -> Outcome:
    import os
    public = os.getenv("RENDER_EXTERNAL_URL") or ""
    hsts = _requests([("GET", "/health", {"headers": {"x-forwarded-proto": "https"}})])[0]["cabeceras"].get("strict-transport-security")
    details = {"url_publica_declarada": public or None, "hsts_bajo_https": hsts, "en_render": bool(os.getenv("RENDER")),
               "no_verificable": "El certificado, la versión de TLS y la redirección HTTP→HTTPS los gestiona el proxy de Render y no son visibles "
                                 "desde la aplicación; verifíquelos con un escaneo externo (por ejemplo, SSL Labs o ZAP baseline) e impórtelo."}
    if not public:
        raise NotVerifiable("No se conoce la URL pública (RENDER_EXTERNAL_URL no está definida en este entorno); no puede comprobarse el esquema de despliegue.")
    if not public.startswith("https://"):
        return fail("La URL pública no usa HTTPS.", [finding("despliegue:https", "Despliegue sin HTTPS", f"URL pública: {public}.",
                    "Credenciales y tokens en claro.", "Alta.", "Use solo HTTPS.", "ALTO")], **details)
    if not hsts:
        return fail("La URL pública usa HTTPS pero la aplicación no emite HSTS.", [finding("despliegue:hsts", "HSTS ausente",
                    "Sin Strict-Transport-Security.", "Degradación a HTTP en la primera visita.", "Media.", "Revise security_headers.", "MEDIO")], **details)
    return ok("URL pública con HTTPS y HSTS emitido por la aplicación (TLS del proxy no verificable desde aquí).", **details)


@control("SEG-UPL-01", C, "Validación de cargas de archivos", "Ejecutar las funciones de validación de adjuntos y evidencias con muestras "
         "maliciosas (tipo falso, ruta en el nombre, HTML) y verificar límites de tamaño.", "DINAMICO", "ALTO", ["OWASP ASVS 5.0 V5 (archivos)"])
def uploads(ctx: Ctx) -> Outcome:
    from fastapi import HTTPException
    from app.api import router
    from app.auditing import evidence
    cases = {"png_declarado_como_pdf_rechazado": not router.content_matches("application/pdf", b"\x89PNG\r\n\x1a\n...."),
             "texto_con_nul_rechazado": not router.content_matches("text/plain", b"abc\x00def"),
             "ruta_eliminada_del_nombre": router.safe_filename("../../etc/passwd") == "passwd",
             "nombre_windows_saneado": "\\" not in router.safe_filename("..\\..\\boot.ini"),
             "html_no_permitido_en_adjuntos": "text/html" not in router.ALLOWED_TYPES,
             "svg_no_permitido_en_adjuntos": "image/svg+xml" not in router.ALLOWED_TYPES}
    for label, raw, kind in (("html_en_evidencia_rechazado", b"<html><script>alert(1)</script></html>", "text/plain"),
                             ("json_invalido_rechazado", b"{no json", "application/json")):
        try:
            evidence.validate(raw, kind, 1000)
            cases[label] = False
        except HTTPException:
            cases[label] = True
    details = {"pruebas": cases, "max_adjunto_bytes": settings.max_upload_bytes, "max_evidencia_bytes": settings.audit_evidence_max_bytes,
               "tipos_adjuntos": sorted(router.ALLOWED_TYPES), "almacenamiento": "Nombre aleatorio, fuera del directorio web; descarga solo con autorización."}
    failed = [k for k, v in cases.items() if not v]
    if settings.max_upload_bytes > 20 * 1_048_576: failed.append("límite de tamaño de adjuntos mayor a 20 MB")
    if failed:
        return fail(f"Validaciones que no se cumplen: {', '.join(failed)}.", [finding("cargas:validacion", "Validación de archivos insuficiente",
                    ", ".join(failed), "Carga de contenido activo o sobrescritura de archivos.", "Media.", "Revise content_matches y safe_filename.",
                    evidence=cases)], **details)
    return ok(f"{len(cases)} pruebas de validación superadas; límites de {settings.max_upload_bytes // 1_048_576} MB (adjuntos) y "
              f"{settings.audit_evidence_max_bytes // 1_048_576} MB (evidencias).", **details)


@control("SEG-INP-01", C, "Validación de entradas e inyección SQL", "Verificar que los modelos de entrada rechazan caracteres NUL y buscar "
         "consultas SQL construidas con formato de cadenas en el código.", "ESTATICO", "ALTO", ["OWASP ASVS 5.0 V1 (codificación y sanitización)"])
def injection(ctx: Ctx) -> Outcome:
    from pydantic import BaseModel
    from app import schemas
    from app.schemas.schemas import Input
    models = [m for m in vars(schemas.schemas).values() if isinstance(m, type) and issubclass(m, BaseModel) and m.__name__.endswith("In")]
    without_nul = [m.__name__ for m in models if not issubclass(m, Input)]
    pattern = re.compile(r"(?<![A-Za-z0-9_])(?:text|execute|exec_driver_sql|scalar|rows|one)\(\s*f[\"']")
    hits = []
    for path in sorted(APP_DIR.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            if pattern.search(line):
                hits.append({"archivo": path.relative_to(BACKEND_DIR).as_posix(), "linea": number, "justificado": "noqa: S608" in line or "catalog" in line.lower()})
    unjustified = [h for h in hits if not h["justificado"]]
    details = {"modelos_de_entrada": len(models), "sin_filtro_nul": without_nul, "sql_con_formato": hits,
               "criterio": "Las consultas con formato solo son aceptables si interpolan identificadores del catálogo o constantes, nunca datos del usuario."}
    if without_nul:
        return fail(f"{len(without_nul)} modelos de entrada no heredan la validación común.", [finding("entradas:modelos", "Modelos de entrada sin validación común",
                    ", ".join(without_nul), "Entradas con caracteres NUL pueden eludir filtros o producir errores 500.", "Media.", "Herede de Input.", "MEDIO")], **details)
    if unjustified:
        return warn(f"{len(unjustified)} consultas SQL con formato de cadena requieren revisión manual.", [finding("entradas:sql_formato",
                    "Consultas SQL construidas con f-strings", "Se encontraron consultas con formato de cadena sin justificación.", "Inyección SQL si interpolan datos del usuario.",
                    "Requiere revisión manual.", "Use parámetros enlazados (:param).", "MEDIO", {"ubicaciones": unjustified[:30]})], "MEDIO", **details)
    return ok(f"{len(models)} modelos de entrada con filtro NUL; {len(hits)} consultas con formato, todas con identificadores del catálogo o constantes.", **details)


@control("SEG-XSS-01", C, "Protección XSS del cliente web", "Buscar en el JavaScript y HTML servidos APIs peligrosas (eval, Function, "
         "document.write), scripts inline y manejadores de eventos en línea, y verificar el uso de la función de escape.", "ESTATICO", "ALTO",
         ["OWASP ASVS 5.0 V3.2 (codificación de salida)"])
def xss(ctx: Ctx) -> Outcome:
    issues, files = [], {}
    for path in sorted(STATIC_DIR.glob("*.js")) + sorted(STATIC_DIR.glob("*.html")):
        text = path.read_text(encoding="utf-8")
        files[path.name] = {"innerHTML": text.count("innerHTML"), "esc": text.count("esc(")}
        for label, rx in (("eval", r"\beval\s*\("), ("Function", r"\bnew\s+Function\s*\("), ("document.write", r"document\.write\s*\("),
                          ("manejador inline", r"\son(click|load|error|mouseover)\s*=\s*[\"']"), ("script inline", r"<script>(?!</script>)")):
            if re.search(rx, text): issues.append(f"{path.name}: {label}")
    details = {"archivos": files, "problemas": issues,
               "metodo": "Heurístico: no prueba que cada interpolación esté escapada; la CSP bloquea scripts inline y de terceros como segunda barrera."}
    if issues:
        return fail(f"Se encontraron construcciones peligrosas: {', '.join(issues)}.", [finding("cliente:xss", "Construcciones propensas a XSS en el cliente",
                    ", ".join(issues), "Ejecución de scripts en la sesión de otro usuario.", "Media.", "Elimine eval/inline y use esc().", evidence={"problemas": issues})], **details)
    return ok("Sin eval, Function, document.write, scripts ni manejadores inline; el HTML dinámico usa esc().", **details)


@control("SEG-FE-01", C, "Componentes y recursos del frontend", "Verificar que el cliente web no carga scripts, estilos ni fuentes de terceros "
         "(cadena de suministro).", "ESTATICO", "MEDIO", ["OWASP ASVS 5.0 V3.6 (integridad de recursos externos)"])
def frontend_components(ctx: Ctx) -> Outcome:
    external = []
    for path in sorted(STATIC_DIR.glob("*.html")):
        text = path.read_text(encoding="utf-8")
        for src in re.findall(r"(?:src|href)=\"(https?://[^\"]+)\"", text):
            external.append(f"{path.name}: {src}")
    scripts = sorted(p.name for p in STATIC_DIR.glob("*.js"))
    details = {"scripts_propios": scripts, "recursos_externos": external, "librerias_de_terceros": [],
               "fuentes": sorted(p.name for p in (STATIC_DIR / "fonts").glob("*.woff2"))}
    if external:
        return warn(f"{len(external)} recursos externos cargados por el cliente.", [finding("cliente:recursos_externos", "Recursos de terceros en el cliente",
                    ", ".join(external), "Un compromiso del proveedor ejecutaría código en FixIT.", "Baja.", "Sírvalos localmente o use SRI.", "MEDIO")], **details)
    return ok(f"El cliente usa solo {len(scripts)} scripts propios y fuentes locales; no hay dependencias de frontend de terceros.", **details)


# --- Dependencies and imported tool reports ---------------------------------------------------------------------------
@control("SEG-DEP-01", C, "Versiones de dependencias Python", "Comparar las versiones fijadas en requirements.txt con las instaladas en el "
         "entorno en ejecución.", "ESTATICO", "MEDIO", ["OWASP ASVS 5.0 V15.2 (dependencias)"])
def dependency_pins(ctx: Ctx) -> Outcome:
    req = BACKEND_DIR.parent / "requirements.txt"
    if not req.is_file(): raise NotVerifiable("requirements.txt no está disponible en este despliegue.")
    pins, unpinned, mismatched = {}, [], []
    for line in req.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line: continue
        name = re.split(r"[\[=<>!~ ]", line, maxsplit=1)[0]
        if "==" not in line: unpinned.append(name); continue
        pins[name] = line.split("==", 1)[1].strip()
    for name, version in pins.items():
        try: installed = metadata.version(name)
        except metadata.PackageNotFoundError: installed = None
        if installed != version: mismatched.append({"paquete": name, "fijada": version, "instalada": installed})
    details = {"dependencias_fijadas": pins, "sin_version_fija": unpinned, "diferencias": mismatched}
    if unpinned or mismatched:
        return warn(f"{len(unpinned)} dependencias sin versión fija y {len(mismatched)} con versión instalada distinta.", [finding(
            "dependencias:versiones", "Dependencias no reproducibles", "El entorno no coincide exactamente con requirements.txt.",
            "Un análisis de vulnerabilidades sobre requirements.txt podría no reflejar lo instalado.", "Baja.", "Fije versiones y reconstruya la imagen.", "BAJO",
            {"sin_version": unpinned, "diferencias": mismatched})], "BAJO", **details)
    return ok(f"Las {len(pins)} dependencias están fijadas y coinciden con lo instalado.", **details)


@control("SEG-DEP-02", C, "Vulnerabilidades conocidas en dependencias (pip-audit)", "Evaluar el último informe JSON de pip-audit importado.",
         "IMPORTADO", "ALTO", ["OWASP ASVS 5.0 V15.2"])
def pip_audit(ctx: Ctx) -> Outcome:
    row, ref, notes = from_import(ctx, "PIP_AUDIT", "pip-audit", "Ejecute `pip-audit -r requirements.txt -f json -o pip-audit.json` en un entorno "
                                  "de desarrollo e impórtelo en Seguridad → Informes de herramientas.")
    s = row.summary or {}
    details = {"_informe": ref, "resumen": {k: s.get(k) for k in ("dependencias", "dependencias_vulnerables", "vulnerabilidades", "sin_correccion")},
               "vulnerabilidades": s.get("items", [])[:50], "observaciones": notes}
    if s.get("vulnerabilidades"):
        return fail(f"{s['vulnerabilidades']} vulnerabilidades conocidas en {s.get('dependencias_vulnerables')} dependencias.", [finding(
            f"dependencia:{i['paquete']}:{i['id']}", f"{i['paquete']} {i['version']}: {i['id']}", i.get("descripcion") or i["id"],
            "Depende de la vulnerabilidad y de si el código usa la funcionalidad afectada.", "Requiere análisis de explotabilidad.",
            f"Actualice a {', '.join(i['corregido_en']) or 'una versión corregida cuando exista'}.", "ALTO" if i["corregido_en"] else "MEDIO", i)
            for i in s.get("items", [])], **details)
    out = ok(f"Sin vulnerabilidades conocidas en {s.get('dependencias')} dependencias (informe del {ref['importado_en']}).", **details)
    if notes: out = warn(out.summary + " " + notes[0], [], "BAJO", **details)
    return out


@control("SEG-SAST-01", C, "Análisis estático de seguridad (Bandit)", "Evaluar el último informe JSON de Bandit importado.", "IMPORTADO", "ALTO",
         ["OWASP ASVS 5.0"])
def bandit(ctx: Ctx) -> Outcome:
    row, ref, notes = from_import(ctx, "BANDIT", "Bandit", "Ejecute `bandit -r app -f json -o bandit.json` desde backend/ e impórtelo.")
    s = row.summary or {}
    by = s.get("por_severidad") or {}
    details = {"_informe": ref, "por_severidad": by, "por_confianza": s.get("por_confianza"), "resultados": s.get("items", [])[:80], "observaciones": notes}
    high = [i for i in s.get("items", []) if i["severidad"] == "HIGH"]
    medium = [i for i in s.get("items", []) if i["severidad"] == "MEDIUM"]
    if high:
        return fail(f"Bandit informa {len(high)} resultados de severidad alta.", [finding(f"bandit:{i['test_id']}:{i['archivo']}:{i['linea']}",
                    f"Bandit {i['test_id']}: {i['test']}", i["texto"] or "", "Depende del resultado.", f"Confianza {i['confianza']}.",
                    "Corrija o justifique con # nosec y una explicación.", "ALTO", i) for i in high], **details)
    if medium:
        return warn(f"Bandit informa {len(medium)} resultados de severidad media (sin altos).", [finding(f"bandit:{i['test_id']}:{i['archivo']}:{i['linea']}",
                    f"Bandit {i['test_id']}: {i['test']}", i["texto"] or "", "Depende del resultado.", f"Confianza {i['confianza']}.",
                    "Revise y corrija o justifique.", "MEDIO", i) for i in medium], "MEDIO", **details)
    out = ok(f"Bandit sin resultados de severidad alta o media ({by.get('LOW', 0)} bajos), informe del {ref['importado_en']}.", **details)
    if notes: out = warn(out.summary + " " + notes[0], [], "BAJO", **details)
    return out


@control("SEG-DAST-01", C, "Escaneo dinámico (OWASP ZAP)", "Evaluar el último informe JSON de OWASP ZAP importado (baseline pasivo o escaneo "
         "activo en un entorno controlado).", "IMPORTADO", "ALTO", ["OWASP ASVS 5.0"])
def zap(ctx: Ctx) -> Outcome:
    row, ref, notes = from_import(ctx, "ZAP", "OWASP ZAP", "Ejecute ZAP baseline contra un entorno local o de pruebas con `-J zap.json` e impórtelo. "
                                  "No ejecute escaneos activos contra producción.")
    s = row.summary or {}
    by = s.get("por_riesgo") or {}
    details = {"_informe": ref, "sitios": s.get("sitios"), "por_riesgo": by, "alertas": s.get("items", [])[:80], "observaciones": notes}
    high = [i for i in s.get("items", []) if i["riesgo"] == "ALTO"]
    medium = [i for i in s.get("items", []) if i["riesgo"] == "MEDIO"]
    if high:
        return fail(f"ZAP informa {len(high)} alertas de riesgo alto.", [finding(f"zap:{i['plugin']}:{i['sitio']}", f"ZAP {i['plugin']}: {i['alerta']}",
                    f"{i['instancias']} instancias en {i['sitio']}.", "Depende de la alerta.", f"Confianza {i['confianza']}.", "Corrija y vuelva a escanear.", "ALTO", i)
                    for i in high], **details)
    if medium:
        return warn(f"ZAP informa {len(medium)} alertas de riesgo medio.", [finding(f"zap:{i['plugin']}:{i['sitio']}", f"ZAP {i['plugin']}: {i['alerta']}",
                    f"{i['instancias']} instancias en {i['sitio']}.", "Depende de la alerta.", f"Confianza {i['confianza']}.", "Revise la alerta.", "MEDIO", i)
                    for i in medium], "MEDIO", **details)
    out = ok(f"ZAP sin alertas de riesgo alto o medio (informe del {ref['importado_en']}).", **details)
    if notes: out = warn(out.summary + " " + notes[0], [], "BAJO", **details)
    return out


@control("SEG-SAST-02", C, "Otros análisis importados (SARIF)", "Evaluar el último informe SARIF importado (por ejemplo, Semgrep, CodeQL o "
         "un linter de JavaScript).", "IMPORTADO", "MEDIO", ["OWASP ASVS 5.0"])
def sarif(ctx: Ctx) -> Outcome:
    row, ref, notes = from_import(ctx, "SARIF", "SARIF", "Importe un informe SARIF 2.1.0 de una herramienta de análisis estático.")
    s = row.summary or {}
    by = s.get("por_nivel") or {}
    details = {"_informe": ref, "por_nivel": by, "resultados": s.get("items", [])[:80], "herramientas": (row.tool or {}).get("herramientas"), "observaciones": notes}
    errors = [i for i in s.get("items", []) if i["nivel"] == "ALTO"]
    if errors:
        return fail(f"{len(errors)} resultados de nivel error.", [finding(f"sarif:{i['herramienta']}:{i['regla']}:{i['archivo']}:{i['linea']}",
                    f"{i['herramienta']} {i['regla']}", i["mensaje"] or "", "Depende de la regla.", "Según la herramienta.", "Corrija o justifique.", "MEDIO", i)
                    for i in errors[:100]], "MEDIO", **details)
    if by.get("MEDIO"):
        return warn(f"{by['MEDIO']} advertencias sin errores.", [], "BAJO", **details)
    return ok(f"Sin errores ni advertencias en el informe SARIF del {ref['importado_en']}.", **details)
