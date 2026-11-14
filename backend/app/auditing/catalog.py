"""Static vocabulary of the audit center: categories, statuses, verification methods, reference criteria and the
finding life cycle. Labels are Spanish (shown in the UI and reports); codes are stable identifiers stored in the DB."""
from app.models.audit_center import CONTROL_STATUSES, FINDING_STATUSES, SEVERITIES

ENGINE_VERSION = "1.0"

CATEGORIES = {
    "BASE_DATOS": {"label": "Base de datos", "slug": "bd", "prefix": "BD",
                   "description": "Estructura, integridad, seguridad (RLS, privilegios, funciones) y actividad SQL de PostgreSQL."},
    "SEGURIDAD": {"label": "Seguridad de la aplicación", "slug": "seguridad", "prefix": "SEG",
                  "description": "Autenticación, autorización, JWT, cabeceras HTTP, validación de entradas, cargas, dependencias y secretos."},
    "ACCESOS": {"label": "Usuarios y accesos", "slug": "accesos", "prefix": "ACC",
                "description": "Cuentas, roles, privilegios, accesos exitosos y fallidos, acciones administrativas y cuentas huérfanas."},
    "PROCESOS": {"label": "Procesos operativos", "slug": "procesos", "prefix": "OPE",
                 "description": "Ciclo de vida de tickets, asignaciones, SLA, tiempos, calificaciones y trazabilidad operativa."},
    "REGISTROS": {"label": "Registros y trazabilidad", "slug": "registros", "prefix": "REG",
                  "description": "Sellos HMAC, inmutabilidad, continuidad y calidad de la auditoría de actividad y de sus exportaciones."},
    "INFRAESTRUCTURA": {"label": "Infraestructura y disponibilidad", "slug": "infraestructura", "prefix": "INF",
                        "description": "API, conexión a la base, migraciones, configuración de producción, servicios internos y errores."},
    "PRIVACIDAD": {"label": "Privacidad y cumplimiento", "slug": "privacidad", "prefix": "PRI",
                   "description": "Términos, aviso de privacidad, aceptaciones, acceso a datos personales, conservación y derechos (Ley N.º 29733)."},
    "CONTINUIDAD": {"label": "Continuidad y recuperación", "slug": "continuidad", "prefix": "CON",
                    "description": "Respaldos, restauración, pruebas de recuperación, dependencias críticas y riesgos de pérdida de datos."},
}

STATUS_LABELS = {"APROBADO": "Aprobado", "FALLIDO": "Fallido", "ADVERTENCIA": "Advertencia", "NO_APLICABLE": "No aplicable",
                 "NO_VERIFICADO": "No verificado", "ERROR_EJECUCION": "Error de ejecución"}
STATUS_MEANING = {
    "APROBADO": "La comprobación se ejecutó y el resultado cumple el criterio.",
    "FALLIDO": "La comprobación se ejecutó y el resultado incumple el criterio.",
    "ADVERTENCIA": "La comprobación se ejecutó; el resultado no incumple el criterio, pero requiere revisión o tiene una limitación.",
    "NO_APLICABLE": "El control no corresponde a este entorno (por ejemplo, requiere PostgreSQL y la base es SQLite).",
    "NO_VERIFICADO": "La comprobación no pudo realizarse (permisos, falta de evidencia, información no accesible o ejecución interrumpida). "
                     "Nunca equivale a aprobado.",
    "ERROR_EJECUCION": "La comprobación falló por un error técnico; su resultado es desconocido.",
}
if set(STATUS_LABELS) != set(CONTROL_STATUSES): raise RuntimeError("STATUS_LABELS no coincide con CONTROL_STATUSES")

SEVERITY_LABELS = {"CRITICO": "Crítico", "ALTO": "Alto", "MEDIO": "Medio", "BAJO": "Bajo", "INFORMATIVO": "Informativo"}
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
if set(SEVERITY_LABELS) != set(SEVERITIES): raise RuntimeError("SEVERITY_LABELS no coincide con SEVERITIES")

METHODS = {
    "SQL": "Consulta de solo lectura al catálogo o a los datos de la base (automática).",
    "ESTATICO": "Inspección del código, la configuración o las rutas de la aplicación sin ejecutarla (automática).",
    "DINAMICO": "Solicitud real procesada dentro del propio proceso (sin tráfico externo ni efectos sobre los datos).",
    "ESTADISTICO": "Análisis estadístico de datos operativos; produce señales de riesgo, no pruebas.",
    "IMPORTADO": "Resultado obtenido de un informe externo importado (Bandit, pip-audit, OWASP ZAP, SARIF, logs exportados).",
    "MANUAL": "Declaración de una persona respaldada por evidencia adjunta (por ejemplo, capturas del panel del proveedor).",
}

FINDING_LABELS = {"ABIERTO": "Abierto", "EN_REVISION": "En revisión", "EN_CORRECCION": "En corrección",
                  "CORREGIDO_PENDIENTE_VERIFICACION": "Corregido, pendiente de verificación", "CERRADO": "Cerrado",
                  "RIESGO_ACEPTADO": "Riesgo aceptado", "FALSO_POSITIVO": "Falso positivo"}
if set(FINDING_LABELS) != set(FINDING_STATUSES): raise RuntimeError("FINDING_LABELS no coincide con FINDING_STATUSES")
OPEN_FINDING_STATUSES = ("ABIERTO", "EN_REVISION", "EN_CORRECCION", "CORREGIDO_PENDIENTE_VERIFICACION")
# Allowed manual transitions. CERRADO additionally requires correction evidence and, for automatic controls, a later run
# in which the finding was not reproduced (see app.auditing.findings).
TRANSITIONS = {
    "ABIERTO": {"EN_REVISION", "EN_CORRECCION", "RIESGO_ACEPTADO", "FALSO_POSITIVO"},
    "EN_REVISION": {"ABIERTO", "EN_CORRECCION", "RIESGO_ACEPTADO", "FALSO_POSITIVO"},
    "EN_CORRECCION": {"EN_REVISION", "CORREGIDO_PENDIENTE_VERIFICACION"},
    "CORREGIDO_PENDIENTE_VERIFICACION": {"EN_CORRECCION", "CERRADO"},
    "CERRADO": {"ABIERTO"},
    "RIESGO_ACEPTADO": {"EN_REVISION", "ABIERTO"},
    "FALSO_POSITIVO": {"EN_REVISION"},
}
# What a TECNICO may do on a finding assigned to them.
TECHNICIAN_TRANSITIONS = {("ABIERTO", "EN_CORRECCION"), ("EN_REVISION", "EN_CORRECCION"),
                          ("EN_CORRECCION", "CORREGIDO_PENDIENTE_VERIFICACION")}

RUN_LABELS = {"PENDIENTE": "Pendiente", "EN_CURSO": "En curso", "COMPLETADA": "Completada",
              "COMPLETADA_CON_ERRORES": "Completada con errores", "CANCELADA": "Cancelada", "INTERRUMPIDA": "Interrumpida"}
RESULT_LABELS = {"FAVORABLE": "Favorable", "CON_OBSERVACIONES": "Con observaciones", "DESFAVORABLE": "Desfavorable",
                 "NO_CONCLUYENTE": "No concluyente"}
RESULT_MEANING = {
    "FAVORABLE": "Todos los controles ejecutados se aprobaron y menos de la mitad quedó sin verificar.",
    "CON_OBSERVACIONES": "Hay controles fallidos de severidad media o baja, o advertencias que requieren revisión.",
    "DESFAVORABLE": "Al menos un control fallido tiene severidad crítica o alta.",
    "NO_CONCLUYENTE": "Ningún control pudo ejecutarse o más de la mitad quedó sin verificar o con error.",
}

# Reference frameworks. They inspire the controls; FixIT does not hold any certification against them.
REFERENCES = {
    "ASVS": {"name": "OWASP Application Security Verification Standard 5.0", "url": "https://asvs.owasp.org/"},
    "OWASP_LOG": {"name": "OWASP Logging Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"},
    "NIST_800_92": {"name": "NIST SP 800-92, Guide to Computer Security Log Management", "url": "https://csrc.nist.gov/pubs/sp/800/92/final"},
    "CIS_PG": {"name": "CIS PostgreSQL Benchmark (controles aplicables a un servicio administrado)", "url": "https://www.cisecurity.org/benchmark/postgresql"},
    "ISO_19011": {"name": "ISO 19011:2018, Directrices para la auditoría de sistemas de gestión", "url": "https://www.iso.org/standard/70017.html"},
    "LPDP": {"name": "Ley N.º 29733, Ley de Protección de Datos Personales (Perú), y su reglamento vigente",
             "url": None},  # consult the official text published by MINJUSDH / El Peruano
    "SUPABASE_PGAUDIT": {"name": "Supabase: extensión pgAudit", "url": "https://supabase.com/docs/guides/database/extensions/pgaudit"},
    "SUPABASE_LOGS": {"name": "Supabase: configuración de registros", "url": "https://supabase.com/docs/guides/observability/configure-logging"},
    "SUPABASE_RLS": {"name": "Supabase: Row Level Security", "url": "https://supabase.com/docs/guides/database/postgres/row-level-security"},
}

METHODOLOGY = [
    "Planificación: se definen nombre, categorías, controles, periodo de evaluación y alcance (ISO 19011, cláusula 6.3).",
    "Ejecución: cada control se ejecuta de forma aislada, con una conexión de solo lectura y un límite de tiempo; su resultado, "
    "evidencia, método y privilegios utilizados se registran.",
    "Evaluación: los resultados FALLIDO y ADVERTENCIA generan o actualizan hallazgos deduplicados por control y recurso afectado.",
    "Informe: los informes ejecutivo y técnico se generan a partir de los resultados almacenados; el paquete ZIP incluye un "
    "manifiesto con el SHA-256 de cada archivo.",
    "Seguimiento: cada hallazgo tiene responsable, fecha límite, plan de acción, evidencias e historial; su cierre requiere evidencia "
    "de corrección y, cuando el control es automático, una nueva ejecución en la que no se reproduzca.",
]

LIMITATIONS = [
    "La auditoría solo examina lo que la aplicación puede ver con su conexión: la configuración de los paneles de Render y "
    "Supabase, la red y el sistema operativo del proveedor no son accesibles y se marcan como NO VERIFICADO salvo evidencia manual.",
    "La actividad SQL histórica solo puede revisarse si pgAudit u otro registro estaba habilitado en su momento; no se reconstruye.",
    "Los controles estáticos y heurísticos inspeccionan el código desplegado; no sustituyen una revisión manual ni una prueba de penetración.",
    "Las señales estadísticas o de Machine Learning indican casos para revisar; no prueban una irregularidad.",
    "Las referencias (OWASP ASVS, NIST SP 800-92, CIS, ISO 19011, Ley N.º 29733) inspiran los controles; su uso no implica "
    "certificación ni cumplimiento legal pleno.",
]
