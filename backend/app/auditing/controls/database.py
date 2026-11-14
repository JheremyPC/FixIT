"""Category BASE_DATOS: PostgreSQL structure, security and SQL activity (Supabase compatible).

Only catalog queries (pg_catalog, information_schema, SQLAlchemy inspector) and COUNT queries are executed, inside a
read-only transaction. No query returns the contents of business tables. Objects in schemas managed by Supabase (auth,
storage, realtime...) are outside the scope and are only counted.
"""
from __future__ import annotations

from sqlalchemy import inspect as sa_inspect
from sqlalchemy import DateTime, String

from app.auditing.controls.common import app_tables, finding, from_import, iso
from app.auditing.registry import Ctx, NotVerifiable, Outcome, control, fail, not_applicable, ok, warn
from app.core.database import Base
from app.models import AUDIT_CENTER_TABLES, AuditExternalLog

C = "BASE_DATOS"
PG = ("postgresql",)
# Tables that exist in the deployed database on purpose without being FixIT models.
KNOWN_EXTERNAL = {"alembic_version": "Versión de migraciones de Alembic",
                  "automation_events": "Cola de eventos de automatización creada en Supabase fuera de Alembic (migración 0002)"}
# Columns named *_id that intentionally have no foreign key.
POLYMORPHIC = {("audit_logs", "entity_id"): "Identificador polimórfico (la entidad varía según el módulo)",
               ("agent_states", "lock_run_id"): "Bloqueo temporal; la ejecución puede no existir todavía",
               ("audit_reports", "audit_log_id"): "Referencia informativa al registro de auditoría (tabla de solo inserción)",
               ("audit_external_logs", "session_id"): "Identificador de sesión de PostgreSQL, no de FixIT"}
SENSITIVE = {"users", "audit_logs", "terms_acceptances", "ml_artifacts", "settings", "automation_events", "tickets", "ticket_comments",
             "ticket_attachments", "ticket_history", "notifications", "ratings", "llm_calls", "agent_runs", *AUDIT_CENTER_TABLES}
PROVIDER_SCHEMAS = ("pg_catalog", "information_schema", "pg_toast", "auth", "storage", "realtime", "extensions", "graphql", "graphql_public",
                    "vault", "pgsodium", "pgsodium_masks", "net", "supabase_functions", "supabase_migrations", "cron", "pgbouncer",
                    "_realtime", "_analytics", "pgtle", "topology", "tiger")
EXPOSED_ROLES = ("anon", "authenticated")
ASVS_DB = ["OWASP ASVS 5.0 V13 (configuración) y V8 (autorización)", "CIS PostgreSQL Benchmark (privilegios y registro)"]


def _model_tables():
    app_tables()
    return {t.name: t for t in Base.metadata.sorted_tables}


def _q(name: str) -> str:
    """Quoted identifier from the catalog (never user input)."""
    return '"' + name.replace('"', '""') + '"'


def _exposed_roles(ctx: Ctx) -> list[str]:
    return [r["rolname"] for r in ctx.rows("SELECT rolname FROM pg_roles WHERE rolname = ANY(:r)", r=list(EXPOSED_ROLES))]


def _relations(ctx: Ctx) -> list[dict]:
    return ctx.rows("""SELECT c.oid, c.relname, c.relkind, c.relrowsecurity AS rls, c.relforcerowsecurity AS force_rls,
                              pg_get_userbyid(c.relowner) AS owner, GREATEST(c.reltuples, 0)::bigint AS filas_estimadas
                       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                       WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') ORDER BY c.relname""")


# --- Structure ------------------------------------------------------------------------------------------------------
@control("BD-EST-01", C, "Inventario y coherencia del esquema", "Comprobar que el esquema desplegado contiene exactamente las tablas y "
         "columnas que define FixIT e identificar objetos no gestionados por la aplicación.", "SQL", "ALTO", ASVS_DB)
def schema_inventory(ctx: Ctx) -> Outcome:
    insp = sa_inspect(ctx.conn)
    models = _model_tables()
    db_tables = set(insp.get_table_names())
    missing = sorted(set(models) - db_tables)
    unexpected = sorted(db_tables - set(models) - set(KNOWN_EXTERNAL))
    missing_cols, extra_cols = [], []
    for name in sorted(set(models) & db_tables):
        db_cols = {c["name"] for c in insp.get_columns(name)}
        model_cols = {c.name for c in models[name].columns}
        missing_cols += [f"{name}.{c}" for c in sorted(model_cols - db_cols)]
        extra_cols += [f"{name}.{c}" for c in sorted(db_cols - model_cols)]
    details = {"tablas_en_base": len(db_tables), "tablas_en_modelos": len(models), "faltantes": missing, "columnas_faltantes": missing_cols,
               "columnas_adicionales": extra_cols, "objetos_externos_conocidos": {k: v for k, v in KNOWN_EXTERNAL.items() if k in db_tables},
               "objetos_inesperados": unexpected}
    if ctx.pg:
        kinds = ctx.rows("""SELECT c.relkind AS tipo, count(*) AS total FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                            WHERE n.nspname = current_schema() GROUP BY c.relkind""")
        names = {"r": "tablas", "p": "tablas_particionadas", "v": "vistas", "m": "vistas_materializadas", "S": "secuencias", "i": "indices",
                 "f": "tablas_externas", "c": "tipos_compuestos", "t": "toast"}
        details["objetos_por_tipo"] = {names.get(k["tipo"], k["tipo"]): k["total"] for k in kinds}
        details["funciones"] = ctx.scalar("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = current_schema()")
        details["triggers"] = ctx.scalar("""SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
                                            JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND NOT t.tgisinternal""")
        details["esquemas_del_proveedor_fuera_de_alcance"] = [r["nspname"] for r in ctx.rows(
            "SELECT nspname FROM pg_namespace WHERE nspname = ANY(:s) ORDER BY 1", s=list(PROVIDER_SCHEMAS[3:]))]
    findings = []
    if missing or missing_cols:
        findings.append(finding("esquema:faltantes", "Tablas o columnas de FixIT ausentes en la base de datos",
                                f"Faltan {len(missing)} tablas y {len(missing_cols)} columnas definidas por los modelos.",
                                "Las funciones que dependen de esos objetos fallan o pierden datos.",
                                "Comprobado directamente en el catálogo de la base.", "Ejecute `alembic upgrade head` y revise migraciones pendientes.",
                                "ALTO", {"tablas": missing, "columnas": missing_cols[:50]}))
        return fail("Faltan objetos del esquema de FixIT en la base de datos.", findings, "ALTO", **details)
    if unexpected or extra_cols:
        findings.append(finding("esquema:inesperados", "Objetos de base de datos no gestionados por FixIT",
                                f"Hay {len(unexpected)} tablas y {len(extra_cols)} columnas que no están en los modelos ni en la lista de objetos conocidos.",
                                "Objetos sin dueño claro pueden quedar sin RLS, sin respaldo o con datos no controlados.",
                                "Depende de quién creó los objetos; requiere revisión.", "Documente su propósito o elimínelos mediante una migración revisada.",
                                "BAJO", {"tablas": unexpected, "columnas": extra_cols[:50]}))
        return warn(f"Esquema completo; {len(unexpected)} tablas y {len(extra_cols)} columnas no gestionadas por FixIT.", findings, "BAJO", **details)
    return ok(f"Las {len(models)} tablas de FixIT y sus columnas existen; no hay objetos inesperados.", **details)


@control("BD-EST-02", C, "Tablas sin clave primaria", "Detectar tablas sin clave primaria, que impiden identificar filas de forma única.",
         "SQL", "MEDIO", ASVS_DB)
def primary_keys(ctx: Ctx) -> Outcome:
    insp = sa_inspect(ctx.conn)
    tables = insp.get_table_names()
    without = [t for t in tables if not (insp.get_pk_constraint(t) or {}).get("constrained_columns")]
    if without:
        return fail(f"{len(without)} tablas no tienen clave primaria.", [finding(f"tabla:{t}", f"Tabla sin clave primaria: {t}",
                    f"La tabla «{t}» no define clave primaria.", "Riesgo de filas duplicadas y de actualizaciones o replicación ambiguas.",
                    "Comprobado en el catálogo.", "Defina una clave primaria mediante una migración.") for t in without],
                    tablas_revisadas=len(tables), sin_clave=without)
    return ok(f"Las {len(tables)} tablas del esquema tienen clave primaria.", tablas_revisadas=len(tables))


@control("BD-EST-03", C, "Integridad referencial declarada", "Verificar que cada relación definida por los modelos tiene su clave foránea "
         "en la base y que no hay restricciones sin validar.", "SQL", "MEDIO", ASVS_DB)
def foreign_keys(ctx: Ctx) -> Outcome:
    insp = sa_inspect(ctx.conn)
    models = _model_tables()
    db_tables = set(insp.get_table_names())
    missing, unreferenced = [], []
    for name, table in models.items():
        if name not in db_tables: continue
        declared = {(fk["constrained_columns"][0], fk["referred_table"]) for fk in insp.get_foreign_keys(name) if fk["constrained_columns"]}
        for column in table.columns:
            for fk in column.foreign_keys:
                if (column.name, fk.column.table.name) not in declared:
                    missing.append(f"{name}.{column.name} → {fk.column.table.name}")
            if column.name.endswith("_id") and not column.foreign_keys and not column.primary_key:
                unreferenced.append({"columna": f"{name}.{column.name}", "motivo": POLYMORPHIC.get((name, column.name), "Sin justificación registrada")})
    not_valid = []
    if ctx.pg:
        not_valid = [f"{r['tabla']}.{r['restriccion']}" for r in ctx.rows(
            """SELECT c.relname AS tabla, k.conname AS restriccion FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
               JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND NOT k.convalidated""")]
    unjustified = [u["columna"] for u in unreferenced if u["motivo"] == "Sin justificación registrada"]
    details = {"relaciones_sin_clave_foranea": missing, "columnas_id_sin_relacion": unreferenced, "restricciones_sin_validar": not_valid}
    if missing:
        return fail(f"{len(missing)} relaciones de los modelos no tienen clave foránea en la base.", [finding(
            "relaciones:faltantes", "Relaciones sin integridad referencial en la base",
            "Los modelos declaran relaciones que la base de datos no impone.", "Pueden existir filas huérfanas (por ejemplo, tickets de usuarios inexistentes).",
            "Comprobado en el catálogo; BD-EST-07 cuantifica las filas huérfanas.", "Cree las claves foráneas mediante una migración tras sanear los datos.",
            evidence={"relaciones": missing[:50]})], **details)
    if not_valid or unjustified:
        return warn("Las relaciones de los modelos existen; hay restricciones sin validar o columnas *_id sin relación justificada.", [finding(
            "relaciones:revision", "Restricciones sin validar o columnas de referencia sin clave foránea",
            "Hay restricciones creadas con NOT VALID o columnas *_id sin clave foránea ni justificación.",
            "Los datos existentes podrían no cumplir la restricción.", "Comprobado en el catálogo.",
            "Ejecute VALIDATE CONSTRAINT o documente la excepción.", "BAJO", {"sin_validar": not_valid, "sin_relacion": unjustified})], **details)
    return ok("Todas las relaciones de los modelos tienen clave foránea; las columnas *_id sin relación están justificadas.", **details)


@control("BD-EST-04", C, "Índices en claves foráneas", "Identificar claves foráneas sin índice en tablas con volumen suficiente para "
         "afectar consultas y eliminaciones.", "SQL", "BAJO", ["CIS PostgreSQL Benchmark (rendimiento operativo)"], requires=PG)
def fk_indexes(ctx: Ctx) -> Outcome:
    threshold = int(ctx.option("filas_minimas_indice", 1000))
    rows = ctx.rows("""
        SELECT c.relname AS tabla, a.attname AS columna, GREATEST(c.reltuples, 0)::bigint AS filas,
               EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = k.conrelid AND i.indkey[0] = k.conkey[1]) AS indexada
        FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
        WHERE k.contype = 'f' AND n.nspname = current_schema() ORDER BY 1, 2""")
    missing = [r for r in rows if not r["indexada"]]
    relevant = [r for r in missing if r["filas"] >= threshold]
    details = {"claves_foraneas": len(rows), "sin_indice": [f"{r['tabla']}.{r['columna']} (~{r['filas']} filas)" for r in missing],
               "criterio": f"Se señala solo si la tabla tiene al menos {threshold} filas estimadas: en tablas pequeñas un índice no aporta."}
    if relevant:
        return warn(f"{len(relevant)} claves foráneas sin índice en tablas con ≥{threshold} filas.", [finding(
            f"indice:{r['tabla']}.{r['columna']}", f"Clave foránea sin índice: {r['tabla']}.{r['columna']}",
            f"La columna {r['tabla']}.{r['columna']} referencia otra tabla y no tiene índice; la tabla tiene ~{r['filas']} filas.",
            "Las consultas por esa relación y las eliminaciones en la tabla referida requieren recorridos completos.",
            "El impacto crece con el volumen; verifíquelo con EXPLAIN en las consultas habituales.",
            f"Evalúe CREATE INDEX CONCURRENTLY sobre {r['tabla']}({r['columna']}) si las consultas lo justifican.") for r in relevant], **details)
    return ok("Las claves foráneas de tablas con volumen relevante tienen índice.", **details)


@control("BD-EST-05", C, "Índices duplicados o redundantes", "Detectar índices idénticos o cuyo prefijo está cubierto por otro índice.",
         "SQL", "BAJO", ["CIS PostgreSQL Benchmark (mantenimiento)"], requires=PG)
def redundant_indexes(ctx: Ctx) -> Outcome:
    rows = ctx.rows("""
        SELECT c.relname AS tabla, ic.relname AS indice, i.indisunique AS unico, i.indisprimary AS primario,
               i.indkey::text AS columnas, (i.indpred IS NOT NULL OR i.indexprs IS NOT NULL) AS especial,
               pg_relation_size(i.indexrelid) AS bytes
        FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid JOIN pg_class ic ON ic.oid = i.indexrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() ORDER BY 1, 2""")
    by_table: dict[str, list[dict]] = {}
    for r in rows:
        if not r["especial"]: by_table.setdefault(r["tabla"], []).append(r)
    issues = []
    for table, indexes in by_table.items():
        for a in indexes:
            cols_a = a["columnas"].split()
            for b in indexes:
                if a is b or a["unico"] or a["primario"]: continue
                cols_b = b["columnas"].split()
                if cols_a == cols_b and (b["unico"] or b["primario"] or a["indice"] > b["indice"]):
                    issues.append({"tabla": table, "indice": a["indice"], "cubierto_por": b["indice"], "tipo": "duplicado", "bytes": a["bytes"]})
                    break
                if len(cols_a) < len(cols_b) and cols_b[:len(cols_a)] == cols_a:
                    issues.append({"tabla": table, "indice": a["indice"], "cubierto_por": b["indice"], "tipo": "prefijo", "bytes": a["bytes"]})
                    break
    details = {"indices_revisados": len(rows), "redundantes": issues,
               "criterio": "Un índice no único es redundante si otro índice tiene las mismas columnas o las empieza igual. "
                           "Se excluyen índices parciales o de expresiones."}
    if issues:
        return warn(f"{len(issues)} índices potencialmente redundantes.", [finding(
            f"indice:{i['tabla']}.{i['indice']}", f"Índice {i['tipo']}: {i['indice']}",
            f"El índice {i['indice']} de {i['tabla']} está cubierto por {i['cubierto_por']}.",
            "Ocupa espacio y encarece las escrituras sin mejorar las consultas.", "Comprobado en el catálogo.",
            "Confirme con pg_stat_user_indexes que no se usa y elimínelo con DROP INDEX CONCURRENTLY mediante una migración.",
            evidence=i) for i in issues], **details)
    return ok(f"Sin índices duplicados ni redundantes entre {len(rows)} índices.", **details)


@control("BD-EST-06", C, "Tipos de datos y restricciones", "Comparar tipos, longitudes, nulabilidad, unicidad y restricciones CHECK de los "
         "modelos con la base desplegada.", "SQL", "MEDIO", ASVS_DB)
def types_and_constraints(ctx: Ctx) -> Outcome:
    insp = sa_inspect(ctx.conn)
    models = _model_tables()
    db_tables = set(insp.get_table_names())
    issues = []
    for name, table in models.items():
        if name not in db_tables: continue
        db_cols = {c["name"]: c for c in insp.get_columns(name)}
        for column in table.columns:
            db = db_cols.get(column.name)
            if not db: continue
            if not column.nullable and db["nullable"] and not column.primary_key:
                issues.append(f"{name}.{column.name}: NOT NULL en el modelo, admite NULL en la base")
            if isinstance(column.type, DateTime) and column.type.timezone and ctx.pg and not getattr(db["type"], "timezone", False):
                issues.append(f"{name}.{column.name}: debería ser TIMESTAMP WITH TIME ZONE")
            if isinstance(column.type, String) and column.type.length and getattr(db["type"], "length", None) and db["type"].length < column.type.length:
                issues.append(f"{name}.{column.name}: longitud {db['type'].length} en la base, {column.type.length} en el modelo")
        checks = {c.get("name") for c in insp.get_check_constraints(name)} if ctx.pg else None
        for constraint in table.constraints:
            kind = type(constraint).__name__
            if kind == "CheckConstraint" and checks is not None and constraint.name and constraint.name not in checks:
                issues.append(f"{name}: falta la restricción CHECK {constraint.name}")
        uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints(name)} | {
            tuple(i["column_names"]) for i in insp.get_indexes(name) if i.get("unique")}
        uniques |= {tuple((insp.get_pk_constraint(name) or {}).get("constrained_columns") or ())}
        for column in table.columns:
            if column.unique and (column.name,) not in uniques:
                issues.append(f"{name}.{column.name}: UNIQUE en el modelo, sin restricción única en la base")
    details = {"diferencias": issues}
    if issues:
        return warn(f"{len(issues)} diferencias de tipos o restricciones entre modelos y base.", [finding(
            "tipos:diferencias", "Diferencias de tipos o restricciones entre los modelos y la base",
            "La base no impone todas las reglas que asume la aplicación.", "Datos inválidos podrían almacenarse sin error.",
            "Comprobado en el catálogo.", "Alinee el esquema con una migración revisada.", evidence={"diferencias": issues[:80]})], **details)
    return ok("Tipos, longitudes, nulabilidad, unicidad y restricciones CHECK coinciden con los modelos.", **details)


@control("BD-EST-07", C, "Filas huérfanas en relaciones", "Contar filas cuya referencia no existe en relaciones no garantizadas por la base "
         "(claves foráneas ausentes, sin validar o no aplicadas por SQLite).", "SQL", "ALTO", ASVS_DB)
def orphans(ctx: Ctx) -> Outcome:
    insp = sa_inspect(ctx.conn)
    models = _model_tables()
    db_tables = set(insp.get_table_names())
    enforced = set()
    if ctx.pg:
        enforced = {(r["tabla"], r["columna"]) for r in ctx.rows("""
            SELECT c.relname AS tabla, a.attname AS columna FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
            WHERE k.contype = 'f' AND k.convalidated AND n.nspname = current_schema()""")}
    checked, results = 0, []
    for name, table in models.items():
        if name not in db_tables: continue
        for column in table.columns:
            for fk in column.foreign_keys:
                if (name, column.name) in enforced: continue
                parent = fk.column.table.name
                if parent not in db_tables: continue
                # Identifiers come from the model metadata and are quoted by _q(); no user input reaches this query.
                count = ctx.scalar(f"SELECT count(*) FROM {_q(name)} c WHERE c.{_q(column.name)} IS NOT NULL AND NOT EXISTS "  # noqa: S608  # nosec B608
                                   f"(SELECT 1 FROM {_q(parent)} p WHERE p.{_q(fk.column.name)} = c.{_q(column.name)})")
                checked += 1
                if count: results.append({"relacion": f"{name}.{column.name} → {parent}", "filas_huerfanas": count})
    details = {"relaciones_revisadas_por_conteo": checked, "relaciones_garantizadas_por_la_base": len(enforced), "huerfanas": results}
    if results:
        return fail(f"{len(results)} relaciones con filas huérfanas.", [finding(
            f"huerfanas:{r['relacion']}", f"Filas huérfanas en {r['relacion']}", f"{r['filas_huerfanas']} filas referencian registros inexistentes.",
            "Historial y reportes incompletos o inconsistentes.", "Comprobado mediante conteo.", "Investigue el origen y corrija los datos; "
            "después cree o valide la clave foránea.", evidence=r) for r in results], **details)
    if checked == 0:
        return ok("Todas las relaciones están garantizadas por claves foráneas validadas; no puede haber filas huérfanas.", **details)
    return ok(f"Sin filas huérfanas en {checked} relaciones revisadas por conteo.", **details)


# --- Security -------------------------------------------------------------------------------------------------------
def _policies(ctx: Ctx) -> list[dict]:
    return ctx.rows("""SELECT tablename AS tabla, policyname AS politica, permissive AS tipo, roles::text[] AS roles, cmd AS operacion,
                              qual AS condicion, with_check AS verificacion FROM pg_policies WHERE schemaname = current_schema()""")


def _open_policy(p: dict, role: str | None = None) -> bool:
    roles = set(p["roles"] or [])
    applies = role is None or bool(roles & {role, "public"})
    trivially_true = (p["condicion"] or "").strip().lower() in ("true", "(true)") or (
        p["operacion"] in ("INSERT",) and (p["verificacion"] or "").strip().lower() in ("true", "(true)"))
    return p["tipo"] == "PERMISSIVE" and applies and trivially_true


@control("BD-SEG-01", C, "Row Level Security en tablas del esquema expuesto", "Verificar que todas las tablas del esquema de la aplicación "
         "tienen RLS habilitado, como exige Supabase para las tablas alcanzables por la API REST.", "SQL", "ALTO",
         ["Supabase: Row Level Security", "OWASP ASVS 5.0 V8 (autorización)"], requires=PG)
def rls_enabled(ctx: Ctx) -> Outcome:
    rels = _relations(ctx)
    roles = _exposed_roles(ctx)
    without = [r["relname"] for r in rels if not r["rls"]]
    details = {"tablas": len(rels), "sin_rls": without, "con_rls_forzado": [r["relname"] for r in rels if r["force_rls"]],
               "roles_expuestos_existentes": roles,
               "nota": "RLS no se aplica al propietario de la tabla salvo FORCE ROW LEVEL SECURITY; la aplicación usa el rol propietario."}
    if without:
        severity = "ALTO" if roles else "MEDIO"
        return fail(f"{len(without)} de {len(rels)} tablas no tienen RLS habilitado.", [finding(
            f"rls:{t}", f"Tabla sin Row Level Security: {t}", f"La tabla «{t}» no tiene RLS habilitado.",
            "Cualquier rol con privilegios sobre la tabla (por ejemplo, anon o authenticated en Supabase) lee o modifica todas sus filas.",
            "Alta si existen roles de la API REST con privilegios (ver BD-SEG-03 y BD-SEG-08)." if roles else "Requiere que alguien obtenga privilegios sobre la tabla.",
            f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY; mediante una migración (el rol propietario de la aplicación no se ve afectado).",
            severity) for t in without], severity, **details)
    return ok(f"Las {len(rels)} tablas del esquema tienen RLS habilitado.", **details)


@control("BD-SEG-02", C, "Políticas RLS", "Examinar las políticas de cada tabla: detectar políticas permisivas con condición siempre "
         "verdadera aplicables a PUBLIC, anon o authenticated.", "SQL", "ALTO", ["Supabase: Row Level Security"], requires=PG)
def rls_policies(ctx: Ctx) -> Outcome:
    rels = {r["relname"]: r for r in _relations(ctx)}
    policies = _policies(ctx)
    risky = [p for p in policies if _open_policy(p) and bool(set(p["roles"] or []) & {"public", *EXPOSED_ROLES})]
    deny_all = sorted(t for t, r in rels.items() if r["rls"] and not any(p["tabla"] == t for p in policies))
    details = {"politicas": [{k: p[k] for k in ("tabla", "politica", "tipo", "roles", "operacion")} for p in policies],
               "tablas_rls_sin_politicas": deny_all,
               "interpretacion": "RLS sin políticas deniega todas las filas a los roles que no son propietarios (comportamiento esperado en FixIT)."}
    if risky:
        return fail(f"{len(risky)} políticas permiten acceso sin condición a roles expuestos.", [finding(
            f"politica:{p['tabla']}.{p['politica']}", f"Política RLS demasiado permisiva: {p['tabla']}.{p['politica']}",
            f"La política «{p['politica']}» ({p['operacion']}) concede acceso con condición verdadera a {', '.join(p['roles'])}.",
            "Anula la protección de RLS: todas las filas quedan accesibles para esos roles.", "Alta si la clave anon es pública.",
            "Restrinja la condición (USING / WITH CHECK) o elimine la política.", evidence={k: p[k] for k in ("tabla", "politica", "roles", "operacion")})
            for p in risky], **details)
    return ok(f"{len(policies)} políticas revisadas; ninguna concede acceso sin condición a roles expuestos.", **details)


def _privileges(ctx: Ctx, role: str) -> dict[str, list[str]]:
    rows = ctx.rows("""SELECT c.relname AS tabla, p.priv FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                       CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) AS p(priv)
                       WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND has_table_privilege(:role, c.oid, p.priv)""", role=role)
    out: dict[str, list[str]] = {}
    for r in rows: out.setdefault(r["tabla"], []).append(r["priv"])
    return out


def _public_privileges(ctx: Ctx) -> dict[str, list[str]]:
    rows = ctx.rows("""SELECT c.relname AS tabla, a.privilege_type AS priv FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                       CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND a.grantee = 0""")
    out: dict[str, list[str]] = {}
    for r in rows: out.setdefault(r["tabla"], []).append(r["priv"])
    return out


def _exposure(ctx: Ctx, tables: set[str] | None) -> tuple[list[dict], list[dict]]:
    """(effectively exposed, granted but blocked by RLS) for roles anon/authenticated and PUBLIC."""
    rels = {r["relname"]: r for r in _relations(ctx)}
    policies = _policies(ctx)
    exposed, blocked = [], []
    grants = {role: _privileges(ctx, role) for role in _exposed_roles(ctx)}
    grants["PUBLIC"] = _public_privileges(ctx)
    for role, by_table in grants.items():
        for table, privs in by_table.items():
            if tables is not None and table not in tables: continue
            rel = rels.get(table)
            if rel is None: continue
            open_policies = [p["politica"] for p in policies if p["tabla"] == table and _open_policy(p, None if role == "PUBLIC" else role)]
            item = {"tabla": table, "rol": role, "privilegios": sorted(privs), "rls": rel["rls"], "politicas_abiertas": open_policies}
            (exposed if not rel["rls"] or open_policies else blocked).append(item)
    return exposed, blocked


@control("BD-SEG-03", C, "Privilegios de anon, authenticated y PUBLIC", "Calcular los privilegios efectivos de los roles de la API REST de "
         "Supabase y de PUBLIC sobre las tablas no sensibles, combinando GRANT, RLS y políticas.", "SQL", "ALTO",
         ["Supabase: Row Level Security", "CIS PostgreSQL Benchmark (privilegios)"], requires=PG)
def exposed_privileges(ctx: Ctx) -> Outcome:
    roles = _exposed_roles(ctx)
    exposed, blocked = _exposure(ctx, {r["relname"] for r in _relations(ctx)} - SENSITIVE)
    details = {"roles_existentes": roles, "expuestas": exposed, "concedidas_pero_bloqueadas_por_rls": blocked,
               "alcance": "Tablas no sensibles; las sensibles se examinan en BD-SEG-08."}
    if exposed:
        return fail(f"{len(exposed)} combinaciones tabla/rol con acceso efectivo sin RLS.", [finding(
            f"exposicion:{e['tabla']}:{e['rol']}", f"Acceso efectivo de {e['rol']} a {e['tabla']}",
            f"El rol {e['rol']} tiene {', '.join(e['privilegios'])} sobre «{e['tabla']}» y RLS no lo restringe.",
            "Lectura o modificación de datos desde la API REST sin autenticación de FixIT.", "Alta si la clave anon es conocida (es pública por diseño).",
            f"Habilite RLS en {e['tabla']} y revoque los privilegios innecesarios (REVOKE ALL ON {e['tabla']} FROM {e['rol'].lower() if e['rol'] != 'PUBLIC' else 'PUBLIC'}).",
            evidence=e) for e in exposed], **details)
    if blocked:
        return warn(f"Sin acceso efectivo; {len(blocked)} privilegios concedidos quedan bloqueados solo por RLS.", [finding(
            "privilegios:innecesarios", "Privilegios innecesarios de roles expuestos (bloqueados por RLS)",
            "Los roles de la API REST conservan GRANT sobre tablas de FixIT; hoy RLS sin políticas los bloquea.",
            "Si se desactiva RLS o se agrega una política permisiva, el acceso queda abierto de inmediato.", "Baja mientras RLS siga activo.",
            "Revoque los privilegios que FixIT no necesita (la aplicación no usa la API REST de Supabase).", "BAJO",
            {"concesiones": blocked[:80]})], "BAJO", **details)
    if not roles:
        return ok("No existen roles anon/authenticated (no es un proyecto Supabase) y PUBLIC no tiene privilegios sobre las tablas.", **details)
    return ok("Los roles expuestos no tienen privilegios sobre las tablas no sensibles.", **details)


@control("BD-SEG-04", C, "Funciones SECURITY DEFINER y search_path", "Detectar funciones que se ejecutan con los privilegios de su "
         "propietario sin search_path fijo o que pueden invocar roles expuestos.", "SQL", "ALTO",
         ["CIS PostgreSQL Benchmark", "Supabase Database Advisor (function_search_path_mutable)"], requires=PG)
def security_definer(ctx: Ctx) -> Outcome:
    rows = ctx.rows("""
        SELECT n.nspname AS esquema, p.proname AS funcion, pg_get_function_identity_arguments(p.oid) AS argumentos, p.prosecdef AS security_definer,
               COALESCE(array_to_string(p.proconfig, ','), '') AS configuracion, pg_get_userbyid(p.proowner) AS propietario,
               has_function_privilege('public', p.oid, 'EXECUTE') AS ejecutable_por_public,
               ARRAY(SELECT x FROM unnest(CAST(:roles AS text[])) AS x WHERE has_function_privilege(x, p.oid, 'EXECUTE')) AS ejecutable_por
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname <> ALL(:excluded) AND n.nspname NOT LIKE 'pg_%'""", excluded=list(PROVIDER_SCHEMAS), roles=_exposed_roles(ctx))
    definer = [r for r in rows if r["security_definer"]]
    no_path = [r for r in definer if "search_path=" not in r["configuracion"]]
    mutable = [r for r in rows if not r["security_definer"] and "search_path=" not in r["configuracion"]]
    details = {"funciones_revisadas": len(rows), "security_definer": [{k: r[k] for k in ("esquema", "funcion", "configuracion", "ejecutable_por_public",
               "ejecutable_por")} for r in definer], "invoker_sin_search_path": [f"{r['esquema']}.{r['funcion']}" for r in mutable]}
    findings = [finding(f"funcion:{r['esquema']}.{r['funcion']}({r['argumentos']})", f"SECURITY DEFINER sin search_path: {r['esquema']}.{r['funcion']}",
                        "La función se ejecuta con los privilegios de su propietario y resuelve objetos según el search_path de quien la llama.",
                        "Un rol con CREATE en algún esquema del search_path podría suplantar objetos y escalar privilegios.",
                        "Depende de quién pueda invocarla: " + (", ".join(r["ejecutable_por"]) or ("PUBLIC" if r["ejecutable_por_public"] else "solo roles internos")),
                        f"ALTER FUNCTION {r['esquema']}.{r['funcion']}({r['argumentos']}) SET search_path = pg_catalog, {r['esquema']};",
                        "ALTO" if (r["ejecutable_por"] or r["ejecutable_por_public"]) else "MEDIO") for r in no_path]
    if findings:
        return fail(f"{len(no_path)} funciones SECURITY DEFINER sin search_path fijo.", findings, **details)
    if mutable:
        return warn(f"Sin SECURITY DEFINER inseguras; {len(mutable)} funciones (invoker) sin search_path fijo.", [finding(
            "funciones:search_path", "Funciones sin search_path fijo", "Funciones del esquema de la aplicación no fijan search_path.",
            "Riesgo bajo: se ejecutan con los privilegios de quien las llama, pero su comportamiento depende del search_path de la sesión.",
            "Baja.", "Fije search_path en la definición de las funciones.", "BAJO", {"funciones": details["invoker_sin_search_path"]})],
            "BAJO", **details)
    return ok(f"{len(rows)} funciones revisadas; ninguna SECURITY DEFINER insegura.", **details)


@control("BD-SEG-05", C, "Extensiones instaladas", "Inventariar extensiones con su versión y esquema y señalar las instaladas en el esquema "
         "expuesto.", "SQL", "BAJO", ["Supabase Database Advisor (extension_in_public)"], requires=PG)
def extensions(ctx: Ctx) -> Outcome:
    rows = ctx.rows("""SELECT e.extname AS extension, e.extversion AS version, n.nspname AS esquema FROM pg_extension e
                       JOIN pg_namespace n ON n.oid = e.extnamespace ORDER BY 1""")
    in_public = [r for r in rows if r["esquema"] == "public" and r["extension"] != "plpgsql"]
    details = {"extensiones": rows}
    if in_public:
        return warn(f"{len(in_public)} extensiones instaladas en el esquema public.", [finding(
            f"extension:{r['extension']}", f"Extensión en el esquema public: {r['extension']}",
            f"La extensión {r['extension']} {r['version']} crea sus objetos en public, el esquema expuesto por la API REST.",
            "Sus funciones pueden quedar invocables por roles expuestos.", "Baja; depende de la extensión.",
            "Muévala a un esquema dedicado (por ejemplo, extensions) si el proveedor lo permite.", evidence=r) for r in in_public], **details)
    return ok(f"{len(rows)} extensiones; ninguna instalada en public.", **details)


@control("BD-SEG-06", C, "Privilegios predeterminados", "Detectar privilegios predeterminados (ALTER DEFAULT PRIVILEGES) que otorgan acceso "
         "automático a roles expuestos sobre los objetos nuevos del esquema.", "SQL", "MEDIO", ["CIS PostgreSQL Benchmark (privilegios)"], requires=PG)
def default_privileges(ctx: Ctx) -> Outcome:
    rows = ctx.rows("""
        SELECT pg_get_userbyid(d.defaclrole) AS creador, COALESCE(n.nspname, '(todos)') AS esquema, d.defaclobjtype AS tipo,
               CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS beneficiario, a.privilege_type AS privilegio
        FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace CROSS JOIN LATERAL aclexplode(d.defaclacl) a
        WHERE n.nspname IS NULL OR n.nspname = current_schema()""")
    kinds = {"r": "tablas", "S": "secuencias", "f": "funciones", "T": "tipos", "n": "esquemas"}
    risky = [dict(r, tipo=kinds.get(r["tipo"], r["tipo"])) for r in rows if r["beneficiario"] in ("PUBLIC", *EXPOSED_ROLES) and r["tipo"] in ("r", "S", "f")]
    details = {"privilegios_predeterminados": [dict(r, tipo=kinds.get(r["tipo"], r["tipo"])) for r in rows]}
    if risky:
        tables = [r for r in risky if r["tipo"] == "tablas"]
        return warn(f"{len(risky)} privilegios predeterminados otorgan acceso automático a roles expuestos.", [finding(
            "privilegios_predeterminados:esquema", "Objetos nuevos reciben privilegios para roles expuestos",
            "Cada tabla, secuencia o función nueva del esquema recibe automáticamente privilegios para anon/authenticated o PUBLIC "
            "(configuración por defecto de Supabase).", "Una tabla creada sin RLS queda expuesta desde su creación.",
            "Media: depende de que cada migración habilite RLS.", "Mantenga la verificación BD-SEG-01 en cada despliegue o revoque estos "
            "privilegios predeterminados para el rol que crea las tablas.", "MEDIO" if tables else "BAJO", {"privilegios": risky[:60]})], **details)
    return ok("No hay privilegios predeterminados para roles expuestos.", **details)


@control("BD-SEG-07", C, "Privilegios de la conexión de auditoría", "Documentar con qué rol y atributos se ejecutan las comprobaciones y "
         "verificar el principio de privilegio mínimo de la conexión.", "SQL", "MEDIO", ["CIS PostgreSQL Benchmark (roles)"], requires=PG)
def audit_connection(ctx: Ctx) -> Outcome:
    from app.auditing.readonly import audit_url
    row = ctx.one("""SELECT current_user AS rol, session_user AS rol_sesion, r.rolsuper AS superusuario, r.rolcreaterole AS crea_roles,
                            r.rolcreatedb AS crea_bases, r.rolbypassrls AS omite_rls, r.rolreplication AS replicacion,
                            current_setting('transaction_read_only') AS transaccion_solo_lectura,
                            (SELECT array_agg(g.rolname::text ORDER BY g.rolname) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                              WHERE m.member = r.oid) AS miembro_de
                     FROM pg_roles r WHERE r.rolname = current_user""") or {}
    _, dedicated = audit_url()
    row["conexion_dedicada"] = dedicated
    issues = [k for k in ("superusuario", "omite_rls", "crea_roles", "replicacion") if row.get(k)]
    if row.get("transaccion_solo_lectura") != "on":
        return fail("La transacción de auditoría no está en modo de solo lectura.", [finding(
            "conexion:solo_lectura", "Conexión de auditoría sin modo de solo lectura", "La transacción no informa transaction_read_only = on.",
            "Un error en un control podría modificar datos.", "Comprobado.", "Revise app.auditing.readonly.", "CRITICO")], "CRITICO", **row)
    if issues or not dedicated:
        text = (f"El rol de la conexión tiene atributos privilegiados: {', '.join(issues)}." if issues else "") + \
               ("" if dedicated else " No hay AUDIT_DATABASE_URL: se usa la conexión de la aplicación (propietaria de las tablas).")
        return warn(f"Solo lectura confirmada. {text.strip()}", [finding(
            "conexion:privilegios", "La auditoría no usa un rol dedicado de solo lectura", text.strip(),
            "La protección depende del modo READ ONLY de la transacción; un rol con menos privilegios limitaría el daño de un error.",
            "Baja: cada control se ejecuta en transacciones de solo lectura que siempre se revierten.",
            "Cree un rol de auditoría con pg_read_all_data o SELECT sobre el esquema, sin BYPASSRLS, y configure AUDIT_DATABASE_URL "
            "(ver docs/auditoria-base-datos.md).", "BAJO")], "BAJO", **row)
    return ok(f"Rol dedicado «{row.get('rol')}» sin atributos privilegiados, en transacción de solo lectura.", **row)


@control("BD-SEG-08", C, "Exposición de las tablas sensibles de FixIT", "Examinar usuarios, tickets, auditoría, automatización, ML y Centro de "
         "Auditoría: RLS, FORCE RLS, políticas, propietario y privilegios efectivos de anon, authenticated y PUBLIC.", "SQL", "CRITICO",
         ["Supabase: Row Level Security", "OWASP ASVS 5.0 V8", "Ley N.º 29733 (medidas de seguridad)"], requires=PG)
def sensitive_tables(ctx: Ctx) -> Outcome:
    rels = {r["relname"]: r for r in _relations(ctx)}
    present = sorted(SENSITIVE & set(rels))
    exposed, blocked = _exposure(ctx, set(present))
    policies = _policies(ctx)
    inventory = [{"tabla": t, "rls": rels[t]["rls"], "force_rls": rels[t]["force_rls"], "propietario": rels[t]["owner"],
                  "politicas": [p["politica"] for p in policies if p["tabla"] == t],
                  "concesiones_a_roles_expuestos": sorted({f"{b['rol']}:{'/'.join(b['privilegios'])}" for b in exposed + blocked if b["tabla"] == t})}
                 for t in present]
    details = {"tablas_sensibles": inventory, "expuestas": exposed}
    if exposed:
        return fail(f"{len({e['tabla'] for e in exposed})} tablas sensibles accesibles para roles expuestos.", [finding(
            f"sensible:{e['tabla']}:{e['rol']}", f"Tabla sensible expuesta: {e['tabla']} ({e['rol']})",
            f"El rol {e['rol']} puede {', '.join(e['privilegios'])} en «{e['tabla']}» sin restricción efectiva de RLS.",
            "Exposición de datos personales, credenciales cifradas o registros de auditoría a cualquier poseedor de la clave pública.",
            "Muy alta en Supabase: la clave anon se distribuye a los clientes.", f"Habilite RLS en {e['tabla']}, elimine políticas abiertas y "
            f"revoque los privilegios de {e['rol']}.", "CRITICO", evidence=e) for e in exposed], "CRITICO", **details)
    missing_rls = [i["tabla"] for i in inventory if not i["rls"]]
    if missing_rls:
        return warn(f"Ninguna tabla sensible accesible para roles expuestos; {len(missing_rls)} sin RLS (defensa en profundidad).", [finding(
            f"sensible:sin_rls:{t}", f"Tabla sensible sin RLS: {t}", f"«{t}» no tiene RLS, aunque hoy ningún rol expuesto tiene privilegios.",
            "Un GRANT futuro la expondría de inmediato.", "Baja.", f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;", "MEDIO") for t in missing_rls],
            "MEDIO", **details)
    return ok(f"Las {len(present)} tablas sensibles tienen RLS y ningún rol expuesto tiene acceso efectivo.", **details)


@control("BD-SEG-09", C, "Esquema public y search_path", "Verificar que PUBLIC y los roles expuestos no pueden crear objetos en el esquema "
         "de la aplicación (CVE-2018-1058) y documentar el search_path.", "SQL", "ALTO", ["CIS PostgreSQL Benchmark"], requires=PG)
def schema_create(ctx: Ctx) -> Outcome:
    schema = ctx.scalar("SELECT current_schema()")
    can = {"PUBLIC": ctx.scalar("SELECT has_schema_privilege('public', current_schema(), 'CREATE')")}
    for role in _exposed_roles(ctx):
        can[role] = ctx.scalar("SELECT has_schema_privilege(:r, current_schema(), 'CREATE')", r=role)
    details = {"esquema": schema, "puede_crear": can, "search_path": ctx.scalar("SELECT current_setting('search_path')")}
    risky = [r for r, v in can.items() if v]
    if risky:
        return fail(f"{', '.join(risky)} pueden crear objetos en el esquema {schema}.", [finding(
            f"esquema:create:{schema}", f"Creación de objetos permitida en {schema}", f"Los roles {', '.join(risky)} tienen CREATE sobre {schema}.",
            "Permite suplantar funciones u operadores que otros roles resuelven por search_path (CVE-2018-1058).", "Media.",
            f"REVOKE CREATE ON SCHEMA {schema} FROM {', '.join(r if r != 'PUBLIC' else 'PUBLIC' for r in risky)};", evidence=can)], **details)
    return ok(f"Ni PUBLIC ni los roles expuestos pueden crear objetos en {schema}.", **details)


@control("BD-SEG-10", C, "Cifrado de la conexión y autenticación", "Verificar que la conexión de la aplicación a la base usa TLS y que las "
         "contraseñas de roles se cifran con SCRAM-SHA-256.", "SQL", "ALTO", ["CIS PostgreSQL Benchmark (conexiones)", "OWASP ASVS 5.0 V12"], requires=PG)
def connection_tls(ctx: Ctx) -> Outcome:
    from app.auditing.readonly import audit_url, host_kind
    ssl = ctx.one("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()") or {}
    encryption = ctx.scalar("SELECT current_setting('password_encryption', true)")
    where = host_kind(audit_url()[0])
    details = {"tls": bool(ssl.get("ssl")), "version_tls": ssl.get("version"), "cifrado": ssl.get("cipher"), "password_encryption": encryption,
               "ubicacion": where}
    if not ssl.get("ssl"):
        if where.endswith("local"):
            return not_applicable("Conexión local sin TLS (entorno de desarrollo); el control aplica a bases remotas.", **details)
        return fail("La conexión a la base remota no está cifrada.", [finding(
            "conexion:tls", "Conexión a la base de datos sin TLS", "La sesión de la aplicación con la base no usa TLS.",
            "Credenciales y datos viajan en claro por la red.", "Media en redes de proveedores; alta en redes compartidas.",
            "Añada sslmode=require (o verify-full) a DATABASE_URL.", "ALTO")], **details)
    if encryption and encryption != "scram-sha-256":
        return warn(f"Conexión cifrada ({ssl.get('version')}); password_encryption = {encryption}.", [finding(
            "conexion:password_encryption", "Cifrado de contraseñas de roles distinto de SCRAM-SHA-256", f"password_encryption = {encryption}.",
            "MD5 es vulnerable a ataques de diccionario si se filtra el catálogo.", "Baja.", "Configure scram-sha-256.", "BAJO")], "BAJO", **details)
    return ok(f"Conexión cifrada ({ssl.get('version')}) y contraseñas de roles con {encryption}.", **details)


@control("BD-SEG-11", C, "Vistas y objetos expuestos", "Detectar vistas del esquema expuesto que se ejecutan con los privilegios de su "
         "propietario (sin security_invoker) y son legibles por roles expuestos, eludiendo RLS.", "SQL", "ALTO",
         ["Supabase Database Advisor (security_definer_view)"], requires=PG)
def exposed_views(ctx: Ctx) -> Outcome:
    views = ctx.rows("""SELECT c.relname AS vista, c.relkind AS tipo, COALESCE(array_to_string(c.reloptions, ','), '') AS opciones,
                               ARRAY(SELECT x FROM unnest(CAST(:roles AS text[])) AS x WHERE has_table_privilege(x, c.oid, 'SELECT')) AS legible_por
                        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relkind IN ('v', 'm')""",
                     roles=_exposed_roles(ctx))
    risky = [v for v in views if v["legible_por"] and "security_invoker=true" not in v["opciones"].replace(" ", "").lower()]
    details = {"vistas": views}
    if risky:
        return fail(f"{len(risky)} vistas legibles por roles expuestos sin security_invoker.", [finding(
            f"vista:{v['vista']}", f"Vista que elude RLS: {v['vista']}", f"La vista «{v['vista']}» se ejecuta con los privilegios de su propietario y "
            f"puede leerla {', '.join(v['legible_por'])}.", "Expone las filas de las tablas subyacentes sin aplicar RLS.", "Alta en Supabase.",
            f"ALTER VIEW {v['vista']} SET (security_invoker = true); o revoque SELECT a los roles expuestos.", evidence=v) for v in risky], **details)
    return ok(f"{len(views)} vistas; ninguna expuesta sin security_invoker." if views else "El esquema no tiene vistas.", **details)


# --- SQL activity ---------------------------------------------------------------------------------------------------
def _setting(ctx: Ctx, name: str):
    try:
        return ctx.scalar("SELECT current_setting(:n, true)", n=name)
    except Exception:  # noqa: BLE001 - some providers restrict settings; reported as not accessible
        return None


@control("BD-ACT-01", C, "Disponibilidad de pgAudit", "Comprobar si la extensión pgAudit está disponible e instalada para registrar la "
         "actividad SQL.", "SQL", "MEDIO", ["Supabase: extensión pgAudit", "NIST SP 800-92"], requires=PG)
def pgaudit_available(ctx: Ctx) -> Outcome:
    available = ctx.one("SELECT name, default_version AS version_disponible, installed_version AS version_instalada FROM pg_available_extensions WHERE name = 'pgaudit'")
    preload = _setting(ctx, "shared_preload_libraries")
    details = {"disponible": bool(available), "instalada": bool(available and available.get("version_instalada")),
               "version": (available or {}).get("version_instalada") or (available or {}).get("version_disponible"),
               "shared_preload_libraries": preload if preload is not None else "no accesible con este rol",
               "limitacion": "Sin pgAudit activo en su momento, la actividad SQL pasada no puede reconstruirse."}
    if not available:
        return warn("pgAudit no está disponible en este servidor PostgreSQL.", [finding(
            "pgaudit:no_disponible", "pgAudit no disponible", "El servidor no ofrece la extensión pgAudit.",
            "La actividad SQL (DDL, cambios de roles, accesos a tablas) no queda registrada en la base.", "No aplica una probabilidad: es una ausencia de control.",
            "Use un proveedor o versión con pgAudit, o centralice los logs de PostgreSQL.", "MEDIO")], "MEDIO", **details)
    if not details["instalada"]:
        return warn("pgAudit está disponible pero no instalado.", [finding(
            "pgaudit:no_instalado", "pgAudit disponible pero no habilitado", "La extensión existe en el servidor pero no está creada en la base.",
            "La actividad SQL no se registra; no podrá revisarse después.", "No aplica: ausencia de control.",
            "En Supabase: Database → Extensions → pgaudit, o `create extension pgaudit;` por un administrador, y configure "
            "pgaudit.log por rol (ver docs/auditoria-base-datos.md). No habilite pgaudit.log_parameter ni log_rows.", "MEDIO")], "MEDIO", **details)
    return ok(f"pgAudit {details['version']} instalado.", **details)


@control("BD-ACT-02", C, "Configuración de pgAudit", "Examinar las clases de eventos registradas (globales y por rol) y detectar opciones que "
         "registran datos sensibles.", "SQL", "MEDIO", ["Supabase: extensión pgAudit", "OWASP Logging Cheat Sheet"], requires=PG)
def pgaudit_config(ctx: Ctx) -> Outcome:
    installed = ctx.scalar("SELECT count(*) FROM pg_extension WHERE extname = 'pgaudit'")
    if not installed: return not_applicable("pgAudit no está instalado (ver BD-ACT-01).")
    names = ("pgaudit.log", "pgaudit.log_catalog", "pgaudit.log_parameter", "pgaudit.log_relation", "pgaudit.log_rows", "pgaudit.log_statement", "pgaudit.role")
    session = {n: _setting(ctx, n) for n in names}
    per_role = []
    for r in ctx.rows("SELECT rolname, rolconfig FROM pg_roles WHERE rolconfig IS NOT NULL"):
        values = [c for c in (r["rolconfig"] or []) if str(c).startswith("pgaudit.")]
        if values: per_role.append({"rol": r["rolname"], "configuracion": values})
    classes = {c.strip().lower() for c in (session.get("pgaudit.log") or "").split(",") if c.strip()}
    for item in per_role:
        for value in item["configuracion"]:
            if value.startswith("pgaudit.log="): classes |= {c.strip().lower() for c in value.split("=", 1)[1].split(",")}
    details = {"sesion": session, "por_rol": per_role, "clases_registradas": sorted(classes - {"none"}),
               "nota": "La configuración por rol solo se ve si el rol de auditoría puede leer pg_roles.rolconfig."}
    findings = []
    sensitive = [n for n in ("pgaudit.log_parameter", "pgaudit.log_rows") if (session.get(n) or "").lower() == "on" or
                 any(v.lower() in (f"{n}=on", f"{n}=true") for i in per_role for v in i["configuracion"])]
    if sensitive:
        findings.append(finding("pgaudit:datos_sensibles", "pgAudit registra parámetros o filas", f"Activado: {', '.join(sensitive)}.",
                                "Los logs pueden contener datos personales o secretos enviados como parámetros.", "Alta mientras esté activo.",
                                "Desactive pgaudit.log_parameter y pgaudit.log_rows.", "MEDIO"))
    if not (classes - {"none"}):
        findings.append(finding("pgaudit:sin_clases", "pgAudit instalado sin clases registradas", "pgaudit.log es none en la sesión y por rol.",
                                "La extensión no registra nada.", "No aplica.", "Configure al menos pgaudit.log = 'ddl, role' para el rol que administra la base "
                                "y 'write, ddl' para el rol de la aplicación.", "MEDIO"))
    elif "all" in classes:
        findings.append(finding("pgaudit:all", "pgAudit registra todas las clases", "pgaudit.log incluye «all».",
                                "Volumen elevado de logs (incluye lecturas) y posible exposición de datos en sentencias.", "Media.",
                                "Limite a ddl, role y write para los roles necesarios.", "BAJO"))
    if findings: return warn("pgAudit instalado con configuración a revisar.", findings, **details)
    return ok(f"pgAudit registra: {', '.join(sorted(classes))}; sin registro de parámetros ni filas.", **details)


@control("BD-ACT-03", C, "Registro de conexiones y sentencias", "Leer la configuración de registro de PostgreSQL accesible desde la conexión "
         "(conexiones, desconexiones, sentencias, duración).", "SQL", "BAJO", ["NIST SP 800-92", "CIS PostgreSQL Benchmark (registro)"], requires=PG)
def logging_settings(ctx: Ctx) -> Outcome:
    names = ("log_connections", "log_disconnections", "log_statement", "log_min_duration_statement", "log_min_error_statement", "log_line_prefix",
             "log_lock_waits", "logging_collector")
    values = {n: _setting(ctx, n) for n in names}
    unreadable = [n for n, v in values.items() if v is None]
    details = {"configuracion": values, "no_accesibles": unreadable,
               "proveedor": "En Supabase estos parámetros los administra el proveedor; los logs se consultan en el panel (Logs Explorer) y pueden "
                            "exportarse e importarse aquí (BD-ACT-04)."}
    if len(unreadable) == len(names): raise NotVerifiable("La conexión no puede leer la configuración de registro de PostgreSQL.")
    gaps = [n for n in ("log_connections", "log_disconnections") if (values.get(n) or "").lower() not in ("on", "true", "all", "receipt,authentication,authorization")]
    if (values.get("log_statement") or "").lower() == "all":
        return warn("log_statement = all: se registran todas las sentencias, incluidas lecturas con posibles datos personales.", [finding(
            "logs:statement_all", "Registro de todas las sentencias SQL", "log_statement = all.", "Volumen alto y datos personales en logs.",
            "Media.", "Use log_statement = ddl y pgAudit para escrituras.", "BAJO")], "BAJO", **details)
    if gaps:
        return warn(f"No se registran: {', '.join(gaps)}.", [finding("logs:conexiones", "Conexiones a la base no registradas",
                    f"Parámetros desactivados: {', '.join(gaps)}.", "No es posible reconstruir quién se conectó y cuándo.", "No aplica.",
                    "Actívelos si el proveedor lo permite (en Supabase lo gestiona el proveedor; documente su configuración).", "BAJO")], "BAJO", **details)
    return ok("Se registran conexiones y desconexiones.", **details)


@control("BD-ACT-04", C, "Actividad SQL importada", "Revisar los logs de pgAudit/PostgreSQL importados para el periodo: DDL, cambios de roles, "
         "fallos de autenticación y permisos denegados.", "IMPORTADO", "MEDIO", ["Supabase: configuración de registros", "NIST SP 800-92"])
def imported_activity(ctx: Ctx) -> Outcome:
    from sqlalchemy import func, select
    start, end = ctx.period()
    s = ctx.session
    base = select(AuditExternalLog).where(AuditExternalLog.log_time >= start, AuditExternalLog.log_time < end)
    total = s.scalar(select(func.count()).select_from(base.subquery()))
    if not total:
        last = from_import(ctx, "LOGS_BD", "logs de base de datos", "Exporte los logs de Postgres desde Supabase (Logs Explorer) en CSV o "
                           "JSON e impórtelos en Base de datos → Actividad SQL.", 10_000)[1]
        raise NotVerifiable(f"No hay registros importados dentro del periodo ({start.date()} a {end.date()}). Última importación: "
                            f"{last['importado_en']} ({last['archivo']}).")
    by_class = dict(s.execute(select(AuditExternalLog.statement_class, func.count()).where(AuditExternalLog.log_time >= start,
                    AuditExternalLog.log_time < end).group_by(AuditExternalLog.statement_class)).all())
    first, last = s.execute(select(func.min(AuditExternalLog.log_time), func.max(AuditExternalLog.log_time)).where(
        AuditExternalLog.log_time >= start, AuditExternalLog.log_time < end)).one()
    sensitive = s.scalars(base.where(AuditExternalLog.statement_class.in_(("DDL", "ROLE"))).order_by(AuditExternalLog.log_time).limit(50)).all()
    auth_failed = by_class.get("AUTENTICACION_FALLIDA", 0)
    denied = by_class.get("PERMISO_DENEGADO", 0)
    details = {"registros_en_periodo": total, "por_clase": by_class, "primer_registro": iso(first), "ultimo_registro": iso(last),
               "eventos_ddl_y_roles": [{"fecha": iso(e.log_time), "rol": e.db_user, "clase": e.statement_class, "comando": e.command,
                                        "objeto": e.object_name, "sentencia": (e.statement or "")[:200]} for e in sensitive],
               "naturaleza": "Registros importados de archivos exportados del proveedor; la cobertura depende de lo que se exportó."}
    findings = []
    if sensitive:
        findings.append(finding("actividad:ddl_roles", "Cambios de estructura o de roles en la base para revisar",
                                f"{by_class.get('DDL', 0)} sentencias DDL y {by_class.get('ROLE', 0)} de roles en el periodo.",
                                "Cambios no autorizados de esquema o privilegios.", "Requiere contrastar con migraciones y cambios aprobados.",
                                "Verifique que cada sentencia corresponde a una migración o cambio autorizado y documéntelo.", "MEDIO",
                                {"muestra": details["eventos_ddl_y_roles"][:20]}))
    if auth_failed >= int(ctx.option("umbral_fallos_bd", 20)) or denied:
        findings.append(finding("actividad:fallos", "Fallos de autenticación o permisos denegados en la base",
                                f"{auth_failed} autenticaciones fallidas y {denied} permisos denegados en el periodo.",
                                "Posibles intentos de acceso directo a la base.", "Requiere revisión de origen.",
                                "Revise los orígenes en el panel del proveedor y rote credenciales si corresponde.", "MEDIO"))
    if findings: return warn(f"{total} registros importados en el periodo con eventos para revisar.", findings, **details)
    return ok(f"{total} registros importados en el periodo sin DDL, cambios de roles ni fallos relevantes.", **details)


@control("BD-ACT-05", C, "Conexiones activas y capacidad", "Resumir las conexiones activas (sin el texto de las consultas), detectar "
         "transacciones inactivas prolongadas y el uso de max_connections.", "SQL", "BAJO", ["CIS PostgreSQL Benchmark"], requires=PG)
def activity_snapshot(ctx: Ctx) -> Outcome:
    rows = ctx.rows("""SELECT COALESCE(usename, '(sistema)') AS rol, COALESCE(NULLIF(application_name, ''), '(sin nombre)') AS aplicacion,
                              COALESCE(state, '(desconocido)') AS estado, count(*) AS conexiones,
                              max(EXTRACT(EPOCH FROM (now() - state_change)))::int AS segundos_max_en_estado
                       FROM pg_stat_activity WHERE datname = current_database() GROUP BY 1, 2, 3 ORDER BY 4 DESC""")
    maximum = int(ctx.scalar("SELECT current_setting('max_connections')::int") or 0)
    total = sum(r["conexiones"] for r in rows)
    idle_tx = [r for r in rows if r["estado"].startswith("idle in transaction") and (r["segundos_max_en_estado"] or 0) > 300]
    details = {"conexiones_por_rol_y_estado": rows, "total": total, "max_connections": maximum, "uso_pct": round(100 * total / maximum, 1) if maximum else None,
               "nota": "No se lee el texto de las consultas. Un rol sin privilegios de monitoreo solo ve el detalle de sus propias conexiones."}
    findings = []
    if idle_tx:
        findings.append(finding("actividad:idle_in_transaction", "Transacciones inactivas prolongadas", f"{sum(r['conexiones'] for r in idle_tx)} conexiones "
                                "llevan más de 5 minutos en «idle in transaction».", "Retienen bloqueos y evitan la limpieza (VACUUM).", "Media.",
                                "Configure idle_in_transaction_session_timeout y revise el código que deja transacciones abiertas.", "BAJO"))
    if maximum and total / maximum > 0.8:
        findings.append(finding("actividad:capacidad", "Conexiones cercanas al máximo", f"{total} de {maximum} conexiones en uso.",
                                "Nuevas conexiones pueden ser rechazadas (indisponibilidad).", "Media.", "Use el pooler del proveedor o reduzca el pool.", "MEDIO"))
    if findings: return warn(f"{total} conexiones; hay condiciones para revisar.", findings, **details)
    return ok(f"{total} conexiones ({details['uso_pct']} % de max_connections); sin transacciones inactivas prolongadas.", **details)
