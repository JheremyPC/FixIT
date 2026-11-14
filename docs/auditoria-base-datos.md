# Auditoría de base de datos (PostgreSQL / Supabase)

Categoría **Base de datos** del Centro de auditoría: 23 controles (`BD-EST-*` estructura, `BD-SEG-*` seguridad, `BD-ACT-*` actividad SQL). Catálogo completo en el anexo de [auditoria.md](auditoria.md).

## Ejecución de solo lectura

| Aspecto | Comportamiento |
|---|---|
| Conexión | `AUDIT_DATABASE_URL` si está definida; si no, `DATABASE_URL`. En ambos casos un motor de conexiones **separado** del de la aplicación |
| PostgreSQL | Cada control abre una transacción `SET TRANSACTION READ ONLY` con `statement_timeout` (`AUDIT_STATEMENT_TIMEOUT_MS`) y `lock_timeout` de 3 s; la transacción **siempre se revierte**. Un intento de escritura falla con «cannot execute … in a read-only transaction», aunque el rol pueda escribir |
| SQLite (pruebas) | Conexión no reutilizada con `PRAGMA query_only = ON` |
| Consultas | Solo catálogo (`pg_catalog`, `information_schema`, inspector de SQLAlchemy) y `COUNT`. Ninguna consulta devuelve el contenido de tablas de negocio; los nombres de tablas y columnas interpolados provienen del catálogo y se entrecomillan |
| Errores | Permiso insuficiente (`42501`) o tiempo límite (`57014`) → **No verificado**; otros errores → **Error de ejecución** |
| Privilegios | Cada ejecución guarda el rol, sus atributos (superusuario, `BYPASSRLS`, `CREATEROLE`, replicación), si la transacción era de solo lectura y cuántas tablas posee; cada resultado indica con qué privilegios se obtuvo. El valor de la URL nunca se guarda ni se muestra |
| Sin cambios | No se modifica configuración, no se crean ni borran objetos y no se aplican correcciones automáticas |

### Rol de auditoría recomendado (opcional)

Sin `AUDIT_DATABASE_URL`, los controles usan el rol de la aplicación (en Supabase, normalmente `postgres`, propietario de las tablas y con privilegios elevados) dentro de transacciones de solo lectura. `BD-SEG-07` lo informa como advertencia. Para aplicar privilegio mínimo, un administrador de la base puede crear un rol dedicado y configurar `AUDIT_DATABASE_URL` en Render **sin publicarlo**:

```sql
-- Ejecutar en Supabase → SQL Editor como administrador. Elija una contraseña larga y guárdela solo en Render.
CREATE ROLE fixit_auditor LOGIN PASSWORD '<contraseña-larga>';
GRANT pg_read_all_data TO fixit_auditor;      -- lectura (no escritura)
GRANT pg_read_all_settings TO fixit_auditor;  -- configuración de registro y pgAudit
GRANT pg_monitor TO fixit_auditor;            -- estadísticas de conexiones
ALTER ROLE fixit_auditor SET default_transaction_read_only = on;
```

Tenga en cuenta que `pg_read_all_data` permite leer todas las tablas: protéjalo como una credencial sensible. Esta configuración es una **acción manual**; la aplicación no crea roles.

## Estructura (`BD-EST-*`)

| Control | Qué se comprueba | Criterio |
|---|---|---|
| BD-EST-01 | Tablas y columnas de los modelos frente a la base; objetos no gestionados | Faltantes = fallido; objetos desconocidos = advertencia (se excluyen `alembic_version` y `automation_events`, creados intencionalmente fuera de los modelos) |
| BD-EST-02 | Tablas sin clave primaria | Cualquiera = fallido |
| BD-EST-03 | Claves foráneas declaradas en los modelos y presentes en la base; restricciones `NOT VALID`; columnas `*_id` sin relación | Las excepciones legítimas (p. ej., `audit_logs.entity_id`, polimórfico) están justificadas en el código |
| BD-EST-04 | Claves foráneas sin índice | Solo se señala si la tabla tiene al menos 1 000 filas estimadas (configurable): un índice ausente no es un defecto por sí mismo |
| BD-EST-05 | Índices duplicados o cuyo prefijo cubre otro índice | Se excluyen índices parciales y de expresiones; recomendación: confirmar con `pg_stat_user_indexes` antes de eliminar |
| BD-EST-06 | Tipos, longitudes, nulabilidad, `UNIQUE` y `CHECK` frente a los modelos | Diferencias = advertencia |
| BD-EST-07 | Filas huérfanas en relaciones no garantizadas por claves foráneas validadas | Conteo; nunca devuelve filas |

## Seguridad (`BD-SEG-*`)

| Control | Qué se comprueba |
|---|---|
| BD-SEG-01 | RLS habilitado en todas las tablas del esquema expuesto |
| BD-SEG-02 | Políticas permisivas con condición siempre verdadera para `PUBLIC`, `anon` o `authenticated`. RLS sin políticas se interpreta como «deniega todo a roles no propietarios» (el diseño de FixIT) |
| BD-SEG-03 | Privilegios efectivos de `anon`, `authenticated` y `PUBLIC` sobre tablas no sensibles: combina `GRANT`, RLS y políticas. Un `GRANT` bloqueado por RLS se informa como privilegio innecesario |
| BD-SEG-04 | Funciones `SECURITY DEFINER` sin `search_path` fijo y quién puede ejecutarlas |
| BD-SEG-05 | Extensiones, versiones y esquema (instaladas en `public` = advertencia) |
| BD-SEG-06 | Privilegios predeterminados que otorgan acceso automático a roles expuestos sobre objetos nuevos (configuración por defecto de Supabase) |
| BD-SEG-07 | Rol y atributos de la conexión de auditoría; confirma `transaction_read_only = on` |
| BD-SEG-08 | Tablas sensibles de FixIT (usuarios, tickets, comentarios, adjuntos, historial, auditoría, aceptaciones, configuración, automatización, ML, LLM, agentes y Centro de auditoría): RLS, `FORCE RLS`, propietario, políticas y accesos efectivos |
| BD-SEG-09 | `CREATE` sobre el esquema para `PUBLIC` o roles expuestos (CVE-2018-1058) y `search_path` |
| BD-SEG-10 | TLS de la conexión (`pg_stat_ssl`) y `password_encryption` |
| BD-SEG-11 | Vistas legibles por roles expuestos sin `security_invoker` (eluden RLS) |

Que una tabla tenga RLS activado no se toma como prueba de seguridad: BD-SEG-02, 03 y 08 examinan las políticas y los privilegios efectivos de cada rol.

## Actividad SQL (`BD-ACT-*`) y pgAudit

| Control | Qué se comprueba |
|---|---|
| BD-ACT-01 | pgAudit disponible (`pg_available_extensions`), instalado (`pg_extension`) y `shared_preload_libraries` si es legible |
| BD-ACT-02 | `pgaudit.log` y opciones (sesión y por rol). Advierte si `pgaudit.log_parameter` o `pgaudit.log_rows` están activos (registran datos sensibles) o si se registra `all` |
| BD-ACT-03 | `log_connections`, `log_disconnections`, `log_statement`, `log_min_duration_statement` y otros, si el rol puede leerlos |
| BD-ACT-04 | Logs importados del periodo: DDL, cambios de roles, autenticaciones fallidas y permisos denegados |
| BD-ACT-05 | Conexiones activas por rol, aplicación y estado (sin el texto de las consultas), transacciones inactivas prolongadas y uso de `max_connections` |

**Limitación importante:** si pgAudit u otro registro no estaba activo en un momento dado, la actividad de ese periodo **no puede reconstruirse**. FixIT no intenta habilitarlo ni cambiar parámetros globales.

### Habilitar pgAudit en Supabase (acción manual del administrador)

Según la documentación de Supabase (<https://supabase.com/docs/guides/database/extensions/pgaudit>):

1. Supabase → Database → Extensions → habilite `pgaudit` (o `create extension pgaudit;`).
2. Configure el registro **por rol**, no globalmente, por ejemplo:
   ```sql
   alter role postgres set pgaudit.log to 'ddl, role';
   -- Opcional, valorar el volumen: escrituras del rol de la aplicación
   -- alter role <rol_app> set pgaudit.log to 'write, ddl';
   ```
3. **No** active `pgaudit.log_parameter` ni `pgaudit.log_rows`.
4. Los registros se consultan en Supabase → Logs (Postgres). Ver <https://supabase.com/docs/guides/observability/configure-logging>.

## Importación de logs exportados

Supabase no expone sus logs a la conexión de la aplicación. Exporte los registros de Postgres desde **Logs Explorer** e impórtelos en **Base de datos → Actividad SQL** (ADMIN o JEFE_TI).

| Aspecto | Comportamiento |
|---|---|
| Formatos | CSV o JSON exportados de Supabase (campos `timestamp`, `event_message` y metadatos anidados), JSON como lista u objeto con `result`/`rows`, o `csvlog` de PostgreSQL (sin encabezado) |
| Selección | Se guardan las líneas de pgAudit (`AUDIT: SESSION|OBJECT,…`) y eventos de conexión, desconexión, autenticación fallida y permiso denegado; el resto se cuenta como descartado |
| Origen | Se guarda el nombre saneado del archivo, su tamaño, su SHA-256, la fecha de importación, quién importó, notas y el formato detectado. El archivo original **no** se conserva |
| Duplicados | Un archivo con el mismo SHA-256 no se importa dos veces (409); cada registro tiene `record_hash` único (SHA-256 de la línea recibida), así que las exportaciones solapadas no duplican registros |
| Validación | UTF-8, sin caracteres NUL, estructura reconocida, máximo `AUDIT_IMPORT_MAX_BYTES` y `AUDIT_IMPORT_MAX_ROWS`. Un archivo inválido se rechaza (422) y queda registrado como `RECHAZADA` |
| Saneamiento | Caracteres de control escapados; contraseñas (`PASSWORD '…'`, `password=`), tokens, JWT, URL con credenciales y claves de API se reemplazan por `[REDACTADO]`; los **parámetros** de pgAudit se eliminan siempre (`[PARAMETROS NO ALMACENADOS]`) |
| Original vs. transformado | `original` guarda los campos recibidos (saneados); `log_time`, `db_user`, `statement_class`, `command`, `object_name`, `statement` son **derivados** del mensaje. La interfaz los muestra por separado y `redacted` indica si hubo redacción |

## Configuración en Supabase revisable solo manualmente

Security Advisor, respaldos, restricciones de red, SSL obligatorio y configuración del pooler pertenecen al panel de Supabase. Adjunte capturas como evidencia en `INF-10` y `CON-02`; sin ellas, esos controles quedan **No verificado**.
