# Centro Integral de Auditoría de FixIT

El Centro Integral de Auditoría (**Gestión → Centro de auditoría**, ruta `#/audit/...`) examina la aplicación, la base de datos, la seguridad, los usuarios y accesos, los procesos operativos, la trazabilidad, la infraestructura, la privacidad y la continuidad de FixIT. Cada resultado proviene de una comprobación real ejecutada por el motor de auditoría, de un informe externo importado o de una evidencia manual identificada como tal. Nada se simula: lo que no puede comprobarse queda **No verificado**, nunca aprobado.

Documentos relacionados:

| Documento | Contenido |
|---|---|
| [auditoria-base-datos.md](auditoria-base-datos.md) | PostgreSQL/Supabase: estructura, RLS, privilegios, pgAudit, importación de logs, conexión de solo lectura |
| [auditoria-seguridad.md](auditoria-seguridad.md) | Seguridad de la aplicación, herramientas (Bandit, pip-audit, OWASP ZAP, SARIF) e importación de informes |
| [auditoria-operativa.md](auditoria-operativa.md) | Usuarios y accesos, procesos operativos, infraestructura, privacidad y continuidad |
| [informes-auditoria.md](informes-auditoria.md) | Informe ejecutivo, informe técnico, paquete ZIP de evidencias y manifiesto SHA-256 |
| [seguridad.md](seguridad.md) | Informe de seguridad del repositorio y resultados de los escaneos |

## Secciones

| Sección | Ruta | Contenido |
|---|---|---|
| Panel general | `#/audit/panel` | Indicadores reales, estado por categoría, ejecuciones recientes, hallazgos por severidad |
| Base de datos | `#/audit/bd` | 23 controles, importación de logs de pgAudit/PostgreSQL y explorador de actividad importada |
| Seguridad | `#/audit/seguridad` | 23 controles e importación de informes de Bandit, pip-audit, ZAP y SARIF |
| Usuarios y accesos | `#/audit/accesos` | 10 controles |
| Procesos | `#/audit/procesos` | 12 controles |
| Registros y trazabilidad | `#/audit/registros` | 9 controles y el visor del registro de actividad (`audit_logs`) con exportación CSV/JSON |
| Infraestructura | `#/audit/infraestructura` | 10 controles |
| Privacidad | `#/audit/privacidad` | 11 controles |
| Continuidad | `#/audit/continuidad` | 8 controles |
| Hallazgos y planes de acción | `#/audit/hallazgos` | Registro central, filtros, responsables, plazos, tareas, evidencias, historial |
| Informes y evidencias | `#/audit/informes` | Descargas por ejecución e historial de informes generados |
| Historial y metodología | `#/audit/historial` | Todas las ejecuciones, metodología, estados, referencias y catálogo de controles |

## Permisos (verificados en el backend)

| Rol | Puede |
|---|---|
| ADMIN | Todo: ejecutar auditorías, habilitar o deshabilitar controles, gestionar hallazgos y responsables, registrar evidencias, importar informes, descargar informes (incluido el paquete sin enmascarar) |
| JEFE_TI | Ejecutar auditorías con los controles habilitados por ADMIN («auditorías autorizadas»), consultar resultados, gestionar hallazgos, tareas y evidencias, importar informes y descargar informes enmascarados |
| TECNICO | Solo **Mis hallazgos**: ver los hallazgos y tareas asignados, pasarlos a corrección o marcarlos como corregidos y adjuntar evidencia de corrección. No ve ejecuciones, informes ni otras categorías |
| USUARIO | Sin acceso |

Cada intento denegado se registra en `audit_logs` (módulo `CENTRO_AUDITORIA`, resultado `DENEGADO`). Ocultar elementos en la interfaz no es la protección: cada endpoint de `/api/audit-center` comprueba el rol y, para técnicos, la asignación del hallazgo o de la tarea. No se creó un rol nuevo de auditor externo: los resultados se comparten mediante los informes y el paquete de evidencias.

## Arquitectura

```
Navegador (audit_center.js)  ──►  /api/audit-center (app/api/audit_center.py)
                                        │ autorización por rol, validación estricta, registro en audit_logs
                                        ▼
                         Motor (app/auditing/engine.py) ── cola en segundo plano (ThreadPoolExecutor)
                                        │
          ┌─────────────────────────────┼──────────────────────────────┐
          ▼                             ▼                              ▼
 Controles (app/auditing/controls)   Hallazgos (findings.py)     Informes (reports.py)
   8 categorías · 106 controles        deduplicación, ciclo        PDF ejecutivo/técnico,
   conexión de solo lectura            de vida, verificación       ZIP con manifiesto
   (readonly.py)
```

* **Un solo motor.** Las ocho categorías comparten el mismo registro de controles (`@control(...)`), la misma ejecución, el mismo almacenamiento de resultados y el mismo sistema de hallazgos.
* **Ejecución en segundo plano.** `POST /api/audit-center/runs` crea la ejecución (`PENDIENTE`) y responde `202`; un hilo del motor la toma con un `UPDATE` condicional (`PENDIENTE → EN_CURSO`), de modo que nunca se ejecuta dos veces. El navegador consulta el progreso cada 2,5 s.
* **Límites.** `AUDIT_MAX_CONCURRENT_RUNS` ejecuciones simultáneas por proceso (1 por defecto), máximo 5 en cola, `AUDIT_RUN_MAX_SECONDS` por ejecución (900 s; los controles restantes quedan **No verificado**), `AUDIT_STATEMENT_TIMEOUT_MS` por consulta en PostgreSQL. No se permiten dos ejecuciones activas con los mismos controles.
* **Reinicios.** Cada control guarda su resultado al terminar, con un latido (`heartbeat_at`). Al iniciar, las ejecuciones `PENDIENTE` se reanudan y las `EN_CURSO` sin latido reciente se cierran como `INTERRUMPIDA`; sus controles pendientes se guardan como **No verificado**. Al apagar, el motor se detiene tras el control en curso.
* **Solo lectura.** Cada control abre su propia transacción de solo lectura (ver [auditoria-base-datos.md](auditoria-base-datos.md)) que siempre se revierte. Las pruebas automatizadas comprueban que una auditoría completa no modifica usuarios, tickets, historial, asignaciones, comentarios, calificaciones ni registros de auditoría previos.
* **Sin SQL ni comandos desde la interfaz.** Las consultas están en el código; los informes de herramientas se importan como archivos; ningún endpoint ejecuta comandos del sistema.
* **Sello de resultados.** Al terminar, los resultados se sellan con HMAC-SHA256 (misma clave que la auditoría de actividad). El control `REG-08` y los informes verifican el sello: si alguien modifica `audit_results` en la base, aparece **ALTERADO**.

### Ejecución y estados

Cada ejecución registra: identificador y código (`AUD-AAAA-NNNN`), nombre, tipo (`COMPLETA`, `CATEGORIA`, `PERSONALIZADA`, `VERIFICACION`), responsable, fechas de creación, inicio y fin en UTC, alcance (categorías, controles, periodo, descripción y criterios configurables), versión de FixIT y compilación (`RENDER_GIT_COMMIT`), herramientas y versiones, conexión y privilegios usados, resumen, resultado general, limitaciones y observaciones.

| Estado de un control | Significado |
|---|---|
| APROBADO | Se ejecutó y cumple el criterio |
| FALLIDO | Se ejecutó e incumple el criterio |
| ADVERTENCIA | Se ejecutó; requiere revisión o tiene una limitación |
| NO APLICABLE | No corresponde a este entorno (p. ej., requiere PostgreSQL y la base es SQLite) |
| NO VERIFICADO | No pudo comprobarse (permisos, falta de evidencia, información inaccesible, ejecución interrumpida). **Nunca equivale a aprobado** |
| ERROR DE EJECUCIÓN | Falló por un error técnico; el resultado es desconocido |

| Resultado general | Regla |
|---|---|
| FAVORABLE | Todos los ejecutados aprobados y menos de la mitad sin verificar |
| CON OBSERVACIONES | Hay fallidos de severidad media/baja o advertencias |
| DESFAVORABLE | Al menos un fallido crítico o alto |
| NO CONCLUYENTE | Nada ejecutado, o más de la mitad sin verificar o con error |

## Hallazgos y planes de acción

Los resultados `FALLIDO` y `ADVERTENCIA` generan hallazgos con código único (`HAL-NNNNN`), título, descripción, categoría, control, recurso afectado, severidad (CRÍTICO, ALTO, MEDIO, BAJO, INFORMATIVO), evidencia, impacto, probabilidad o justificación del riesgo, recomendación, responsable, fecha límite, estado, historial, evidencias de corrección y resultado de la última verificación.

* **Deduplicación.** Un hallazgo se identifica por `sha256(control | recurso)`. Una nueva detección incrementa `ocurrencias` y actualiza la evidencia; no crea otro hallazgo.
* **Verificación.** Cada ejecución que incluye el control vuelve a evaluar sus hallazgos: `REPRODUCIDO`, `NO_REPRODUCIDO` o `NO_CONCLUYENTE` (si el control no pudo ejecutarse). «Verificar ahora» lanza una ejecución de tipo `VERIFICACION` con ese control.
* **Ciclo de vida.**

| Desde | Hacia |
|---|---|
| ABIERTO | EN REVISIÓN, EN CORRECCIÓN, RIESGO ACEPTADO, FALSO POSITIVO |
| EN REVISIÓN | ABIERTO, EN CORRECCIÓN, RIESGO ACEPTADO, FALSO POSITIVO |
| EN CORRECCIÓN | EN REVISIÓN, CORREGIDO PENDIENTE DE VERIFICACIÓN (requiere evidencia de corrección) |
| CORREGIDO PENDIENTE DE VERIFICACIÓN | EN CORRECCIÓN, CERRADO |
| CERRADO | ABIERTO |
| RIESGO ACEPTADO | EN REVISIÓN, ABIERTO |
| FALSO POSITIVO | EN REVISIÓN |

* **Cierre.** Solo ADMIN o JEFE_TI, con evidencia de corrección adjunta y una verificación `NO_REPRODUCIDO` obtenida **después** de marcarlo como corregido. Pulsar un botón no basta.
* **Riesgo aceptado.** Solo ADMIN o JEFE_TI, con justificación (mínimo 20 caracteres) y fecha de revisión futura (máximo un año). **Falso positivo** también exige justificación.
* **Reaparición.** Si un hallazgo cerrado vuelve a detectarse, se reabre (evento `REAPARECIDO`); si uno marcado como corregido se reproduce, vuelve a `EN CORRECCIÓN`.
* **Historial.** `audit_finding_events` conserva cada detección, verificación, cambio de estado, asignación, tarea y evidencia. Ningún endpoint lo edita ni borra hallazgos.
* **Planes de acción.** Tareas por hallazgo con responsable (ADMIN, JEFE_TI o TECNICO), fecha límite y estado (`PENDIENTE`, `EN_CURSO`, `COMPLETADA`, `DESCARTADA`). Los responsables reciben una notificación.

## Evidencias

* **Manual** (ADMIN/JEFE_TI): para controles de método MANUAL (paneles de Render y Supabase, respaldos, políticas institucionales). Requiere archivo, resultado declarado y fecha de la evidencia; el control la usa si está dentro de su vigencia (p. ej., 7 días para el último respaldo) y muestra que el resultado proviene de una declaración manual.
* **Corrección**: adjunta a un hallazgo por su responsable o por ADMIN/JEFE_TI (archivo o descripción de al menos 20 caracteres).
* Tipos aceptados: PDF, PNG, JPEG, TXT, CSV y JSON, validados por su contenido (firma de archivo, UTF-8, JSON válido, sin HTML ni scripts), hasta `AUDIT_EVIDENCE_MAX_BYTES` (10 MB). Se guardan con nombre aleatorio en `UPLOAD_DIR/auditoria`, fuera del directorio web, con su SHA-256; solo se descargan por la API, como adjunto, y cada descarga se registra (`DESCARGAR_EVIDENCIA`).

## Modelo de datos (migración `0006_audit_center`)

| Tabla | Contenido |
|---|---|
| `audit_controls` | Catálogo de controles (sincronizado desde el código al iniciar); `enabled` lo administra ADMIN |
| `audit_runs` | Ejecuciones: alcance, periodo, estado, progreso, herramientas, conexión, resumen, resultado, limitaciones, sello |
| `audit_results` | Resultado de cada control en cada ejecución (único por ejecución y control) |
| `audit_findings` | Registro central de hallazgos (código y huella únicos) |
| `audit_finding_events` | Historial de cada hallazgo |
| `audit_action_items` | Planes de acción |
| `audit_evidences` | Evidencias manuales y de corrección |
| `audit_imports` | Archivos importados (tipo, nombre, SHA-256, tamaño, estado, conteos, herramienta, resumen) |
| `audit_external_logs` | Registros de actividad SQL importados (originales saneados + campos derivados) |
| `audit_reports` | Informes y paquetes generados, con SHA-256 y referencia al registro de auditoría de la descarga |

La migración es aditiva e idempotente, crea restricciones `CHECK` e índices, no modifica tablas existentes (tampoco `audit_logs`) y habilita RLS sin políticas en PostgreSQL para las tablas nuevas que pertenecen al rol que migra (los roles de la API REST de Supabase no pueden leerlas; el rol propietario de la aplicación no se ve afectado). Su `downgrade` elimina solo estas diez tablas y está pensado para bases de prueba: **no lo ejecute en producción**.

Las tres capas de registro son distintas aunque relacionadas: **actividad** (qué hicieron usuarios y procesos, `audit_logs`), **seguridad** (subconjunto de `audit_logs`: autenticación, denegaciones, exportaciones) y **resultados de auditoría** (qué concluyó una auditoría: `audit_runs`, `audit_results`, `audit_findings`).

## Variables de entorno nuevas (todas opcionales)

| Variable | Defecto | Uso |
|---|---|---|
| `AUDIT_DATABASE_URL` | vacía | Conexión dedicada para los controles, idealmente con un rol de solo lectura. Nunca se muestra |
| `AUDIT_MAX_CONCURRENT_RUNS` | 1 | Ejecuciones simultáneas por proceso |
| `AUDIT_RUN_MAX_SECONDS` | 900 | Duración máxima de una ejecución |
| `AUDIT_STATEMENT_TIMEOUT_MS` | 15000 | `statement_timeout` de cada transacción de control (PostgreSQL) |
| `AUDIT_EVIDENCE_MAX_BYTES` | 10485760 | Tamaño máximo de una evidencia |
| `AUDIT_IMPORT_MAX_BYTES` | 20971520 | Tamaño máximo de un archivo importado |
| `AUDIT_IMPORT_MAX_ROWS` | 200000 | Registros máximos por importación de logs |

Se recomienda además definir `AUDIT_HMAC_KEY` (sellos estables) y `TRUSTED_PROXY_HOPS` (IP real detrás de Render).

## Procedimiento de uso

1. **Primera auditoría.** Centro de auditoría → **Nueva auditoría** → deje todas las categorías, el periodo de los últimos 30 días y pulse **Ejecutar auditoría**. La ficha muestra el progreso; puede cerrarla.
2. **Completar lo no verificado.** En cada categoría, abra los controles **No verificado**: los de método MANUAL indican qué evidencia adjuntar (por ejemplo, `CON-02`: captura de Supabase → Database → Backups con la fecha del último respaldo); los IMPORTADO indican qué informe importar.
3. **Importar informes.** Base de datos → importar logs exportados de Supabase; Seguridad → importar Bandit, pip-audit, ZAP o SARIF (comandos en [auditoria-seguridad.md](auditoria-seguridad.md)).
4. **Gestionar hallazgos.** Hallazgos → filtre por severidad o categoría → asigne responsable y fecha límite → cree tareas. El responsable adjunta evidencia y lo marca como corregido; luego **Verificar ahora** y, si no se reproduce, ciérrelo.
5. **Informes.** Desde la ficha de la ejecución o la sección Informes, descargue el informe ejecutivo, el técnico o el paquete ZIP para auditores externos.
6. **Seguimiento.** Repita la auditoría (botón **Repetir**) y use **Comparar con la anterior** para ver mejoras y retrocesos.

## Procedimientos de verificación

* Pruebas automatizadas: `pytest tests/test_audit_center.py` (SQLite) y, con un PostgreSQL local, `FIXIT_TEST_POSTGRES_URL=... pytest tests/test_audit_center_pg.py` (migraciones sobre base vacía y sobre base 0005 con datos, `downgrade` en base de prueba, los 106 controles en PostgreSQL y un escenario de exposición: tabla sin RLS con GRANT a `anon`, política `USING (true)`, función SECURITY DEFINER sin `search_path`, índice duplicado y trigger de solo inserción desactivado).
* Integridad de un informe: compare el SHA-256 del archivo descargado con la cabecera `X-Content-SHA256` o con la sección Informes; dentro del ZIP, `sha256sum -c SHA256SUMS.txt`.
* Integridad de los resultados: ejecute `REG-08` (verifica el sello de las últimas ejecuciones).

## Limitaciones

* La auditoría solo ve lo accesible con su conexión: paneles de Render y Supabase, red y sistema operativo del proveedor quedan **No verificado** salvo evidencia manual.
* La actividad SQL histórica solo puede revisarse si pgAudit u otro registro estaba activo en su momento.
* Los controles estáticos e heurísticos (rutas, IDOR, XSS) no sustituyen una revisión manual ni una prueba de penetración.
* Las señales estadísticas y de Machine Learning (`OPE-11`) indican casos para revisar, no prueban irregularidades.
* El motor y su cola funcionan por proceso; con varias instancias, el `UPDATE` condicional impide ejecuciones duplicadas, pero cada instancia aplica su propio límite de concurrencia.
* Las referencias (OWASP ASVS 5.0, OWASP Logging Cheat Sheet, NIST SP 800-92, CIS PostgreSQL, ISO 19011, Ley N.º 29733) inspiran los controles; su uso **no implica certificación ni cumplimiento legal**.

---

# Registro de actividad (`audit_logs`)

FixIT registra las acciones relevantes en la tabla `audit_logs` y permite consultarlas y exportarlas para auditorías externas desde **Centro de auditoría → Registros**. Se conserva sin cambios (sello HMAC, trigger de solo inserción y formato de exportación 1.0).

## Quién puede acceder

- Solo los roles **ADMIN** y **JEFE_TI** pueden consultar (`GET /api/audit`, `GET /api/audit/facets`) y exportar (`GET /api/audit/export`).
- La autorización se comprueba en el backend. Un usuario autenticado con otro rol recibe `403` y el intento queda registrado como `ACCESO_DENEGADO` con resultado `DENEGADO`. Sin sesión, la respuesta es `401`.
- No existe ningún endpoint para modificar o eliminar registros de auditoría.

## Qué se registra

Cada registro contiene: identificador, fecha y hora (UTC), usuario (o «Sistema»), acción, módulo, entidad e identificador de la entidad, resultado (`EXITO`, `FALLO` o `DENEGADO`), dirección IP, navegador (`User-Agent`), valores anterior y nuevo cuando corresponde, y un sello de integridad.

Además de las operaciones de tickets, usuarios, catálogos, configuración, IA y agentes, se registran:

| Acción | Resultado | Cuándo |
|---|---|---|
| `LOGIN` | EXITO | Inicio de sesión correcto |
| `LOGIN_FALLIDO` | FALLO | Contraseña incorrecta o cuenta inactiva de una cuenta **existente** |
| `LOGIN_BLOQUEADO` | DENEGADO | La cuenta alcanzó el límite de intentos fallidos |
| `CONSULTAR` | EXITO | Consulta de la auditoría (una por búsqueda; la paginación no se registra de nuevo) |
| `EXPORTAR` | EXITO | Exportación CSV/JSON, con formato, filtros y número de registros |
| `ACCESO_DENEGADO` | DENEGADO | Intento de acceder a la auditoría sin el rol requerido |
| `ACEPTAR_TERMINOS` | EXITO | Aceptación expresa de una versión de los Términos y condiciones |
| `DESACTIVAR_CUENTA_DEMO` | EXITO | Migración 0005: desactivación de cuentas del módulo demo retirado |

### Acciones del Centro de auditoría

Además, el Centro de auditoría registra con el módulo `CENTRO_AUDITORIA`: `CREAR_AUDITORIA`, `REPETIR_AUDITORIA`, `CANCELAR_AUDITORIA`, `AUDITORIA_EJECUTADA` (con estado, resultado y conteos), `CONFIGURAR_CONTROL`, `ACTUALIZAR_HALLAZGO`, `CAMBIAR_ESTADO_HALLAZGO`, `VERIFICAR_HALLAZGO`, `CREAR_TAREA`, `ACTUALIZAR_TAREA`, `REGISTRAR_EVIDENCIA`, `DESCARGAR_EVIDENCIA`, `IMPORTAR_EVIDENCIA`, `EXPORTAR_INFORME` (con tipo, SHA-256 y si estaba enmascarado) y `ACCESO_DENEGADO`.

Los intentos con correos inexistentes no se guardan en la base de datos: permitirían a cualquiera llenar la auditoría con texto arbitrario.

### Datos que nunca se guardan

- Los valores de claves cuyo nombre indica contraseñas, tokens, secretos, claves de API, cookies, credenciales o sesiones se sustituyen por `[REDACTADO]` antes de guardarse (y de nuevo al consultar o exportar).
- No se guardan contraseñas, tokens JWT ni el contenido de las conversaciones con el asistente.

### Normalización contra inyección de registros

Los caracteres de control (CR, LF, tabulaciones, secuencias ANSI, separadores de línea Unicode) de los campos de texto se convierten en escapes visibles (`\x0d`, `\x0a`, ` `…), de modo que un valor no puede simular líneas o registros adicionales al leer la auditoría como texto, log o CSV.

## Filtros

| Parámetro | Descripción |
|---|---|
| `date_from` | Inicio del intervalo, **inclusive**. ISO 8601; sin zona horaria se interpreta como UTC |
| `date_to` | Fin del intervalo, **exclusivo** |
| `user_id` | Identificador de usuario, o `SISTEMA` para registros sin usuario |
| `action`, `module`, `entity` | Coincidencia exacta (letras, números, `_ . : -`) |
| `entity_id`, `ip` | Coincidencia exacta |
| `outcome` | `EXITO`, `FALLO` o `DENEGADO` |
| `q` | Texto contenido en acción, módulo, entidad o identificador de entidad |

En la interfaz, las fechas se eligen en la hora local del navegador y se convierten a UTC; «Hasta» incluye el día completo seleccionado.

La consulta en pantalla devuelve hasta 500 registros por página (cabecera `X-Total-Count` con el total). La exportación rechaza con `422` las consultas que superen `AUDIT_EXPORT_MAX_ROWS` (50 000 por defecto) y pide acotar los filtros.

## Formato de exportación (versión 1.0)

Nombre de archivo: `fixit-auditoria_<AAAAMMDDTHHMMSSZ>[_<desde>_<hasta>].csv|json`. Los registros se ordenan por fecha ascendente y las fechas están en UTC con sufijo `Z` y microsegundos.

### Columnas / campos

| Campo | Contenido |
|---|---|
| `id` | Identificador del registro |
| `fecha_utc` | Fecha y hora UTC (`2026-10-28T15:04:05.123456Z`) |
| `usuario_id`, `usuario_nombre`, `usuario_email` | Usuario que realizó la acción («Sistema» si no hay usuario) |
| `usuario_rol_actual` | Rol del usuario **al exportar** (no necesariamente el que tenía en la fecha del evento) |
| `accion`, `modulo`, `entidad`, `entidad_id` | Qué se hizo y sobre qué |
| `resultado` | `EXITO`, `FALLO` o `DENEGADO` |
| `ip`, `navegador` | Dirección IP y `User-Agent` registrados |
| `valor_anterior`, `valor_nuevo` | JSON (en CSV, como texto JSON) |
| `integridad` | `VALIDO`, `ALTERADO`, `SIN_SELLO` o `CLAVE_DISTINTA` (ver abajo) |

### CSV

- UTF-8 con BOM, separador coma, comillas dobles según RFC 4180 y fin de línea CRLF.
- Las primeras filas son **metadatos** con la forma `# clave,valor`; la primera es `# filas_metadatos,N`. Después hay una fila vacía y la fila de encabezados. Para leerlo con pandas: `pd.read_csv(f, skiprows=N + 1)`.
- Protección contra CSV/formula injection: los textos que empiezan con `=`, `+`, `-`, `@`, tabulación o retorno de carro llevan un apóstrofo inicial (`'=1+2`) para que las hojas de cálculo no los ejecuten. Es la única transformación del contenido, además de la normalización de caracteres de control y la redacción de secretos.

### JSON

```json
{
  "metadatos": {
    "formato": "fixit-auditoria", "version_formato": "1.0",
    "aplicacion": {"nombre": "FixIT", "version": "1.1.0", "compilacion": "<commit de Render o null>"},
    "exportado_en": "…Z", "zona_horaria": "UTC",
    "exportado_por": {"id": "…", "nombre": "…", "email": "…", "rol": "ADMIN"},
    "evento_exportacion_id": "<id del registro EXPORTAR>",
    "filtros": {"modulo": "AUTH"},
    "intervalo_solicitado": {"desde": "…", "hasta_exclusivo": null},
    "intervalo_registros": {"primero": "…", "ultimo": "…"},
    "total_registros": 123, "orden": "fecha_utc ascendente",
    "integridad": {"metodo": "…", "clave_id": "1a2b3c4d", "resumen": {"VALIDO": 120, "SIN_SELLO": 3}, "estados": {}, "alcance": "…"},
    "redaccion": "…", "notas": ["…"]
  },
  "registros": [{"id": "…", "fecha_utc": "…", "…": "…"}]
}
```

El evento `EXPORTAR` de cada exportación se registra antes de generar el archivo y su identificador aparece en los metadatos; ese evento no se incluye en el propio archivo.

## Integridad y sus límites

**Sello por registro.** Al crear cada registro, la aplicación calcula un HMAC-SHA256 sobre su contenido canónico (todos los campos, incluida la fecha) con una clave del servidor (`AUDIT_HMAC_KEY` o, si no se define, una derivada de `JWT_SECRET_KEY`). Al consultar o exportar se vuelve a calcular:

| Estado | Significado |
|---|---|
| `VALIDO` | El contenido coincide con el sello |
| `ALTERADO` | El registro se modificó después de crearse (por ejemplo, editándolo directamente en la base) |
| `SIN_SELLO` | Registro anterior a la migración 0005, o cuyo sello se perdió (un `downgrade` de la migración elimina la columna) |
| `CLAVE_DISTINTA` | Sellado con otra clave (se rotó `JWT_SECRET_KEY` o `AUDIT_HMAC_KEY`) |

Los registros del worker de automatización y del importador sintético también se sellan.

**Solo inserción en PostgreSQL.** La migración 0005 crea un trigger que rechaza `UPDATE`, `DELETE` y `TRUNCATE` sobre `audit_logs`, también para el rol de la aplicación.

**Lo que esto no garantiza:**

- Quien administre la base de datos puede desactivar el trigger y borrar registros; el sello detecta cambios en un registro, pero **no detecta registros eliminados**.
- Quien conozca la clave del servidor podría recalcular sellos. Mantenga `AUDIT_HMAC_KEY` / `JWT_SECRET_KEY` solo en las variables de entorno de Render.
- El sello y los metadatos **no acreditan el origen ni la autoría del archivo exportado**. Para conservar evidencia, guarde el archivo en un repositorio de solo escritura o entréguelo al auditor con una constancia de recepción (por ejemplo, registrando su SHA-256 en un acta).
- Para una cadena de custodia más fuerte se recomienda enviar periódicamente la auditoría a un almacenamiento externo inmutable (WORM) o a un sistema de logs centralizado.

---

## Anexo: catálogo de controles

Generado a partir del registro del código (`app/auditing/controls`). Método: SQL (consulta de solo lectura), ESTATICO (código y configuración), DINAMICO (solicitud interna al proceso), ESTADISTICO, IMPORTADO (informe externo) o MANUAL (evidencia aportada por personas).

### Base de datos (BASE_DATOS)

| Control | Comprobación | Método | Severidad base | Requiere |
|---|---|---|---|---|
| `BD-EST-01` | Inventario y coherencia del esquema | SQL | ALTO | — |
| `BD-EST-02` | Tablas sin clave primaria | SQL | MEDIO | — |
| `BD-EST-03` | Integridad referencial declarada | SQL | MEDIO | — |
| `BD-EST-04` | Índices en claves foráneas | SQL | BAJO | postgresql |
| `BD-EST-05` | Índices duplicados o redundantes | SQL | BAJO | postgresql |
| `BD-EST-06` | Tipos de datos y restricciones | SQL | MEDIO | — |
| `BD-EST-07` | Filas huérfanas en relaciones | SQL | ALTO | — |
| `BD-SEG-01` | Row Level Security en tablas del esquema expuesto | SQL | ALTO | postgresql |
| `BD-SEG-02` | Políticas RLS | SQL | ALTO | postgresql |
| `BD-SEG-03` | Privilegios de anon, authenticated y PUBLIC | SQL | ALTO | postgresql |
| `BD-SEG-04` | Funciones SECURITY DEFINER y search_path | SQL | ALTO | postgresql |
| `BD-SEG-05` | Extensiones instaladas | SQL | BAJO | postgresql |
| `BD-SEG-06` | Privilegios predeterminados | SQL | MEDIO | postgresql |
| `BD-SEG-07` | Privilegios de la conexión de auditoría | SQL | MEDIO | postgresql |
| `BD-SEG-08` | Exposición de las tablas sensibles de FixIT | SQL | CRITICO | postgresql |
| `BD-SEG-09` | Esquema public y search_path | SQL | ALTO | postgresql |
| `BD-SEG-10` | Cifrado de la conexión y autenticación | SQL | ALTO | postgresql |
| `BD-SEG-11` | Vistas y objetos expuestos | SQL | ALTO | postgresql |
| `BD-ACT-01` | Disponibilidad de pgAudit | SQL | MEDIO | postgresql |
| `BD-ACT-02` | Configuración de pgAudit | SQL | MEDIO | postgresql |
| `BD-ACT-03` | Registro de conexiones y sentencias | SQL | BAJO | postgresql |
| `BD-ACT-04` | Actividad SQL importada | IMPORTADO | MEDIO | — |
| `BD-ACT-05` | Conexiones activas y capacidad | SQL | BAJO | postgresql |

### Seguridad de la aplicación (SEGURIDAD)

| Control | Comprobación | Método | Severidad base | Requiere |
|---|---|---|---|---|
| `SEG-AUT-01` | Autenticación requerida en la API | ESTATICO | CRITICO | — |
| `SEG-AUT-02` | Privilegios por rol en rutas sensibles | ESTATICO | ALTO | — |
| `SEG-IDOR-01` | Autorización a nivel de objeto (IDOR/BOLA) | ESTATICO | ALTO | — |
| `SEG-JWT-01` | Configuración de JWT | ESTATICO | CRITICO | — |
| `SEG-PWD-01` | Almacenamiento de contraseñas | SQL | CRITICO | — |
| `SEG-PWD-02` | Política de contraseñas y factores de autenticación | ESTATICO | MEDIO | — |
| `SEG-LOG-01` | Control de intentos de inicio de sesión | ESTATICO | MEDIO | — |
| `SEG-SES-01` | Gestión de sesiones en el cliente | ESTATICO | MEDIO | — |
| `SEG-SEC-01` | Protección de secretos y configuración sensible | ESTATICO | ALTO | — |
| `SEG-HTTP-01` | Cabeceras de seguridad HTTP | DINAMICO | MEDIO | — |
| `SEG-CSP-01` | Calidad de la Content Security Policy | DINAMICO | MEDIO | — |
| `SEG-ERR-01` | Manejo de errores y exposición de información | DINAMICO | MEDIO | — |
| `SEG-CORS-01` | CORS y CSRF | ESTATICO | MEDIO | — |
| `SEG-HTTPS-01` | HTTPS en el despliegue | DINAMICO | ALTO | — |
| `SEG-UPL-01` | Validación de cargas de archivos | DINAMICO | ALTO | — |
| `SEG-INP-01` | Validación de entradas e inyección SQL | ESTATICO | ALTO | — |
| `SEG-XSS-01` | Protección XSS del cliente web | ESTATICO | ALTO | — |
| `SEG-FE-01` | Componentes y recursos del frontend | ESTATICO | MEDIO | — |
| `SEG-DEP-01` | Versiones de dependencias Python | ESTATICO | MEDIO | — |
| `SEG-DEP-02` | Vulnerabilidades conocidas en dependencias (pip-audit) | IMPORTADO | ALTO | — |
| `SEG-SAST-01` | Análisis estático de seguridad (Bandit) | IMPORTADO | ALTO | — |
| `SEG-DAST-01` | Escaneo dinámico (OWASP ZAP) | IMPORTADO | ALTO | — |
| `SEG-SAST-02` | Otros análisis importados (SARIF) | IMPORTADO | MEDIO | — |

### Usuarios y accesos (ACCESOS)

| Control | Comprobación | Método | Severidad base | Requiere |
|---|---|---|---|---|
| `ACC-01` | Inventario de cuentas | SQL | ALTO | — |
| `ACC-02` | Cuentas administrativas y privilegio mínimo | SQL | MEDIO | — |
| `ACC-03` | Cambios de privilegios | SQL | MEDIO | — |
| `ACC-04` | Inicios de sesión exitosos y fallidos | SQL | MEDIO | — |
| `ACC-05` | Intentos de acceso no autorizado | SQL | MEDIO | — |
| `ACC-06` | Acciones administrativas y actividad fuera de horario | SQL | BAJO | — |
| `ACC-07` | Cuentas potencialmente huérfanas | SQL | MEDIO | — |
| `ACC-08` | Coherencia entre roles y perfiles técnicos | SQL | BAJO | — |
| `ACC-09` | Acceso a recursos sensibles | SQL | ALTO | — |
| `ACC-10` | Cambios de configuración | SQL | BAJO | — |

### Procesos operativos (PROCESOS)

| Control | Comprobación | Método | Severidad base | Requiere |
|---|---|---|---|---|
| `OPE-01` | Creación y registro inicial de tickets | SQL | MEDIO | — |
| `OPE-02` | Coherencia de estados y marcas de tiempo | SQL | MEDIO | — |
| `OPE-03` | Cambios posteriores al cierre | SQL | MEDIO | — |
| `OPE-04` | Reaperturas | SQL | BAJO | — |
| `OPE-05` | Asignaciones y reasignaciones | SQL | MEDIO | — |
| `OPE-06` | Cambios de prioridad y plazos | SQL | MEDIO | — |
| `OPE-07` | Cumplimiento de SLA | SQL | MEDIO | — |
| `OPE-08` | Tiempos de primera respuesta y resolución | ESTADISTICO | INFORMATIVO | — |
| `OPE-09` | Calificaciones | SQL | MEDIO | — |
| `OPE-10` | Trazabilidad de intervenciones | SQL | MEDIO | — |
| `OPE-11` | Señales de anomalía (estadística y Machine Learning) | ESTADISTICO | BAJO | — |
| `OPE-12` | Operaciones administrativas sobre tickets | SQL | BAJO | — |

### Registros y trazabilidad (REGISTROS)

| Control | Comprobación | Método | Severidad base | Requiere |
|---|---|---|---|---|
| `REG-01` | Verificación de sellos HMAC de la auditoría | SQL | CRITICO | — |
| `REG-02` | Protección de solo inserción | SQL | CRITICO | postgresql |
| `REG-03` | Continuidad del registro | SQL | MEDIO | — |
| `REG-04` | Calidad de los eventos registrados | SQL | BAJO | — |
| `REG-05` | Cobertura de eventos de seguridad | ESTATICO | MEDIO | — |
| `REG-06` | Exportaciones registradas | SQL | MEDIO | — |
| `REG-07` | Conservación y centralización de registros | MANUAL | MEDIO | evidencia ≤ 365 días |
| `REG-08` | Integridad de los resultados de auditorías anteriores | SQL | ALTO | — |
| `REG-09` | Clasificación de registros del periodo | SQL | INFORMATIVO | — |

### Infraestructura y disponibilidad (INFRAESTRUCTURA)

| Control | Comprobación | Método | Severidad base | Requiere |
|---|---|---|---|---|
| `INF-01` | Estado y versión de la API | DINAMICO | INFORMATIVO | — |
| `INF-02` | Conexión y latencia de la base de datos | SQL | MEDIO | — |
| `INF-03` | Migraciones de base de datos | SQL | ALTO | — |
| `INF-04` | Variables de entorno requeridas | ESTATICO | MEDIO | — |
| `INF-05` | Configuración de producción | ESTATICO | MEDIO | — |
| `INF-06` | Servicios internos | ESTATICO | MEDIO | — |
| `INF-07` | Errores registrados de servicios | SQL | MEDIO | — |
| `INF-08` | Proceso sin privilegios | ESTATICO | MEDIO | — |
| `INF-09` | Almacenamiento de adjuntos y evidencias | ESTATICO | ALTO | — |
| `INF-10` | Configuración de Render y Supabase | MANUAL | MEDIO | evidencia ≤ 180 días |

### Privacidad y cumplimiento (PRIVACIDAD)

| Control | Comprobación | Método | Severidad base | Requiere |
|---|---|---|---|---|
| `PRI-01` | Documentos legales publicados y versionados | ESTATICO | MEDIO | — |
| `PRI-02` | Información pendiente de validación institucional | ESTATICO | MEDIO | — |
| `PRI-03` | Aceptación de la versión vigente de los términos | SQL | MEDIO | — |
| `PRI-04` | Integridad del registro de aceptaciones | SQL | MEDIO | — |
| `PRI-05` | Acceso a datos personales | ESTATICO | ALTO | — |
| `PRI-06` | Minimización en exportaciones e informes | ESTATICO | BAJO | — |
| `PRI-07` | Conservación y eliminación de datos | MANUAL | MEDIO | evidencia ≤ 365 días |
| `PRI-08` | Derechos de los titulares | MANUAL | MEDIO | evidencia ≤ 365 días |
| `PRI-09` | Encargados del tratamiento y transferencias | MANUAL | MEDIO | evidencia ≤ 365 días |
| `PRI-10` | Responsable del tratamiento y banco de datos | MANUAL | MEDIO | evidencia ≤ 730 días |
| `PRI-11` | Datos sensibles en tickets y comentarios | ESTADISTICO | MEDIO | — |

### Continuidad y recuperación (CONTINUIDAD)

| Control | Comprobación | Método | Severidad base | Requiere |
|---|---|---|---|---|
| `CON-01` | Estrategia de respaldos documentada | MANUAL | ALTO | evidencia ≤ 365 días |
| `CON-02` | Evidencia de respaldo reciente | MANUAL | ALTO | evidencia ≤ 7 días |
| `CON-03` | Procedimiento de restauración | MANUAL | ALTO | evidencia ≤ 365 días |
| `CON-04` | Prueba de restauración | MANUAL | ALTO | evidencia ≤ 180 días |
| `CON-05` | Dependencias críticas | ESTATICO | BAJO | — |
| `CON-06` | Riesgos de pérdida de datos | ESTATICO | MEDIO | — |
| `CON-07` | Plan de contingencia | MANUAL | MEDIO | evidencia ≤ 365 días |
| `CON-08` | Disponibilidad de servicios críticos | SQL | ALTO | — |
