# Auditoría de FixIT

FixIT registra las acciones relevantes en la tabla `audit_logs` y permite consultarlas y exportarlas para auditorías externas desde **Gestión → Auditoría**.

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
