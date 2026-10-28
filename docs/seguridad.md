# Informe de seguridad — FixIT 1.1.0

Fecha: 2026-10-28 · Alcance: repositorio FixIT (backend FastAPI, frontend estático, migraciones, Docker) en el commit que introduce este informe. No contiene secretos.

## 1. Alcance y método

| Área | Qué se revisó |
|---|---|
| Autenticación | Login, registro, JWT (acceso/refresh), expiración, limitación de intentos, retiro de los accesos demo |
| Autorización | Control por rol en todos los endpoints, acceso a objetos (tickets, adjuntos, comentarios, usuarios, auditoría) |
| Entradas | Validación Pydantic, consultas SQLAlchemy parametrizadas, cargas de archivos, exportaciones CSV/Excel |
| Auditoría | Registro, consulta, exportación, integridad e inmutabilidad |
| Frontend | Escape de HTML, CSP, almacenamiento de tokens, recursos de terceros |
| Despliegue | Dockerfile, docker-compose, variables de entorno, migraciones en PostgreSQL/Supabase |
| Dependencias | `requirements.txt` completo |

**Herramientas y pruebas ejecutadas**

| Herramienta | Resultado final |
|---|---|
| `pytest` (SQLite) | 74 pruebas aprobadas; 3 omitidas por requerir PostgreSQL |
| `pytest` con `FIXIT_TEST_POSTGRES_URL` (PostgreSQL 16 local) | 3/3 aprobadas |
| Migraciones Alembic en PostgreSQL 16 local | 0001→0005 sobre base nueva; 0004→0005 sobre datos existentes; `downgrade` 0005→0004 y nuevo `upgrade` |
| Prueba de humo de la app en PostgreSQL | Ciclo de ticket, registro con aceptación, exportaciones, insert sellado del worker, trigger de solo inserción |
| `pip-audit` | Antes: 19 avisos en 5 paquetes. Después: sin vulnerabilidades conocidas |
| `bandit` | 0 altos; 2 falsos positivos (ver 4.3); 1 bajo corregido |
| `ruff` (reglas F, B, S) | Hallazgos en archivos tocados corregidos; quedan avisos de estilo preexistentes (B904/B905) |
| OWASP ZAP Baseline (pasivo), contenedor local | Antes: 0 FAIL, 5 WARN. Después: 0 FAIL, 2 WARN informativos |
| OWASP ZAP API Scan (activo, autenticado como ADMIN), contenedor local | Antes: 0 FAIL, 2 WARN (incluidos errores 500/502). Después: 0 FAIL, 1 WARN (falso positivo) |
| Chromium headless (Playwright) | Login, registro, auditoría, exportación, términos: sin violaciones de CSP ni errores de JavaScript |
| Búsqueda de secretos (árbol y todo el historial de Git) | Sin coincidencias |

Las pruebas activas se ejecutaron solo contra un contenedor local con una base PostgreSQL desechable. **No se escaneó producción** (ver 5).

## 2. Hallazgos corregidos

| # | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| 1 | Alta | Módulo temporal «Accesos de demostración»: con `DEMO_ACCESS_ENABLED=true`, cualquiera obtenía una sesión de administrador sin contraseña | Módulo eliminado (endpoints, JS, CSS, variable, pruebas). La migración 0005 desactiva, sin borrar, las cuentas `*@demo.fixit.example` que existan y lo audita |
| 2 | Alta | Dependencias vulnerables: `starlette` 0.41.3 (DoS por cabecera Range y multipart, reconstrucción de URL por Host, entre otras), `python-multipart` 0.0.20 (varios DoS), `python-jose` 3.3.0 (confusión de algoritmos, DoS JWE; algunas sin parche), `ecdsa` (sin parche) | FastAPI 0.162.0 / Starlette 1.10.0, python-multipart 0.0.32, pytest 9.0.3. `python-jose` reemplazado por PyJWT 2.15.1 (compatible con los tokens HS256 actuales; `ecdsa` deja de instalarse) |
| 3 | Media | Sin límite de intentos de inicio de sesión; los tiempos de respuesta revelaban qué correos existían | Bloqueo temporal por cuenta (10 fallos en 15 min, configurable; opcional por IP). Verificación bcrypt también para cuentas inexistentes. Fallos y bloqueos auditados |
| 4 | Media | Inyección de fórmulas (CSV/Excel) en el reporte de tickets y el dataset de ML: un título `=HYPERLINK(...)` se ejecutaba al abrir el archivo | Celdas de texto neutralizadas en CSV (apóstrofo inicial) y escritas como texto literal en Excel |
| 5 | Media | Adjuntos: se confiaba en el tipo y la extensión enviados por el cliente; el archivo se leía completo en memoria antes de validar el tamaño | Verificación del contenido real (firmas PNG/JPEG/PDF, UTF-8 para texto), extensión según el tipo, lectura acotada, nombre saneado |
| 6 | Media | Sin cabeceras de seguridad HTTP | CSP sin orígenes externos ni scripts inline, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP/COEP, HSTS bajo HTTPS, `Cache-Control: no-store` en la API |
| 7 | Media | Auditoría modificable desde la base de datos, sin resultado ni filtros, sin exportación y sin registro de accesos denegados | Trigger de solo inserción (PostgreSQL), sello HMAC por registro, campo de resultado, filtros, exportación CSV/JSON con metadatos, registro de consultas, exportaciones y accesos denegados. Detalle en [auditoria.md](auditoria.md) |
| 8 | Media | Tablas de FixIT sin RLS en el esquema `public` de Supabase, alcanzables por los roles de la API REST si se usa la clave `anon` | Migración 0005: RLS sin políticas en las tablas propiedad del rol de la aplicación (el propietario no se ve afectado; verificado con un rol tipo `anon` que no ve filas) |
| 9 | Media | El administrador inicial se creaba con una contraseña por defecto conocida si faltaba `FIXIT_ADMIN_PASSWORD` | Sin contraseña configurada no se crea la cuenta (aviso en el log) |
| 10 | Baja | Errores de validación devolvían los valores enviados (incluida la contraseña) | Solo se devuelven campo, mensaje y tipo |
| 11 | Baja | `GET /api/technicians` exponía los correos de los técnicos a cualquier usuario | Restringido a ADMIN y JEFE_TI (único uso en la interfaz) |
| 12 | Baja | Errores 500/502 detectados por el escaneo activo: prioridades duplicadas y caracteres NUL en textos | Validación de duplicados (409), rechazo de NUL en todas las entradas (422), manejo global de `IntegrityError` (409) y `DataError` (422) |
| 13 | Baja | Un administrador podía desactivarse o quitarse el rol a sí mismo; `area_id` y especialidades inválidas producían 500 | Validaciones con 422 |
| 14 | Baja | Documentación interactiva (`/docs`, `/openapi.json`) pública | Desactivada salvo `API_DOCS_ENABLED=true` |
| 15 | Baja | Contenedor como `root`; `JWT_SECRET_KEY` pasado al contenedor de PostgreSQL; puertos de compose abiertos en todas las interfaces; cabecera `server: uvicorn` | Usuario sin privilegios (uid 10001), secreto retirado, puertos en `127.0.0.1`, `--no-server-header` |
| 16 | Baja | Tipografías desde Google Fonts sin SRI (no aplicable a su CSS dinámico) y envío de la IP de los usuarios a Google | Fuentes Geist (OFL 1.1) servidas por FixIT |
| 17 | Baja | Excepciones silenciadas en `event_bus` y errores 500 sin registro | Se registran en el log sin datos sensibles |
| 18 | Info | Inyección en registros (CR/LF, ANSI) y secretos en valores auditados | Normalización de caracteres de control y redacción de claves sensibles |

## 3. Controles verificados sin cambios

- Consultas SQL: todas vía SQLAlchemy con parámetros; los filtros nuevos validan formato y escapan comodines `LIKE`.
- Acceso a objetos: tickets, comentarios internos, adjuntos, resúmenes de IA y búsqueda respetan rol y propiedad (pruebas con dos solicitantes y dos técnicos).
- Frontend: los datos del servidor se insertan con escape; no hay `eval`, manejadores inline ni `<style>` dinámicos.
- CSRF: no aplica; la API usa el encabezado `Authorization` (sin cookies) y no hay CORS habilitado, por lo que solo el mismo origen puede leer respuestas.
- Proveedores de IA: la clave vive solo en el backend; los errores del proveedor se muestran con secretos redactados.

## 4. Riesgos pendientes y decisiones

### 4.1 Pendientes que requieren acción fuera del código

| Severidad | Pendiente | Acción recomendada |
|---|---|---|
| Media | **Escaneo pasivo de producción no ejecutado**: la URL de Render no figura en el repositorio | `docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://<url-de-render> -I` (solo pasivo) |
| Media | Render antepone un proxy: sin `TRUSTED_PROXY_HOPS`, la IP auditada es probablemente la del proxy y el límite por IP no es utilizable | Confirmar cuántos saltos añade Render, fijar `TRUSTED_PROXY_HOPS` y verificar en la auditoría que se registran IP de clientes |
| Media | `automation_events` (creada fuera de Alembic) no se modificó | Revisar en Supabase → Security Advisor que RLS esté activo en todas las tablas, incluida esa, tras confirmar que el worker sigue funcionando |
| Media | Documentos legales en borrador | Completar los `[PENDIENTE DE VALIDACIÓN INSTITUCIONAL]` y revisión por la entidad y un especialista legal (Ley N.º 29733 y su reglamento vigente) |
| Baja | `AUDIT_HMAC_KEY` no definida: el sello usa una clave derivada de `JWT_SECRET_KEY` | Definir una clave larga y estable en Render; rotar `JWT_SECRET_KEY` deja registros como `CLAVE_DISTINTA` |
| Baja | HSTS depende de que Render envíe `X-Forwarded-Proto: https` | Verificar la cabecera en producción |

### 4.2 Riesgos aceptados o fuera de alcance

- **Tokens en `localStorage`**: un XSS permitiría robarlos. Mitigado con la CSP (`script-src 'self'`) y el escape sistemático; pasar a cookies `HttpOnly` cambiaría la autenticación e introduciría CSRF.
- **Sin revocación individual de refresh tokens** (7 días) ni cierre de sesión en el servidor. Desactivar la cuenta invalida sus sesiones de inmediato.
- **Límite de intentos en memoria**, por proceso: con varias instancias cada una cuenta por separado. El bloqueo por cuenta permite a un tercero bloquear temporalmente (15 min) una cuenta conocida.
- **Registro abierto de solicitantes** sin CAPTCHA ni restricción de dominio; solo otorga el rol USUARIO.
- Sin MFA ni política de contraseñas más allá de 8 caracteres; sin endpoint de cambio de contraseña.
- **`style-src-attr 'unsafe-inline'`**: necesario para los atributos `style` de las plantillas y gráficos. Navegadores sin CSP nivel 3 (p. ej., Safari < 15.4) bloquearán esos estilos y la interfaz se verá degradada.
- **Integridad de auditoría**: el sello no detecta registros eliminados por quien pueda desactivar el trigger, ni acredita el origen de un archivo exportado ([auditoria.md](auditoria.md)).
- La imagen de producción incluye `pytest` y `httpx` (dependencias de prueba).

### 4.3 Falsos positivos justificados

| Herramienta | Aviso | Motivo |
|---|---|---|
| ZAP 10027 | Comentarios sospechosos en JS | Los comentarios mencionan nombres de roles; el código del frontend es público por naturaleza y no contiene secretos |
| ZAP 10049 | Contenido no almacenable | Intencional: `no-store` en HTML y API para no dejar datos personales en cachés |
| ZAP 100001 | Content-Type inesperado | Las descargas CSV/PDF y la página HTML no son JSON por diseño |
| bandit B105 | «Contraseña» `"access"` | Es el tipo de token, no una credencial |
| bandit B608 | SQL por concatenación en la migración 0002 | El texto concatenado es una constante del código, sin entrada de usuario |

## 5. Despliegue en Render

1. El arranque ejecuta `alembic upgrade head`, que aplica la migración **0005** (aditiva): columnas de auditoría, tabla `terms_acceptances`, trigger de solo inserción, RLS y desactivación de cuentas demo. No borra datos ni recarga los datos sintéticos.
2. Retirar `DEMO_ACCESS_ENABLED` de las variables de Render si existe (ya no se usa).
3. Variables nuevas opcionales: `AUDIT_HMAC_KEY`, `TRUSTED_PROXY_HOPS`, `LOGIN_MAX_FAILURES`, `LOGIN_IP_MAX_FAILURES`, `LOGIN_WINDOW_MINUTES`, `AUDIT_EXPORT_MAX_ROWS`, `API_DOCS_ENABLED` (ver `.env.example`).
4. El contenedor ahora corre sin privilegios: si se montara un disco persistente en `uploads/`, debe ser escribible por el uid 10001.
5. Tras el despliegue: confirmar el login, una exportación de auditoría y las cabeceras de seguridad, y ejecutar el escaneo pasivo de 4.1.

Ninguna herramienta garantiza seguridad absoluta ni que un escáner externo no reporte nuevos avisos; este informe refleja el estado verificado en la fecha indicada.
