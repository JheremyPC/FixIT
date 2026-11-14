# Auditoría de seguridad de la aplicación

Categoría **Seguridad** del Centro de auditoría: 23 controles `SEG-*`. Cada uno declara su método:

| Método | Qué significa aquí |
|---|---|
| ESTATICO | Inspección del código y la configuración desplegados: árbol de dependencias de cada ruta de FastAPI, modelos de entrada, archivos del cliente web, variables (solo si están definidas, nunca su valor) |
| DINAMICO | Solicitudes HTTP reales procesadas **dentro del mismo proceso** (transporte ASGI): no salen a la red, no se autentican y no llegan a endpoints que escriban datos |
| SQL | Consulta de solo lectura (p. ej., prefijo del hash de contraseñas, nunca el hash completo) |
| IMPORTADO | Resultado de un informe de herramienta importado |

## Controles

| Control | Comprueba | Método |
|---|---|---|
| SEG-AUT-01 | Solo las rutas públicas previstas (login, registro, refresco, documentos legales, salud) aceptan solicitudes sin sesión | ESTATICO |
| SEG-AUT-02 | Los roles aceptados por cada ruta sensible (usuarios, configuración, reportes, ML, agentes, auditoría, Centro de auditoría) cumplen la política de privilegio mínimo | ESTATICO |
| SEG-IDOR-01 | Rutas con identificador accesibles a roles no administrativos muestran una comprobación de propiedad (heurístico; complementa las pruebas de acceso cruzado) | ESTATICO |
| SEG-JWT-01 | Algoritmo fijo (HS256), claims `exp/iat/sub`, tipo de token, clave larga y distinta de valores publicados, vigencias ≤ 60 min / ≤ 14 días | ESTATICO |
| SEG-PWD-01 | Todas las contraseñas con bcrypt costo ≥ 10 | SQL |
| SEG-PWD-02 | Longitud mínima, MFA y verificación contra contraseñas filtradas | ESTATICO |
| SEG-LOG-01 | Bloqueo tras intentos fallidos por cuenta y por IP | ESTATICO |
| SEG-SES-01 | Almacenamiento de tokens en el cliente y revocación en el servidor | ESTATICO |
| SEG-SEC-01 | Secretos requeridos definidos, `AUDIT_HMAC_KEY`, documentación de la API desactivada, sin secretos ni `.env` en `/static` | ESTATICO |
| SEG-HTTP-01 | CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP y HSTS bajo HTTPS | DINAMICO |
| SEG-CSP-01 | Calidad de la CSP (sin `unsafe-inline`/`unsafe-eval` en scripts, `object-src` y `frame-ancestors` `'none'`) | DINAMICO |
| SEG-ERR-01 | Errores sin trazas ni valores enviados (valor testigo), 401 sin sesión, `/docs` y `/openapi.json` no expuestos | DINAMICO |
| SEG-CORS-01 | CORS y aplicabilidad de CSRF (autenticación por cabecera, sin cookies) | ESTATICO |
| SEG-HTTPS-01 | URL pública declarada (`RENDER_EXTERNAL_URL`) con HTTPS y HSTS emitido | DINAMICO |
| SEG-UPL-01 | Validación real de adjuntos y evidencias con muestras maliciosas (tipo falso, rutas en el nombre, HTML, JSON inválido) y límites de tamaño | DINAMICO |
| SEG-INP-01 | Modelos de entrada con filtro NUL; consultas SQL con formato de cadena (solo aceptables con identificadores del catálogo) | ESTATICO |
| SEG-XSS-01 | `eval`, `new Function`, `document.write`, scripts y manejadores inline en el cliente; uso de `esc()` (heurístico; la CSP es la segunda barrera) | ESTATICO |
| SEG-FE-01 | Sin scripts, estilos ni fuentes de terceros en el cliente | ESTATICO |
| SEG-DEP-01 | Versiones de `requirements.txt` frente a las instaladas | ESTATICO |
| SEG-DEP-02 | Vulnerabilidades conocidas en dependencias (pip-audit) | IMPORTADO |
| SEG-SAST-01 | Análisis estático Bandit | IMPORTADO |
| SEG-SAST-02 | Otros análisis en formato SARIF 2.1.0 (Semgrep, CodeQL, linters de JavaScript) | IMPORTADO |
| SEG-DAST-01 | Escaneo dinámico OWASP ZAP | IMPORTADO |

Los criterios se inspiran en OWASP ASVS 5.0 (<https://asvs.owasp.org/>). No constituyen una certificación.

## Herramientas externas: ejecución e importación

La interfaz web **no ejecuta comandos**. Las herramientas se ejecutan en un equipo de desarrollo o en un entorno controlado y su informe se importa en **Seguridad → Informes de herramientas** (ADMIN o JEFE_TI). Un informe con más de 30 días se marca como posiblemente desactualizado.

```bash
cd backend
bandit -r app -f json -o bandit.json                                  # Bandit (JSON)
pip-audit -r ../requirements.txt -f json -o pip-audit.json            # pip-audit (JSON)
# OWASP ZAP Baseline (pasivo) contra un entorno LOCAL o de pruebas, nunca un escaneo activo contra producción:
docker run --rm -v "$(pwd):/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://<host-de-pruebas>:8000 -J zap.json -I
```

Del informe solo se conserva un resumen (conteos por severidad y hasta 300 elementos) con rutas de archivo reducidas a su ruta dentro del proyecto (`app/...`); el archivo original no se guarda, solo su nombre, tamaño y SHA-256. Un mismo archivo no puede importarse dos veces.

| Informe | Criterio del control |
|---|---|
| Bandit | Algún resultado HIGH = fallido; MEDIUM = advertencia |
| pip-audit | Alguna vulnerabilidad = fallido (severidad ALTA si existe corrección, MEDIA si no) |
| ZAP | Alertas de riesgo alto = fallido; medio = advertencia |
| SARIF | Nivel `error` = fallido; `warning` = advertencia |

## Escaneos activos

Los escaneos activos (ZAP *full scan* o *API scan*) se ejecutan solo contra un contenedor local con una base desechable. Para producción, como máximo un escaneo **pasivo** (baseline) autorizado; su resultado se importa como cualquier otro informe.

## Verificación

* `pytest tests/test_audit_center.py -k "tool_reports or full_audit"`: importación de informes y ejecución de los controles.
* Resultado de las herramientas sobre este repositorio: ver [seguridad.md](seguridad.md).
