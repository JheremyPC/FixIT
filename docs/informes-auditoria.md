# Informes y paquetes de evidencias

Cada ejecución finalizada del Centro de auditoría produce, bajo demanda, tres productos. Se generan a partir de los resultados **almacenados** (no se vuelve a ejecutar nada) y solo pueden descargarlos ADMIN y JEFE_TI desde la ficha de la ejecución o **Centro de auditoría → Informes**.

| Producto | Endpoint | Destinatarios |
|---|---|---|
| Informe ejecutivo (PDF) | `GET /api/audit-center/runs/{id}/report/executive` | Responsables institucionales y directivos |
| Informe técnico (PDF) | `GET /api/audit-center/runs/{id}/report/technical` | Auditores y especialistas |
| Paquete de evidencias (ZIP) | `GET /api/audit-center/runs/{id}/report/package` | Auditores externos (sin acceso a FixIT ni a la base) |

## Contenido

**Ejecutivo:** portada, identificación del sistema, fecha, alcance y objetivos, resumen ejecutivo, resultado general, indicadores, hallazgos por severidad, riesgos principales, recomendaciones, conclusiones y limitaciones.

**Técnico:** metodología, métodos de verificación y significado de los estados, herramientas y versiones, conexión y privilegios usados, alcance, criterios de referencia, tabla de controles ejecutados, resultados detallados con su evidencia estructurada, hallazgos completos (descripción, impacto, probabilidad, recomendación, responsable, plazos, verificación), evidencias manuales y de corrección (con SHA-256), informes importados, controles no verificados y limitaciones técnicas, y el sello HMAC de los resultados con su verificación.

**Paquete ZIP:**

| Archivo | Contenido |
|---|---|
| `informe-ejecutivo.pdf`, `informe-tecnico.pdf` | Los dos informes |
| `resultados.json` | Resultado y evidencia de cada control |
| `hallazgos.json`, `hallazgos.csv` | Inventario de hallazgos |
| `registros/auditoria-actividad.csv` / `.json` | Registro de actividad (`audit_logs`) del periodo evaluado (hasta `AUDIT_EXPORT_MAX_ROWS`), con el estado de su sello HMAC |
| `evidencias/…` e `evidencias/indice.json` | Archivos de evidencia vinculados a los controles y hallazgos (máximo 50 MB en total); el índice indica si el SHA-256 coincide con el registrado y qué archivos se omitieron y por qué |
| `importaciones.json` | Resúmenes de los informes de herramientas usados |
| `metadatos.json` | Sistema, versión, ejecución, alcance, herramientas, conexión, sello, redacción y limitaciones |
| `manifiesto.json`, `SHA256SUMS.txt` | Ruta, tamaño y SHA-256 de cada archivo del paquete |

## Redacción

Por defecto, correos (`j***z@fixit.org`) e IP (`190.12.x.x`) se enmascaran, el navegador se abrevia y los secretos se eliminan. Solo un ADMIN puede pedir `?redact=false`; el archivo lleva el sufijo `_sin-enmascarar`, el PDF lo indica en cada página y la descarga queda registrada. Contraseñas, tokens y claves nunca se incluyen porque nunca se almacenan.

En CSV, los textos que empiezan con `=`, `+`, `-`, `@`, tabulación o retorno de carro llevan un apóstrofo inicial para que las hojas de cálculo no los ejecuten (protección contra CSV injection).

## Registro de cada descarga

Cada informe genera un registro en `audit_reports` (tipo, nombre, SHA-256, tamaño, si estaba enmascarado, quién y cuándo) y un evento `EXPORTAR_INFORME` en `audit_logs`. La respuesta incluye la cabecera `X-Content-SHA256`. El control `REG-06` verifica que todo informe generado tenga su registro.

## Integridad y sus límites

```bash
unzip fixit-paquete-evidencias_AUD-2026-0001.zip -d paquete && cd paquete
sha256sum -c SHA256SUMS.txt        # Linux/macOS; en Windows: Get-FileHash <archivo> -Algorithm SHA256
```

El manifiesto permite detectar si un archivo del paquete se modificó después de generarlo. **No es una firma digital** ni garantiza por sí solo la autenticidad: quien modifique un archivo puede recalcular el manifiesto. Para conservar evidencia, registre el SHA-256 del ZIP (visible en Informes) en un acta o en un sistema independiente al entregarlo.

Los archivos se generan en memoria y se envían como adjunto; no quedan copias en el servidor ni rutas internas, variables de entorno o credenciales en su contenido.
