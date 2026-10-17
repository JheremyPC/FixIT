# Decisiones de arquitectura

## D-001: monolito modular
La primera versión usa FastAPI modular y PostgreSQL en vez de microservicios. Los límites `api`, `services`, `models` y `events` permiten separar servicios o sustituir el bus de eventos posteriormente sin reescribir el dominio.

## D-002: clasificación y prioridad
La categoría representa la clasificación inicial; puede asociarse a una especialidad. La prioridad se propone por defecto como `MEDIA` y el solicitante puede seleccionarla. El SLA se calcula al crear el ticket desde la prioridad almacenada, por lo que cambios posteriores no alteran compromisos existentes.

## D-003: asignación
La asignación es determinista. Excluye técnicos inactivos, no disponibles, sin especialidad requerida, o con carga completa. Los pesos se almacenan en `settings` y cada decisión conserva puntaje y motivo en `ticket_assignments`.

## D-004: seguridad de adjuntos
Los ficheros tienen lista blanca de MIME, límite de tamaño configurable, nombre UUID no predecible y descarga autenticada con la misma autorización de propiedad del ticket. No se publican como archivos estáticos.

## D-005: estados
Las transiciones se controlan centralmente en `services/tickets.py`; las restricciones no se delegan al navegador. Un ticket no se borra: finaliza como `CERRADO` o `CANCELADO`.

## D-006: reportes
CSV, XLSX y PDF están implementados para el reporte de tickets. La capa de reporte permanece separada para incorporar los demás tipos de informe y formatos institucionales sin afectar la lógica operativa.

## D-007: datos sintéticos sin cambios de esquema
Los registros sintéticos se marcan con el prefijo de número `SYN-` y el dominio `@sintetico.fixit.example` en lugar de añadir columnas. Así no se requieren migraciones en Supabase y la marca es consultable y visible. El importador rechaza bases remotas por defecto y la purga solo afecta a esos registros.

## D-008: Machine Learning con scikit-learn y evaluación temporal
Se usan modelos de scikit-learn (gradient boosting, regresión logística, Ridge) por ser suficientes para datos tabulares de este tamaño y no requerir infraestructura adicional. Las variables se calculan con un barrido temporal para evitar fugas, y la evaluación siempre es fuera de tiempo. Los artefactos se versionan en la base de datos (`ml_artifacts`, firmados con HMAC; `ML_MODEL_DIR` es solo caché) con metadatos que registran el origen real/sintético de los datos.

## D-009: proveedor LLM configurable y opcional
El asistente usa el SDK oficial de Anthropic o un endpoint compatible con `/chat/completions`, elegido por variables de entorno. Sin credenciales, el sistema lo informa y no simula respuestas; la búsqueda contextual local funciona igualmente. El contexto enviado al LLM se filtra por los permisos del usuario.
