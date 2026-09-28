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
