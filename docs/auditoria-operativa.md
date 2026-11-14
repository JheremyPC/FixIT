# Auditoría operativa: accesos, procesos, infraestructura, privacidad y continuidad

Este documento describe cinco categorías del Centro de auditoría. Todas evalúan el **periodo** de la ejecución (por defecto, los últimos 30 días) y nunca modifican datos: los tickets solo se cuentan y se identifican por número; las cuentas aparecen como correo enmascarado (`j***z@fixit.org`), rol y primeros caracteres del identificador.

## Criterios configurables por ejecución

| Opción | Defecto | Uso |
|---|---|---|
| Tickets a evaluar (`origen`) | todos | `reales` excluye los tickets sintéticos `SYN-`; `sinteticos` evalúa solo esos. Los resultados siempre desglosan reales y sintéticos |
| Objetivo de cumplimiento SLA | 85 % | OPE-07. El valor institucional oficial está pendiente de definición |
| Días de inactividad | 90 | ACC-02 y ACC-07 |
| Máximo de administradores | 3 | ACC-02 |
| Umbral de inicios fallidos | 5 | ACC-04 |

## Usuarios y accesos (`ACC-*`)

| Control | Comprueba |
|---|---|
| ACC-01 | Cuentas activas e inactivas por rol; cuentas del módulo demo retirado activas (fallido); cuentas sintéticas activas en una base remota (fallido: su contraseña está documentada) |
| ACC-02 | Número de administradores frente al máximo y cuentas ADMIN/JEFE_TI sin uso en el plazo (solo cuentas más antiguas que el plazo) |
| ACC-03 | Cambios de rol y creación de cuentas privilegiadas en el periodo (cada asignación privilegiada es un hallazgo a contrastar con su autorización) |
| ACC-04 | Inicios de sesión exitosos, fallidos y bloqueos; cuentas con fallos repetidos |
| ACC-05 | Accesos denegados por cuenta |
| ACC-06 | Acciones administrativas por módulo y las realizadas entre 00:00 y 05:59 (hora de Lima, UTC−5) |
| ACC-07 | Cuentas activas sin inicio de sesión en el plazo (potencialmente huérfanas) |
| ACC-08 | Coherencia entre rol TECNICO y perfil técnico; perfiles disponibles de cuentas inactivas |
| ACC-09 | Consultas y exportaciones de la auditoría y descargas de informes y evidencias; realizadas por roles no autorizados = fallido |
| ACC-10 | Cambios de configuración (reglas de asignación, agentes, controles de auditoría) con su autor |

Limitación: los intentos de inicio de sesión con correos inexistentes no se registran, y las denegaciones 403 fuera de los módulos de auditoría tampoco (lo informa `REG-05`).

## Procesos operativos (`OPE-*`)

| Control | Comprueba |
|---|---|
| OPE-01 | Cada ticket del periodo tiene evento de creación |
| OPE-02 | Coherencia de estado y fechas: cerrados sin fecha de cierre, resueltos sin solución, fechas anteriores a la creación, cierre antes de resolución, asignados sin técnico |
| OPE-03 | Eventos en el historial posteriores al cierre o cancelación |
| OPE-04 | Tasa de reapertura y tickets reabiertos dos o más veces |
| OPE-05 | Técnico asignado sin registro de asignación, asignaciones manuales sin motivo y reasignaciones excesivas |
| OPE-06 | Plazo (`due_at`) que no corresponde al SLA de la prioridad actual sin un cambio registrado (cambios de prioridad o de plazo no trazados) |
| OPE-07 | Cumplimiento de SLA por prioridad y abiertos vencidos |
| OPE-08 | Mediana y promedio de primera respuesta y de resolución por prioridad |
| OPE-09 | Calificaciones en tickets no resueltos, emitidas por alguien distinto del solicitante o de técnicos no asignados |
| OPE-10 | Tickets cuyo estado actual no está explicado por su historial |
| OPE-11 | Señales: resoluciones atípicas (más de Q3 + 3·IQR horas en su prioridad, mínimo 20 tickets), cierres en menos de un minuto y, si el modelo está entrenado, tickets abiertos con riesgo alto de incumplir el SLA según Machine Learning. **Son señales de riesgo, no pruebas de irregularidad** |
| OPE-12 | Cancelaciones y asignaciones manuales del periodo |

Los controles operativos no alteran tickets ni ejecutan acciones correctivas.

## Infraestructura y disponibilidad (`INF-*`)

| Control | Comprueba |
|---|---|
| INF-01 | Versión de FixIT, compilación, Python y marcos; respuesta de `/health` y `/api/legal` en el proceso |
| INF-02 | Latencia de la base y su versión y tamaño |
| INF-03 | `alembic_version` frente a la última migración del código |
| INF-04 | Variables obligatorias y recomendadas definidas (nunca su valor); `TRUSTED_PROXY_HOPS=0` en Render = advertencia |
| INF-05 | Motor de base de datos, depuración, documentación de la API y `sslmode` declarado |
| INF-06 | Worker de automatización, planificador de agentes, modelos ML y configuración del LLM (sin llamar al proveedor) |
| INF-07 | Tasas de error de agentes, llamadas al LLM y eventos de automatización |
| INF-08 | El proceso no se ejecuta como root (no verificable en Windows) |
| INF-09 | Directorio de archivos escribible y existencia en disco de cada adjunto y evidencia registrados |
| INF-10 | Configuración de Render y Supabase: **evidencia manual** (vigencia 180 días) |

No se afirma que Render o Supabase estén configurados de forma segura: lo que depende de sus paneles requiere evidencia.

## Privacidad y cumplimiento (`PRI-*`)

Referencia: Ley N.º 29733 y su reglamento. **Este módulo no declara cumplimiento legal ni certificación.** Lo que corresponde a la entidad (responsable, fundamento, plazos, canal de derechos, inscripción del banco de datos) aparece como **pendiente de validación** mientras no exista evidencia.

| Control | Comprueba |
|---|---|
| PRI-01 | Términos y Aviso de privacidad publicados en `/legal` con versión; si siguen en borrador |
| PRI-02 | Secciones marcadas «[PENDIENTE DE VALIDACIÓN INSTITUCIONAL]» |
| PRI-03 | Cuentas activas que aceptaron la versión vigente de los términos |
| PRI-04 | Aceptaciones con fecha coherente y registradas en la auditoría |
| PRI-05 | Rutas que devuelven datos personales de terceros limitadas a ADMIN y JEFE_TI |
| PRI-06 | Datos personales en exportaciones; informes del Centro enmascarados por defecto |
| PRI-07 | Política de conservación y eliminación (manual) |
| PRI-08 | Procedimiento de derechos de los titulares (manual) |
| PRI-09 | Encargados (Render, Supabase, proveedor de IA) y transferencias internacionales (manual; advertencia si el asistente de IA está activo sin garantías documentadas) |
| PRI-10 | Responsable del tratamiento e inscripción del banco de datos (manual) |
| PRI-11 | Números de tarjeta válidos (Luhn) y contraseñas escritas en tickets y comentarios del periodo; solo se informan números de ticket |

La página `/legal` y el registro de aceptaciones se conservan sin cambios.

## Continuidad y recuperación (`CON-*`)

| Control | Comprueba |
|---|---|
| CON-01 | Estrategia de respaldos documentada (manual, 365 días) |
| CON-02 | Respaldo de la base de los últimos 7 días (manual: captura de Supabase → Database → Backups) |
| CON-03 | Procedimiento de restauración (manual) |
| CON-04 | Prueba de restauración de los últimos 180 días (manual) |
| CON-05 | Dependencias críticas y puntos únicos de falla |
| CON-06 | Datos fuera de los respaldos de la base (adjuntos y evidencias en el disco del servicio) |
| CON-07 | Plan de contingencia (manual) |
| CON-08 | Disponibilidad en la ejecución: base, migraciones y procesos internos |

La auditoría nunca ejecuta restauraciones ni borra datos.

## Cómo registrar una evidencia manual

1. Abra la categoría y el control (p. ej., Continuidad → `CON-02`).
2. **Registrar evidencia manual**: título, resultado que acredita (aprobado, advertencia, fallido o no aplicable), fecha a la que corresponde y archivo (PDF, PNG, JPEG, TXT, CSV o JSON).
3. Ejecute de nuevo la categoría: el control mostrará el resultado declarado con método **MANUAL**, la evidencia (título, fecha, SHA-256, quién la registró) y la advertencia de que FixIT no pudo comprobarla técnicamente. Si la evidencia supera la vigencia del control, vuelve a **No verificado**.
