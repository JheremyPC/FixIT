# Datos sintéticos de FixIT

Generador reproducible de tickets ficticios para desarrollo, demostración y entrenamiento de los modelos de IA.

## Reglas de seguridad

1. **Solo bases locales.** `import`, `purge` y `status` aceptan únicamente SQLite o PostgreSQL en `localhost`, `127.0.0.1`, `db`, `postgres` o `host.docker.internal`. Cualquier otro host —incluidos Supabase y Render— se rechaza. Se pueden añadir hosts locales con `FIXIT_LOCAL_DB_HOSTS`.
2. **Destino adicional explícito y separado.** Para otra base existe el comando `import-remote`, que exige a la vez `--target-url`, `--confirm-host <host exacto>` y la variable `FIXIT_ALLOW_REMOTE_SYNTHETIC=1`. No se recomienda usarlo en producción.
3. **Nunca se borran tickets reales.** La purga solo elimina tickets cuyo número empieza por `SYN-` y sus registros hijos. Los usuarios sintéticos que tengan actividad real (por ejemplo, alguien inició sesión con una cuenta demo) se desactivan en lugar de borrarse.
4. **Sin duplicados accidentales.** Si ya existen tickets `SYN-`, `import` se detiene; `--replace` los regenera.

## Identificación

| Elemento | Marca |
|---|---|
| Tickets | número `SYN-000001` … `SYN-005000`, etiqueta «Sintético» en la interfaz, campo `synthetic: true` en la API |
| Usuarios | correo `@sintetico.fixit.example` (dominio reservado, nunca es un buzón real) |
| Metadatos | ajuste `synthetic.dataset` (semilla, fecha, resumen) y evento de auditoría `IMPORTAR_SINTETICOS` |
| Modelos | `metadata.json` registra el porcentaje de datos sintéticos; el Centro de IA muestra un aviso visible |

## Comandos

Desde `backend/` (o con `docker compose exec api` delante):

```bash
python -m app.synthetic csv --out ../outputs/fixit_synthetic_tickets.csv   # solo CSV, no toca la base
python -m app.synthetic import                                              # genera e importa 5.000 tickets (base local)
python -m app.synthetic import --replace --csv ../outputs/fixit_synthetic_tickets.csv
python -m app.synthetic status                                              # cuenta reales y sintéticos
python -m app.synthetic purge --yes                                         # elimina solo los SYN-
```

Opciones de generación: `--count` (5000), `--seed` (42), `--end-date AAAA-MM-DD` (por defecto ayer) y `--days` (540). La misma semilla y fecha producen exactamente el mismo dataset. La base de destino es `DATABASE_URL` o `--database-url`.

Con Docker Compose la API ya apunta a la base local `db`:

```bash
docker compose exec api python -m app.synthetic import --csv /srv/fixit/outputs/fixit_synthetic_tickets.csv
```

## Qué se genera

- 150 solicitantes en 8 áreas y 14 técnicos con especialidades, velocidad, calidad y carga máxima distintas (uno no disponible).
- 15 categorías asociadas a 9 especialidades, 4 prioridades con su SLA (72/48/24/4 h).
- 5.000 tickets en 540 días con tendencia creciente, estacionalidad semanal y mensual, horarios laborales y días de incidente.
- Ciclos de vida que respetan las transiciones reales (`services/tickets.py`): asignación, atención, espera por repuestos, escalamientos, reaperturas, cancelaciones permitidas, resolución y cierre.
- Diagnósticos y soluciones por categoría, comentarios públicos e internos, historial, asignaciones y calificaciones coherentes con el cumplimiento del SLA.
- El tiempo de resolución depende de la complejidad de la categoría, la prioridad, la velocidad y la carga del técnico, el horario y la descripción, de modo que los modelos tienen relaciones reales que aprender y evaluar (~22 % de incumplimiento de SLA).

El CSV incluye las columnas de análisis (`attention_hours`, `resolution_hours`, `sla_met`, `rating`, `reopened`, `synthetic=1`). El endpoint `GET /api/ml/dataset.csv` exporta además la tabla de variables sin fuga de información que usan los modelos, tanto de datos reales como sintéticos.
