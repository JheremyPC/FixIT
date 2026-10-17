# Datos sintéticos de FixIT

Generador reproducible de tickets ficticios para desarrollo, demostración y entrenamiento de los modelos de IA.

## Reglas de seguridad

1. **Solo bases locales.** `import`, `purge` y `status` aceptan únicamente SQLite o PostgreSQL en `localhost`, `127.0.0.1`, `db`, `postgres` o `host.docker.internal`. Cualquier otro host —incluidos Supabase y Render— se rechaza. Se pueden añadir hosts locales con `FIXIT_LOCAL_DB_HOSTS`.
2. **Destino adicional explícito y separado.** Para otra base existe el comando `import-remote`, que exige a la vez `--target-url`, `--confirm-host <host exacto>` y la variable `FIXIT_ALLOW_REMOTE_SYNTHETIC=1`. No se recomienda usarlo en producción.
3. **Nunca se borran tickets reales.** La purga solo elimina tickets cuyo número empieza por `SYN-` y sus registros hijos. Los usuarios sintéticos que tengan actividad real (por ejemplo, alguien inició sesión con una cuenta demo) se desactivan en lugar de borrarse.
4. **Sin duplicados accidentales.** Si ya existen tickets `SYN-`, `import` se detiene; `--replace` los regenera.
5. **Sin automatizaciones por datos ficticios.** Si la base tiene la función de Supabase `fixit_enqueue_automation_event()`, la importación exige la migración `0002_skip_synthetic_automation` y se niega antes de escribir nada si falta. Ver «Importación en Supabase».

## Identificación

| Elemento | Marca |
|---|---|
| Tickets | número `SYN-000001` … `SYN-005000`, etiqueta «Sintético» en la interfaz, campo `synthetic: true` en la API |
| Usuarios | correo `@sintetico.fixit.example` (dominio reservado, nunca es un buzón real) |
| Metadatos | ajuste `synthetic.dataset` (semilla, fecha, resumen) y evento de auditoría `IMPORTAR_SINTETICOS` |
| Modelos | `metadata.json` registra el porcentaje de datos sintéticos; la pestaña Métricas de Machine Learning lo documenta |

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

## Importación en Supabase

Supabase tiene triggers (`trg_*_automation_events`) que, por cada fila insertada en `tickets`, `ticket_assignments`, `ticket_comments` y `ratings`, encolan un evento en `automation_events`; el worker de Render lo convierte en notificaciones y auditorías. Importar 5.000 tickets generaría ~18.450 eventos, ~15.000 notificaciones y ~18.450 auditorías ficticias que `purge` no puede retirar.

**Protección.** La migración `0002_skip_synthetic_automation` añade al inicio de `fixit_enqueue_automation_event()` una condición: la fila se omite solo si **a la vez** la variable de transacción `fixit.synthetic_import` vale `on` **y** la fila pertenece a un ticket `SYN-`. El importador activa esa variable con `set_config('fixit.synthetic_import', 'on', true)` dentro de su única transacción, de modo que:

- desaparece con el `COMMIT`/`ROLLBACK` y nunca llega a otras sesiones ni a conexiones reutilizadas del pooler;
- los tickets reales (de usuarios, la API o el worker) generan eventos igual que antes, incluso si alguien activara la variable;
- la actividad posterior sobre tickets de demostración (por ejemplo, editarlos desde la aplicación) sí se automatiza.

La migración se niega a sobrescribir la función si su cuerpo no es exactamente el original conocido (no se pierden cambios manuales), es idempotente y su `downgrade` restaura el cuerpo original. En bases sin esa función (SQLite, PostgreSQL local) no hace nada.

### Procedimiento

Comandos para Git Bash desde `backend/`. La URL se lee de `FIXIT_REMOTE_DATABASE_URL` en `.env` (driver `postgresql+psycopg://`) y nunca se escribe en pantalla.

1. **Desplegar primero el código que contiene la migración 0002.** Render ejecuta `alembic upgrade head` al arrancar y la aplicará. No la aplique a mano antes de desplegar: si `alembic_version` pasara a `0002_…` mientras Render ejecuta código anterior, el siguiente arranque fallaría con «Can't locate revision».
   Si prefiere aplicarla a mano una vez desplegado el código:
   ```bash
   export FIXIT_REMOTE_DATABASE_URL="$(grep '^FIXIT_REMOTE_DATABASE_URL=' ../.env | cut -d= -f2-)"
   DATABASE_URL="$FIXIT_REMOTE_DATABASE_URL" JWT_SECRET_KEY=unused python -m alembic upgrade head
   DATABASE_URL="$FIXIT_REMOTE_DATABASE_URL" JWT_SECRET_KEY=unused python -m alembic current   # 0002_skip_synthetic_automation (head)
   ```
2. **Comprobar la protección** (SQL Editor de Supabase, solo lectura):
   ```sql
   select position('fixit.synthetic_import' in prosrc) > 0 as protegido, pg_get_userbyid(proowner) as owner
   from pg_proc where proname = 'fixit_enqueue_automation_event';
   select count(*) from tickets where number like 'SYN-%';   -- debe ser 0
   select count(*) from automation_events;                   -- anote el valor
   ```
3. **Importar** (una sola transacción; si algo falla no queda nada escrito):
   ```bash
   export FIXIT_REMOTE_DATABASE_URL="$(grep '^FIXIT_REMOTE_DATABASE_URL=' ../.env | cut -d= -f2-)"
   FIXIT_ALLOW_REMOTE_SYNTHETIC=1 python -m app.synthetic import-remote \
     --target-url "$FIXIT_REMOTE_DATABASE_URL" --confirm-host aws-0-sa-east-1.pooler.supabase.com \
     --count 5000 --seed 42
   ```
   Sin `--replace`. Códigos de salida: `0` importado, `2` destino rechazado, `3` ya hay tickets `SYN-` (no se toca nada), `4` falta la migración 0002 (no se escribe nada).
4. **Verificar** (solo lectura):
   ```sql
   select count(*) filter (where number like 'SYN-%') as sinteticos,
          count(*) filter (where number not like 'SYN-%') as reales from tickets;          -- 5000 / reales sin cambios
   select count(*) from automation_events e join tickets t on t.id = e.aggregate_id::text
   where t.number like 'SYN-%';                                                           -- 0
   select count(*) from automation_events;               -- igual que en el paso 2 (más la actividad real del intervalo)
   select count(*) from audit_logs where action = 'IMPORTAR_SINTETICOS';                  -- 1
   ```

`status` y `purge` solo aceptan bases locales: no hay un procedimiento soportado para retirar los datos de demostración de Supabase una vez importados.

Las pruebas `tests/test_synthetic_automation_pg.py` reproducen la función y los triggers de Supabase en un esquema temporal de un PostgreSQL local (`FIXIT_TEST_POSTGRES_URL`, ver el encabezado del archivo); sin esa variable se omiten.
