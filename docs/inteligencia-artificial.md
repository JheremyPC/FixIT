# Inteligencia Artificial en FixIT

## Centro de IA (ADMIN y JEFE_TI)

Menú **Inteligencia artificial → Centro de IA**, con pestañas:

| Pestaña | Contenido |
|---|---|
| Resumen y entrenamiento | Tickets reales/sintéticos, estado y versión de cada modelo, botón «Entrenar ahora», historial de entrenamientos |
| Riesgo SLA | Tickets abiertos ordenados por probabilidad de incumplir el SLA, tiempo estimado, factores que influyen y técnico recomendado; filtros por área, categoría, prioridad, técnico y origen |
| Técnicos | Carga actual vs. capacidad, desempeño histórico y recomendaciones para la cola, con botón «Asignar» |
| Demanda | Histórico diario, proyección de 4 semanas con intervalo, evaluación fuera de muestra y reparto por categoría |
| Patrones | Tickets e incumplimiento por periodo, categorías, prioridades, mapa categoría × prioridad, día × hora y tabla de técnicos |
| Simulador | Prioridad sugerida, tiempo, riesgo y mejores técnicos para un ticket hipotético |
| Métricas | MAE, precisión/recall/F1/AUC, matriz de confusión, calibración, importancia de variables, métricas del pronóstico y backtest del recomendador |
| Asistente | Chat LLM (también disponible para todos los roles en «Asistente») |

Todas las cifras vienen de `/api/ml/*`. Cuando un modelo no está entrenado o no hay datos suficientes, la interfaz lo dice y no muestra valores. Si los datos de entrenamiento son sintéticos, aparece el aviso «Resultados obtenidos con datos sintéticos — no validados con datos reales».

## Modelos (`backend/app/ml`)

| Modelo | Algoritmo | Métricas | Mínimo de datos |
|---|---|---|---|
| Tiempo de resolución | HistGradientBoostingRegressor sobre log(horas) | MAE, mediana del error, R² (log), % con error ≤ 50 %, comparación con la mediana por prioridad | 150 tickets resueltos |
| Riesgo SLA | HistGradientBoostingClassifier con clases balanceadas | Precisión, recall, F1, ROC AUC, matriz de confusión, calibración, comparación con la regla «ALTA/CRÍTICA = riesgo» | 150 tickets con resultado y 15 por clase |
| Prioridad sugerida | TF-IDF + regresión logística (texto, área, categoría) | Exactitud y P/R/F1 macro y por clase | 200 tickets |
| Demanda | Ridge con día de la semana, tendencia y rezagos de 7–28 días, recursivo | MAE, RMSE, sMAPE, MAPE vs. base estacional (repetir la última semana) | 97 días de historia |
| Recomendación de técnicos | Ranking por riesgo SLA y tiempo estimados para cada técnico candidato (especialidad, disponibilidad y capacidad) | Backtest observacional: coincidencia top-1/top-3 y resultados reales cuando se asignó al recomendado | Requiere los dos primeros |

### Prevención de fugas de información

- Las variables se calculan **con la información disponible al crear el ticket**: área, categoría, prioridad, texto del solicitante, técnico asignado, carga abierta de ese momento y estadísticas de tickets **ya terminados** antes de esa fecha (barrido temporal en `dataset.py`).
- Nunca son variables: estado, fechas de atención/resolución/cierre, diagnóstico, solución, comentarios ni calificación.
- Evaluación temporal: se entrena con el 80 % más antiguo **cuyo resultado ya se conocía en la fecha de corte** y se evalúa con el 20 % más reciente. Después, el modelo final se reentrena con todos los datos etiquetados.
- Semillas fijas; los artefactos (`*.joblib`) y `metadata.json` con versión, fechas, librerías, métricas y origen de los datos se guardan en `ML_MODEL_DIR` (por defecto `backend/ml_models`, fuera de Git).

### Explicaciones

Para cada predicción se reemplaza un grupo de factores (prioridad, categoría, área, técnico, carga, horario, mes, texto) por su valor típico del entrenamiento y se mide cuánto cambia la probabilidad de incumplimiento. Se muestran los factores con mayor impacto, indicando si aumentan o reducen el riesgo.

## Endpoints

| Método | Ruta | Rol |
|---|---|---|
| GET | `/api/ml/status` | ADMIN, JEFE_TI |
| POST | `/api/ml/train` `{include_synthetic}` | ADMIN, JEFE_TI |
| GET | `/api/ml/predictions?area_id&category_id&priority&technician_id&source&limit` | ADMIN, JEFE_TI |
| GET | `/api/ml/tickets/{id}` | ADMIN, JEFE_TI |
| POST | `/api/ml/predict` | ADMIN, JEFE_TI |
| GET | `/api/ml/recommendations` | ADMIN, JEFE_TI |
| GET | `/api/ml/forecast` | ADMIN, JEFE_TI |
| GET | `/api/ml/insights?period&days&...` | ADMIN, JEFE_TI |
| GET | `/api/ml/dataset.csv?source` | ADMIN, JEFE_TI |
| GET | `/api/llm/status` | todos |
| POST | `/api/llm/chat` `{message, history}` | todos |
| GET | `/api/llm/search?q` | todos (filtrado por permisos) |
| POST | `/api/llm/tickets/{id}/summary` | quien puede ver el ticket |
| POST | `/api/llm/tickets/{id}/suggestions` | ADMIN, JEFE_TI, TECNICO asignado |

Los antiguos `POST /api/ml/predict`, `/api/ml/train` y `/api/llm/chat` sin autenticación (reglas fijas y respuestas simuladas) se eliminaron.

## Asistente LLM

Configuración en el backend (`.env` o variables de Render):

```env
# Opción A: Anthropic (SDK oficial). Modelo por defecto: claude-opus-5-5
LLM_PROVIDER=anthropic
LLM_API_KEY=<clave de la consola de Anthropic>
# LLM_MODEL=claude-opus-5-5
# LLM_EFFORT=low

# Opción B: cualquier endpoint compatible con /chat/completions (por ejemplo Ollama local)
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama3.1
# LLM_API_KEY=   # si el servicio la requiere

# Opción C: Gemini mediante su endpoint compatible con OpenAI (usa la misma integración que la opción B)
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_MODEL=gemini-3.8-flash
LLM_API_KEY=<clave de Google AI Studio>
LLM_MAX_TOKENS=8192   # Gemini descuenta su razonamiento interno de este límite
LLM_EFFORT=low        # se envía como reasoning_effort (minimal | low | medium | high)
LLM_FALLBACK_MODEL=gemini-3.5-flash-lite   # alternativo si LLM_MODEL sigue en HTTP 503; vacío lo desactiva
```

Ante HTTP 503 (modelo saturado) el backend reintenta hasta 3 veces con esperas de 1, 2 y 4 s y, si persiste, repite el ciclo con `LLM_FALLBACK_MODEL` (solo con Gemini). Los errores de autenticación, 400, 404 y 429 no se reintentan. Los mensajes de error se registran sin la API key ni tokens.

Una suscripción de Claude Code no incluye una API key: la clave debe crearse en la consola del proveedor. Sin proveedor configurado, el asistente informa que falta la configuración, muestra solo resultados de la búsqueda local y nunca simula una respuesta.

Funcionamiento: la búsqueda contextual (TF-IDF local) recupera tickets similares que el usuario puede ver (ADMIN/JEFE_TI: todos; TECNICO: resueltos como base de conocimiento y los propios; USUARIO: solo los suyos) y agrega cifras operativas de su alcance. El LLM recibe ese contexto como datos, con instrucciones de citar los números de ticket, no inventar cifras e ignorar instrucciones incrustadas en los tickets.

## Flujo recomendado para la demostración

1. `docker compose up -d --build`
2. `docker compose exec api python -m app.synthetic import`
3. Entrar como administrador → Centro de IA → «Entrenar ahora».
4. Revisar Riesgo SLA, Técnicos, Demanda, Patrones, Simulador y Métricas.
5. (Opcional) Configurar `LLM_PROVIDER` y reiniciar para habilitar el asistente.
6. Para volver a datos reales: `docker compose exec api python -m app.synthetic purge --yes` y reentrenar desmarcando «Incluir tickets sintéticos».

## Limitaciones conocidas

- Con datos sintéticos las métricas solo demuestran que el pipeline funciona; deben recalcularse con datos reales antes de usar las predicciones para decidir.
- El conjunto de evaluación más reciente tiende a contener tickets cortos (los largos aún no han terminado), lo que puede subestimar el error del modelo de tiempos.
- El técnico usado como variable es el asignado actualmente; si hubo reasignaciones, puede diferir del técnico inicial.
- El entrenamiento es síncrono (segundos para 5.000 tickets) y los modelos se guardan en disco: en Render se pierden al reiniciar si no hay disco persistente.
- El recomendador se evalúa con un backtest observacional, no con un experimento controlado.
