FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     PIP_NO_CACHE_DIR=1
WORKDIR /srv/fixit
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /srv/fixit/backend

# The Python package is backend/app. Keeping that directory on PYTHONPATH makes
# imports identical for Alembic, Uvicorn, tests, and one-off administrative jobs.
ENV PYTHONPATH=/srv/fixit/backend
WORKDIR /srv/fixit/backend
# Unprivileged user: the code is read-only for it; it can only write uploads and the ML model cache.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin fixit     && mkdir -p /srv/fixit/backend/uploads /srv/fixit/backend/ml_models     && chown -R fixit:fixit /srv/fixit/backend/uploads /srv/fixit/backend/ml_models
USER fixit
EXPOSE 8000

CMD sh -c "alembic -c /srv/fixit/backend/alembic.ini upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --no-server-header"
