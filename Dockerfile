FROM python:3.12-slim
WORKDIR /srv/fixit
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /srv/fixit/backend

# The Python package is backend/app. Keeping that directory on PYTHONPATH makes
# imports identical for Alembic, Uvicorn, tests, and one-off administrative jobs.
ENV PYTHONPATH=/srv/fixit/backend
WORKDIR /srv/fixit/backend
RUN mkdir -p /srv/fixit/backend/uploads
EXPOSE 8000

CMD sh -c "alembic -c /srv/fixit/backend/alembic.ini upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"