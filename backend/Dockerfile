FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONSAFEPATH=1
WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

COPY backend/app ./backend/app
COPY backend/migrations ./backend/migrations
COPY backend/alembic.ini ./backend/alembic.ini
COPY backend/pyproject.toml ./backend/pyproject.toml
COPY frontend/institutional ./frontend/institutional
COPY frontend/public/vendor ./frontend/public/vendor
COPY frontend/public/assets/favicon.svg ./frontend/public/assets/favicon.svg

RUN useradd --create-home --uid 10001 app \
    && mkdir -p /var/lib/jyxia/synthetic_storage \
    && chown -R app:app /app /var/lib/jyxia

USER app
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=2)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
