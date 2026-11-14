FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt requirements-lock.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c requirements-lock.txt && useradd --create-home --uid 10001 app
COPY app.py integration.py index.html demo.html demo.js records.js vault.js vault-crypto.js teleconsultation.js runtime-config.js style.css patient-search.js integrations.js integration-demo.json synthetic-import.js paciente-ficticio-01.json anexo-ficticio-01.txt ./
USER app
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
