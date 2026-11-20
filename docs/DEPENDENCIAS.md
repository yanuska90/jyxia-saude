# Dependências do projeto (`v3.2.0` + Backend Institucional `0.1.0`)

## 1. Frontend estático (`frontend/public/`, `frontend/lab/` e `tests/benchmark/`)

PDF.js (`pdfjs-dist`) `6.5.438`, pacote oficial do registro npm:
`https://registry.npmjs.org/pdfjs-dist/-/pdfjs-dist-6.5.438.tgz`

Integridade SHA512 do pacote conferida na preparação:
`vg8Pw1x+AFKy4AMDvhuWl5cOYV8d698UoEANoFFhc79hqXDnZQqnOXoxw3HG907WHOg1JYOvLhP756boddFxpA==`

Arquivos distribuídos localmente em [`frontend/public/vendor/`](../frontend/public/vendor/) (Apache 2.0): `pdf.min.mjs`, `pdf.worker.min.mjs` e `PDFJS-LICENSE.txt`. Nenhuma dependência é carregada por CDN em execução.

Os testes JavaScript usam Node.js `24` (ou superior `>= 22`) sem `npm install` externo em runtime.

## 2. Backend institucional (`backend/` `0.1.0`) e utilitários

Python `3.13` executa tanto os utilitários em [`tools/`](../tools/) e testes legados em [`tests/legacy/`](../tests/legacy/) quanto a fundação institucional em [`backend/`](../backend/), com versões fixadas em [`backend/requirements.txt`](../backend/requirements.txt):

- `fastapi==0.142.2`
- `pydantic==2.13.4`
- `sqlalchemy==2.1.1`
- `alembic==1.20.0`
- `psycopg==3.3.6` e `psycopg-binary==3.3.6`
- `uvicorn==0.54.0`
- `httpx==0.28.1`
- `pytest==8.2.2`

As imagens Docker [`Dockerfile.documental`](../Dockerfile.documental) e [`backend/Dockerfile`](../backend/Dockerfile) usam a mesma imagem base `python:3.13-slim` fixada por digest SHA-256, e [`compose.institutional.yaml`](../compose.institutional.yaml) usa `postgres:16-alpine`. Fixar versões não elimina vulnerabilidades; revisar dependências continuamente antes de operação institucional.
