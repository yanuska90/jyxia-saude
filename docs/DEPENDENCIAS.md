# Dependências e Reprodutibilidade (`v3.2.0` + Backend Institucional `0.1.0` · Etapa 3.1)

## 1. Frontend estático (`frontend/public/`, `frontend/lab/` e `tests/benchmark/`)

- **PDF.js (`pdfjs-dist`) `6.5.438`** (`https://registry.npmjs.org/pdfjs-dist/-/pdfjs-dist-6.5.438.tgz`), SHA-512 conferido:
  `vg8Pw1x+AFKy4AMDvhuWl5cOYV8d698UoEANoFFhc79hqXDnZQqnOXoxw3HG907WHOg1JYOvLhP756boddFxpA==`
- Distribuído localmente em [`frontend/public/vendor/`](../frontend/public/vendor/) (Apache 2.0: `pdf.min.mjs`, `pdf.worker.min.mjs`, `PDFJS-LICENSE.txt`), sem CDN em execução.
- Testes JavaScript executam em Node.js `24` (`>= 22`) sem `npm install` externo em runtime.

## 2. Backend institucional (`backend/` `0.1.0`) — Fonte única de verdade

Na **Etapa 3.1**, [`backend/pyproject.toml`](../backend/pyproject.toml) passou a ser a **única fonte canônica** de dependências (Python `>= 3.13, < 3.14`), com exportação determinística verificada por [`tools/sync_backend_deps.py`](../tools/sync_backend_deps.py):

- **Dependências de runtime ([`backend/requirements.txt`](../backend/requirements.txt) — usadas por `backend/Dockerfile`):**
  - `alembic==1.20.0` (LGPL/MIT ecosystem)
  - `fastapi==0.142.2` (MIT)
  - `psycopg==3.3.6` e `psycopg-binary==3.3.6` (LGPL-3.0)
  - `pydantic==2.13.4` (MIT)
  - `sqlalchemy==2.1.1` (MIT)
  - `uvicorn==0.54.0` (BSD-3-Clause)
- **Dependências exclusivas de teste e auditoria ([`backend/requirements-dev.txt`](../backend/requirements-dev.txt) — fora da imagem Docker de produção):**
  - Inclui todas as dependências de runtime acima mais:
  - `certifi==2026.10.23` (MPL-2.0; atualizada sobre `2026.7.22` identificada com `GHSA-6q48-6c7w-9gw2`)
  - `httpx==0.28.1` (BSD-3-Clause)
  - `pip-audit==2.10.1` (Apache-2.0)
  - `pytest==9.2.0` (MIT; atualizada para CI em substituição a `pytest==8.2.2`, que possuía avisos `GHSA-6w46-j5rx-g56g` / `PYSEC-2026-1845` corrigidos a partir de `9.0.3`, e removida totalmente do runtime de produção)

## 3. Auditoria de vulnerabilidades e containers

- Localmente na estação Windows (`pytest==8.2.2` pré-instalado no sistema global, sem alterar o Python global do host), a auditoria via API OSV indicou zero vulnerabilidades nas 7 dependências diretas de runtime (`fastapi`, `pydantic`, `sqlalchemy`, `alembic`, `psycopg`, `psycopg-binary`, `uvicorn`) e sinalizou os avisos corrigidos em `pytest>=9.0.3` e `certifi>=2026.10.18`; além disso, o pacote local auxiliar `opentelemetry-api==1.45.0` no ambiente global do host possui avisos OSV (`GHSA-mf5v-w3w3-f6cg`, `GHSA-xcq7-p3pf-p88h` corrigidos em `1.45.2`), motivo pelo qual **não é dependência do backend** e permanece ausente da imagem e dos requisitos do projeto.
- Em CI ([`.github/workflows/security.yml`](../.github/workflows/security.yml)), um ambiente virtual isolado instala exclusivamente `backend/requirements-dev.txt`, confere paridade via `python3 tools/sync_backend_deps.py --check` e executa `pip-audit` em todas as dependências diretas e transitivas.
- As imagens [`Dockerfile.documental`](../Dockerfile.documental) e [`backend/Dockerfile`](../backend/Dockerfile) usam `python:3.13-slim` fixada por digest SHA-256 (`USER 10001`, `PYTHONSAFEPATH=1`, health check nativo), e [`compose.institutional.yaml`](../compose.institutional.yaml) usa `postgres:16-alpine` vinculado apenas a `127.0.0.1`.
