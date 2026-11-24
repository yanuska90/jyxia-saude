# Dependências e Reprodutibilidade (`v3.2.0` + Backend Institucional `0.2.0` · Etapa 3.2)

## 1. Frontend estático (`frontend/public/`, `frontend/lab/` e `tests/benchmark/`)

- **PDF.js (`pdfjs-dist`) `6.5.438`** (`https://registry.npmjs.org/pdfjs-dist/-/pdfjs-dist-6.5.438.tgz`), SHA-512 conferido:
  `vg8Pw1x+AFKy4AMDvhuWl5cOYV8d698UoEANoFFhc79hqXDnZQqnOXoxw3HG907WHOg1JYOvLhP756boddFxpA==`
- Distribuído localmente em [`frontend/public/vendor/`](../frontend/public/vendor/) (Apache 2.0: `pdf.min.mjs`, `pdf.worker.min.mjs`, `PDFJS-LICENSE.txt`), sem CDN em execução.
- Testes JavaScript executam em Node.js `24` (`>= 22`) sem `npm install` externo em runtime.

## 2. Backend institucional (`backend/` `0.2.0`) — Fonte única de verdade

[`backend/pyproject.toml`](../backend/pyproject.toml) é a **única fonte canônica** de dependências (Python `>= 3.13, < 3.14`), sincronizada deterministicamente via [`tools/sync_backend_deps.py`](../tools/sync_backend_deps.py):

- **Dependências de runtime ([`backend/requirements.txt`](../backend/requirements.txt) — usadas por `backend/Dockerfile`):**
  - `alembic==1.20.0` (MIT)
  - `certifi==2026.10.23` (MPL-2.0 — CA root verificável para conexões HTTPS OIDC/JWKS)
  - `cryptography==50.0.0` (Apache-2.0 / BSD — AES-256-GCM PKCE e validação de chaves assimétricas)
  - `fastapi==0.142.2` (MIT)
  - `httpx==0.28.1` (BSD-3-Clause — cliente HTTP assíncrono/síncrono para discovery, JWKS e token endpoint OIDC)
  - `pdfminer.six==20260107` (MIT — parser PDF puro em Python, offline, sem execução de JavaScript ou rede, com suporte a texto, caixas delimitadoras por caractere/linha/bloco, `CropBox`, `MediaBox` e rotação)
  - `psycopg==3.3.6` e `psycopg-binary==3.3.6` (LGPL-3.0)
  - `pydantic==2.13.4` (MIT)
  - `PyJWT==2.15.1` (MIT — verificação RS256/ES256 de ID Tokens OIDC com JWKS)
  - `sqlalchemy==2.1.1` (MIT)
  - `uvicorn==0.54.0` (BSD-3-Clause)
- **Dependências exclusivas de teste, lint e auditoria ([`backend/requirements-dev.txt`](../backend/requirements-dev.txt) — fora da imagem Docker de produção):**
  - Inclui todas as dependências de runtime acima mais:
  - `pip-audit==2.10.1` (Apache-2.0)
  - `pytest==9.2.0` (MIT)
  - `ruff==0.17.6` (MIT — linter estático executado localmente e em CI)

## 3. Provedor de identidade de desenvolvimento/CI e containers

- **Keycloak `26.8.2` (`quay.io/keycloak/keycloak:26.8.2`, Apache-2.0):** utilizado apenas como IdP OIDC padrão de desenvolvimento local em [`compose.institutional.yaml`](../compose.institutional.yaml) (`127.0.0.1:8080`) e nos testes E2E reais em CI ([`.github/workflows/security.yml`](../.github/workflows/security.yml)), importando o realm sintético [`backend/keycloak/jyxia-dev-realm.json`](../backend/keycloak/jyxia-dev-realm.json) com PKCE `S256` e fluxo TOTP LoA 2 (`urn:jyxia:loa:mfa`).
- As imagens [`Dockerfile.documental`](../Dockerfile.documental) e [`backend/Dockerfile`](../backend/Dockerfile) usam `python:3.13-slim` fixada por digest SHA-256 (`USER 10001`, `PYTHONSAFEPATH=1`), e [`compose.institutional.yaml`](../compose.institutional.yaml) usa `postgres:16-alpine` vinculado apenas a `127.0.0.1` com separação entre owner de migrações e role runtime `jyxia_app`.
- Em CI ([`.github/workflows/security.yml`](../.github/workflows/security.yml)), um ambiente virtual limpo instala `backend/requirements-dev.txt`, valida `tools/sync_backend_deps.py --check` e executa `pip-audit`.
