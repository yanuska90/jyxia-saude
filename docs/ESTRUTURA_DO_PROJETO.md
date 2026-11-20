# Estrutura Canônica do Repositório JYXIA (Etapa 3.0)

Sincronizada em 20 de novembro de 2026 (`jyxia-develop`) para eliminar duplicidade de pastas, separar responsabilidades com clareza e preparar a base para a fundação institucional em `backend/`.

## Árvore do repositório ativo (`jyxia-saude-trabalho`)

| Caminho | Responsabilidade principal | Publicado no GitHub Pages? |
| --- | --- | --- |
| `README.md` | Ponto de entrada enxuto com resumo do projeto, modalidades e links para `docs/` e demonstração pública | Não |
| `docs/` | Documentação canônica única do repositório (arquitetura, segurança, validação, dependências, estrutura, changelog e materiais de submissão) | Não |
| `frontend/public/` | **Modalidade A — Demonstração pública (`v3.2.0`):** exatos `31` arquivos estáticos publicados via `.github/workflows/pages.yml` (`index.html`, `demo.html`, núcleo ES modules, `documental-manifest.json`, `assets/`, `vendor/` e `fixtures/`) | **Sim (exclusivamente)** |
| `frontend/lab/` | **Modalidade B — Laboratório experimental local (`lab-local.html`, `lab-local.mjs`, `lab-extractor.mjs`):** restrito a `127.0.0.1` / `localhost`, bloqueado com HTTP `404` em `tools/serve_documental.py` | Não |
| `backend/` | **Modalidade C — Fundação institucional (`0.1.0`):** API FastAPI com endpoints `/api/v1/health/live` e `/api/v1/health/ready`, modelos relacionais SQLAlchemy 2.x multi-tenant, migrações Alembic para PostgreSQL e armazenamento controlado sintético | Não |
| `tests/backend/` | Suíte `pytest` institucional (health checks, configuração, sanitização de logs, migrações Alembic, DDL PostgreSQL, 11 modelos/restrições, isolamento multi-tenant e storage controlado) | Não |
| `tests/frontend/` | Suítes JavaScript Node v3, integração real PDF.js e testes do laboratório/benchmark | Não |
| `tests/e2e/` | Teste E2E automatizado com Chromium/Edge via CDP (`test_documental_e2e.mjs`) cobrindo isolamento HTTP, acessibilidade de viewports e fluxo completo das Modalidades A e B | Não |
| `tests/benchmark/` | Gerador e executor determinístico do benchmark sintético interno separado (`benchmark-manifest.json`, `8` casos artificiais) | Não |
| `tests/legacy/` | Testes históricos preservados da fase `v2.x` (`test_security.cjs`, `test_synthetic_import.cjs`, `test_integration.py`) | Não |
| `tools/` | Servidores locais restritos e scripts de verificação (`serve_documental.py`, `serve_lab.py`, `check_publication.py`, `verify_pages_package.py`) | Não |
| `legacy/v2/` | Arquivo histórico isolado da fase `v2.x` (sem reutilização no núcleo v3 nem no novo `backend/`) | Não |
| `.github/workflows/` | Pipelines `security.yml` (`synthetic-checks` + `backend-checks` com PostgreSQL 16) e `pages.yml` (`frontend/public` -> `_site`) | Não |
| `compose.documental.yaml` / `Dockerfile.documental` | Empacotamento local isolado exclusivo da Modalidade A | Não |
| `compose.institutional.yaml` / `backend/Dockerfile` | Compose local institucional com `postgres:16-alpine` e `backend` vinculados a `127.0.0.1` | Não |

## Justificativa explícita para manutenção de `legacy/v2/`

O diretório [`legacy/v2/`](../legacy/v2/) reúne os artefatos da versão `v2.x` (`demo-v2.html`, `vault-crypto.js`, `teleconsultation.js`, `synthetic-import.js`, `integration.py`, `app.py` e fixtures sintéticas antigas) exclusivamente como **arquivo de preservação histórica para execução das suítes de regressão em [`tests/legacy/`](../tests/legacy/)** (`18` testes JS + `11` testes Python).

Decisões estritas sobre `legacy/v2/`:
1. **Sem mistura com `frontend/public/`:** nenhum arquivo de `legacy/v2/` entra no pacote publicado no GitHub Pages (`pages.yml`) nem participa da demonstração documental `v3.2.0`.
2. **Sem reutilização em `backend/`:** a fundação institucional em [`backend/`](../backend/) foi escrita do zero com FastAPI, Pydantic, SQLAlchemy 2.x, Alembic e `psycopg`; não importa e não copia código de `legacy/v2/app.py` nem `legacy/v2/integration.py`.

## Política de pastas fora do Git (`JYXIA_LOCAL_WORK/`)

Backups históricos pré-Git, arquivos antigos aposentados, rascunhos internos fora do escopo versionado e o diretório padrão de armazenamento local sintético (`JYXIA_STORAGE_ROOT=../JYXIA_LOCAL_WORK/synthetic_storage`) residem exclusivamente fora do repositório em `JYXIA_LOCAL_WORK/`, jamais versionados no GitHub.
