# Estrutura Canônica do Repositório JYXIA (Etapa 3.0 · Revisada na Etapa 3.1)

Organização definitiva mantida integralmente na **Etapa 3.1** na branch `jyxia-develop`, sem criação de novas pastas de etapa ou cópias paralelas.

## Árvore do repositório ativo (`jyxia-saude-trabalho`)

| Caminho | Responsabilidade principal | Publicado no GitHub Pages? |
| --- | --- | --- |
| `README.md` | Ponto de entrada enxuto com resumo, modalidades e links para `docs/` e demo pública | Não |
| `docs/` | Documentação canônica única (`ARQUITETURA.md`, `ARQUITETURA_INSTITUCIONAL.md`, `SEGURANCA.md`, `VALIDACAO_DOCUMENTAL.md`, `DEPENDENCIAS.md`, `ESTRUTURA_DO_PROJETO.md`, `DADOS_FICTICIOS.md`, `INTEGRACOES.md`, `AGENTS.md`, `CHANGELOG.md`, `Submissao_e_video_JYXIA.txt`) | Não |
| `frontend/public/` | **Modalidade A — Demonstração pública (`v3.2.0`):** exatos `31` arquivos estáticos publicados via `.github/workflows/pages.yml` (`index.html`, `demo.html`, núcleo ES modules, `documental-manifest.json`, `assets/`, `vendor/` e `fixtures/`) | **Sim (exclusivamente)** |
| `frontend/lab/` | **Modalidade B — Laboratório experimental local (`lab-local.html`, `lab-local.mjs`, `lab-extractor.mjs`):** restrito a `127.0.0.1` / `localhost`, HTTP `404` em `tools/serve_documental.py` | Não |
| `backend/` | **Modalidade C — Fundação institucional (`0.1.0`):** FastAPI (`/api/v1/health/live` e `/ready`), `11` modelos SQLAlchemy 2.x multi-tenant endurecidos, migrations Alembic `0001` e `0002`, triggers PostgreSQL/SQLite em `audit_events`, storage sintético atômico e `pyproject.toml` como fonte única de dependências (`requirements.txt` runtime e `requirements-dev.txt` dev/CI) | Não |
| `tests/backend/` | Suíte `pytest` institucional (health checks, configuração fail-closed, contratos, sanitização de logs, paridade de dependências, migrações `0001`/`0002`, DDL PostgreSQL, 11 modelos, triggers SQL `UPDATE`/`DELETE`, concorrência de auditoria, detecção de adulteração, isolamento multi-tenant e storage controlado) | Não |
| `tests/frontend/` | Suítes JavaScript Node v3, integração real PDF.js e testes do laboratório/benchmark | Não |
| `tests/e2e/` | Teste E2E automatizado com Chromium/Edge via CDP (`test_documental_e2e.mjs`) | Não |
| `tests/benchmark/` | Gerador e executor determinístico do benchmark sintético separado (`8` casos artificiais) | Não |
| `tests/legacy/` | Testes históricos preservados da fase `v2.x` (`test_security.cjs`, `test_synthetic_import.cjs`, `test_integration.py`) | Não |
| `tools/` | Servidores locais restritos e scripts de verificação (`serve_documental.py`, `serve_lab.py`, `check_publication.py`, `verify_pages_package.py`, `sync_backend_deps.py`) | Não |
| `legacy/v2/` | Arquivo histórico isolado da fase `v2.x` (sem reutilização em `frontend/public/` nem em `backend/`) | Não |
| `.github/workflows/` | Pipelines `security.yml` (`synthetic-checks` + `backend-checks` com PostgreSQL 16 e `pip-audit`) e `pages.yml` (`frontend/public` -> `_site`) | Não |
| `compose.documental.yaml` / `Dockerfile.documental` | Empacotamento local isolado exclusivo da Modalidade A | Não |
| `compose.institutional.yaml` / `backend/Dockerfile` | Compose local institucional endurecido (`127.0.0.1`, `read_only: true`, `postgres:16-alpine`) | Não |

## Justificativa explícita para manutenção de `legacy/v2/`

O diretório [`legacy/v2/`](../legacy/v2/) preserva os artefatos da versão `v2.x` exclusivamente para execução das regressões históricas em [`tests/legacy/`](../tests/legacy/) (`18` JS + `11` Python), sem mistura com `frontend/public/` e sem qualquer import ou reutilização no [`backend/`](../backend/).

## Política de pastas fora do Git (`JYXIA_LOCAL_WORK/`)

Backups (incluindo bundles Git pré-Etapa 3.0 e pré-Etapa 3.1 com manifestos SHA-256), pacotes históricos arquivados, registros de proveniência Hack Brasil 2026 e o diretório padrão de armazenamento sintético (`JYXIA_STORAGE_ROOT=../JYXIA_LOCAL_WORK/synthetic_storage`) residem exclusivamente fora do repositório em `JYXIA_LOCAL_WORK/`.
