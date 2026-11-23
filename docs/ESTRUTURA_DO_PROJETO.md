# Estrutura Canônica do Repositório JYXIA (Etapa 3.0 · Atualizada na Etapa 3.2)

Organização definitiva mantida integralmente na **Etapa 3.2** na branch `jyxia-develop`, sem criação de novas pastas de etapa ou cópias paralelas.

## Árvore do repositório ativo (`jyxia-saude-trabalho`)

| Caminho | Responsabilidade principal | Publicado no GitHub Pages? |
| --- | --- | --- |
| `README.md` | Ponto de entrada enxuto com resumo, modalidades e links para `docs/` e demo pública | Não |
| `docs/` | Documentação canônica única (`ARQUITETURA.md`, `ARQUITETURA_INSTITUCIONAL.md`, `IDENTIDADE_E_AUTORIZACAO.md`, `SEGURANCA.md`, `VALIDACAO_DOCUMENTAL.md`, `DEPENDENCIAS.md`, `ESTRUTURA_DO_PROJETO.md`, `DADOS_FICTICIOS.md`, `INTEGRACOES.md`, `AGENTS.md`, `CHANGELOG.md`, `Submissao_e_video_JYXIA.txt`) | Não |
| `frontend/public/` | **Modalidade A — Demonstração pública (`v3.2.0`):** exatos `31` arquivos estáticos publicados via `.github/workflows/pages.yml` (`index.html`, `demo.html`, núcleo ES modules, `documental-manifest.json`, `assets/`, `vendor/` e `fixtures/`) | **Sim (exclusivamente)** |
| `frontend/lab/` | **Modalidade B — Laboratório experimental local (`lab-local.html`, `lab-local.mjs`, `lab-extractor.mjs`):** restrito a `127.0.0.1` / `localhost`, HTTP `404` em `tools/serve_documental.py` | Não |
| `backend/` | **Modalidade C — Backend institucional (`0.2.0`):** FastAPI com BFF OIDC PKCE `S256` + MFA obrigatório (`acr` + `amr`) + anti-SSRF com pinning de IP no transporte TCP/TLS, `auth_sessions` com rotação e CSRF/Origin estruturado, matriz RBAC de 5 papéis (`document_reviewer` canônico, `document:upload` restrito a `org_admin`/`admin_operator`), `15` modelos SQLAlchemy 2.x, migrations `0001`–`0007` com `FORCE ROW LEVEL SECURITY`/roles separadas `jyxia_app` + `jyxia_worker`/funções `SECURITY DEFINER`, ingestão documental `multipart/form-data` em streaming com enfileiramento atômico em `ProcessingRun`, worker assíncrono independente (`python -m app.worker`), `LocalControlledSyntheticStorage` e etapa determinística `verify_object_integrity` | Não |
| `tests/backend/` | Suíte `pytest` institucional (`51` testes: health, config fail-closed `production`/`staging` inclusive para worker, OIDC/JWKS/PKCE/MFA/anti-SSRF/pinning TCP+TLS+SNI, sessões/rotação/CSRF/RBAC/multi-tenancy/`document_reviewer`, ingestão documental autenticada/validação PDF+PNG/limites em streaming/idempotência/compensação/recuperação, fila assíncrona durável/leases/fencing/reclaim/retry backoff/erros permanentes e consultas HTTP, roles PG `jyxia_app` e `jyxia_worker`/FORCE RLS/`FOR UPDATE SKIP LOCKED` PG16/SECURITY DEFINER anti-spoofing, E2E real Keycloak `26.8.2` + TOTP válido e inválido, migrations `0001`–`0007` e storage controlado) | Não |
| `tests/frontend/` | Suítes JavaScript Node v3, integração real PDF.js e testes do laboratório/benchmark | Não |
| `tests/e2e/` | Teste E2E automatizado com Chromium/Edge via CDP (`test_documental_e2e.mjs`) | Não |
| `tests/benchmark/` | Gerador e executor determinístico do benchmark sintético separado (`8` casos artificiais) | Não |
| `tests/legacy/` | Testes históricos preservados da fase `v2.x` (`test_security.cjs`, `test_synthetic_import.cjs`, `test_integration.py`) | Não |
| `tools/` | Servidores locais restritos e scripts de verificação/CI (`serve_documental.py`, `serve_lab.py`, `check_publication.py`, `verify_pages_package.py`, `sync_backend_deps.py`, `ci_setup_keycloak_e2e.py`) | Não |
| `legacy/v2/` | Arquivo histórico isolado da fase `v2.x` (sem reutilização em `frontend/public/` nem em `backend/`) | Não |
| `.github/workflows/` | Pipelines `security.yml` (`synthetic-checks` + `backend-checks` com PostgreSQL 16 RLS, roles `jyxia_app` e `jyxia_worker`, Keycloak `26.8.2` real e `pip-audit`) e `pages.yml` (`frontend/public` -> `_site`) | Não |
| `compose.documental.yaml` / `Dockerfile.documental` | Empacotamento local isolado exclusivo da Modalidade A | Não |
| `compose.institutional.yaml` / `backend/Dockerfile` | Compose local institucional endurecido (`127.0.0.1`, `postgres:16-alpine`, `keycloak:26.8.2`, backend `read_only: true` conectado como `jyxia_app` e worker `read_only: true` conectado como `jyxia_worker`) | Não |

## Justificativa explícita para manutenção de `legacy/v2/`

O diretório [`legacy/v2/`](../legacy/v2/) preserva os artefatos da versão `v2.x` exclusivamente para execução das regressões históricas em [`tests/legacy/`](../tests/legacy/) (`18` JS + `11` Python), sem mistura com `frontend/public/` e sem qualquer import ou reutilização no [`backend/`](../backend/).

## Política de pastas fora do Git (`JYXIA_LOCAL_WORK/`)

Backups (incluindo bundles Git pré-Etapa 3.0 e pré-Etapa 3.1 com manifestos SHA-256), pacotes históricos arquivados, registros de proveniência Hack Brasil 2026 e o diretório padrão de armazenamento sintético (`JYXIA_STORAGE_ROOT=../JYXIA_LOCAL_WORK/synthetic_storage`) residem exclusivamente fora do repositório em `JYXIA_LOCAL_WORK/`.
