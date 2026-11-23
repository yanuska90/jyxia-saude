# JYXIA Inteligência Documental em Saúde

Demonstração pública **3.2.0** (`frontend/public/`) · Backend institucional **0.2.0** (`backend/` · Etapa 3.3.3) · Documentação sincronizada em **23 de novembro de 2026** · Yanuska e João.

A JYXIA é uma camada administrativa de conferência e organização de documentos externos em saúde, complementar ao prontuário eletrônico (PEP), com vinculação visual à página original e revisão humana obrigatória. O primeiro recorte em investigação é a **conferência documental para procedimentos eletivos**.

- [Site HTTPS (Modalidade A)](https://yanuska90.github.io/jyxia-saude/)
- [Demo documental HTTPS](https://yanuska90.github.io/jyxia-saude/demo.html)
- [Projeto completo em DOCX](frontend/public/assets/Projeto_JYXIA_Inteligencia_Documental_v3.docx)
- [18 exemplos fictícios para baixar](frontend/public/assets/fixtures-jyxia.zip)

## Modalidades e estrutura canônica (`Etapas 3.0–3.2`)

1. **Modalidade A — Demonstração pública (`frontend/public/`):** exatos **`31` arquivos** estáticos publicados seletivamente pelo [`.github/workflows/pages.yml`](.github/workflows/pages.yml), restritos ao catálogo sintético fechado de `18` fixtures validados por SHA-256 (`documental-manifest.json`) e `9` cenários no navegador, com Mozilla PDF.js `6.5.438` (`frontend/public/vendor/`). Permanece 100% estática e desconectada do backend.
2. **Modalidade B — Laboratório experimental local (`frontend/lab/` + `tools/serve_lab.py`):** ambiente estritamente isolado em `127.0.0.1` / `localhost` (**fora do GitHub Pages e bloqueado com HTTP `404` em `tools/serve_documental.py`**) para testes de diagramação, rotações e aliases explícitos sem OCR e sem persistência em disco.
3. **Modalidade C — Backend institucional (`backend/` `0.2.0`):** FastAPI com BFF OpenID Connect (PKCE `S256` + JWKS + **MFA obrigatório exigindo `acr` e segundo fator em `amr`** + proteção anti-SSRF com pinning de IP no transporte TCP/TLS `_PinnedOidcNetworkBackend`, Keycloak `26.8.2` em dev/CI), cookies opacos com rotação na troca de organização e proteção CSRF/`Origin` estruturada, vinculação `(issuer, subject)`, matriz RBAC administrativa em `5` papéis (`org_admin`, `admin_operator`, `document_reviewer`, `auditor_readonly`, `read_only`), `15` modelos relacionais em SQLAlchemy 2.x, migrations `0001`–`0008`, PostgreSQL 16 com separação `jyxia_app` + `jyxia_worker` vs. `migration_owner`, **`FORCE ROW LEVEL SECURITY`**, trilha append-only (`AuditEvent` e `SecurityAuditEvent` via `SECURITY DEFINER` com comprovação de sessão ativa ou lease de worker + triggers `UPDATE`/`DELETE`/`TRUNCATE`), ingestão documental sintética autenticada, fila PostgreSQL 16 (`ProcessingRun`, `FOR UPDATE SKIP LOCKED`, leases com prova `lease_token_hash`, recuperação de leases expirados, backoff exponencial com jitter), **encadeamento transacional de `verify_object_integrity` -> `extract_pdf_text` (Etapa 3.3.3)** com extração determinística por página via `pdfminer.six`, normalização conservadora por allowlist explícita (`11` chaves contratuais), evidências espaciais normalizadas `[x, y, w, h]` com `CropBox`/`MediaBox` e rotação `0°/90°/180°/270°`, abstenção explícita para PDFs sem camada textual/parciais/corrompidos/criptografados e PNG (`OCR_NOT_IMPLEMENTED`), persistência idempotente em `ExtractedField` + `EvidenceReference` e consultas HTTP autenticadas (`extracted-fields`, `evidence`) sob RBAC e RLS. **OCR, visão computacional, LLM, comparação automatizada dos 4 eixos no backend, equivalências clínicas, revisão humana completa, S3/KMS/WORM e conectores hospitalares permanecem intencionalmente fora desta entrega.**
4. **Arquivo histórico preservado isoladamente (`legacy/v2/`):** artefatos da fase `v2.x` mantidos exclusivamente para as regressões em `tests/legacy/`, sem conexão com `frontend/public/` e sem reutilização em `backend/`.

## Como executar e verificar localmente

```sh
# 1. Demonstração pública (Modalidade A — localhost)
python tools/serve_documental.py --bind 127.0.0.1 --port 8000

# 2. Laboratório experimental local (Modalidade B — localhost exclusivo)
python tools/serve_lab.py --bind 127.0.0.1 --port 8099

# 3. API institucional e Worker assíncrono (Modalidade C — PostgreSQL + IdP OIDC em dev/CI)
uvicorn --app-dir backend app.main:app --host 127.0.0.1 --port 8001
PYTHONPATH=backend python -m app.worker --once

# 4. Suítes automatizadas completas
node --test tests/frontend/test_documental.mjs tests/frontend/test_documental_pdfjs.mjs tests/frontend/test_lab_and_benchmark.mjs tests/legacy/test_security.cjs tests/legacy/test_synthetic_import.cjs
python -m unittest discover -s tests/legacy -v
pytest tests/backend -v
python tools/check_publication.py
node tests/e2e/test_documental_e2e.mjs
python tools/verify_pages_package.py
```

## Documentação canônica (`docs/`)

Consulte exclusivamente [`docs/`](docs/):
- [`docs/ESTRUTURA_DO_PROJETO.md`](docs/ESTRUTURA_DO_PROJETO.md) — mapa definitivo de diretórios e justificativa de `legacy/v2/`.
- [`docs/ARQUITETURA_INSTITUCIONAL.md`](docs/ARQUITETURA_INSTITUCIONAL.md) — arquitetura `backend/` `0.2.0`, modelos multi-tenant, migrações e hardening.
- [`docs/IDENTIDADE_E_AUTORIZACAO.md`](docs/IDENTIDADE_E_AUTORIZACAO.md) — fluxo BFF OIDC PKCE/MFA, sessões, CSRF, `(issuer, subject)`, RBAC em 5 papéis e PostgreSQL RLS/`jyxia_app`.
- [`docs/ARQUITETURA.md`](docs/ARQUITETURA.md) — visão consolidada das Modalidades A, B e C.
- [`docs/SEGURANCA.md`](docs/SEGURANCA.md) — fronteiras, controles atuais, lacunas e requisitos para dados reais.
- [`docs/VALIDACAO_DOCUMENTAL.md`](docs/VALIDACAO_DOCUMENTAL.md) — métricas observadas e pendências honestas.
- [`docs/DADOS_FICTICIOS.md`](docs/DADOS_FICTICIOS.md), [`docs/DEPENDENCIAS.md`](docs/DEPENDENCIAS.md), [`docs/INTEGRACOES.md`](docs/INTEGRACOES.md), [`docs/AGENTS.md`](docs/AGENTS.md) e [`docs/CHANGELOG.md`](docs/CHANGELOG.md).
