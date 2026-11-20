# JYXIA Inteligência Documental em Saúde

Demonstração pública **3.2.0** (`frontend/public/`) · Fundação institucional inicial **0.1.0** (`backend/`) · Documentação sincronizada em **20 de novembro de 2026** · Yanuska e João.

A JYXIA é uma camada administrativa de conferência e organização de documentos externos em saúde, complementar ao prontuário eletrônico (PEP), com vinculação visual à página original e revisão humana obrigatória. O primeiro recorte em investigação é a **conferência documental para procedimentos eletivos**.

- [Site HTTPS (Modalidade A)](https://yanuska90.github.io/jyxia-saude/)
- [Demo documental HTTPS](https://yanuska90.github.io/jyxia-saude/demo.html)
- [Projeto completo em DOCX](frontend/public/assets/Projeto_JYXIA_Inteligencia_Documental_v3.docx)
- [18 exemplos fictícios para baixar](frontend/public/assets/fixtures-jyxia.zip)

## Modalidades e estrutura canônica (`Etapa 3.0`)

1. **Modalidade A — Demonstração pública (`frontend/public/`):** exatos **`31` arquivos** estáticos publicados seletivamente pelo [`.github/workflows/pages.yml`](.github/workflows/pages.yml), restritos ao catálogo sintético fechado de `18` fixtures validados por SHA-256 (`documental-manifest.json`) e `9` cenários no navegador, com Mozilla PDF.js `6.5.438` (`frontend/public/vendor/`).
2. **Modalidade B — Laboratório experimental local (`frontend/lab/` + `tools/serve_lab.py`):** ambiente estritamente isolado em `127.0.0.1` / `localhost` (**fora do GitHub Pages e bloqueado com HTTP `404` em `tools/serve_documental.py`**) para testes de diagramação, rotações e aliases explícitos sem OCR e sem persistência em disco.
3. **Modalidade C — Fundação institucional (`backend/` `0.1.0`):** API inicial em FastAPI (`GET /api/v1/health/live` e `GET /api/v1/health/ready`), `11` modelos relacionais multi-tenant em SQLAlchemy 2.x com FKs compostas por organização, migração Alembic pronta para PostgreSQL 16, trilha append-only `AuditEvent` encadeada por SHA-256, `LocalControlledSyntheticStorage` confinado em `../JYXIA_LOCAL_WORK/synthetic_storage` e contratos preparatórios de OIDC/MFA/RBAC e processamento. **Rotas clínicas/administrativas HTTP, OIDC/MFA ativo, OCR, LLM, S3 e conectores hospitalares permanecem intencionalmente fora desta entrega.**
4. **Arquivo histórico preservado isoladamente (`legacy/v2/`):** artefatos da fase `v2.x` mantidos exclusivamente para as regressões em `tests/legacy/`, sem conexão com `frontend/public/` e sem reutilização em `backend/`.

## Como executar e verificar localmente

```sh
# 1. Demonstração pública (Modalidade A — localhost)
python tools/serve_documental.py --bind 127.0.0.1 --port 8000

# 2. Laboratório experimental local (Modalidade B — localhost exclusivo)
python tools/serve_lab.py --bind 127.0.0.1 --port 8099

# 3. API institucional inicial (Modalidade C — apenas /api/v1/health/live e /ready)
# Requer JYXIA_DATABASE_URL configurado localmente (ver .env.example e compose.institutional.yaml)
uvicorn --app-dir backend app.main:app --host 127.0.0.1 --port 8001

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
- [`docs/ARQUITETURA_INSTITUCIONAL.md`](docs/ARQUITETURA_INSTITUCIONAL.md) — fundação `backend/` `0.1.0`, modelos multi-tenant, migrações e limites.
- [`docs/ARQUITETURA.md`](docs/ARQUITETURA.md) — visão consolidada das Modalidades A, B e C.
- [`docs/SEGURANCA.md`](docs/SEGURANCA.md) — fronteiras, controles atuais, lacunas e requisitos para dados reais.
- [`docs/VALIDACAO_DOCUMENTAL.md`](docs/VALIDACAO_DOCUMENTAL.md) — métricas observadas e pendências honestas.
- [`docs/DADOS_FICTICIOS.md`](docs/DADOS_FICTICIOS.md), [`docs/DEPENDENCIAS.md`](docs/DEPENDENCIAS.md), [`docs/INTEGRACOES.md`](docs/INTEGRACOES.md), [`docs/AGENTS.md`](docs/AGENTS.md) e [`docs/CHANGELOG.md`](docs/CHANGELOG.md).
