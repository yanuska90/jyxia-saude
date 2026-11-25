# JYXIA Inteligência Documental em Saúde

Demonstração pública **3.2.0** (`frontend/public/`) · Backend e Interface Institucional de Revisão Humana **0.2.0** (`backend/` + `frontend/institutional/` · Etapa 3.3.5 / motor `3.3.4.1`) · Yanuska e João.

A JYXIA é uma camada administrativa de conferência e organização de documentos externos em saúde, complementar ao prontuário eletrônico (PEP), com vinculação visual à página original, orientação explícita de pendências e revisão humana obrigatória. O primeiro recorte em investigação é a **conferência documental para procedimentos eletivos**.

- [Site HTTPS (Modalidade A)](https://yanuska90.github.io/jyxia-saude/)
- [Demo documental HTTPS](https://yanuska90.github.io/jyxia-saude/demo.html)
- [Plano base v3.0 de 14/11/2026 em DOCX](frontend/public/assets/Projeto_JYXIA_Inteligencia_Documental_v3.docx)
- [18 exemplos fictícios para baixar](frontend/public/assets/fixtures-jyxia.zip)

## Modalidades e estrutura canônica

1. **Modalidade A — Demonstração pública (`frontend/public/`):** exatos **`31` arquivos** estáticos publicados seletivamente pelo [`.github/workflows/pages.yml`](.github/workflows/pages.yml), restritos ao catálogo sintético fechado de `18` fixtures validados por SHA-256 (`documental-manifest.json`) e `9` cenários no navegador, com Mozilla PDF.js `6.5.438` (`frontend/public/vendor/`). Incorpora as melhorias de usabilidade e acessibilidade da entrega `3.1.0` (`22/11/2026` em `origin/main`: seções educativas em `index.html`, guia `<details class="demo-guide">`, `<noscript>`, `taskGuidance` + `Abrir documento` com foco em `#document-name`, `@media (forced-colors: active)`, escalas legíveis para `320px`/`390px` e cache-busting `?v=3.2.0`), mantendo os `4` eixos e `5` estados gerais da `3.2.0`. Permanece 100% estática e desconectada do backend.
2. **Modalidade B — Laboratório experimental local (`frontend/lab/` + `tools/serve_lab.py`):** ambiente estritamente isolado em `127.0.0.1` / `localhost` (**fora do GitHub Pages e bloqueado com HTTP `404` em `tools/serve_documental.py`**) para testes de diagramação, rotações e aliases explícitos sem OCR e sem persistência em disco.
3. **Modalidade C — Backend e Interface Institucional de Revisão Humana (`backend/` `0.2.0` + `frontend/institutional/`):** FastAPI com BFF OpenID Connect (PKCE `S256` + JWKS + **MFA obrigatório exigindo `acr` e segundo fator em `amr`** + proteção anti-SSRF com pinning de IP no transporte TCP/TLS `_PinnedOidcNetworkBackend`, Keycloak `26.8.2` em dev/CI), cookies opacos com rotação na troca de organização e proteção CSRF/`Origin` estruturada, vinculação `(issuer, subject)`, matriz RBAC administrativa em `5` papéis (`org_admin`, `admin_operator`, `document_reviewer`, `auditor_readonly`, `read_only`), `18` modelos relacionais em SQLAlchemy 2.x, migrations `0001`–`0010`, PostgreSQL 16 com separação `jyxia_app` + `jyxia_worker` vs. `migration_owner`, **`FORCE ROW LEVEL SECURITY`**, trilha append-only (`AuditEvent` e `SecurityAuditEvent` via `SECURITY DEFINER` com comprovação de sessão ativa ou lease de worker + triggers `UPDATE`/`DELETE`/`TRUNCATE`), ingestão documental sintética autenticada, fila PostgreSQL 16 (`ProcessingRun`, `FOR UPDATE SKIP LOCKED`, leases com prova `lease_token_hash`, recuperação de leases expirados, backoff exponencial com jitter), **encadeamento transacional `verify_object_integrity` -> `extract_pdf_text` -> barreira `compare_consistency` (Etapa 3.3.4 / `3.3.4.1`)** com extração determinística por página via `pdfminer.six`, **motor determinístico de consistência dos 4 eixos (`identidade`, `procedimento_codigo`, `lateralidade`, `temporalidade`)** e **fluxo ponta a ponta de revisão humana administrativa (`HumanReview` append-only protegido por triggers e revogação SQL + unicidade transacional + enfileiramento atômico de `compare_consistency` + interface same-origin `/institutional/` com PDF.js local, sequenciador monotônico anti-corrida, destaque espacial de evidências, comparação lado a lado e reavaliação determinística pós-revisão na Etapa 3.3.5)** sob RBAC (`field:review` / `document:read` / `document:upload`), `no-store` e RLS. **OCR, LLM, equivalências clínicas, aprovação clínica (`clinical_approval=false`), S3/KMS/WORM e conectores hospitalares permanecem intencionalmente fora desta entrega.**
4. **Arquivo histórico preservado isoladamente (`legacy/v2/`):** artefatos da fase `v2.x` (`demo-v2.html`, cofre local e API antiga) mantidos exclusivamente para as regressões em `tests/legacy/`, sem conexão com `frontend/public/` e sem reutilização em `backend/`.

## Escopo real, validação e pesquisa em planejamento

- A demonstração pública usa **extração determinística de PDFs com texto** (sem OCR de imagens, sem IA generativa, sem login e sem envio de arquivos a servidor). Imagens ilegíveis entram em quarentena/abstenção; “Documentação conferida” refere-se às regras administrativas dos exemplos e **não autoriza procedimento clínico**.
- **Atividades em planejamento (não executadas até o momento):** iniciar entrevistas de descoberta com `3–5` profissionais de apoio/pré-operatório, investigar comparativamente a hipótese de preparação documental para convênios versus conferência interna, e avaliar um conjunto exploratório separado de cerca de `30` casos sintéticos adicionais frente ao trabalho manual (incluindo acessibilidade assistida). Nenhuma validação clínica, hospitalar ou benefício operacional foi medido ou reivindicado ainda.

## Como executar e verificar localmente

```sh
# 1. Demonstração pública (Modalidade A — localhost)
python tools/serve_documental.py --bind 127.0.0.1 --port 8000
# ou via Docker estático endurecido (read_only, 127.0.0.1:8000):
docker compose -f compose.documental.yaml up --build

# 2. Laboratório experimental local (Modalidade B — localhost exclusivo)
python tools/serve_lab.py --bind 127.0.0.1 --port 8099

# 3. API institucional e Worker assíncrono (Modalidade C — PostgreSQL + IdP OIDC em dev/CI)
uvicorn --app-dir backend app.main:app --host 127.0.0.1 --port 8001
PYTHONPATH=backend python -m app.worker --once

# 4. Suítes automatizadas completas
node --test tests/frontend/test_documental.mjs tests/frontend/test_documental_pdfjs.mjs tests/frontend/test_lab_and_benchmark.mjs tests/frontend/test_institutional_ui.mjs tests/legacy/test_security.cjs tests/legacy/test_synthetic_import.cjs
python -m unittest discover -s tests/legacy -v
pytest tests/backend -v -rs
python tools/check_publication.py
node tests/e2e/test_documental_e2e.mjs
node tests/e2e/test_institutional_e2e.mjs
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
