# Validação Técnica e Documental da JYXIA (`v3.2.0` + Fundação `0.1.0`)

## 1. Verificações automatizadas executadas (`20/11/2026`, branch `jyxia-develop`)

- **Núcleo v3 + PDF.js real + Laboratório e Benchmark (`37` testes automatizados em Node — `37/37` pass):**
  - **`28` testes unitários (`tests/frontend/test_documental.mjs`):** catálogo SHA-256 de `18` fixtures e limites; evidência espacial e quarentena em ambiguidade; **Cenário 1 parcial convergindo para `abstencao` e Cenário 9 completo convergindo para `conferida`**; deduplicação e bloqueio de auto-substituição; conflito e ausência de identificador; imagem PNG em quarentena sem análise de assinatura; justificativa de correção e preservação do valor extraído; cadeia de substituições sem ciclos; exportação JSON/CSV e integridade da cadeia SHA-256 (`verifyEventsReport`); comparação conservadora de procedimentos/códigos sem inventar sinônimos clínicos; `syntheticMarkerCue` separado de `humanVisualObservation`; todos os `5` estados gerais e `6` estados de eixo; neutralização `csvSafeCell`.
  - **`6` testes reais com `frontend/public/vendor/pdf.min.mjs` (`tests/frontend/test_documental_pdfjs.mjs`):** extração real com coordenadas `[0,1]^4` nos `15` PDFs do catálogo; execução completa de ponta a ponta incluindo Cenário 1 (`abstencao`) e Cenário 9 (`conferida`); recusa `>5` páginas via `loadingTask.destroy`; PDF corrompido; PDF sem texto + `rotate: 90`; conflito real `OD × OE`.
  - **`3` testes de laboratório local e benchmark (`tests/frontend/test_lab_and_benchmark.mjs` + `tests/benchmark/run_benchmark.mjs`):** trava estrita de `localhost` e assinatura `%PDF-`; aliases explícitos e abstenção em ambiguidade/dados sem rótulo; benchmark sintético interno (`8/8` casos artificiais aprovados, `0` falsos positivos e `0` falsos negativos críticos em Identidade e Lateralidade).
- **Regressão histórica v2.x preservada isoladamente (`tests/legacy/`):** `18` testes JS (`test_security.cjs` + `test_synthetic_import.cjs`) e `11` testes Python (`test_integration.py`) = **`29` testes legados aprovados (`55/55` totais no Node + `11/11` Python)**.
- **Fundação Institucional `0.1.0` (`tests/backend/` — `17/17` testes Pytest aprovados):**
  - Inicialização FastAPI sem rotas clínicas/administrativas expostas e desligamento de `/docs` em produção;
  - `GET /api/v1/health/live` (`200`) e `GET /api/v1/health/ready` (`200` saudável / `503` sanitizado sem vazamento de DSN ou credenciais);
  - Validação fail-closed de configuração de ambiente (`load_settings`), contratos preparatórios OIDC/MFA/RBAC (`StubOidcAuthenticator`), contratos puros de processamento (`UnimplementedOcrAdapter`) e sanitização de logs (`SanitizingFilter` + teste de não-vazamento em `record_extracted_field`);
  - Varredura de ausência de segredos e ausência total de imports de `legacy/v2`;
  - Ciclo completo Alembic (`upgrade head` -> comparação sem divergência -> `downgrade base` -> `upgrade head`) e compilação DDL explícita para PostgreSQL (`JSONB`, `TIMESTAMP WITH TIME ZONE` e FKs compostas);
  - Persistência integral dos `11` modelos multi-tenant e trilha append-only `AuditEvent` com encadeamento SHA-256 e bloqueio de adulteração/exclusão;
  - Bloqueio cross-tenant em consultas, serviços e chaves estrangeiras compostas `(organization_id, <fk_id>)`, além de validação `%PDF-`/PNG, path traversal e confinamento fora do repositório em `LocalControlledSyntheticStorage`.
  - *Ressalva explícita de ambiente:* localmente no host Windows (sem Docker Desktop nem PostgreSQL nativo instalados), a suíte `tests/backend` e o CLI `alembic` rodam sobre SQLite com `PRAGMA foreign_keys=ON` acompanhados de checagem DDL para dialeto PostgreSQL; a execução contra **PostgreSQL 16 real (`postgres:16-alpine`)** roda automaticamente no job `backend-checks` de [`.github/workflows/security.yml`](../.github/workflows/security.yml).
- **Higiene básica de publicação (`tools/check_publication.py`):** aprovada (`0` ocorrências bloqueantes).
- **Empacotamento GitHub Pages local (`tools/verify_pages_package.py`):** pacote montado com **`31/31` arquivos permitidos de `frontend/public/`**, **`0` vazamentos** (`backend/`, `docs/`, `legacy/`, `tests/`, `tools/`, `frontend/lab/` estritamente ausentes) e **E2E aprovado no pacote estático sob subcaminho `/jyxia-saude/`**.
- **Conferência E2E em navegador real (`tests/e2e/test_documental_e2e.mjs` em Edge/Chromium):**
  - Isolamento HTTP (`404` para `tools/`, `backend/`, `docs/`, `legacy/v2/`, `frontend/lab/`, `tests/` e rotas relativas) e `/assets/favicon.svg` `200`;
  - Upload manual de PDF e PNG, validação ARIA (`role="alert"`, `aria-invalid="true"`), todos os `9` cenários, Modalidade B via `tools/serve_lab.py` em `localhost` e viewports **`320px`, `390px`, `768px`, `1024px` e `1280px`** sem overflow horizontal e sem erros de console.

## 2. O que falta validar antes de uso com dados reais

1. **Pesquisa de campo e entrevistas (`0` realizadas):** validação em campo ainda pendente.
2. **Qualidade em documentos reais/degradados e OCR:** o benchmark de `8` documentos e os `18` fixtures são sintéticos; OCR permanece fora desta entrega.
3. **Autenticação, infra produtiva e regulação:** OIDC/MFA ativo, object storage cifrado com KMS, antivírus/CDR, DPA/RIPD e parecer ANVISA/CFM permanecem pendentes antes de qualquer piloto com pacientes reais.
