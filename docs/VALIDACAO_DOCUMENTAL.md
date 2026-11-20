# Validação Técnica e Documental da JYXIA (`v3.2.0` + Fundação `0.1.0` · Etapa 3.1)

## 1. Verificações automatizadas executadas (`20/11/2026`, branch `jyxia-develop`)

- **Núcleo v3 + PDF.js real + Laboratório e Benchmark (`37` testes Node — `37/37` pass):**
  - `28` testes unitários em [`tests/frontend/test_documental.mjs`](../tests/frontend/test_documental.mjs);
  - `6` testes reais com `frontend/public/vendor/pdf.min.mjs` em [`tests/frontend/test_documental_pdfjs.mjs`](../tests/frontend/test_documental_pdfjs.mjs);
  - `3` testes do laboratório localhost e benchmark sintético (`8/8` casos artificiais) em [`tests/frontend/test_lab_and_benchmark.mjs`](../tests/frontend/test_lab_and_benchmark.mjs) e [`tests/benchmark/run_benchmark.mjs`](../tests/benchmark/run_benchmark.mjs).
- **Regressão histórica v2.x preservada isoladamente (`tests/legacy/`):** `18` testes JS + `11` Python = **`29` testes legados aprovados (`55/55` totais no Node + `11/11` Python)**.
- **Fundação Institucional Endurecida `0.1.0` (`tests/backend/` — `22/22` testes Pytest aprovados):**
  - `test_health_and_app.py` (`4` testes): inicialização apenas com `/api/v1/health/live` e `/api/v1/health/ready`, produção desativando `/docs` + `/openapi.json`, respostas `200`/`503` sanitizadas e mascaramento em exceções HTTP/500;
  - `test_config_security_and_logging.py` (`7` testes): configuração fail-closed de produção (SQLite, storage local, debug/DEBUG logging, OIDC inativo, CORS inseguro, senhas fracas), mascaramento de URIs/queries, contratos OIDC/RBAC/MFA, contratos de processamento (`NormalizedBoundingBox` + idempotência + recusa OCR), sanitização recursiva de logs (JWT, Bearer, DSN, CPF, nested PII), não-vazamento de `raw_value` em `record_extracted_field`, paridade `pyproject.toml` <-> `requirements*.txt` + scan de segredos e verificação AST sem imports de `legacy/v2`;
  - `test_migrations.py` (`2` testes): ciclo incremental `0001 -> 0002 (head)` com `compare_metadata == []`, `downgrade 20261120_0001`, `downgrade base` e re-upgrade completo + compilação DDL PostgreSQL dos 11 modelos e FKs compostas;
  - `test_persistence_and_constraints.py` (`2` testes): fluxo completo nos 11 modelos + `11` casos diretos de violação de integridade no banco (aprovação clínica proibida, `external_reference` único com múltiplos nulos permitidos, substituição cross-documento bloqueada, SHA-256 maiúsculo, timestamps invertidos, `abstained` incoerente, campo/evidência cross-versão na mesma org bloqueados por FKs de 3 colunas, bbox fora da página e revisor sem vínculo);
  - `test_audit_hardening.py` (`4` testes): canonicalização determinística UTC/JSON (`jyxia.audit.v1`), rejeição de payloads sensíveis, **rejeição de `UPDATE` e `DELETE` SQL diretos pelos triggers no banco**, **execução concorrente real em múltiplas sessões/threads no mesmo tenant e entre tenants distintos** sem lacunas/ramificações e detecção das 8 classes de adulteração em cópias destacadas;
  - `test_tenant_isolation_and_storage.py` (`3` testes): isolamento cross-tenant em consultas, serviços e **todas as FKs compostas diretamente no banco**, armazenamento seguro de PDF e PNG real com CRC-32, bloqueio de leitura cross-tenant, traversal, extensões enganosas, PDF truncado sem `%%EOF`, PNG truncado/corrompido, **detecção de symlink/junction NTFS** e limpeza atômica em erro de escrita.
  - *Ambiente local vs. CI:* estação local Windows executa sobre SQLite (`PRAGMA foreign_keys=ON`) + DDL PostgreSQL (sem Docker/PostgreSQL local instalados); o workflow [`.github/workflows/security.yml`](../.github/workflows/security.yml) valida **ciclo completo Alembic + `pip-audit` + todos os `22/22` testes Pytest (incluindo concorrência e triggers PL/pgSQL)** contra **`postgres:16-alpine` real** em CI.
- **Qualidade estática e ferramentas:** `ruff check` (`0` erros), [`tools/sync_backend_deps.py --check`](../tools/sync_backend_deps.py) aprovado, [`tools/check_publication.py`](../tools/check_publication.py) aprovado, E2E em Edge/Chromium (`tests/e2e/test_documental_e2e.mjs` -> `E2E_ALL_PASSED`) e [`tools/verify_pages_package.py`](../tools/verify_pages_package.py) (`31/31` arquivos, `0` vazamentos, E2E estático aprovado).

## 2. O que falta validar antes de uso com dados reais

1. **Pesquisa de campo (`0` entrevistas executadas)** e benchmark independente em documentos degradados reais (OCR ausente).
2. **OIDC/MFA ativo, endpoints autenticados e hardening de produção:** KMS/object storage cifrado, role de banco restrita separada do dono das migrações, antivírus/CDR, DPA/RIPD, parecer ANVISA/CFM e pentest independente.
