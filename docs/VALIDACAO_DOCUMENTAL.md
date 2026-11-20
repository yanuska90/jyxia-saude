# Validação Técnica e Documental da JYXIA (`v3.2.0` + Backend `0.2.0` · Etapa 3.2)

## 1. Verificações automatizadas executadas (`20/11/2026`, branch `jyxia-develop`)

- **Núcleo v3 + PDF.js real + Laboratório e Benchmark (`37` testes Node — `37/37` pass):**
  - `28` testes unitários em [`tests/frontend/test_documental.mjs`](../tests/frontend/test_documental.mjs);
  - `6` testes reais com `frontend/public/vendor/pdf.min.mjs` em [`tests/frontend/test_documental_pdfjs.mjs`](../tests/frontend/test_documental_pdfjs.mjs);
  - `3` testes do laboratório localhost e benchmark sintético (`8/8` casos artificiais) em [`tests/frontend/test_lab_and_benchmark.mjs`](../tests/frontend/test_lab_and_benchmark.mjs) e [`tests/benchmark/run_benchmark.mjs`](../tests/benchmark/run_benchmark.mjs).
- **Regressão histórica v2.x preservada isoladamente (`tests/legacy/`):** `18` testes JS + `11` Python = **`29` testes legados aprovados (`55/55` totais no Node + `11/11` Python)**.
- **Backend Institucional `0.2.0` (`tests/backend/` — `31` testes totais):**
  - **`29/29` testes locais aprovados (e `2` integrados exclusivos de infraestrutura PG 16 / Keycloak):**
    - `test_health_and_app.py` (`4` testes): rotas `/api/v1/health/*`, `/api/v1/auth/*` e `/api/v1/organizations/*`, produção desativando `/docs` + `/openapi.json`, respostas sanitizadas;
    - `test_config_security_and_logging.py` (`7` testes): configuração fail-closed (SQLite, `oidc_allow_http_dev`, `session_cookie_secure=false`, segredos/CORS fracos), mascaramento DSN, `StandardOidcProviderAdapter` sem config e `require_tenant_permission` em MFA/cross-tenant, contratos `processing_contracts.py`, sanitização recursiva de logs, paridade `pyproject.toml` <-> `requirements*.txt` + scan de segredos e zero imports de `legacy/v2`;
    - `test_oidc_and_mfa.py` (`3` testes): `503` em OIDC não configurado, validações criptográficas `PyJWT` (`RS256`/`ES256`), bloqueio de `at+jwt` e `token_use=access`, rejeição de `["pwd"]`, ausência/expiração de `auth_time`, `alg=none`, `HS256`, chave adulterada, rotação + cooldown anti-DoS em JWKS, cifragem AES-256-GCM de `code_verifier`, replay de `state`, Login CSRF (`jyxia_oidc_tx`) e indisponibilidade `503`;
    - `test_auth_sessions_rbac_and_tenancy.py` (`3` testes): vinculação exclusiva `(issuer, subject)` resistente a troca de e-mail, colisão de `subject` em emissor distinto, recusa sem autoprovisionamento por e-mail, prevenção de Session Fixation, armazenamento exclusivo de digests HMAC-SHA256, timeouts idle + absoluto, revogação no logout/suspensão, matriz completa CSRF/Origin, seleção multi-organização, recusa de `X-Organization-ID` forjado, revogação mid-session de vínculo e **matriz RBAC completa de `5` papéis** (`org_admin`, `admin_operator`, `clinical_reviewer`, `auditor_readonly`, `read_only`) + trilha `SecurityAuditEvent` e `AuditEvent`;
    - `test_migrations.py` (`2` testes): ciclo `0001 -> 0002 -> 0003 (head)` com `compare_metadata == []`, downgrades incrementais `0002`, `0001`, `base`, re-upgrade e compilação DDL PostgreSQL dos `15` modelos;
    - `test_db_roles_and_rls.py` (`2` testes): triggers SQL `BEFORE UPDATE/DELETE` em `security_auth_events` (executado localmente) + verificação real PostgreSQL 16 com role `jyxia_app` (`NOSUPERUSER`, `NOBYPASSRLS`), zero linhas sem `app.current_organization_id`, bloqueio de leitura/escrita cross-tenant por RLS, recusa de DDL/`TRUNCATE`/escrita direta em auditoria e escrita autorizada apenas via `SECURITY DEFINER` (executado em CI contra `postgres:16-alpine`);
    - `test_keycloak_integration.py` (`1` teste E2E completo): fluxo real contra **`quay.io/keycloak/keycloak:26.8.2`** + TOTP RFC 6238 real -> JYXIA BFF -> **`jyxia_app` PostgreSQL 16 RLS** -> logout + recusa de usuário não vinculado + recusa de cliente password-only sem MFA (executado em CI sem skips);
    - `test_persistence_and_constraints.py` (`2`), `test_audit_hardening.py` (`4`) e `test_tenant_isolation_and_storage.py` (`3`) preservados integralmente.
- **Qualidade estática e ferramentas:** `ruff check` (`0` erros), [`tools/sync_backend_deps.py --check`](../tools/sync_backend_deps.py) aprovado, [`tools/check_publication.py`](../tools/check_publication.py) aprovado, E2E em Edge/Chromium (`tests/e2e/test_documental_e2e.mjs` -> `E2E_ALL_PASSED`) e [`tools/verify_pages_package.py`](../tools/verify_pages_package.py) (`31/31` arquivos, `0` vazamentos, E2E estático aprovado).

## 2. O que falta validar antes de uso com dados reais

1. **Pesquisa de campo (`0` entrevistas executadas)** e benchmark independente em documentos degradados reais (OCR ausente).
2. **Camada operacional de produção:** endpoints HTTP completos de casos/upload/revisão humana, UI de login conectada ao BFF, gestão administrativa de vínculos, object storage com KMS, WORM externo de auditoria, antivírus/CDR, DPA/RIPD, parecer ANVISA/CFM e pentest independente.
