# Arquitetura Institucional da JYXIA — Identidade, OIDC/MFA, RBAC e Hardening (`0.2.0` · Etapa 3.2)

Documento técnico atualizado na **Etapa 3.2** (`backend/` `0.2.0`), evoluindo a fundação relacional multi-tenant para autenticação institucional via OIDC/PKCE/MFA obrigatório, sessões seguras no servidor, autorização RBAC em 5 papéis, separação de roles no PostgreSQL 16 e políticas Row-Level Security (`RLS`). Detalhamento completo do fluxo de identidade em [`IDENTIDADE_E_AUTORIZACAO.md`](IDENTIDADE_E_AUTORIZACAO.md).

## 1. Camadas e controles implementados (`backend/app/`)

- **`core/` (`config.py`, `constants.py`, `logging.py`, `session_crypto.py`, `oidc.py`, `rbac.py`, `processing_contracts.py`):**
  - **Configuração (`config.py`):** `Settings` fail-closed recusa em `JYXIA_ENV=production`: SQLite, armazenamento local sintético, `debug=True`, `JYXIA_LOG_LEVEL=DEBUG`, OIDC inativo, `oidc_allow_http_dev=true`, OIDC/CORS sem HTTPS ou com `*`, além de `session_secret`/`csrf_secret`/senhas fracas ou placeholders. Inclui `migration_database_url` separado do runtime;
  - **Criptografia de sessão e PKCE (`session_crypto.py`):** tokens opacos aleatórios, digests HMAC-SHA256 com chaves/contextos separados e cifra AES-256-GCM para `code_verifier` em repouso;
  - **Adaptador OIDC padrão (`oidc.py`):** discovery com pinning de `issuer`, cache JWKS limitado com cooldown anti-DoS, verificação `RS256`/`ES256` via `PyJWT`, separação estrita de ID Token vs. Access Token (`at+jwt` / `token_use=access` recusados) e validação obrigatória de MFA (`acr`, `amr`, `auth_time`, bloqueando `["pwd"]` isolado);
  - **RBAC centralizado (`rbac.py`):** matriz declarativa `ROLE_PERMISSIONS` para `org_admin`, `admin_operator`, `clinical_reviewer` (mantido para compatibilidade apenas na revisão de campos/evidências), `auditor_readonly` e `read_only`;
  - **Logs e contratos (`logging.py`, `processing_contracts.py`):** sanitização recursiva estendida para cookies/tokens/verifiers PKCE/nonces e contratos de extração sem OCR/LLM.

- **`db/` (`base.py`, `session.py`):**
  - `apply_pg_rls_context()` vincula `app.current_organization_id` e `app.current_user_id` transacionalmente via `set_config(..., true)` para enforcement efetivo do RLS no PostgreSQL 16.

- **`models/entities.py` (`15` modelos relacionais multi-tenant + identidade):**
  - Preserva integralmente os `11` modelos multi-tenant (`Organization`, `User`, `OrganizationMembership` incluindo `read_only` e status `suspended`/`revoked`, `DocumentCase`, `Document`, `DocumentVersion`, `ProcessingRun`, `ExtractedField`, `EvidenceReference`, `HumanReview`, `AuditEvent`);
  - Adiciona **`4` modelos de identidade e segurança:**
    12. `ExternalIdentity` (`external_identities`) — vinculação única `(issuer, subject)` -> `user_id` sem matching por e-mail;
    13. `OidcAuthState` (`oidc_auth_states`) — transação PKCE efêmera com `state_hash`, `nonce_hash`, `code_verifier_ciphertext` (AES-256-GCM) e consumo único atômico (`consumed_at`);
    14. `AuthSession` (`auth_sessions`) — sessão BFF server-side com digests `session_token_hash` / `csrf_token_hash`, `acr`, `amr_json`, `mfa_verified_at`, timeouts de ociosidade/absoluto e `revoked_at` (sem tokens OIDC em claro);
    15. `SecurityAuditEvent` (`security_auth_events`) — trilha global append-only encadeada (`jyxia.sec_audit.v1`) para logins, recusas MFA, CSRF, cross-tenant e negações RBAC.

## 2. Separação de privilégios no PostgreSQL 16, RLS e trilha append-only

- **Migration `20261120_0003` + [`backend/infra/postgres_init_roles.sql`](../backend/infra/postgres_init_roles.sql):**
  - Separa `migration_owner` (dona do schema/DDL/funções `SECURITY DEFINER`) da role restrita de runtime `jyxia_app` (`NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION`, sem `DDL`, sem `DELETE`/`TRUNCATE` e sem `INSERT` direto nas tabelas de auditoria);
  - Habilita **Row-Level Security (RLS)** nas tabelas organizacionais e de auditoria vinculadas a `app.current_organization_id` (e `app.current_user_id` em `organization_memberships`);
  - Instala triggers **`BEFORE TRUNCATE`** em `audit_events` e triggers `BEFORE UPDATE / DELETE / TRUNCATE` em `security_auth_events`;
  - Em PostgreSQL, `AuditEventRepository` e `SecurityAuditRepository` gravam via funções **`SECURITY DEFINER SET search_path = pg_catalog, public`** (`jyxia_append_audit_event`, `jyxia_append_security_event`, `jyxia_get_security_audit_head`).

## 3. Endpoints HTTP (`backend/` `0.2.0`)

- **Públicos / infraestrutura:** `/api/v1/health/live`, `/api/v1/health/ready`, `/api/v1/auth/login`, `/api/v1/auth/callback`;
- **Sessão autenticada (com CSRF + `Origin` em mutações):** `POST /api/v1/auth/logout`, `GET /api/v1/auth/session`, `POST /api/v1/auth/select-organization`, `GET /api/v1/me`, `GET /api/v1/me/organizations`;
- **Organizacionais protegidos por RBAC + vínculo ativo + RLS:** `/api/v1/organizations/{organization_id}/access-context`, `/cases`, `/members` e `/audit-events`.

## 4. Storage sintético local e validação PostgreSQL 16 + Keycloak 26.8.2

- **Storage (`services/storage.py`):** preservado integralmente (`LocalControlledSyntheticStorage` fora do Git com rejeição de symlinks/junctions e CRC-32).
- **Local vs. CI:** localmente no Windows (sem Docker Desktop/PostgreSQL instalados), os testes executam contra SQLite + JWKS/IdP simulados com criptografia RSA/EC real; em CI ([`.github/workflows/security.yml`](../.github/workflows/security.yml)), toda a suíte é validada contra **`postgres:16-alpine` real com role `jyxia_app` + RLS** e **`quay.io/keycloak/keycloak:26.8.2` real com fluxo MFA/TOTP**.
