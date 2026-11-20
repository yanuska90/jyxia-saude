# Identidade Institucional, Autenticação OIDC/MFA, Sessões, RBAC e Multi-Tenancy (`backend/` `0.2.0` · Etapa 3.2)

Documento técnico canônico da arquitetura de identidade e autorização da **Modalidade C (`backend/` `0.2.0`)**, mantendo a demonstração pública **Modalidade A (`frontend/public/` `v3.2.0`)** e o laboratório **Modalidade B (`frontend/lab/`)** integralmente estáticos e isolados.

## 1. Fronteira e princípio arquitetural BFF (Backend for Frontend)

- A autenticação institucional opera exclusivamente no modelo **confidential client + BFF no servidor (`backend/`)**.
- O navegador recebe apenas cookies de sessão opaca (`jyxia_session`: `HttpOnly`, `SameSite=Lax`, `Secure` obrigatório em produção) e de proteção CSRF (`jyxia_csrf`), nunca tokens OIDC (`id_token`, `access_token`, `refresh_token`) em `localStorage`, `sessionStorage` ou respostas HTTP.
- Toda resposta em `/api/v1/auth/*`, `/api/v1/me*` e `/api/v1/organizations/*` retorna `Cache-Control: no-store, no-cache, must-revalidate` e recusa tokens `Authorization: Bearer` diretos na API de aplicação.

## 2. Fluxo OIDC real, PKCE S256, JWKS e separação de tokens (`app/core/oidc.py`)

- **Adaptador desacoplado de provedor (`OidcProviderAdapter` / `StandardOidcProviderAdapter`):** compatível com qualquer provedor OpenID Connect padrão (validado continuamente contra **Keycloak `26.8.2`** em desenvolvimento e CI), sem dependência proprietária no domínio.
- **Authorization Code + PKCE `S256` (`oidc_auth_states`):**
  - `GET /api/v1/auth/login` gera `state`, `nonce` e `code_verifier` aleatórios; grava apenas digests HMAC-SHA256 de `state` e `nonce` no banco e **cifra `code_verifier` com AES-256-GCM** usando AAD vinculado ao `state_hash`; vincula adicionalmente um cookie `HttpOnly` de transação (`jyxia_oidc_tx`) contra Login CSRF.
  - `GET /api/v1/auth/callback` valida e **consome atomicamente** o registro `oidc_auth_states` em uso único (`consumed_at IS NULL AND expires_at > now`) para neutralizar replay.
- **Validação rigorosa do ID Token e cache JWKS:**
  - Discovery `.well-known/openid-configuration` com pinning estrito de `issuer` e proibição de HTTP não criptografado em `production` (`oidc_allow_http_dev=true` permitido apenas localmente em loopback/dev).
  - Cache JWKS limitado (`ttl` padrão `300s`) com janela de **cooldown (`15s`)** para `kid` desconhecido, evitando tempestades/DoS de requisições contra o provedor.
  - Assinatura verificada explicitamente para `RS256` / `ES256`, recusando `alg=none` e downgrade simétrico (`HS256`), além de validação de `iss`, `aud`, `azp` (quando `aud` múltiplo), `exp`, `nbf`, `iat`, skew limitado e `nonce`.
  - **Separação estrita entre ID Token e Access Token:** rejeição explícita de tokens com cabeçalho `typ: at+jwt` / `application/at+jwt` ou claim `token_use == "access"`.

## 3. Política MFA obrigatória (`acr`, `amr`, `auth_time`)

- O acesso autenticado exige evidência verificável de segundo fator no ID Token assinado:
  - `auth_time` numérico obrigatório dentro da janela máxima (`oidc_max_auth_age_seconds`, padrão `3600s`).
  - Conferência de `acr` (ex.: `urn:jyxia:loa:mfa`) e/ou `amr` contendo método MFA válido (`otp`, `totp`, `hwk`, `fido`, `webauthn`, `mfa`).
  - **Bloqueio explícito de senha isolada:** tokens contendo apenas `amr: ["pwd"]` ou desprovidos de segundo fator são recusados com HTTP `401` (`OIDC_TOKEN_OR_MFA_REJECTED`) e auditados em `security_auth_events`.
  - Tentativas de bypass por cabeçalhos (`X-MFA-Verified`) ou query strings não produzem efeito e não autenticam sessões.

## 4. Vinculação estrita `(issuer, subject)` e bloqueio de autocriação (`external_identities`)

- A resolução do usuário institucional consulta **exclusivamente** `(external_identities.issuer, external_identities.subject)` com índice único (`uq_external_identities_iss_sub`).
- **Mudança de e-mail no IdP** preserva o vínculo ao usuário correto; **colisões de `subject` entre provedores distintos** não se misturam; **correspondência apenas por e-mail nunca autentica** e não existe autoprovisionamento de usuários ou organizações no login.
- Usuários inativos (`users.is_active = false`), identidades suspensas/revogadas (`external_identities.status <> 'active'`) ou usuários sem associação ativa em organização ativa são bloqueados com HTTP `403`.

## 5. Sessões server-side, timeouts, logout e proteção CSRF

- **Armazenamento seguro (`auth_sessions`):** apenas digests HMAC-SHA256 com chaves distintas de sessão (`JYXIA_SESSION_SECRET`) e CSRF (`JYXIA_CSRF_SECRET`) são gravados no banco; um novo login sempre emite `session_id` e segredo inéditos (**prevenção de Session Fixation**).
- **Expiração dual e revogação imediata:** expiração por ociosidade deslizante (`idle_expires_at`, padrão `1800s`) e teto absoluto (`absolute_expires_at`, padrão `28800s`). `POST /api/v1/auth/logout` revoga a sessão no banco (`revoked_at`), limpa cookies e retorna URL opcional de logout RP-initiated; invalidações mid-session de usuário/identidade revogam e rejeitam requisições seguintes imediatamente.
- **Proteção CSRF e Origin:** toda rota mutável autenticada (`POST /api/v1/auth/logout`, `POST /api/v1/auth/select-organization`) exige correspondência simultânea entre cabeçalho `X-CSRF-Token`, cookie `jyxia_csrf` e digest HMAC armazenado na sessão no banco, além de validação estrita dos cabeçalhos `Origin` / `Referer` contra `JYXIA_APP_BASE_URL` e `JYXIA_CORS_ALLOWED_ORIGINS`.

## 6. Multi-tenancy operacional e matriz RBAC administrativa (`app/core/rbac.py`)

- **Derivação confiável de `TenantContext`:** `X-Organization-ID` conflitante é explicitamente recusado (`403` + auditoria `TENANT_HEADER_SPOOF_REJECTED`). Usuários com uma organização iniciam com ela ativa; usuários multi-tenant selecionam explicitamente a organização via `POST /api/v1/auth/select-organization`, validado contra associação `active` em `organization_memberships`.
- **Autoridade estritamente administrativa:** `AccessContext` retorna sempre `administrative_only: true` e `clinical_approval: false`. O nome técnico `clinical_reviewer` é preservado apenas para compatibilidade do enum, representando revisor documental de campos extraídos e evidências.

| Papel (`OrganizationRole`) | Escopo principal | `/access-context` (`organization:read`) | `/cases` (`case:read`) | `/members` (`membership:read`) | `/audit-events` (`audit:read`) | Escrita / Gestão (`case:write`, `field:review`, `membership:manage`) |
| --- | --- | --- | --- | --- | --- | --- |
| `org_admin` | Administração institucional da organização | `200` | `200` | `200` | `200` | Conforme permissões administrativas da org |
| `admin_operator` | Preparação operacional e de dossiês administrativos | `200` | `200` | `200` | `403` | `case:write`, `document:prepare` |
| `clinical_reviewer` | Revisão documental de campos/evidências (sem aprovação clínica) | `200` | `200` | `403` | `403` | `case:write`, `field:review` |
| `auditor_readonly` | Auditoria e conferência exclusivamente leitura | `200` | `200` | `200` | `200` | Nenhuma (somente leitura) |
| `read_only` | Consulta básica de contexto e lista administrativa | `200` | `200` | `403` | `403` | Nenhuma (somente leitura) |

## 7. Endurecimento PostgreSQL 16 (`migration 0003`): separação de roles, RLS e trilha imutável

- **Separação de privilégios:**
  - `migration_owner` (`POSTGRES_USER` / `JYXIA_MIGRATION_DATABASE_URL`): executa DDL, migrações Alembic e é dono das funções `SECURITY DEFINER`.
  - `jyxia_app` (`JYXIA_DATABASE_URL`): role exclusiva de runtime com `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`, sem permissão de DDL, sem `DELETE`/`TRUNCATE` e **sem permissão de `INSERT` direta** nas tabelas de auditoria.
- **Row-Level Security (RLS):** habilitada no PostgreSQL nas tabelas `organization_memberships` (escopo por `app.current_organization_id` ou `app.current_user_id`), `document_cases`, `documents`, `document_versions`, `processing_runs`, `extracted_fields`, `evidence_references`, `human_reviews`, `audit_events` e `security_auth_events`, vinculada ao contexto transacional `set_config(..., true)`.
- **Trilha de auditoria (`audit_events` e `security_auth_events`):**
  - Triggers `BEFORE UPDATE`, `BEFORE DELETE` e `BEFORE TRUNCATE` (`trg_audit_events_no_truncate` e `trg_security_auth_events_no_*`);
  - Escrita pela aplicação em PostgreSQL exclusivamente via funções **`SECURITY DEFINER SET search_path = pg_catalog, public`** (`jyxia_append_audit_event`, `jyxia_append_security_event` e `jyxia_get_security_audit_head`), validando sequência e `prev_event_hash` dentro da transação.

## 8. Verificação automatizada e limites declarados

- **Execução local (Windows sem Docker/PostgreSQL):** testa criptografia PKCE/AEAD, todas as validações JWKS/RSA/EC/MFA com `httpx.MockTransport` e chaves efêmeras `cryptography`, sessões, CSRF/Origin, vinculação `(issuer, subject)`, matriz RBAC completa e triggers SQLite.
- **Execução real em CI ([`.github/workflows/security.yml`](../.github/workflows/security.yml)):** provisiona **`postgres:16-alpine`** com role real `jyxia_app` + ciclo Alembic `0003` + **`quay.io/keycloak/keycloak:26.8.2`** importando [`jyxia-dev-realm.json`](../backend/keycloak/jyxia-dev-realm.json), executa login OIDC PKCE `S256` + TOTP RFC 6238 real fim a fim e exige zero testes ignorados (`skipped`).
- **Fora desta entrega (`0.2.0`):** interface web de login na Modalidade A, autocadastro, rotas completas de upload/processamento documental/revisão HTTP, S3/KMS, OCR/LLM/FHIR, antivírus/CDR e certificação clínica ou pentest independente.
