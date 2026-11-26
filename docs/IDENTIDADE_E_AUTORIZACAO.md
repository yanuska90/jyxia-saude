# Identidade Institucional, Autenticação OIDC/MFA, Sessões, RBAC e Multi-Tenancy (`backend/` `0.2.0` · Etapa 3.3.5 · `main`)

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
- **Validação rigorosa do ID Token, proteção anti-SSRF com pinning de socket e cache JWKS:**
  - Discovery `.well-known/openid-configuration`, `jwks_uri`, `token_endpoint` e `end_session_endpoint` com pinning estrito de origem (`(scheme, hostname, port)` idênticos ao `oidc_issuer`), proibição de userinfo/redirects HTTP (`follow_redirects=False`), proibição de HTTP e de transports injetados em `production`/`staging`, rejeição de IPs literais ou resolvidos via DNS em faixas privadas/loopback/link-local/multicast/reservadas e **conexão TCP diretamente ao IP validado via `_PinnedOidcNetworkBackend` (`httpcore.NetworkBackend`)** sem segunda resolução DNS (eliminando janelas TOCTOU de DNS rebinding enquanto preserva SNI e verificação X.509 contra o hostname original).
  - Cache JWKS limitado (`ttl` padrão `300s`) com janela de **cooldown (`15s`)** para `kid` desconhecido, evitando tempestades/DoS de requisições contra o provedor, com suporte verificado à rotação positiva de chaves.
  - Assinatura verificada explicitamente para `RS256` / `ES256`, recusando `alg=none` e downgrade simétrico (`HS256`), além de validação de `iss`, `aud`, `azp` (quando `aud` múltiplo), `exp`, `nbf`, `iat`, skew limitado e `nonce`.
  - **Separação estrita entre ID Token e Access Token:** rejeição explícita de tokens com cabeçalho `typ: at+jwt` / `application/at+jwt` ou claim `token_use == "access"`.

## 3. Política MFA obrigatória (`acr`, `amr`, `auth_time`)

- O acesso autenticado exige evidência verificável de segundo fator no ID Token assinado (`oidc_require_both_acr_and_amr=True` por padrão e obrigatório em `production`/`staging`):
  - `auth_time` numérico obrigatório dentro da janela máxima (`oidc_max_auth_age_seconds`, padrão `3600s`).
  - Conferência obrigatória simultânea de `acr` autorizado (ex.: `urn:jyxia:loa:mfa`) **e** de `amr` não vazio contendo método MFA de segundo fator válido (`otp`, `totp`, `hwk`, `fido`, `webauthn`, `mfa`).
  - **Bloqueio explícito de senha isolada ou fatores fracos:** tokens com `amr: []`, `amr: ["pwd"]` ou apenas métodos não autorizados (como `["pwd", "email"]` ou `["email", "sms"]`) — mesmo que apresentem `acr` — são recusados com HTTP `401` (`OIDC_TOKEN_OR_MFA_REJECTED`) e auditados em `security_auth_events`.
  - Tentativas de bypass por cabeçalhos (`X-MFA-Verified`) ou query strings não produzem efeito e não autenticam sessões.

## 4. Vinculação estrita `(issuer, subject)` e bloqueio de autocriação (`external_identities`)

- A resolução do usuário institucional consulta **exclusivamente** `(external_identities.issuer, external_identities.subject)` com índice único (`uq_external_identities_iss_sub`).
- **Mudança de e-mail no IdP** preserva o vínculo ao usuário correto; **colisões de `subject` entre provedores distintos** não se misturam; **correspondência apenas por e-mail nunca autentica** e não existe autoprovisionamento de usuários ou organizações no login.
- Usuários inativos (`users.is_active = false`), identidades suspensas/revogadas (`external_identities.status <> 'active'`) ou usuários sem associação ativa em organização ativa são bloqueados com HTTP `403`.

## 5. Sessões server-side, rotação, timeouts, logout e proteção CSRF

- **Armazenamento seguro e rotação (`auth_sessions`):** apenas digests HMAC-SHA256 com chaves distintas e obrigatórias de sessão (`JYXIA_SESSION_SECRET`) e CSRF (`JYXIA_CSRF_SECRET`) são gravados no banco; todo novo login emite `session_id` e segredo inéditos (**prevenção de Session Fixation**), e toda troca de organização ativa (`POST /api/v1/auth/select-organization`) **revoga a sessão anterior (`rotated_on_organization_select`) e emite novos tokens/cookies de sessão e CSRF**, invalidando imediatamente os tokens antigos.
- **Expiração dual e revogação imediata:** expiração por ociosidade deslizante (`idle_expires_at`, padrão `1800s`) e teto absoluto (`absolute_expires_at`, padrão `28800s`). `POST /api/v1/auth/logout` revoga a sessão no banco (`revoked_at`), limpa cookies e retorna URL opcional de logout RP-initiated; invalidações mid-session de usuário ou identidade (`status` `suspended` ou `revoked`) revogam e rejeitam requisições seguintes imediatamente.
- **Proteção CSRF e Origin estruturada:** toda rota mutável autenticada (`POST /api/v1/auth/logout`, `POST /api/v1/auth/select-organization`) exige correspondência simultânea entre cabeçalho `X-CSRF-Token`, cookie `jyxia_csrf` e digest HMAC armazenado na sessão no banco, além de validação estruturada de `(scheme, hostname, port)` contra `JYXIA_APP_BASE_URL` e `JYXIA_CORS_ALLOWED_ORIGINS`. Quando o header `Origin` está presente (inclusive `Origin: null`, malformado, subdomínio ou porta divergente), ele é validado diretamente **sem jamais fazer fallback para `Referer`**; o `Referer` só é aceito quando `Origin` está completamente ausente.

## 6. Multi-tenancy operacional e matriz RBAC administrativa (`app/core/rbac.py`)

- **Derivação confiável de `TenantContext`:** `X-Organization-ID` conflitante é explicitamente recusado (`403` + auditoria `TENANT_HEADER_SPOOF_REJECTED`). Usuários com uma organização iniciam com ela ativa; usuários multi-tenant selecionam explicitamente a organização via `POST /api/v1/auth/select-organization`, validado contra associação `active` em `organization_memberships`.
- **Autoridade estritamente administrativa:** `AccessContext` retorna sempre `administrative_only: true` e `clinical_approval: false`. O identificador externo canônico na API JSON e no schema OpenAPI é **`document_reviewer`** (com leitura transparente de registros históricos `'clinical_reviewer'` no banco e aceitação dos aliases `'clinical_reviewer'` / `'administrative_reviewer'` na entrada), representando exclusivamente revisor documental administrativo de campos extraídos e evidências (zero decisão clínica).

| Papel (`OrganizationRole`) | Escopo principal | `/access-context` (`organization:read`) | `/cases` (`case:read`) | `/members` (`membership:read`) | `/audit-events` (`audit:read`) | Upload Documental (`document:upload`) | Consulta / Download (`document:read`) | Escrita / Gestão (`case:write`, `field:review`, `membership:manage`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `org_admin` | Administração institucional da organização | `200` | `200` | `200` | `200` | `201` / `200` | `200` | Conforme permissões administrativas da org |
| `admin_operator` | Preparação operacional e de dossiês administrativos | `200` | `200` | `200` | `403` | `201` / `200` | `200` | `case:write`, `document:prepare`, `document:upload` |
| `document_reviewer` (alias legado `clinical_reviewer` / `administrative_reviewer`) | Revisão administrativa de campos/evidências (zero aprovação ou decisão clínica) | `200` | `200` | `403` | `403` | `403` | `200` | `case:write`, `field:review` |
| `auditor_readonly` | Auditoria e conferência exclusivamente leitura | `200` | `200` | `200` | `200` | `403` | `200` | Nenhuma (somente leitura) |
| `read_only` | Consulta básica de contexto e lista administrativa | `200` | `200` | `403` | `403` | `403` | `200` | Nenhuma (somente leitura) |

## 7. Endurecimento PostgreSQL 16 (`migrations 0003` a `0010`): separação de roles (`jyxia_app`, `jyxia_worker`, `migration_owner`), FORCE RLS e trilha imutável

- **Separação de privilégios:**
  - `migration_owner` (`POSTGRES_USER` / `JYXIA_MIGRATION_DATABASE_URL`): executa DDL, migrações Alembic e é dono das funções `SECURITY DEFINER`.
  - `jyxia_app` (`JYXIA_DATABASE_URL`): role exclusiva de runtime da API HTTP com `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`, sem permissão de DDL, sem `DELETE`/`TRUNCATE`, sem `UPDATE`/`DELETE`/`TRUNCATE` em `human_reviews` (`GRANT SELECT, INSERT` apenas) e **sem permissão de `INSERT` direta** nas tabelas de auditoria ou de avaliação de consistência.
  - `jyxia_worker` (`JYXIA_WORKER_DATABASE_URL`): role exclusiva do worker assíncrono com `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS` e zero privilégios diretos em tabelas, operando exclusivamente por funções `SECURITY DEFINER SET search_path = pg_catalog, public` com verificação de `session_user` e prova criptográfica de lease (`lease_token_hash`).
- **Row-Level Security (`ENABLE` + `FORCE ROW LEVEL SECURITY`) e classificação de tabelas globais:**
  - `FORCE ROW LEVEL SECURITY` ativo em `organization_memberships`, `document_cases`, `documents`, `document_versions`, `processing_runs`, `extracted_fields`, `evidence_references`, `human_reviews`, `audit_events`, `consistency_assessments`, `consistency_axis_results`, `consistency_axis_evidences` e nas tabelas sensíveis de identidade/sessão `auth_sessions` (isolada estritamente por `app.current_session_token_hash` correspondente a sessão não revogada e não expirada, sem confiar em `app.current_user_id`), `external_identities` (isolada por sessão ativa validada via `jyxia_is_session_authorized_for_identity` ou callback OIDC vinculado a `oidc_auth_states` consumido e não expirado via `jyxia_is_valid_oidc_callback_lookup`, sem confiar em `app.current_user_id`) e `oidc_auth_states` (isolada por `app.current_oidc_state_hash` não consumido e não expirado). `security_auth_events` mantém `ENABLE ROW LEVEL SECURITY` por `app.current_organization_id` para leitura pela aplicação enquanto permite encadeamento global pelas funções `SECURITY DEFINER`.
  - As tabelas de catálogo `users` e `organizations` permanecem restritas a `SELECT`-only para `jyxia_app` (sem `INSERT`/`UPDATE`/`DELETE`) a fim de viabilizar `JOIN`s controlados durante resolução de identidade e associação multi-tenant.
  - Todo contexto é aplicado transacionalmente com `set_config(..., true)` (`is_local=true`), garantindo limpeza automática ao término da transação e zero vazamento em conexões reutilizadas do pool.
- **Trilha de auditoria (`audit_events` e `security_auth_events`), imutabilidade de `human_reviews` e prova de sessão nas funções `SECURITY DEFINER`:**
  - Triggers `BEFORE UPDATE`, `BEFORE DELETE` e `BEFORE TRUNCATE` em `audit_events`, `security_auth_events` e `human_reviews` (`trg_audit_events_no_*`, `trg_security_auth_events_no_*`, `trg_human_reviews_append_only` e `trg_human_reviews_no_truncate`), além de triggers `BEFORE UPDATE/DELETE` nas tabelas `consistency_*`;
  - Escrita pela aplicação em PostgreSQL exclusivamente via funções **`SECURITY DEFINER SET search_path = pg_catalog, public`** (`jyxia_append_audit_event`, `jyxia_append_security_event` e `jyxia_get_security_audit_head`);
  - Na migration `20261122_0005`, `jyxia_append_audit_event` e `jyxia_append_security_event` exigem de `jyxia_app` uma prova não enumerável de sessão autenticada (`app.current_session_token_hash` correspondente a uma sessão ativa, não revogada, não expirada e com MFA verificado em `public.auth_sessions` cujo `user_id` e `active_organization_id` coincidam com o ator e a organização do evento, ou `app.current_oidc_state_hash` correspondente a uma transação OIDC ativa exclusivamente para os eventos pré-sessão do fluxo de login/callback), além de usuário ativo, organização ativa e **membership ativa (`status = 'active'`) em `organization_memberships`**, impedindo que `jyxia_app` falsifique eventos apenas definindo `app.current_user_id` e `app.current_organization_id`.

## 8. Verificação automatizada e limites declarados

- **Execução local (Windows sem Docker/PostgreSQL):** testa criptografia PKCE/AEAD, todas as validações JWKS/RSA/EC/MFA com `httpx.MockTransport` e chaves efêmeras `cryptography`, sessões, CSRF/Origin, vinculação `(issuer, subject)`, matriz RBAC completa, triggers SQLite e E2E da interface `/institutional/` com sessão BFF pré-semeada (`node tests/e2e/test_institutional_e2e.mjs`).
- **Execução real em CI ([`.github/workflows/security.yml`](../.github/workflows/security.yml)):** provisiona **`postgres:16-alpine`** com roles reais `jyxia_app` e `jyxia_worker` + ciclo Alembic completo `0001`–`0010` (cabeça única `20261125_0010`) + **`quay.io/keycloak/keycloak:26.8.2`** importando [`jyxia-dev-realm.json`](../backend/keycloak/jyxia-dev-realm.json), executa o login OIDC PKCE `S256` + TOTP RFC 6238 real fim a fim por integração HTTP (`tests/backend/test_keycloak_integration.py`), exige zero testes ignorados (`77/77` no Pytest sem `skipped`) e executa `node tests/e2e/test_institutional_e2e.mjs` em Chrome headless via CDP com sessão BFF pré-semeada.
- **Fora desta entrega (`0.2.0`):** interface web de login na Modalidade A, autocadastro, S3/KMS, WORM externo, OCR/LLM/FHIR/conectores hospitalares, antivírus/CDR e certificação/aprovação clínica ou pentest independente.
