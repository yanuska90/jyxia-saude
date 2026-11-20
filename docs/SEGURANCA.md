# Segurança e privacidade da JYXIA (v3.2.0 + Backend Institucional 0.2.0 · Etapa 3.2)

## 1. Fronteira entre Modalidade A (Pública), Modalidade B (Local) e Modalidade C (Backend)

- **Modalidade A — Demo pública ([`frontend/public/`](../frontend/public/)):** estritamente sintética, sem login e sem envio de arquivos pela rede. O catálogo [`documental-manifest.json`](../frontend/public/documental-manifest.json) (`18` arquivos) recusa qualquer arquivo fora da whitelist SHA-256 antes da leitura textual. Tudo roda apenas na memória da aba.
- **Modalidade B — Laboratório experimental local ([`frontend/lab/`](../frontend/lab/) + [`tools/serve_lab.py`](../tools/serve_lab.py)):** estritamente isolado em `localhost` (`serve_lab.py` rejeita bind não-loopback e `assertLocalhostEnvironment()` bloqueia origens externas). **Não compõe o pacote do GitHub Pages e retorna HTTP `404` em [`tools/serve_documental.py`](../tools/serve_documental.py)**.
- **Modalidade C — Identidade institucional, sessões e autorização ([`backend/`](../backend/) `0.2.0`):** BFF OpenID Connect com PKCE `S256`, MFA obrigatório, cookies opacos com CSRF/Origin, vinculação `(issuer, subject)`, RBAC em 5 papéis, separação de roles no PostgreSQL (`jyxia_app` vs. `migration_owner`) e Row-Level Security (`RLS`). Detalhes completos em [`docs/IDENTIDADE_E_AUTORIZACAO.md`](IDENTIDADE_E_AUTORIZACAO.md).

## 2. Classificação honesta do estado de segurança

### A) Segurança implementada e verificada em testes
- **Demo pública e ferramentas:** PDF.js `6.5.438` local com `isEvalSupported: false`, CSP estrita (`frame-ancestors 'none'`), `textContent`, `csvSafeCell()`, pacote Pages restrito a `31` arquivos e higiene [`tools/check_publication.py`](../tools/check_publication.py).
- **Configuração fail-closed (`backend/app/core/config.py`):** produção proíbe SQLite, storage sintético local, `DEBUG`, OIDC desabilitado/sem HTTPS, `oidc_allow_http_dev`, `session_cookie_secure=false`, CORS `*`/HTTP e segredos/placeholders fracos; `main.py` desativa `/docs`, `/redoc` e `/openapi.json` em produção e sanitiza erros.
- **Autenticação OIDC PKCE `S256`, JWKS e MFA obrigatório (`backend/app/core/oidc.py`, `services/auth_service.py`):** discovery com pinning de `issuer`, validação `RS256`/`ES256` (rejeita `alg=none`/HS256), separação estrita ID Token vs. Access Token (`at+jwt`/`token_use=access` recusados), `code_verifier` cifrado com AES-256-GCM, consumo atômico de `state` contra replay, cache JWKS com cooldown contra DoS e recusa de logins com apenas senha (`["pwd"]`) ou sem `acr`/`amr`/`auth_time`. Validado contra **Keycloak `26.8.2` real com TOTP RFC 6238** em CI.
- **Vinculação `(issuer, subject)`, sessões BFF e CSRF:** matching exclusivamente por `(issuer, subject)` sem autoprovisionamento e sem fallback por e-mail; cookies `HttpOnly` + hashes HMAC-SHA256 distintos no banco, proteção contra session fixation, expiração idle + absoluta, revogação imediata no logout/suspensão, `X-CSRF-Token` + validação de `Origin`/`Referer` e `Cache-Control: no-store`.
- **Multi-tenancy, RBAC e PostgreSQL RLS (`backend/app/core/rbac.py`, migration `0003`):** `TenantContext` derivado exclusivamente de sessão autenticada + vínculo ativo; headers forjados (`X-Organization-ID`) rejeitados (`403`); matriz RBAC completa em 5 papéis administrativos; **role de runtime `jyxia_app`** (`NOSUPERUSER`, `NOBYPASSRLS`, sem DDL, sem `DELETE`/`TRUNCATE` e sem `INSERT` direto em auditoria); e **políticas Row-Level Security (`RLS`)** aplicadas no PostgreSQL 16.
- **Auditoria encadeada e proteção anti-adulteração (`AuditEvent` e `SecurityAuditEvent`):** hash canônico SHA-256 (`jyxia.audit.v1` e `jyxia.sec_audit.v1`), escrita em PostgreSQL exclusivamente via funções `SECURITY DEFINER`, e triggers SQL `BEFORE UPDATE / DELETE / TRUNCATE`.
- **Storage sintético local controlado e logs:** [`LocalControlledSyntheticStorage`](../backend/app/services/storage.py) com validação de symlinks/junctions, PDF `%%EOF` e PNG CRC-32; `SanitizingFilter` mascarando tokens/PKCE verifiers/nonces/JWTs/DSN/CPFs; [`compose.institutional.yaml`](../compose.institutional.yaml) publicado apenas em `127.0.0.1` e auditoria `pip-audit` em CI.

### B) Segurança apenas preparada (contratos / interfaces sem fluxo operacional ativo)
- Contratos internos de processamento, idempotência e recusa explícita de OCR (`processing_contracts.py`).

### C) Segurança pendente para etapas futuras
- Endpoints HTTP completos de criação/upload de dossiês, processamento documental real e revisão humana autenticada;
- Gestão administrativa segura (UI/API) de organizações, convites, vinculação e rotação operacional de segredos;
- Cobertura adicional de SAST/DAST contínuo em pipeline.

### D) Segurança dependente de infraestrutura externa e governança jurídica
- Object storage privado cifrado com KMS e repositório de auditoria externo WORM resistente inclusive a administradores locais;
- Scanner antivírus/CDR para uploads reais, WAF/TLS de borda e cofre externo de segredos;
- Contratos LGPD (Lei nº 13.709/2018: Controlador/Operadora, DPA, RIPD), guarda legal do PEP (Lei nº 13.787/2018), incidente (Res. CD/ANPD nº 15/2024), parecer **RDC ANVISA nº 657/2022**, **Resolução CFM nº 2.454/2026**, assinaturas **Lei nº 14.063/2020** e pentest independente antes de dados reais.

**Limites explícitos:** este trabalho **não garante** imutabilidade absoluta contra administradores privilegiados do servidor/banco, não equivale a auditoria/pentest independente e não habilita uso clínico ou com pacientes reais.

## 3. Versão histórica preservada

O cofre criptografado de navegador da v2.3 permanece isolado em [`legacy/v2/demo-v2.html`](../legacy/v2/demo-v2.html) apenas para regressão histórica (`29` testes legados em `tests/legacy/`), sem conexão com a versão `3.2.0` nem com `backend/`.
