# Segurança e privacidade da JYXIA (v3.2.0 + Fundação Backend 0.1.0 · Etapa 3.1)

## 1. Fronteira entre Modalidade A (Pública), Modalidade B (Local) e Modalidade C (Backend)

- **Modalidade A — Demo pública ([`frontend/public/`](../frontend/public/)):** estritamente sintética, sem login e sem envio de arquivos pela rede. O catálogo [`documental-manifest.json`](../frontend/public/documental-manifest.json) (`18` arquivos) recusa qualquer arquivo fora da whitelist SHA-256 antes da leitura textual. Tudo roda apenas na memória da aba.
- **Modalidade B — Laboratório experimental local ([`frontend/lab/`](../frontend/lab/) + [`tools/serve_lab.py`](../tools/serve_lab.py)):** estritamente isolado em `localhost` (`serve_lab.py` rejeita bind não-loopback e `assertLocalhostEnvironment()` bloqueia origens externas). **Não compõe o pacote do GitHub Pages e retorna HTTP `404` em [`tools/serve_documental.py`](../tools/serve_documental.py)**.
- **Modalidade C — Fundação institucional inicial ([`backend/`](../backend/) `0.1.0`):** prepara persistência multi-tenant em PostgreSQL e armazenamento controlado sintético fora do repositório (`JYXIA_STORAGE_ROOT`), expondo **exclusivamente** `/api/v1/health/live` e `/api/v1/health/ready`.

## 2. Classificação honesta do estado de segurança

### A) Segurança implementada e verificada em testes
- **Demo pública e ferramentas:** PDF.js `6.5.438` local com `isEvalSupported: false`, CSP estrita (`frame-ancestors 'none'`), `textContent`, `csvSafeCell()`, pacote Pages restrito a `31` arquivos e higiene [`tools/check_publication.py`](../tools/check_publication.py).
- **Configuração fail-closed (`backend/app/core/config.py`):** produção proíbe SQLite, storage sintético local, `DEBUG`, OIDC desabilitado/sem HTTPS, CORS `*` ou HTTP, e senhas/placeholders fracos no banco; `main.py` desativa `/docs`, `/redoc` e `/openapi.json` em produção e sanitiza erros.
- **Isolamento multi-tenant e integridade referencial em 2 camadas:** `TenantContext` obrigatório nos serviços/repositórios **e** FKs compostas de 2 e 3 colunas no banco (`organization_id`, `document_id`, `document_version_id`, `organization_memberships`) impedindo vinculações cross-tenant ou entre documentos/versões diferentes até por SQL direto.
- **Auditoria encadeada endurecida (`AuditEvent`):** hash canônico determinístico (`jyxia.audit.v1`) incluindo ator e timestamp UTC; serialização transacional concorrente via `SELECT ... FOR UPDATE` em `organizations` no PostgreSQL; bloqueio de chaves sensíveis no payload; listeners ORM **e triggers SQL `BEFORE UPDATE / DELETE`** em PostgreSQL e SQLite (migration `20261120_0002`); e verificador detalhado detectando lacunas, reordenação, duplicidade, alteração e quebras de hash.
- **Storage sintético local controlado (`LocalControlledSyntheticStorage`):** rejeição de symlinks e junctions NTFS em toda a hierarquia, bloqueio de gravação na árvore Git, bloqueio de path traversal e extensão divergente, validação estrutural PDF (`%PDF-1.`/`2.0` + `%%EOF`) e PNG (`IHDR`..`IEND` + CRC-32), escrita atômica com `tempfile` + `fsync` + `os.replace` + conferência SHA-256 e limpeza automática em erro.
- **Logs e readiness sanitizados:** `SanitizingFilter` + `build_safe_log_extra` mascaram recursivamente tokens Bearer, JWTs, senhas em DSN, CPFs e chaves PII/documentais; `/api/v1/health/ready` não expõe DSN nem stacktraces.
- **Container e dependências:** [`compose.institutional.yaml`](../compose.institutional.yaml) publica Postgres e backend apenas em `127.0.0.1` (`read_only: true`, `cap_drop: ALL`, `no-new-privileges`); [`backend/Dockerfile`](../backend/Dockerfile) roda sem root e sem ferramentas de teste/auditoria; dependências unificadas em [`backend/pyproject.toml`](../backend/pyproject.toml) com auditoria `pip-audit` automatizada em CI.

### B) Segurança apenas preparada (contratos / interfaces sem fluxo operacional ativo)
- Contratos **OIDC + MFA + RBAC** (`StubOidcAuthenticator` recusando tokens em `security_prep.py`, modelo `User.external_subject` + `mfa_enrolled`, roles em `OrganizationMembership`);
- Portas e contratos de pipeline/idempotência/OCR (`processing_contracts.py` recusando OCR até validação futura).

### C) Segurança pendente para etapas futuras
- Autenticação OIDC real com JWKS/PKCE/MFA obrigatório, sessões e autorização RBAC/ABAC efetiva nos endpoints HTTP;
- APIs HTTP autenticadas de casos, upload e revisão humana;
- Segregação efetiva de credenciais de banco em PostgreSQL (`migration_owner` separado da role restrita da aplicação sem `TRIGGER`/`ALTER`/`TRUNCATE`).

### D) Segurança dependente de infraestrutura externa e governança jurídica
- Object storage privado cifrado com KMS e armazenamento de auditoria resistente a administrador local (WORM / log sink externo);
- Scanner antivírus/CDR para uploads reais, WAF/TLS de borda, gestão de segredos em cofre externo;
- Contratos LGPD (Lei nº 13.709/2018: Controlador/Operadora, DPA, RIPD), guarda legal do PEP (Lei nº 13.787/2018), incidente (Res. CD/ANPD nº 15/2024), parecer **RDC ANVISA nº 657/2022**, **Resolução CFM nº 2.454/2026**, assinaturas **Lei nº 14.063/2020** e pentest independente antes de dados reais.

**Limites explícitos:** este trabalho **não garante** imutabilidade absoluta contra administradores de banco privilegiados, não equivale a auditoria/pentest independente e não habilita uso clínico ou com pacientes reais.

## 3. Versão histórica preservada

O cofre criptografado de navegador da v2.3 permanece isolado em [`legacy/v2/demo-v2.html`](../legacy/v2/demo-v2.html) apenas para regressão histórica (`29` testes legados em `tests/legacy/`), sem conexão com a versão `3.2.0` nem com `backend/`.
