# Segurança e privacidade da JYXIA (v3.2.0 + Fundação Backend 0.1.0)

## 1. Fronteira entre Modalidade A (Pública), Modalidade B (Local) e Modalidade C (Backend)

- **Modalidade A — Demo pública ([`frontend/public/`](../frontend/public/)):** estritamente sintética, sem login e sem envio de arquivos pela rede. O catálogo [`documental-manifest.json`](../frontend/public/documental-manifest.json) (`18` arquivos) recusa qualquer arquivo fora da whitelist SHA-256 antes da leitura textual. Tudo roda apenas na memória da aba.
- **Modalidade B — Laboratório experimental local ([`frontend/lab/`](../frontend/lab/) + [`tools/serve_lab.py`](../tools/serve_lab.py)):** estritamente isolado em `localhost` (`serve_lab.py` rejeita bind não-loopback e `assertLocalhostEnvironment()` bloqueia origens externas). **Não compõe o pacote do GitHub Pages e retorna HTTP `404` em [`tools/serve_documental.py`](../tools/serve_documental.py)**.
- **Modalidade C — Fundação institucional inicial ([`backend/`](../backend/) `0.1.0`):** prepara persistência multi-tenant em PostgreSQL e storage isolado em disco sintético fora do repositório (`JYXIA_STORAGE_ROOT`), expondo **exclusivamente** `/api/v1/health/live` e `/api/v1/health/ready` enquanto OIDC + MFA + RBAC reais não forem ativados.

**Controles implementados na demo pública e ferramentas locais:**
- Mozilla PDF.js `6.5.438` em `frontend/public/vendor/` com `isEvalSupported: false`; CSP estrita (`default-src 'self'`, `object-src 'none'`, `form-action 'none'`); cabeçalhos `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` e `frame-ancestors 'none'` nos servidores Python;
- Inserção segura via `textContent` e neutralização `csvSafeCell()` em downloads CSV;
- Cadeia local SHA-256 em memória (`actorAuthenticated: false`, apenas demonstrativa);
- Empacotamento GitHub Pages restrito a `31` arquivos de `frontend/public/`, validado em [`tools/verify_pages_package.py`](../tools/verify_pages_package.py);
- Verificação básica de higiene em [`tools/check_publication.py`](../tools/check_publication.py) recusando `.env*` (exceto `.env.example`), bancos locais `.db`/`.sqlite*`, pastas `JYXIA_LOCAL_WORK` ou chaves/DSNs externos.

**Controles implementados no backend institucional `0.1.0`:**
- **Fail-closed para autenticação:** `StubOidcAuthenticator` recusa qualquer token enquanto OIDC real não existir; nenhuma rota clínica/administrativa de dados fica ativa em HTTP sem autenticação real;
- **Isolamento multi-tenant em duas camadas:** `TenantContext` obrigatório nos repositórios e serviços, além de chaves estrangeiras compostas `(organization_id, <fk_id>)` no esquema PostgreSQL/SQLite impedindo vinculação cruzada entre organizações;
- **Auditoria append-only:** `AuditEvent` com encadeamento SHA-256 por organização e listeners SQLAlchemy impedindo atualização ou exclusão;
- **Storage sintético confinado:** `LocalControlledSyntheticStorage` exige magic bytes válidos (`%PDF-` ou PNG), respeita teto em bytes, rejeita path traversal (`..`), restringe chaves à subpasta da organização e proíbe gravar dentro da árvore do repositório Git;
- **Logs sanitizados e readiness sem vazamento:** `SanitizingFilter` mascara tokens, senhas em DSN, padrões de CPF e chaves sensíveis; `/api/v1/health/ready` retorna HTTP `503` sem expor string de conexão ou traceback.
- **Bind restrito no Compose institucional:** [`compose.institutional.yaml`](../compose.institutional.yaml) publica Postgres e backend apenas em `127.0.0.1` e exclui `MONGO_PASSWORD`/`JYXIA_API_TOKEN` herdados da versão antiga.

Nenhuma dessas proteções substitui auditoria independente de segurança ou pentest antes de uso com dados reais.

## 2. Requisitos antes de tratar dados reais em produção

- **Governança LGPD e contratos (Lei nº 13.709/2018):** formalização de Controlador/Operadora, DPA, RIPD, bases legais (arts. 7º e 11), retenção operacional distinta da guarda legal de 20 anos no PEP (Lei nº 13.787/2018) e plano de comunicação de incidentes (Res. CD/ANPD nº 15/2024);
- **Autenticação e storage institucionais:** ativação real de OIDC + MFA + RBAC/ABAC no servidor, KMS/object storage cifrado privado e antivírus/CDR em uploads antes de habilitar endpoints HTTP de upload/revisão;
- **Regulação sanitária e assinaturas:** parecer perante **RDC ANVISA nº 657/2022**, **Resolução CFM nº 2.454/2026** e **Lei nº 14.063/2020** (ICP-Brasil / assinatura avançada).

## 3. Versão histórica preservada

O cofre criptografado de navegador da v2.3 permanece isolado em [`legacy/v2/demo-v2.html`](../legacy/v2/demo-v2.html) apenas para regressão histórica (`29` testes legados em `tests/legacy/`), sem conexão com a versão `3.2.0` nem com `backend/`.
