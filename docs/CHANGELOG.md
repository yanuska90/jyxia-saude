# Registro de decisões e versões

## Etapa 3.0 — 20 de novembro de 2026 (Consolidação definitiva, Fundação Backend `0.1.0` e CI PostgreSQL 16)

Reorganização estrutural na branch `jyxia-develop` preservando semanticamente intacta a demonstração pública `v3.2.0` (`frontend/public/`) e construindo a fundação institucional inicial (`backend/` `0.1.0`) do zero, sem reutilizar código de `legacy/v2/`:

- **Consolidação de pastas:** separação definitiva em `frontend/public/` (`31` arquivos Pages), `frontend/lab/` (Modalidade B `localhost`), `backend/` (`0.1.0`), `docs/` (documentação canônica única), `tests/{backend,frontend,e2e,benchmark,legacy}`, `tools/` e `legacy/v2/` isolado; eliminação de múltiplas pastas irmãs externas concentrando backups e armazenamento local sintético exclusivamente em `../JYXIA_LOCAL_WORK/`.
- **Fundação institucional (`backend/` `0.1.0`):** FastAPI com `/api/v1/health/live` e `/api/v1/health/ready` (zero rotas de dados sem autenticação real), `11` modelos SQLAlchemy 2.x multi-tenant com chaves estrangeiras compostas `(organization_id, <fk_id>)`, primeira migração Alembic pronta para PostgreSQL (`JSONB`, `DateTime(timezone=True)`), `TenantContext` obrigatório, trilha `AuditEvent` append-only encadeada por SHA-256, `LocalControlledSyntheticStorage` confinado e contratos preparatórios OIDC/MFA/RBAC e pipeline sem OCR/LLM.
- **CI/Verificação ampliada:** `17/17` testes Pytest em `tests/backend/` + ciclo CLI Alembic local + compilação DDL PostgreSQL + novo job `backend-checks` com `postgres:16-alpine` no GitHub Actions, somados aos `55/55` testes Node, `11/11` Python legados, E2E real e pacote Pages `31/31`.

## 3.2.0 — 20 de novembro de 2026 (Etapa 2.3 — Precisão semântica, motor conservador, separação de modalidades e acessibilidade)

Evolução técnica na branch `jyxia-develop` preservando integralmente DE-01 a DE-05 (sem OCR, LLM/VLM, decisão clínica, persistência em servidor ou invenção de dicionários médicos):

- **Marcador sintético vs. assinatura (Problema 1):** substituído `signatureCue` por `syntheticMarkerCue` (`literal_synthetic_text_marker`, `authenticatesSignature: false`), separando detecção textual literal de `'MARCA FICTICIA'` da ação humana `humanVisualObservation` (`unknown`/`observed`/`not_observed`) e removendo expressões que indicavam análise visual ou autenticação em PNGs, JSON (`jyxia.documental-session.v2`) e CSV (`19` colunas com `marcador_textual_sintetico` e `observacao_visual_humana`).
- **Estados explícitos dos eixos e readiness (Problema 2):** taxonomia de `6` estados nos quatro eixos (`ok`, `conflito`, `abstencao`, `nao_avaliado`, `nao_aplicavel`, `pendente`) e `5` estados gerais (`pendente`, `bloqueado`, `abstencao`, `conferida_com_escopo_limitado`, `conferida`). **Cenário 1** conclui em `abstencao` e **Cenário 9 (`quatro_eixos`)** avalia os quatro eixos completos (`18` fixtures e `31` arquivos públicos).
- **Comparação conservadora de procedimentos e códigos (Problema 3):** sem inventar sinônimos clínicos (`"Cirurgia de catarata"` × `"Facoemulsificação"`), distinguindo código com vs. sem sistema identificado (`procedureCodeSystem`).
- **Modalidade A × Modalidade B × Benchmark separado:** laboratório `localhost` isolado com aliases explícitos invariantes à rotação (`0°/90°/180°/270°`) e benchmark sintético de `8` casos.
- **Temporalidade, rastreabilidade, quarentena e acessibilidade:** regra temporal caracterizada como ilustrativa para `laudo`, bloqueio de `resolve()` em texto livre sobre conflitos críticos, verificação completa da cadeia de eventos e viewports `320px`–`1280px`.

## 3.1.0 (Sincronização Documental) — 20 de novembro de 2026

Auditoria estratégica integral e sincronização documental na branch `jyxia-develop`.

## 3.1.0 — 19 de novembro de 2026 (Etapas 2 e 2.1)

Quatro eixos determinísticos em `consistencyAxes()`, `normalizeLaterality()`, delta UTC, CSV hardening, cenário `8 · Lateralidade divergente`, `14` fixtures e `27` arquivos Pages.

## 3.0.0 — 14 de novembro de 2026

Decisão por Clinical Document Intelligence administrativo em procedimentos eletivos, preservando `demo-v2.html` e testes históricos sem migração destrutiva.
