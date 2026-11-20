# Registro de decisões e versões

## Etapa 3.1 — 20 de novembro de 2026 (Hardening estrutural da fundação `0.1.0`, triggers SQL e auditoria concorrente)

Auditoria crítica completa da fundação institucional `0.1.0` na branch `jyxia-develop` sem expandir escopo para login funcional, OIDC ativo, OCR ou rotas documentais:

- **Integridade relacional multi-tenant (`entities.py`, `schemas/tenant.py`, migration `20261120_0002`):** adicionadas FKs compostas de 3 colunas (`fk_doc_versions_org_doc_supersede`, `fk_extracted_fields_org_ver_run`, `fk_evidence_refs_org_ver_field`, `fk_human_reviews_org_ver_evidence`), vínculo obrigatório à `organization_memberships` para criadores, revisores e atores (`fk_document_cases_org_creator`, `fk_human_reviews_org_reviewer`, `fk_audit_events_org_actor`), `DocumentCase.external_reference` com índice único parcial por organização preservando nulos, `DocumentVersion.original_filename` sanitizado, `ProcessingRun.idempotency_key`, limites `bbox_x + bbox_w <= 1.00001` / `bbox_y + bbox_h <= 1.00001`, timestamps `finished_at >= started_at`, coerência de `abstained`, justificativa mínima de descarte e remoção de `cascade="all, delete-orphan"` preservando `ON DELETE RESTRICT`.
- **Auditoria institucional concorrente e proteção no banco (`repositories/institutional.py`, migration `0002`):** hash canônico completo (`jyxia.audit.v1`) incluindo `actor_user_id` e `created_at` UTC normalizado; bloqueio de chaves sensíveis em `payload_json`; serialização transacional concorrente por organização via `SELECT ... FOR UPDATE` no PostgreSQL (e bloqueio local + retentativa controlada em SQLite); instalação de triggers `BEFORE UPDATE` e `BEFORE DELETE` (`trg_audit_events_no_update`, `trg_audit_events_no_delete`) no PostgreSQL e SQLite; verificador detalhado cobrindo todas as formas de adulteração (sem alegar imutabilidade absoluta contra administradores privilegiados).
- **Hardening de storage sintético (`storage.py`):** validação de symlinks e junctions NTFS em toda a cadeia de caminhos, verificação estrutural PDF (`%PDF-1.`/`2.0` + `%%EOF`) e PNG (`IHDR`..`IEND` com CRC-32), escrita atômica com `tempfile` + `fsync` + `os.replace` e limpeza garantida em erro.
- **Configuração fail-closed, contratos e fonte única de dependências (`config.py`, `logging.py`, `main.py`, `processing_contracts.py`, `pyproject.toml`, `tools/sync_backend_deps.py`, `.github/workflows/security.yml`):** bloqueio de placeholders/debug/OIDC ausente/CORS `*` em `production`, desligamento de `/openapi.json` em produção, contratos completos de execução/reprocessamento/abstenção, separação runtime (`requirements.txt` sem `pytest`) vs. dev (`requirements-dev.txt` com `pytest==9.2.0` e `certifi==2026.10.23`), auditoria `pip-audit` em CI com PostgreSQL 16 e container backend `read_only: true`.
- **Testes ampliados:** `22/22` Pytest aprovados localmente e no PostgreSQL 16 em CI, preservando `55/55` Node, `11/11` Python legados, E2E real e pacote Pages `31/31`.

## Etapa 3.0 — 20 de novembro de 2026 (Consolidação definitiva, Fundação Backend `0.1.0` e CI PostgreSQL 16)

Reorganização estrutural na branch `jyxia-develop` consolidando pastas (`frontend/public/`, `frontend/lab/`, `backend/`, `docs/`, `tests/`, `tools/`, `legacy/v2/` isolado), criação dos `11` modelos relacionais iniciais, migration `0001`, API health e `17/17` testes iniciais.

## 3.2.0 — 20 de novembro de 2026 (Etapa 2.3 — Precisão semântica, motor conservador, separação de modalidades e acessibilidade)

Motor de quatro eixos, `6` estados por eixo, `5` estados gerais, `syntheticMarkerCue` separado de `humanVisualObservation`, comparação conservadora de códigos e laboratório Modalidade B.

## 3.1.0 (Sincronização Documental) / 3.1.0 (Etapas 2–2.1) / 3.0.0

Histórico preservado da evolução documental e v3 sem misturar legado `demo-v2.html`.
