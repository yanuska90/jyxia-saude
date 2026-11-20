# Arquitetura Institucional da JYXIA — Fundação Endurecida (`0.1.0` · Etapa 3.1)

Documento técnico atualizado na **Etapa 3.1** (`backend/` `0.1.0`), detalhando a fundação relacional multi-tenant após auditoria estrutural e correções de integridade, auditoria concorrente, armazenamento sintético e gestão determinística de dependências.

## 1. Camadas e endurecimentos implementados (`backend/app/`)

- **`core/` (`config.py`, `constants.py`, `logging.py`, `security_prep.py`, `processing_contracts.py`):**
  - **Configuração (`config.py`):** `Settings` fail-closed recusa em `JYXIA_ENV=production`: SQLite, armazenamento local sintético (`JYXIA_ALLOW_LOCAL_SYNTHETIC_STORAGE=true`), `debug=True`, `JYXIA_LOG_LEVEL=DEBUG`, OIDC inativo (`oidc_enabled=false`), OIDC sem HTTPS, CORS com `*` ou HTTP, além de senhas fracas/placeholders (`SYNTHETIC_LOCAL_ONLY_CHANGE_ME`, `< 12` caracteres etc.). `mask_database_url()` remove usuário, senha e query strings sensíveis;
  - **Logs (`logging.py`):** `SanitizingFilter` e `build_safe_log_extra` mascaram recursivamente tokens Bearer, JWTs (`eyJ...`), senhas em DSN, CPFs e chaves proibidas (`document_text`, `raw_value`, `quote_excerpt`, `patient_name`, `birth_date`, `cpf`, `client_secret`, `oidc_token`);
  - **Contratos preparatórios OIDC + MFA + RBAC (`security_prep.py`):** `StubOidcAuthenticator` falha fechado por padrão; `require_permission` valida organização, MFA obrigatório para escrita/admin e papel RBAC (`OrganizationRole`);
  - **Contratos puros de processamento (`processing_contracts.py`):** `NormalizedBoundingBox` valida limites em `[0, 1]` com `x + w <= 1.00001` e `y + h <= 1.00001`; `ExtractionOutcomeStatus` e `FieldCandidateContract` distinguem extração falhada/incompleta, campo ausente/ambíguo/ilegível e revisão humana obrigatória (`human_reviewed: Literal[False]`); `compute_processing_idempotency_key` e `ReprocessingPolicyContract` garantem preservação de runs anteriores e revisões humanas; `UnimplementedOcrAdapter` recusa OCR.

- **`db/` (`base.py`, `session.py`):**
  - Engine compatível com `postgresql+psycopg` (`connect_timeout=2`, `pool_pre_ping=True`) e SQLite local (`PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`); `check_db_connectivity()` retorna apenas `reachable` / `unconfigured` / `unavailable` sem vazar DSN.

- **`models/entities.py` (`11` modelos relacionais multi-tenant + políticas `ON DELETE`):**
  1. `Organization` (`organizations`) — preserva membros e casos (`passive_deletes="all"`, sem `cascade="all, delete-orphan"`);
  2. `User` (`users`) — identidade global preparatória (`external_subject` nullable único para OIDC, e-mail em minúsculas);
  3. `OrganizationMembership` (`organization_memberships`) — papel e status por organização com `UNIQUE(organization_id, user_id)` e `ON DELETE RESTRICT`;
  4. `DocumentCase` (`document_cases`) — `case_code` único por organização, **`external_reference` opcional com índice único parcial `WHERE external_reference IS NOT NULL`** por organização (permitindo nulos múltiplos sem colisões), `CheckConstraint` garantindo `administrative_only = TRUE` e `clinical_approval = FALSE`, e FK composta `fk_document_cases_org_creator` (`created_by_user_id` vinculado à membership na mesma organização, `ON DELETE RESTRICT`);
  5. `Document` (`documents`) — FK composta `fk_documents_org_case` impedindo vínculo cross-tenant de caso; descarte exige justificativa mínima de 3 caracteres;
  6. `DocumentVersion` (`document_versions`) — SHA-256 em minúsculas com 64 caracteres, MIME restrito (`application/pdf`, `image/png`), tamanho positivo, `original_filename` opcional sanitizado sem `/`, `\`, `..`, e **auto-FK composta de 3 colunas `fk_doc_versions_org_doc_supersede`** garantindo que substituições pertençam à mesma organização e ao mesmo `document_id`;
  7. `ProcessingRun` (`processing_runs`) — `idempotency_key` opcional único por organização, constraint `finished_at >= started_at`, e chave composta `(organization_id, document_version_id, id)`;
  8. `ExtractedField` (`extracted_fields`) — **FK composta de 3 colunas `fk_extracted_fields_org_ver_run`** vinculando campo, run e versão documental; coerência obrigatória `(status <> 'abstained') OR (abstained = TRUE)`; nunca misturado com `HumanReview`;
  9. `EvidenceReference` (`evidence_references`) — coordenadas normalizadas top-left `[0.0, 1.0]` (`bbox_x`, `bbox_y`, `bbox_w`, `bbox_h` com checks `bbox_x + bbox_w <= 1.00001` e `bbox_y + bbox_h <= 1.00001`), **FK composta de 3 colunas `fk_evidence_refs_org_ver_field`**;
  10. `HumanReview` (`human_reviews`) — **FK composta `fk_human_reviews_org_reviewer`** exigindo associação do revisor na organização em `organization_memberships`, e **FK composta de 3 colunas `fk_human_reviews_org_ver_evidence`** garantindo evidência da mesma organização e versão;
  11. `AuditEvent` (`audit_events`) — `schema_version` (`jyxia.audit.v1`), `fk_audit_events_org_actor` vinculado à membership quando `actor_user_id` presente, trilha encadeada por `sequence_number` e `event_hash` canônico.

  *Política de exclusão:* todas as relações críticas utilizam `ON DELETE RESTRICT` visando preservação controlada de histórico até definição jurídica/operacional de retenção.

## 2. Auditoria institucional concorrente, canonicalização e triggers

- **Canonicalização (`AUDIT_SCHEMA_VERSION = 'jyxia.audit.v1'`):** `compute_audit_event_hash()` serializa em JSON ordenado e determinístico: `schema_version`, `organization_id`, `sequence_number`, `actor_user_id`, `event_type`, `target_entity_type`, `target_entity_id`, `created_at` normalizado em UTC ISO-8601 (`%Y-%m-%dT%H:%M:%S.%fZ`), `payload_json` validado contra chaves/valores sensíveis (`AuditPayloadError`) e `prev_event_hash`.
- **Serialização concorrente por organização:** `AuditEventRepository.append_event()` adquire bloqueio transacional `SELECT id FROM organizations WHERE id = :org_id FOR UPDATE` no PostgreSQL (serializando transações concorrentes na mesma organização sem bloquear outras organizações), combinado com `UNIQUE(organization_id, sequence_number)` e `append_event_atomic()` com bloqueio local por organização para SQLite e retentativas limitadas.
- **Proteção no banco contra `UPDATE`/`DELETE` SQL diretos:** a migration incremental [`20261120_0002_harden_constraints_audit_triggers.py`](../backend/migrations/versions/20261120_0002_harden_constraints_audit_triggers.py) instala os triggers `trg_audit_events_no_update` e `trg_audit_events_no_delete` no PostgreSQL (`BEFORE UPDATE / DELETE`) e triggers equivalentes no SQLite local (`RAISE(ABORT, ...)`), além dos listeners ORM em `AuditEvent`.
- **Limite obrigatório:** triggers **não conferem imutabilidade absoluta**. Um administrador privilegiado do banco (`superuser` / role dona da tabela) ainda pode desabilitar triggers, executar `TRUNCATE` ou restaurar backups alterados; garantia mais forte exigirá futuramente separação de roles (`app_user` sem DDL/TRIGGER vs. `migration_owner`) e ancoragem/armazenamento WORM externo.

## 3. Storage controlado sintético e API HTTP (`0.1.0`)

- [`LocalControlledSyntheticStorage`](../backend/app/services/storage.py) bloqueia symlinks e junctions NTFS em toda a cadeia de diretórios, rejeita nomes e chaves maliciosas, valida assinaturas estruturais de PDF (`%PDF-1.`/`2.0` com trailer `%%EOF`) e PNG (cabeçalho + walk completo de chunks `IHDR`..`IEND` com verificação CRC-32), grava via arquivo temporário + `fsync` + verificação SHA-256 + `os.replace()` atômico e limpa arquivos parciais em falhas. **Uso restrito a binários sintéticos em dev/teste.**
- A API expõe **apenas** `GET /api/v1/health/live` e `GET /api/v1/health/ready` (`200` ou `503` sanitizado) e desativa `/docs` + `/openapi.json` quando `JYXIA_ENV=production`.

## 4. Migrações e validação PostgreSQL 16 vs. local

- Migrações incrementais preservadas em [`backend/migrations/versions/`](../backend/migrations/versions): `20261120_0001` (esquema inicial) e `20261120_0002` (hardening relacional + triggers append-only).
- Localmente (estação Windows sem Docker Desktop nem PostgreSQL nativo): `22/22` testes em `tests/backend/` executados contra SQLite com `PRAGMA foreign_keys=ON` e verificação de DDL PostgreSQL;
- Em CI ([`.github/workflows/security.yml`](../.github/workflows/security.yml)): validação real contra **`postgres:16-alpine`** cobrindo ciclo `upgrade head` -> `downgrade 20261120_0001` -> `downgrade base` -> `upgrade head` e toda a suíte `tests/backend/` (incluindo concorrência em múltiplas sessões PostgreSQL e rejeição de `UPDATE`/`DELETE` pelos triggers).
