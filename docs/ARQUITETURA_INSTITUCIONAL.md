# Arquitetura Institucional da JYXIA — Fundação Inicial (`0.1.0`)

Documento técnico da **Etapa 3.0** (`backend/` `0.1.0`), registrando a fundação relacional e de serviços criada para evoluir a futura **Modalidade C** sem interromper a demonstração pública `v3.2.0` (`frontend/public/`) e sem prometer recursos ainda não implementados.

## 1. Papel da fundação `0.1.0` e separação de responsabilidades

O diretório [`backend/`](../backend/) estabelece a base estrutural em Python (`3.13`), **FastAPI**, **Pydantic v2**, **SQLAlchemy 2.x**, **Alembic** e **PostgreSQL** (`psycopg 3`), totalmente independente de [`legacy/v2/`](../legacy/v2/).

Camadas implementadas sob `backend/app/`:
- **`core/` (`config.py`, `constants.py`, `logging.py`, `security_prep.py`, `processing_contracts.py`):**
  - Validação fail-closed de variáveis de ambiente (`Settings` / `load_settings`), proibindo SQLite e armazenamento local sintético quando `JYXIA_ENV=production` e exigindo HTTPS ao habilitar OIDC; mascaramento obrigatório de credenciais em `masked_database_url()` e `__repr__`;
  - Taxonomias administrativas explícitas (`CaseReadinessState` com `administrative_only=True` e `clinical_approval=False`, `AxisStatus`, `HumanReviewAction`, `OrganizationRole`, `ProcessingStatus`);
  - Sanitização de logs (`SanitizingFilter`, `build_safe_log_extra`) removendo bearer tokens, senhas de DSN, padrões semelhantes a CPF e chaves proibidas (`document_text`, `raw_value`, `quote_excerpt`, `patient_name`, `birth_date`, `token`, `secret`);
  - Contratos explícitos de preparação **OIDC + MFA + RBAC** (`StubOidcAuthenticator` recusando chamadas ativas por padrão, sem usuários sintéticos implícitos) e contratos puros de extração/eixos (`UnimplementedOcrAdapter` recusando chamadas porque OCR permanece fora desta etapa).
- **`db/` (`base.py`, `session.py`):**
  - `DeclarativeBase` com convenção determinística de nomes para índices, chaves únicas, checks e chaves estrangeiras;
  - `create_db_engine` compatível com `postgresql+psycopg` (`connect_timeout=2`, `pool_pre_ping=True`) e SQLite de testes locais (`PRAGMA foreign_keys=ON`);
  - `check_db_connectivity` executando `SELECT 1` e retornando estado sanitizado (`reachable` / `unconfigured` / `unavailable`) sem expor DSN ou mensagens internas de driver.
- **`models/entities.py` (`11` modelos relacionais multi-tenant):**
  1. `Organization` (`organizations`)
  2. `User` (`users`)
  3. `OrganizationMembership` (`organization_memberships`)
  4. `DocumentCase` (`document_cases` — com `CheckConstraint` garantindo `administrative_only = TRUE` e `clinical_approval = FALSE` no próprio banco)
  5. `Document` (`documents`)
  6. `DocumentVersion` (`document_versions` — SHA-256 obrigatório, MIME estrito `application/pdf` ou `image/png`, tamanho positivo e controle de substituição sem auto-ciclo)
  7. `ProcessingRun` (`processing_runs`)
  8. `ExtractedField` (`extracted_fields`)
  9. `EvidenceReference` (`evidence_references` — coordenadas normalizadas validadas em `[0, 1]`)
  10. `HumanReview` (`human_reviews` — justificativa mínima de 5 caracteres e vínculo consistente à versão/evidência)
  11. `AuditEvent` (`audit_events` — trilha encadeada por `sequence_number`, `prev_event_hash` e `event_hash` por organização, protegida por listeners `before_update` e `before_delete` em modo append-only).
- **`schemas/` e `repositories/institutional.py`:**
  - Todas as operações de negócio e auditoria exigem `TenantContext(organization_id, actor_user_id)`;
  - Isolamento estrutural em duas camadas: filtros explícitos por `organization_id` no repositório **e** chaves estrangeiras compostas `(organization_id, <fk_id>)` no esquema PostgreSQL/SQLite impedindo vinculação cruzada entre organizações mesmo em SQL direto.
- **`services/` (`health_service.py`, `storage.py`, `institutional_service.py`):**
  - `LocalControlledSyntheticStorage` implementa a interface `DocumentStoragePort` validando assinatura binária (`%PDF-` ou cabeçalho PNG), limite de tamanho, extensão permitida, bloqueio de path traversal, confinamento à subpasta da organização e proibição explícita de gravar dentro da árvore do repositório Git;
  - `InstitutionalService` coordena transações internas registrando `AuditEvent` encadeado nas operações críticas sem gravar conteúdo documental bruto nos logs.
- **`api/` (`main.py`, `api/router.py`, `api/routes/health.py`):**
  - Expõe exclusivamente `GET /api/v1/health/live` e `GET /api/v1/health/ready` (`HTTP 200` ou `503` sanitizado) e handlers globais de erro sem stacktrace;
  - Nenhuma rota de casos, documentos ou revisão humana foi exposta em HTTP antes da implementação real de OIDC + MFA + RBAC por organização.

## 2. Migrações e ambiente de verificação

As migrações ficam em [`backend/migrations/`](../backend/migrations/) com configuração [`backend/alembic.ini`](../backend/alembic.ini) e revisão inicial [`20261120_0001_initial_institutional_foundation.py`](../backend/migrations/versions/20261120_0001_initial_institutional_foundation.py). Tipos JSON usam `JSON().with_variant(JSONB(), "postgresql")`, e todos os timestamps usam `DateTime(timezone=True)`.

**Limitação local e validação em CI (informação honesta):**
- A estação local Windows onde esta entrega foi desenvolvida não possui Docker Desktop nem serviço PostgreSQL nativo instalados;
- Localmente foram executados e aprovados: toda a suíte `pytest tests/backend` sobre SQLite com `PRAGMA foreign_keys=ON`, ciclo completo `alembic upgrade head` -> `downgrade base` -> `upgrade head`, verificação `compare_metadata == []` e compilação DDL explícita para o dialeto PostgreSQL (`JSONB`, `TIMESTAMP WITH TIME ZONE` e FKs compostas);
- O workflow [`.github/workflows/security.yml`](../.github/workflows/security.yml) executa o job `backend-checks` com um container de serviço **`postgres:16-alpine`**, rodando o ciclo real `alembic` e toda a suíte `pytest tests/backend` contra PostgreSQL 16 em CI.

## 3. O que explicitamente NÃO existe na versão `0.1.0`

- Login real OIDC/MFA ativo ou endpoints HTTP de casos, upload e revisão humana;
- Processamento de OCR, modelos de IA/LLM ou extração server-side conectada à API;
- Armazenamento em nuvem (S3/GCS com KMS), antivírus/CDR de arquivos ou conectores hospitalares (MV, Tasy, RNDS, FHIR ativo);
- Parecer jurídico-regulatório (LGPD/DPA/ANVISA/CFM) ou autorização de uso com pacientes reais.
