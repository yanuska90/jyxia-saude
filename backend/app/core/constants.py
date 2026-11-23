"""Domain constants and constrained taxonomies for JYXIA institutional backend."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import GetJsonSchemaHandler
from pydantic_core import CoreSchema

APP_NAME = "JYXIA Institutional Foundation"
APP_VERSION = "0.2.0"
DEFAULT_POLICY_VERSION = "3.2.0"
DEFAULT_MAX_DOCUMENT_BYTES = 20 * 1024 * 1024  # 20 MiB ceiling for controlled synthetic binaries

ALLOWED_MIME_TYPES: frozenset[str] = frozenset({"application/pdf", "image/png"})
ALLOWED_ENVIRONMENTS: frozenset[str] = frozenset({"development", "test", "staging", "production"})

SESSION_COOKIE_NAME = "jyxia_session"
CSRF_COOKIE_NAME = "jyxia_csrf"
OIDC_TX_COOKIE_NAME = "jyxia_oidc_tx"
CSRF_HEADER_NAME = "X-CSRF-Token"
IDEMPOTENCY_KEY_HEADER_NAME = "Idempotency-Key"


class OrganizationStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class OrganizationRole(StrEnum):
    ORG_ADMIN = "org_admin"
    # Canonical external and internal role identifier is 'document_reviewer' (strictly administrative).
    # Legacy 'clinical_reviewer' and 'administrative_reviewer' resolve as aliases to DOCUMENT_REVIEWER.
    DOCUMENT_REVIEWER = "document_reviewer"
    CLINICAL_REVIEWER = "document_reviewer"
    ADMINISTRATIVE_REVIEWER = "document_reviewer"
    ADMIN_OPERATOR = "admin_operator"
    AUDITOR_READONLY = "auditor_readonly"
    READ_ONLY = "read_only"

    @classmethod
    def _missing_(cls, value: object) -> OrganizationRole | None:
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"clinical_reviewer", "administrative_reviewer", "document_reviewer"}:
                return cls.DOCUMENT_REVIEWER
        return None

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> dict[str, Any]:
        json_schema = handler(core_schema)
        json_schema["enum"] = [member.value for member in cls]
        return json_schema


class MembershipStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class ExternalIdentityStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class SecurityAuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class CaseReadinessState(StrEnum):
    PENDENTE = "pendente"
    BLOQUEADO = "bloqueado"
    ABSTENCAO = "abstencao"
    CONFERIDA_COM_ESCOPO_LIMITADO = "conferida_com_escopo_limitado"
    CONFERIDA = "conferida"


class AxisName(StrEnum):
    IDENTIDADE = "identidade"
    PROCEDIMENTO_CODIGO = "procedimento_codigo"
    LATERALIDADE = "lateralidade"
    TEMPORALIDADE = "temporalidade"


class AxisStatus(StrEnum):
    OK = "ok"
    CONFLITO = "conflito"
    ABSTENCAO = "abstencao"
    NAO_AVALIADO = "nao_avaliado"
    NAO_APLICAVEL = "nao_aplicavel"
    PENDENTE = "pendente"


class DocumentKind(StrEnum):
    LAUDO = "laudo"
    PEDIDO = "pedido"
    TERMO = "termo"
    IMAGEM = "imagem"
    DESCONHECIDO = "desconhecido"


class ProcessingStatus(StrEnum):
    QUEUED = "queued"
    PENDING = "pending"
    RUNNING = "running"
    RETRY_WAIT = "retry_wait"
    SUCCEEDED = "succeeded"
    COMPLETED = "completed"
    ABSTAINED = "abstained"
    QUARANTINED = "quarantined"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ProcessingStepType(StrEnum):
    VERIFY_OBJECT_INTEGRITY = "verify_object_integrity"
    EXTRACT_PDF_TEXT = "extract_pdf_text"
    COMPARE_CONSISTENCY = "compare_consistency"


ACTIVE_PROCESSING_STATUSES: tuple[str, ...] = (
    ProcessingStatus.QUEUED.value,
    ProcessingStatus.RUNNING.value,
    ProcessingStatus.RETRY_WAIT.value,
)
DEFAULT_PROCESSING_POLICY_VERSION = "3.3.2"
DEFAULT_INTEGRITY_EXTRACTOR_VERSION = "integrity-verifier-3.3.2"
DEFAULT_PDF_TEXT_EXTRACTOR_VERSION = "pdfminer-deterministic-3.3.3"
DEFAULT_CONSISTENCY_ENGINE_NAME = "jyxia-deterministic-consistency"
DEFAULT_CONSISTENCY_ENGINE_VERSION = "3.3.4"
DEFAULT_CONSISTENCY_POLICY_VERSION = "3.3.4"
DEFAULT_CONSISTENCY_TEMPORALITY_MAX_AGE_DAYS = 30
DEFAULT_WORKER_ID = "jyxia-worker-1"
DEFAULT_WORKER_POLL_INTERVAL_SECONDS = 1.0
DEFAULT_WORKER_LEASE_SECONDS = 60
DEFAULT_PROCESSING_MAX_ATTEMPTS = 5
DEFAULT_PROCESSING_RETRY_BACKOFF_MIN_SECONDS = 2.0
DEFAULT_PROCESSING_RETRY_BACKOFF_MAX_SECONDS = 60.0
DEFAULT_PROCESSING_RETRY_JITTER_RATIO = 0.2
DEFAULT_WORKER_MAX_JOBS_PER_CYCLE = 10
DEFAULT_PDF_MAX_PAGES = 50
DEFAULT_PDF_MAX_EXTRACTED_CHARS = 250_000
DEFAULT_PDF_MAX_WORDS_PER_DOC = 50_000
DEFAULT_PDF_MAX_BLOCKS_PER_PAGE = 1_000
DEFAULT_PDF_EXTRACTION_TIMEOUT_SECONDS = 10.0
DEFAULT_PDF_MAX_COMPLEXITY_OBJECTS = 20_000

EXPLICIT_ALLOWLIST_FIELD_KEYS: tuple[str, ...] = (
    "document_type",
    "subfamily",
    "patient",
    "birth_date",
    "identifier",
    "issue_date",
    "origin",
    "procedure",
    "procedure_code_system",
    "procedure_code",
    "laterality",
)


class ExtractedFieldStatus(StrEnum):
    EXTRACTED = "extracted"
    MISSING = "missing"
    ABSTAINED = "abstained"
    AMBIGUOUS = "ambiguous"
    UNREADABLE = "unreadable"


class HumanReviewAction(StrEnum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    DATE_CORRECTION = "date_correction"
    QUARANTINE_ACK = "quarantine_ack"
    CASE_LINK_CONFIRMATION = "case_link_confirmation"
    REPLACEMENT_CONFIRMATION = "replacement_confirmation"
    ABSTENTION_REVIEW = "abstention_review"


class StorageDriver(StrEnum):
    LOCAL_CONTROLLED_SYNTHETIC = "local_controlled_synthetic"
