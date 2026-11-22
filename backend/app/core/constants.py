"""Domain constants and constrained taxonomies for JYXIA institutional backend."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import GetJsonSchemaHandler
from pydantic_core import CoreSchema

APP_NAME = "JYXIA Institutional Foundation"
APP_VERSION = "0.2.0"
DEFAULT_POLICY_VERSION = "3.2.0"
DEFAULT_MAX_DOCUMENT_BYTES = 10 * 1024 * 1024  # 10 MiB ceiling for controlled synthetic binaries

ALLOWED_MIME_TYPES: frozenset[str] = frozenset({"application/pdf", "image/png"})
ALLOWED_ENVIRONMENTS: frozenset[str] = frozenset({"development", "test", "staging", "production"})

SESSION_COOKIE_NAME = "jyxia_session"
CSRF_COOKIE_NAME = "jyxia_csrf"
OIDC_TX_COOKIE_NAME = "jyxia_oidc_tx"
CSRF_HEADER_NAME = "X-CSRF-Token"


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
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ABSTAINED = "abstained"
    QUARANTINED = "quarantined"
    FAILED = "failed"


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
