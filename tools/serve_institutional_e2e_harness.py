"""Self-contained local institutional harness (FastAPI + background ProcessingWorker + seeded synthetic cases)
used exclusively by tests/e2e/test_institutional_e2e.mjs for real-browser CDP E2E verification.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import threading
import time

import uvicorn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

from app.core.config import Settings  # noqa: E402
from app.core.constants import DocumentKind, OrganizationRole  # noqa: E402
from app.core.session_crypto import hmac_token_digest  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import create_db_engine, create_session_factory  # noqa: E402
from app.main import create_app  # noqa: E402
import app.models.entities  # noqa: F401, E402
from app.repositories.identity import IdentityAndSessionRepository  # noqa: E402
from app.repositories.institutional import OrganizationRepository  # noqa: E402
from app.schemas.tenant import DocumentCaseCreateInput, TenantContext  # noqa: E402
from app.services.institutional_service import InstitutionalService  # noqa: E402
from app.services.processing_worker import ProcessingWorker  # noqa: E402
from app.services.storage import LocalControlledSyntheticStorage  # noqa: E402
from tests.backend.test_human_review_and_institutional_ui import (  # noqa: E402
    _build_synthetic_selectable_pdf,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8035)
    parser.add_argument("--session-token", default="e2e-raw-session-token-335-secret-value")
    parser.add_argument("--csrf-token", default="e2e-raw-csrf-token-335-secret-value")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="jyxia-inst-e2e-335-") as tmp:
        tmp_path = Path(tmp)
        db_url = f"sqlite:///{(tmp_path / 'inst_e2e.sqlite3').as_posix()}"
        storage_dir = tmp_path / "synthetic_storage"

        settings = Settings(
            env="test",
            app_base_url=f"http://127.0.0.1:{args.port}",
            database_url=db_url,
            storage_root=str(storage_dir),
            allow_local_synthetic_storage=True,
            session_secret="E2E_Session_Hmac_Aead_Key_32_Bytes_Minimum_335!",
            csrf_secret="E2E_Csrf_Hmac_Key_32_Bytes_Minimum_Value_335!",
            session_cookie_secure=False,
            oidc_enabled=False,
        )
        engine = create_db_engine(db_url)
        Base.metadata.create_all(engine)
        factory = create_session_factory(engine)
        storage = LocalControlledSyntheticStorage(
            storage_dir,
            enabled=True,
            max_bytes=settings.max_document_bytes,
        )
        worker = ProcessingWorker(factory, storage, settings, worker_id="e2e-worker-335")

        session = factory()
        try:
            org = OrganizationRepository.create_organization(
                session, slug="hospital-sintetico-335", name="Hospital Sintetico JYXIA"
            )
            reviewer = OrganizationRepository.create_user(
                session,
                email="revisor.e2e@jyxia.local",
                display_name="Dra. Clara Revisora (Sintetica)",
                mfa_enrolled=True,
            )
            OrganizationRepository.assign_membership(
                session,
                TenantContext(organization_id=org.id),
                user_id=reviewer.id,
                role=OrganizationRole.ORG_ADMIN.value,
            )
            ext = IdentityAndSessionRepository.bind_external_identity(
                session,
                user_id=reviewer.id,
                issuer="https://idp.jyxia.local/realms/e2e",
                subject="sub-e2e-reviewer-335",
                email_at_binding=reviewer.email,
            )
            now = datetime.now(timezone.utc)
            IdentityAndSessionRepository.create_auth_session(
                session,
                user_id=reviewer.id,
                external_identity_id=ext.id,
                active_organization_id=org.id,
                session_token_hash=hmac_token_digest(
                    args.session_token, secret=settings.session_secret, context="session_token"
                ),
                csrf_token_hash=hmac_token_digest(
                    args.csrf_token, secret=settings.csrf_secret, context="csrf_token"
                ),
                auth_method="oidc_authorization_code_pkce",
                acr="urn:jyxia:loa:mfa",
                amr_json=["pwd", "otp"],
                mfa_verified_at=now,
                oidc_auth_time=now,
                idle_expires_at=now + timedelta(minutes=30),
                absolute_expires_at=now + timedelta(hours=8),
                now=now,
            )

            ctx = TenantContext(organization_id=org.id, actor_user_id=reviewer.id)

            # Scenario A: Coherent 4-axis case (awaiting human review -> transitions to conferida)
            case_a = InstitutionalService.create_case(
                session,
                ctx,
                DocumentCaseCreateInput(
                    case_code="CASO-E2E-COERENTE-A",
                    procedure_reference="TUSS:31309054",
                    external_reference="GUIA-E2E-001",
                    declared_laterality="OD",
                ),
            )
            InstitutionalService.ingest_case_document(
                session,
                ctx,
                storage=storage,
                case_id=case_a.id,
                content=_build_synthetic_selectable_pdf(
                    [
                        "Tipo: solicitacao",
                        "Subfamilia: oftalmologia",
                        "Origem: Ambulatorio Sintetico E2E",
                        "Paciente: Helena Sintetica Oliveira",
                        "Nascimento: 1975-08-14",
                        "Identificador: CPF-SYN-335-01",
                        "Emissao: 2026-10-10",
                        "Procedimento: Facoemulsificacao com implante de lente intraocular",
                        "Sistema: TUSS",
                        "Codigo: 31309054",
                        "Lateralidade: OD",
                    ]
                ),
                mime_type="application/pdf",
                original_filename="solicitacao-coerente-a.pdf",
                document_kind=DocumentKind.PEDIDO,
                source_label="Solicitacao Medica A",
            )
            InstitutionalService.ingest_case_document(
                session,
                ctx,
                storage=storage,
                case_id=case_a.id,
                content=_build_synthetic_selectable_pdf(
                    [
                        "Tipo: laudo",
                        "Subfamilia: oftalmologia",
                        "Origem: Centro Diagnostico Sintetico E2E",
                        "Paciente: Helena Sintetica Oliveira",
                        "Nascimento: 1975-08-14",
                        "Identificador: CPF-SYN-335-01",
                        "Emissao: 2026-10-12",
                        "Procedimento: Facoemulsificacao com implante de lente intraocular",
                        "Sistema: TUSS",
                        "Codigo: 31309054",
                        "Lateralidade: Olho Direito (OD)",
                    ]
                ),
                mime_type="application/pdf",
                original_filename="laudo-coerente-b.pdf",
                document_kind=DocumentKind("laudo"),
                source_label="Laudo Biometria B",
            )

            # Scenario B: Conflicting Laterality (OD vs OE -> remains bloqueado even after human review)
            case_b = InstitutionalService.create_case(
                session,
                ctx,
                DocumentCaseCreateInput(
                    case_code="CASO-E2E-CONFLITO-B",
                    procedure_reference="TUSS:31309054",
                    external_reference="GUIA-E2E-002",
                ),
            )
            InstitutionalService.ingest_case_document(
                session,
                ctx,
                storage=storage,
                case_id=case_b.id,
                content=_build_synthetic_selectable_pdf(
                    [
                        "Tipo: solicitacao",
                        "Paciente: Marcos Sintetico Souza",
                        "Nascimento: 1968-02-20",
                        "Identificador: CPF-SYN-335-02",
                        "Emissao: 2026-10-15",
                        "Procedimento: Facoemulsificacao",
                        "Sistema: TUSS",
                        "Codigo: 31309054",
                        "Lateralidade: OD",
                    ]
                ),
                mime_type="application/pdf",
                original_filename="solicitacao-conflito-od.pdf",
                document_kind=DocumentKind.PEDIDO,
                source_label="Solicitacao OD",
            )
            InstitutionalService.ingest_case_document(
                session,
                ctx,
                storage=storage,
                case_id=case_b.id,
                content=_build_synthetic_selectable_pdf(
                    [
                        "Tipo: laudo",
                        "Paciente: Marcos Sintetico Souza",
                        "Nascimento: 1968-02-20",
                        "Identificador: CPF-SYN-335-02",
                        "Emissao: 2026-10-15",
                        "Procedimento: Facoemulsificacao",
                        "Sistema: TUSS",
                        "Codigo: 31309054",
                        "Lateralidade: OE",
                    ]
                ),
                mime_type="application/pdf",
                original_filename="laudo-conflito-oe.pdf",
                document_kind=DocumentKind("laudo"),
                source_label="Laudo Divergente OE",
            )
            session.commit()
        finally:
            session.close()

        # Drain initial extraction + barrier comparison before starting HTTP server
        for _ in range(8):
            st = worker.process_one_cycle(max_jobs=15)
            if st.claimed == 0:
                break

        stop_event = threading.Event()

        def _worker_loop() -> None:
            while not stop_event.is_set():
                try:
                    worker.process_one_cycle(max_jobs=10)
                except Exception:
                    pass
                time.sleep(0.15)

        worker_thread = threading.Thread(target=_worker_loop, daemon=True)
        worker_thread.start()

        app = create_app(settings, engine=engine, storage=storage)
        try:
            uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
        finally:
            stop_event.set()
            engine.dispose()


if __name__ == "__main__":
    main()
