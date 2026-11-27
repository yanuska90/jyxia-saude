"""Self-contained institutional E2E harness (FastAPI + subprocess ProcessingWorker + seeded synthetic cases)
used by tests/e2e/test_institutional_e2e.mjs for real-browser CDP E2E verification.

Supports:
- Mandatory PostgreSQL 16 mode in CI (`JYXIA_E2E_REQUIRE_POSTGRES=1` / `--require-postgres`) with strict
  role separation (`jyxia_app` for HTTP backend, `jyxia_worker` for worker subprocess, and
  `jyxia_migration_owner` exclusively for identity bootstrap), `NOBYPASSRLS` and `FORCE ROW LEVEL SECURITY`
  verification, and Alembic revision `20261125_0010` validation without silent SQLite fallback.
- Local file-based SQLite multiprocess fallback when PostgreSQL is not configured and
  `JYXIA_E2E_REQUIRE_POSTGRES` is not active.
- Real independent worker subprocess (`python -m app.worker`) with `PYTHONSAFEPATH=1`, explicit minimal
  environment, log file capture (no unconsumed pipe buffers), and deterministic queue drainage polling.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, TextIO
import time

from fastapi import Request, Response
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker
import uvicorn

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.config import Settings  # noqa: E402
from app.core.constants import (  # noqa: E402
    ACTIVE_PROCESSING_STATUSES,
    DocumentKind,
    HumanReviewAction,
    OrganizationRole,
    ProcessingStatus,
    ProcessingStepType,
)
from app.core.session_crypto import hmac_token_digest  # noqa: E402
from app.db.base import Base, new_uuid  # noqa: E402
from app.db.session import (  # noqa: E402
    apply_pg_identity_context,
    apply_pg_rls_context,
    clear_pg_rls_context,
    create_db_engine,
    create_session_factory,
)
from app.main import create_app  # noqa: E402
import app.models.entities  # noqa: F401, E402
from app.repositories.identity import IdentityAndSessionRepository  # noqa: E402
from app.repositories.institutional import (  # noqa: E402
    OrganizationRepository,
    ProcessingQueueRepository,
)
from app.schemas.tenant import DocumentCaseCreateInput, TenantContext  # noqa: E402
from app.services.institutional_service import InstitutionalService  # noqa: E402
from app.services.storage import LocalControlledSyntheticStorage  # noqa: E402
from tests.backend.test_human_review_and_institutional_ui import (  # noqa: E402
    _build_synthetic_selectable_pdf,
)

EXPECTED_ALEMBIC_HEAD = "20261125_0010"

REQUIRED_FORCE_RLS_TABLES: tuple[str, ...] = (
    "organization_memberships",
    "document_cases",
    "documents",
    "document_versions",
    "processing_runs",
    "extracted_fields",
    "evidence_references",
    "consistency_assessments",
    "consistency_axis_results",
    "consistency_axis_evidences",
    "human_reviews",
    "audit_events",
    "external_identities",
    "oidc_auth_states",
    "auth_sessions",
)

_ESSENTIAL_OS_ENV_KEYS: tuple[str, ...] = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "windir",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "LD_LIBRARY_PATH",
)

_ACTIVE_WIN_JOB_HANDLES: list[Any] = []


def _is_truthy_env(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _is_postgres_url(url: str) -> bool:
    cleaned = url.strip().lower()
    return cleaned.startswith("postgresql://") or cleaned.startswith("postgresql+psycopg://")


def _resolve_and_validate_db_urls(
    *,
    require_postgres: bool,
    sqlite_fallback_path: Path | None,
    env_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate database URLs with fail-closed semantics when PostgreSQL is required."""
    src = env_map if env_map is not None else os.environ
    app_url = src.get("JYXIA_DATABASE_URL", "").strip()
    worker_url = src.get("JYXIA_WORKER_DATABASE_URL", "").strip()
    migration_url = src.get("JYXIA_MIGRATION_DATABASE_URL", "").strip()

    if require_postgres:
        if not app_url:
            raise RuntimeError(
                "JYXIA_E2E_REQUIRE_POSTGRES=1: missing mandatory JYXIA_DATABASE_URL."
            )
        if not worker_url:
            raise RuntimeError(
                "JYXIA_E2E_REQUIRE_POSTGRES=1: missing mandatory JYXIA_WORKER_DATABASE_URL."
            )
        if not _is_postgres_url(app_url):
            raise RuntimeError(
                "JYXIA_E2E_REQUIRE_POSTGRES=1: JYXIA_DATABASE_URL must be a PostgreSQL URL "
                "(SQLite fallback is strictly forbidden)."
            )
        if not _is_postgres_url(worker_url):
            raise RuntimeError(
                "JYXIA_E2E_REQUIRE_POSTGRES=1: JYXIA_WORKER_DATABASE_URL must be a PostgreSQL URL "
                "(SQLite fallback is strictly forbidden)."
            )
        if migration_url and not _is_postgres_url(migration_url):
            raise RuntimeError(
                "JYXIA_E2E_REQUIRE_POSTGRES=1: JYXIA_MIGRATION_DATABASE_URL must be a PostgreSQL URL."
            )
        return {
            "db_mode": "postgresql",
            "app_db_url": app_url,
            "worker_db_url": worker_url,
            "migration_db_url": migration_url or app_url,
        }

    # Optional PostgreSQL mode when configured without require_postgres flag
    if app_url or worker_url:
        if _is_postgres_url(app_url) or _is_postgres_url(worker_url):
            if not (_is_postgres_url(app_url) and _is_postgres_url(worker_url)):
                raise RuntimeError(
                    "Both JYXIA_DATABASE_URL and JYXIA_WORKER_DATABASE_URL must be PostgreSQL URLs."
                )
            return {
                "db_mode": "postgresql",
                "app_db_url": app_url,
                "worker_db_url": worker_url,
                "migration_db_url": migration_url or app_url,
            }
        if ":memory:" in app_url or ":memory:" in worker_url:
            raise RuntimeError(
                "In-memory SQLite is forbidden for multiprocess E2E harness execution."
            )

    if sqlite_fallback_path is None:
        raise RuntimeError("SQLite fallback path is required when PostgreSQL is not configured.")
    sqlite_url = f"sqlite:///{sqlite_fallback_path.resolve().as_posix()}"
    return {
        "db_mode": "sqlite_file",
        "app_db_url": sqlite_url,
        "worker_db_url": sqlite_url,
        "migration_db_url": sqlite_url,
    }


def _verify_postgres_environment(
    *,
    app_engine: Engine,
    worker_db_url: str,
    migration_db_url: str,
) -> dict[str, Any]:
    """Actively verify PostgreSQL 16, least-privilege roles, NOBYPASSRLS, FORCE RLS, and Alembic head."""
    with app_engine.connect() as app_conn:
        app_row = app_conn.execute(
            text(
                "SELECT current_user, "
                "current_setting('server_version_num')::int, "
                "current_setting('server_version')"
            )
        ).first()
        if app_row is None:
            raise RuntimeError("Failed to query PostgreSQL identity on JYXIA_DATABASE_URL.")
        app_user, pg_version_num, pg_version_str = (
            str(app_row[0]),
            int(app_row[1]),
            str(app_row[2]),
        )
        if app_user != "jyxia_app":
            raise RuntimeError(
                f"Expected backend connection user 'jyxia_app', but connected as '{app_user}'."
            )
        if not (160000 <= pg_version_num < 170000):
            raise RuntimeError(
                f"Expected PostgreSQL 16 (160000..169999), got server_version_num={pg_version_num}."
            )

        role_flags = app_conn.execute(
            text(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).first()
        if role_flags is None or any(bool(flag) for flag in role_flags):
            raise RuntimeError(
                f"Role 'jyxia_app' has excessive privileges (expected all false): {role_flags}"
            )

        for table_name in REQUIRED_FORCE_RLS_TABLES:
            rls_row = app_conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity "
                    "FROM pg_class WHERE relname = :tbl"
                ),
                {"tbl": table_name},
            ).first()
            if rls_row != (True, True):
                raise RuntimeError(
                    f"Table '{table_name}' does not enforce ENABLE + FORCE ROW LEVEL SECURITY: {rls_row}"
                )

    app_check_session = create_session_factory(app_engine)()
    try:
        clear_pg_rls_context(app_check_session)
        visible_cases = int(
            app_check_session.execute(text("SELECT count(*) FROM document_cases")).scalar() or 0
        )
        visible_sessions = int(
            app_check_session.execute(text("SELECT count(*) FROM auth_sessions")).scalar() or 0
        )
        if visible_cases != 0 or visible_sessions != 0:
            raise RuntimeError(
                "FORCE ROW LEVEL SECURITY check failed: rows visible without tenant/session context."
            )
    finally:
        app_check_session.close()

    worker_probe_engine = create_db_engine(worker_db_url)
    try:
        with worker_probe_engine.connect() as w_conn:
            w_row = w_conn.execute(
                text(
                    "SELECT current_user, "
                    "current_setting('server_version_num')::int, "
                    "rolsuper, "
                    "rolbypassrls "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            ).first()
            if w_row is None:
                raise RuntimeError("Failed to query PostgreSQL identity on JYXIA_WORKER_DATABASE_URL.")
            worker_user, w_ver_num, w_super, w_bypass = (
                str(w_row[0]),
                int(w_row[1]),
                bool(w_row[2]),
                bool(w_row[3]),
            )
            if worker_user != "jyxia_worker":
                raise RuntimeError(
                    f"Expected worker connection user 'jyxia_worker', but connected as '{worker_user}'."
                )
            if not (160000 <= w_ver_num < 170000):
                raise RuntimeError(
                    f"Expected PostgreSQL 16 on worker connection, got {w_ver_num}."
                )
            if w_super or w_bypass:
                raise RuntimeError(
                    f"Role 'jyxia_worker' must not have superuser or bypassrls: super={w_super}, bypass={w_bypass}"
                )
    finally:
        worker_probe_engine.dispose()

    mig_probe_engine = create_db_engine(migration_db_url)
    try:
        with mig_probe_engine.connect() as m_conn:
            alembic_ver = str(
                m_conn.execute(text("SELECT version_num FROM alembic_version")).scalar() or ""
            ).strip()
            if alembic_ver != EXPECTED_ALEMBIC_HEAD:
                raise RuntimeError(
                    f"Expected Alembic migration head '{EXPECTED_ALEMBIC_HEAD}', got '{alembic_ver}'."
                )
    finally:
        mig_probe_engine.dispose()

    return {
        "db_mode": "postgresql",
        "backend_db_user": app_user,
        "worker_db_user": worker_user,
        "pg_server_version_num": pg_version_num,
        "pg_server_version": pg_version_str,
        "app_rolbypassrls": False,
        "worker_rolbypassrls": False,
        "force_rls_verified": True,
        "force_rls_tables_count": len(REQUIRED_FORCE_RLS_TABLES),
        "alembic_version": alembic_ver,
    }


def _bind_process_to_windows_kill_on_close_job(pid: int) -> Any | None:
    """Bind child process to a Win32 Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        job_handle = kernel32.CreateJobObjectW(None, None)
        if not job_handle:
            return None

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job_handle,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            kernel32.CloseHandle(job_handle)
            return None

        proc_handle = kernel32.OpenProcess(0x0100 | 0x0001, False, int(pid))
        if not proc_handle:
            kernel32.CloseHandle(job_handle)
            return None
        try:
            if not kernel32.AssignProcessToJobObject(job_handle, proc_handle):
                kernel32.CloseHandle(job_handle)
                return None
        finally:
            kernel32.CloseHandle(proc_handle)

        _ACTIVE_WIN_JOB_HANDLES.append(job_handle)
        return job_handle
    except Exception:
        return None


def _build_worker_subprocess_env(
    *,
    app_db_url: str,
    worker_db_url: str,
    storage_dir: Path,
    settings: Settings,
    worker_id: str,
) -> dict[str, str]:
    """Construct an explicit minimal environment for `python -m app.worker`."""
    worker_env: dict[str, str] = {}
    for key in _ESSENTIAL_OS_ENV_KEYS:
        val = os.environ.get(key)
        if val is not None:
            worker_env[key] = val

    worker_env.update(
        {
            "PYTHONPATH": str(BACKEND_DIR),
            "PYTHONSAFEPATH": "1",
            "PYTHONUNBUFFERED": "1",
            "JYXIA_ENV": "test",
            "JYXIA_WORKER_ENABLED": "true",
            "JYXIA_WORKER_ID": worker_id,
            "JYXIA_WORKER_DATABASE_URL": worker_db_url,
            "JYXIA_DATABASE_URL": app_db_url,
            "JYXIA_STORAGE_ROOT": str(storage_dir),
            "JYXIA_ALLOW_LOCAL_SYNTHETIC_STORAGE": "true",
            "JYXIA_WORKER_POLL_INTERVAL_SECONDS": "0.15",
            "JYXIA_SESSION_SECRET": settings.session_secret,
            "JYXIA_CSRF_SECRET": settings.csrf_secret,
            "JYXIA_LOG_LEVEL": "INFO",
        }
    )
    return worker_env


def _read_worker_log_tail(log_path: Path | None, *, max_chars: int = 4000) -> str:
    if log_path is None or not log_path.exists():
        return "<no worker log available>"
    try:
        text_content = log_path.read_text(encoding="utf-8", errors="replace")
        return text_content[-max_chars:] if len(text_content) > max_chars else text_content
    except Exception as exc:
        return f"<failed to read worker log: {exc}>"


def _start_worker_subprocess(
    *,
    app_db_url: str,
    worker_db_url: str,
    storage_dir: Path,
    settings: Settings,
    worker_id: str,
    log_path: Path,
) -> tuple[Any, TextIO]:
    import subprocess

    log_fh = open(log_path, "w+", encoding="utf-8")
    worker_env = _build_worker_subprocess_env(
        app_db_url=app_db_url,
        worker_db_url=worker_db_url,
        storage_dir=storage_dir,
        settings=settings,
        worker_id=worker_id,
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.worker"],
        cwd=str(BACKEND_DIR),
        env=worker_env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
    )
    _bind_process_to_windows_kill_on_close_job(proc.pid)

    # Confirm the worker process did not fail immediately on startup/import
    time.sleep(0.25)
    if proc.poll() is not None:
        log_fh.flush()
        tail = _read_worker_log_tail(log_path)
        log_fh.close()
        raise RuntimeError(
            f"Worker subprocess exited immediately during startup (code={proc.returncode}).\n"
            f"Worker log:\n{tail}"
        )
    return proc, log_fh


def _stop_worker_subprocess(
    proc: Any | None,
    log_fh: TextIO | None,
    *,
    timeout_seconds: float = 5.0,
) -> int | None:
    exit_code: int | None = None
    try:
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout_seconds)
                except Exception:
                    proc.kill()
                    proc.wait(timeout=3.0)
            exit_code = proc.poll()
            if exit_code is None:
                raise RuntimeError(f"Worker subprocess PID {proc.pid} remained active after kill().")
    finally:
        if log_fh is not None:
            try:
                log_fh.flush()
                log_fh.close()
            except Exception:
                pass
    return exit_code


def _inspect_cases_queue_snapshot(
    session: Session,
    ctx: TenantContext,
    case_expectations: dict[str, dict[str, Any]],
) -> tuple[bool, dict[str, Any]]:
    """Inspect queue and assessment state for target cases under authenticated tenant RLS context."""
    apply_pg_identity_context(session, session_token_hash=ctx.session_token_hash)
    apply_pg_rls_context(
        session,
        organization_id=ctx.organization_id,
        user_id=ctx.actor_user_id,
    )

    all_ready = True
    cases_report: dict[str, Any] = {}

    for case_id, exp in case_expectations.items():
        runs_rows, _ = ProcessingQueueRepository.list_case_runs(
            session,
            ctx,
            case_id=case_id,
            limit=200,
            offset=0,
        )
        runs = [r for r, _, _ in runs_rows]
        active_runs = [
            r.id for r in runs if r.status in ACTIVE_PROCESSING_STATUSES or r.status == "pending"
        ]
        active_leases = [
            r.id
            for r in runs
            if r.lease_token_hash is not None
            or r.lease_expires_at is not None
            or r.status == ProcessingStatus.RUNNING.value
        ]
        failed_runs = [
            {
                "run_id": r.id,
                "step_type": r.step_type,
                "status": r.status,
                "error_code": r.last_error_code,
                "error_detail": r.last_error_detail,
            }
            for r in runs
            if r.status in (ProcessingStatus.FAILED.value, ProcessingStatus.CANCELLED.value)
        ]
        succeeded_by_step: dict[str, int] = {
            ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value: 0,
            ProcessingStepType.EXTRACT_PDF_TEXT.value: 0,
            ProcessingStepType.COMPARE_CONSISTENCY.value: 0,
        }
        for r in runs:
            if r.status == ProcessingStatus.SUCCEEDED.value and r.step_type in succeeded_by_step:
                succeeded_by_step[r.step_type] += 1

        assessments_rows, assessments_total = (
            ProcessingQueueRepository.list_case_consistency_assessments(
                session,
                ctx,
                case_id=case_id,
                limit=50,
                offset=0,
            )
        )
        latest_assessment = assessments_rows[0][0] if assessments_rows else None
        latest_readiness = latest_assessment.readiness_state if latest_assessment else None
        latest_seq = int(latest_assessment.assessment_sequence) if latest_assessment else 0
        latest_hrc = bool(latest_assessment.human_review_completed) if latest_assessment else False

        exp_docs = int(exp.get("expected_docs", 2))
        min_assessments = int(exp.get("min_assessments", 1))
        exp_readiness = exp.get("expected_readiness")
        exp_hrc = exp.get("expected_human_review_completed")

        steps_ok = (
            succeeded_by_step[ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value] >= exp_docs
            and succeeded_by_step[ProcessingStepType.EXTRACT_PDF_TEXT.value] >= exp_docs
            and succeeded_by_step[ProcessingStepType.COMPARE_CONSISTENCY.value] >= min_assessments
        )
        assessments_ok = (
            assessments_total >= min_assessments
            and (exp_readiness is None or latest_readiness == exp_readiness)
            and (exp_hrc is None or latest_hrc is bool(exp_hrc))
        )
        case_ok = (
            len(active_runs) == 0
            and len(active_leases) == 0
            and len(failed_runs) == 0
            and steps_ok
            and assessments_ok
        )
        if not case_ok:
            all_ready = False

        cases_report[case_id] = {
            "case_code": exp.get("case_code"),
            "drained": case_ok,
            "total_runs": len(runs),
            "active_runs": active_runs,
            "active_leases": active_leases,
            "failed_runs": failed_runs,
            "succeeded_by_step": succeeded_by_step,
            "assessments_total": assessments_total,
            "latest_assessment_sequence": latest_seq,
            "latest_readiness_state": latest_readiness,
            "latest_human_review_completed": latest_hrc,
        }

    return all_ready, cases_report


def wait_for_cases_queue_drained(
    *,
    app_factory: sessionmaker[Session],
    ctx: TenantContext,
    case_expectations: dict[str, dict[str, Any]],
    worker_proc: Any | None = None,
    worker_log_path: Path | None = None,
    timeout_seconds: float = 25.0,
    poll_interval_seconds: float = 0.15,
) -> dict[str, Any]:
    """Poll database until all expected case runs are terminal, lease-free, and assessments exist."""
    deadline = time.monotonic() + timeout_seconds
    last_snapshot: dict[str, Any] = {}

    while time.monotonic() < deadline:
        if worker_proc is not None and worker_proc.poll() is not None:
            tail = _read_worker_log_tail(worker_log_path)
            raise RuntimeError(
                f"Worker subprocess terminated unexpectedly while draining queue "
                f"(exit_code={worker_proc.returncode}).\nWorker log:\n{tail}"
            )

        session = app_factory()
        try:
            ready, last_snapshot = _inspect_cases_queue_snapshot(
                session, ctx, case_expectations
            )
            if ready:
                return last_snapshot
        finally:
            session.rollback()
            session.close()

        time.sleep(poll_interval_seconds)

    tail = _read_worker_log_tail(worker_log_path)
    raise RuntimeError(
        f"Timeout ({timeout_seconds}s) waiting for processing queue to drain.\n"
        f"Cases diagnostic: {json.dumps(last_snapshot, ensure_ascii=False)}\n"
        f"Worker log tail:\n{tail}"
    )


def _seed_harness_data(
    *,
    bootstrap_factory: sessionmaker[Session],
    app_factory: sessionmaker[Session],
    storage: LocalControlledSyntheticStorage,
    settings: Settings,
    session_token: str,
    csrf_token: str,
    run_uid: str,
) -> dict[str, Any]:
    """Bootstrap identity via privileged session, then create cases/documents strictly via app_factory."""
    sess_hash = hmac_token_digest(
        session_token, secret=settings.session_secret, context="session_token"
    )
    csrf_hash = hmac_token_digest(
        csrf_token, secret=settings.csrf_secret, context="csrf_token"
    )

    bootstrap_db = bootstrap_factory()
    try:
        # Remove any stale test session with identical token hash from a prior run on the same DB
        bootstrap_db.execute(
            text("DELETE FROM auth_sessions WHERE session_token_hash = :h"),
            {"h": sess_hash},
        )
        org = OrganizationRepository.create_organization(
            bootstrap_db,
            slug=f"hospital-sintetico-335-{run_uid}",
            name=f"Hospital Sintetico JYXIA {run_uid}",
        )
        reviewer = OrganizationRepository.create_user(
            bootstrap_db,
            email=f"revisor.e2e.{run_uid}@jyxia.local",
            display_name="Dra. Clara Revisora (Sintetica)",
            mfa_enrolled=True,
        )
        OrganizationRepository.assign_membership(
            bootstrap_db,
            TenantContext(organization_id=org.id),
            user_id=reviewer.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        ext = IdentityAndSessionRepository.bind_external_identity(
            bootstrap_db,
            user_id=reviewer.id,
            issuer="https://idp.jyxia.local/realms/e2e",
            subject=f"sub-e2e-reviewer-335-{run_uid}",
            email_at_binding=reviewer.email,
        )
        now = datetime.now(timezone.utc)
        IdentityAndSessionRepository.create_auth_session(
            bootstrap_db,
            user_id=reviewer.id,
            external_identity_id=ext.id,
            active_organization_id=org.id,
            session_token_hash=sess_hash,
            csrf_token_hash=csrf_hash,
            auth_method="oidc_authorization_code_pkce",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now,
            oidc_auth_time=now,
            idle_expires_at=now + timedelta(minutes=30),
            absolute_expires_at=now + timedelta(hours=8),
            now=now,
        )
        bootstrap_db.commit()
        org_id = str(org.id)
        reviewer_id = str(reviewer.id)
    finally:
        bootstrap_db.close()

    ctx = TenantContext(
        organization_id=org_id,
        actor_user_id=reviewer_id,
        session_token_hash=sess_hash,
        source="authenticated_request",
    )

    def _bind_app_tx(sess: Session) -> None:
        apply_pg_identity_context(sess, session_token_hash=sess_hash)
        apply_pg_rls_context(sess, organization_id=org_id, user_id=reviewer_id)

    app_db = app_factory()
    try:
        # Scenario A: Coherent 4-axis case (awaiting human review -> transitions to conferida)
        _bind_app_tx(app_db)
        case_a = InstitutionalService.create_case(
            app_db,
            ctx,
            DocumentCaseCreateInput(
                case_code="CASO-E2E-COERENTE-A",
                procedure_reference="TUSS:31309054",
                external_reference=f"GUIA-E2E-001-{run_uid}",
                declared_laterality="OD",
            ),
        )
        app_db.commit()
        case_a_id = str(case_a.id)

        _bind_app_tx(app_db)
        ing_a1 = InstitutionalService.ingest_case_document(
            app_db,
            ctx,
            storage=storage,
            case_id=case_a_id,
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

        _bind_app_tx(app_db)
        ing_a2 = InstitutionalService.ingest_case_document(
            app_db,
            ctx,
            storage=storage,
            case_id=case_a_id,
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
        _bind_app_tx(app_db)
        case_b = InstitutionalService.create_case(
            app_db,
            ctx,
            DocumentCaseCreateInput(
                case_code="CASO-E2E-CONFLITO-B",
                procedure_reference="TUSS:31309054",
                external_reference=f"GUIA-E2E-002-{run_uid}",
            ),
        )
        app_db.commit()
        case_b_id = str(case_b.id)

        _bind_app_tx(app_db)
        ing_b1 = InstitutionalService.ingest_case_document(
            app_db,
            ctx,
            storage=storage,
            case_id=case_b_id,
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

        _bind_app_tx(app_db)
        ing_b2 = InstitutionalService.ingest_case_document(
            app_db,
            ctx,
            storage=storage,
            case_id=case_b_id,
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

        return {
            "organization_id": org_id,
            "reviewer_user_id": reviewer_id,
            "session_token_hash": sess_hash,
            "ctx": ctx,
            "case_a_id": case_a_id,
            "case_b_id": case_b_id,
            "case_a_versions": [
                (str(ing_a1.document.id), str(ing_a1.version.id)),
                (str(ing_a2.document.id), str(ing_a2.version.id)),
            ],
            "case_b_versions": [
                (str(ing_b1.document.id), str(ing_b1.version.id)),
                (str(ing_b2.document.id), str(ing_b2.version.id)),
            ],
        }
    finally:
        app_db.close()


def _write_report_file(report_path: Path | None, payload: dict[str, Any]) -> None:
    if report_path is None:
        return
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = report_path.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_file.replace(report_path)
    except Exception:
        pass


def _is_pid_running(pid: int | None) -> bool:
    if pid is None or pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            SYNCHRONIZE = 0x00100000
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
            )
            if not handle:
                return False
            try:
                WAIT_OBJECT_0 = 0x00000000
                res = kernel32.WaitForSingleObject(handle, 0)
                return res != WAIT_OBJECT_0
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    else:
        try:
            os.kill(int(pid), 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True


def _run_self_test_fail_closed() -> None:
    """Verify fail-closed rejection when JYXIA_E2E_REQUIRE_POSTGRES=1 and PG URLs are missing/SQLite."""
    for bad_env, expected_msg in (
        ({}, "missing mandatory JYXIA_DATABASE_URL"),
        (
            {"JYXIA_DATABASE_URL": "postgresql+psycopg://jyxia_app:pw@127.0.0.1:5432/db"},
            "missing mandatory JYXIA_WORKER_DATABASE_URL",
        ),
        (
            {
                "JYXIA_DATABASE_URL": "sqlite:///tmp/fallback.db",
                "JYXIA_WORKER_DATABASE_URL": "postgresql+psycopg://jyxia_worker:pw@127.0.0.1:5432/db",
            },
            "SQLite fallback is strictly forbidden",
        ),
        (
            {
                "JYXIA_DATABASE_URL": "postgresql+psycopg://jyxia_app:pw@127.0.0.1:5432/db",
                "JYXIA_WORKER_DATABASE_URL": "sqlite:///tmp/fallback.db",
            },
            "SQLite fallback is strictly forbidden",
        ),
    ):
        try:
            _resolve_and_validate_db_urls(
                require_postgres=True,
                sqlite_fallback_path=Path("/tmp/should_not_be_used.db"),
                env_map=bad_env,
            )
        except RuntimeError as exc:
            if expected_msg not in str(exc):
                raise AssertionError(
                    f"Expected '{expected_msg}' in error, got: {exc}"
                ) from exc
        else:
            raise AssertionError(f"Expected RuntimeError for invalid config: {bad_env}")

    # If live PostgreSQL URLs are present in environment, also verify wrong-role rejection
    mig_url = os.environ.get("JYXIA_MIGRATION_DATABASE_URL", "").strip()
    app_url = os.environ.get("JYXIA_DATABASE_URL", "").strip()
    worker_url = os.environ.get("JYXIA_WORKER_DATABASE_URL", "").strip()
    if _is_postgres_url(mig_url) and _is_postgres_url(app_url) and _is_postgres_url(worker_url):
        wrong_engine = create_db_engine(mig_url)
        try:
            try:
                _verify_postgres_environment(
                    app_engine=wrong_engine,
                    worker_db_url=worker_url,
                    migration_db_url=mig_url,
                )
            except RuntimeError as exc:
                assert "Expected backend connection user 'jyxia_app'" in str(exc), str(exc)
            else:
                raise AssertionError(
                    "Expected _verify_postgres_environment to reject non-jyxia_app backend user."
                )
        finally:
            wrong_engine.dispose()

    print("HARNESS_FAIL_CLOSED_SELF_TEST_OK")


def _run_self_test_sqlite_lifecycle(
    *,
    drain_timeout: float = 25.0,
    drain_interval: float = 0.15,
) -> None:
    """Verify multiprocess SQLite fallback + worker subprocess + post-review re-assessment + clean exit."""
    run_uid = new_uuid()[:8]
    session_token = "self-test-session-token-335-secret"
    csrf_token = "self-test-csrf-token-335-secret"

    with tempfile.TemporaryDirectory(prefix="jyxia-inst-selftest-") as tmp:
        tmp_path = Path(tmp)
        db_cfg = _resolve_and_validate_db_urls(
            require_postgres=False,
            sqlite_fallback_path=tmp_path / "selftest.sqlite3",
            env_map={},
        )
        assert db_cfg["db_mode"] == "sqlite_file"
        storage_dir = tmp_path / "synthetic_storage"
        worker_log_path = tmp_path / "worker_subprocess.log"

        settings = Settings(
            env="test",
            app_base_url="http://127.0.0.1:8035",
            database_url=db_cfg["app_db_url"],
            worker_database_url=db_cfg["worker_db_url"],
            storage_root=str(storage_dir),
            allow_local_synthetic_storage=True,
            session_secret="E2E_Session_Hmac_Aead_Key_32_Bytes_Minimum_335!",
            csrf_secret="E2E_Csrf_Hmac_Key_32_Bytes_Minimum_Value_335!",
            session_cookie_secure=False,
            oidc_enabled=False,
        )
        engine = create_db_engine(db_cfg["app_db_url"])
        Base.metadata.create_all(engine)
        app_factory = create_session_factory(engine)
        storage = LocalControlledSyntheticStorage(
            storage_dir,
            enabled=True,
            max_bytes=settings.max_document_bytes,
        )

        seeded = _seed_harness_data(
            bootstrap_factory=app_factory,
            app_factory=app_factory,
            storage=storage,
            settings=settings,
            session_token=session_token,
            csrf_token=csrf_token,
            run_uid=run_uid,
        )
        ctx: TenantContext = seeded["ctx"]
        case_a_id: str = seeded["case_a_id"]
        case_b_id: str = seeded["case_b_id"]

        worker_proc = None
        worker_log_fh = None
        try:
            worker_proc, worker_log_fh = _start_worker_subprocess(
                app_db_url=db_cfg["app_db_url"],
                worker_db_url=db_cfg["worker_db_url"],
                storage_dir=storage_dir,
                settings=settings,
                worker_id=f"selftest-worker-{run_uid}",
                log_path=worker_log_path,
            )
            worker_pid = worker_proc.pid

            initial_snap = wait_for_cases_queue_drained(
                app_factory=app_factory,
                ctx=ctx,
                case_expectations={
                    case_a_id: {
                        "case_code": "CASO-E2E-COERENTE-A",
                        "expected_docs": 2,
                        "min_assessments": 1,
                        "expected_readiness": "pendente",
                    },
                    case_b_id: {
                        "case_code": "CASO-E2E-CONFLITO-B",
                        "expected_docs": 2,
                        "min_assessments": 1,
                        "expected_readiness": "bloqueado",
                    },
                },
                worker_proc=worker_proc,
                worker_log_path=worker_log_path,
                timeout_seconds=drain_timeout,
                poll_interval_seconds=drain_interval,
            )
            assert initial_snap[case_a_id]["drained"] is True
            assert initial_snap[case_b_id]["drained"] is True

            # Record human reviews across active versions of Case A and Case B while worker subprocess runs
            rev_session = app_factory()
            try:
                for doc_id, ver_id in seeded["case_a_versions"] + seeded["case_b_versions"]:
                    InstitutionalService.record_document_version_human_review(
                        rev_session,
                        ctx,
                        document_id=doc_id,
                        version_id=ver_id,
                        action_type=HumanReviewAction.OBSERVED,
                        justification="Conferencia administrativa de autoteste multiprocesso concluida.",
                    )
            finally:
                rev_session.close()

            final_snap = wait_for_cases_queue_drained(
                app_factory=app_factory,
                ctx=ctx,
                case_expectations={
                    case_a_id: {
                        "case_code": "CASO-E2E-COERENTE-A",
                        "expected_docs": 2,
                        "min_assessments": 2,
                        "expected_readiness": "conferida",
                        "expected_human_review_completed": True,
                    },
                    case_b_id: {
                        "case_code": "CASO-E2E-CONFLITO-B",
                        "expected_docs": 2,
                        "min_assessments": 2,
                        "expected_readiness": "bloqueado",
                        "expected_human_review_completed": True,
                    },
                },
                worker_proc=worker_proc,
                worker_log_path=worker_log_path,
                timeout_seconds=drain_timeout,
                poll_interval_seconds=drain_interval,
            )
            assert final_snap[case_a_id]["latest_readiness_state"] == "conferida"
            assert final_snap[case_a_id]["latest_human_review_completed"] is True
            assert final_snap[case_b_id]["latest_readiness_state"] == "bloqueado"
            assert final_snap[case_b_id]["latest_human_review_completed"] is True
        finally:
            exit_code = _stop_worker_subprocess(worker_proc, worker_log_fh, timeout_seconds=5.0)
            engine.dispose()

        assert exit_code is not None, "Worker subprocess did not terminate cleanly."
        assert not _is_pid_running(worker_pid), f"Worker PID {worker_pid} still running after stop."
        print(
            json.dumps(
                {
                    "status": "SQLITE_MULTIPROCESS_LIFECYCLE_OK",
                    "worker_pid": worker_pid,
                    "worker_exit_code": exit_code,
                    "case_a_readiness": final_snap[case_a_id]["latest_readiness_state"],
                    "case_b_readiness": final_snap[case_b_id]["latest_readiness_state"],
                }
            )
        )


def _verify_post_e2e_report(
    report_path: Path,
    *,
    require_postgres: bool,
    drain_timeout: float = 15.0,
    drain_interval: float = 0.15,
) -> None:
    """Verify post-E2E report, process termination, and live PostgreSQL 16 drained queue state."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and not report_path.exists():
        time.sleep(0.15)
    if not report_path.exists():
        raise RuntimeError(f"E2E harness report file was not created at {report_path}.")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    worker_pid = report.get("worker_pid")
    harness_pid = report.get("harness_pid")

    # Wait for both harness and worker subprocess to exit completely
    proc_deadline = time.monotonic() + 10.0
    while time.monotonic() < proc_deadline:
        if not _is_pid_running(worker_pid) and not _is_pid_running(harness_pid):
            break
        time.sleep(0.15)

    if _is_pid_running(worker_pid):
        raise RuntimeError(f"Orphan worker subprocess PID {worker_pid} is still active after E2E!")
    if _is_pid_running(harness_pid):
        raise RuntimeError(f"Harness process PID {harness_pid} is still active after E2E!")

    # Re-read report in case harness updated it during its finally block
    report = json.loads(report_path.read_text(encoding="utf-8"))
    db_info = report.get("db_info") or {}
    db_mode = db_info.get("db_mode")

    if require_postgres:
        if db_mode != "postgresql":
            raise RuntimeError(f"Expected db_mode='postgresql' in CI, got '{db_mode}'.")
        if db_info.get("backend_db_user") != "jyxia_app":
            raise RuntimeError(f"Invalid backend_db_user: {db_info.get('backend_db_user')}")
        if db_info.get("worker_db_user") != "jyxia_worker":
            raise RuntimeError(f"Invalid worker_db_user: {db_info.get('worker_db_user')}")
        if db_info.get("force_rls_verified") is not True:
            raise RuntimeError("FORCE ROW LEVEL SECURITY was not verified in report.")
        if db_info.get("alembic_version") != EXPECTED_ALEMBIC_HEAD:
            raise RuntimeError(f"Unexpected alembic_version: {db_info.get('alembic_version')}")

        # Live PostgreSQL 16 query as jyxia_app confirming final drained state of both cases
        app_url = os.environ["JYXIA_DATABASE_URL"].strip()
        app_engine = create_db_engine(app_url)
        try:
            app_factory = create_session_factory(app_engine)
            ctx = TenantContext(
                organization_id=str(report["organization_id"]),
                actor_user_id=str(report["reviewer_user_id"]),
                session_token_hash=str(report["session_token_hash"]),
                source="authenticated_request",
            )
            case_a_id = str(report["case_a_id"])
            case_b_id = str(report["case_b_id"])
            live_snap = wait_for_cases_queue_drained(
                app_factory=app_factory,
                ctx=ctx,
                case_expectations={
                    case_a_id: {
                        "case_code": "CASO-E2E-COERENTE-A",
                        "expected_docs": 2,
                        "min_assessments": 2,
                        "expected_readiness": "conferida",
                        "expected_human_review_completed": True,
                    },
                    case_b_id: {
                        "case_code": "CASO-E2E-CONFLITO-B",
                        "expected_docs": 2,
                        "min_assessments": 2,
                        "expected_readiness": "bloqueado",
                        "expected_human_review_completed": True,
                    },
                },
                timeout_seconds=drain_timeout,
                poll_interval_seconds=drain_interval,
            )
        finally:
            app_engine.dispose()
    else:
        live_snap = report.get("cases_snapshot") or {}
        if not report.get("e2e_cases_drained_verified"):
            raise RuntimeError(
                f"Cases queue drainage was not verified during E2E run: {json.dumps(report)}"
            )
        for cid, c_info in live_snap.items():
            if not c_info.get("drained") or not c_info.get("latest_human_review_completed"):
                raise RuntimeError(
                    f"Case {cid} did not finish with drained=True and human_review_completed=True: {c_info}"
                )

    print(
        json.dumps(
            {
                "status": "POST_E2E_VERIFICATION_PASSED",
                "db_mode": db_mode,
                "backend_db_user": db_info.get("backend_db_user"),
                "worker_db_user": db_info.get("worker_db_user"),
                "pg_server_version_num": db_info.get("pg_server_version_num"),
                "force_rls_verified": db_info.get("force_rls_verified"),
                "alembic_version": db_info.get("alembic_version"),
                "worker_pid": worker_pid,
                "worker_process_alive": False,
                "cases_drained": live_snap,
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8035)
    parser.add_argument("--session-token", default="e2e-raw-session-token-335-secret-value")
    parser.add_argument("--csrf-token", default="e2e-raw-csrf-token-335-secret-value")
    parser.add_argument(
        "--require-postgres",
        action="store_true",
        default=_is_truthy_env(os.environ.get("JYXIA_E2E_REQUIRE_POSTGRES")),
    )
    parser.add_argument(
        "--report-file",
        default=os.environ.get("JYXIA_E2E_REPORT_FILE", "").strip() or None,
    )
    parser.add_argument(
        "--drain-timeout",
        type=float,
        default=float(os.environ.get("JYXIA_E2E_DRAIN_TIMEOUT_SECONDS", "25.0")),
    )
    parser.add_argument(
        "--drain-interval",
        type=float,
        default=float(os.environ.get("JYXIA_E2E_DRAIN_INTERVAL_SECONDS", "0.15")),
    )
    parser.add_argument("--self-test-fail-closed", action="store_true")
    parser.add_argument("--self-test-sqlite-lifecycle", action="store_true")
    parser.add_argument("--verify-report", default=None)
    args = parser.parse_args()

    if args.self_test_fail_closed:
        _run_self_test_fail_closed()
        return

    if args.self_test_sqlite_lifecycle:
        _run_self_test_sqlite_lifecycle(
            drain_timeout=args.drain_timeout,
            drain_interval=args.drain_interval,
        )
        return

    if args.verify_report:
        _verify_post_e2e_report(
            Path(args.verify_report),
            require_postgres=bool(args.require_postgres),
            drain_timeout=args.drain_timeout,
            drain_interval=args.drain_interval,
        )
        return

    report_path = Path(args.report_file) if args.report_file else None
    run_uid = new_uuid()[:8]

    with tempfile.TemporaryDirectory(prefix="jyxia-inst-e2e-335-") as tmp:
        tmp_path = Path(tmp)
        db_cfg = _resolve_and_validate_db_urls(
            require_postgres=bool(args.require_postgres),
            sqlite_fallback_path=tmp_path / "inst_e2e.sqlite3",
        )
        db_mode: str = db_cfg["db_mode"]
        app_db_url: str = db_cfg["app_db_url"]
        worker_db_url: str = db_cfg["worker_db_url"]
        migration_db_url: str = db_cfg["migration_db_url"]

        storage_dir = tmp_path / "synthetic_storage"
        worker_log_path = tmp_path / "worker_subprocess.log"

        settings = Settings(
            env="test",
            app_base_url=f"http://127.0.0.1:{args.port}",
            database_url=app_db_url,
            worker_database_url=worker_db_url,
            storage_root=str(storage_dir),
            allow_local_synthetic_storage=True,
            session_secret="E2E_Session_Hmac_Aead_Key_32_Bytes_Minimum_335!",
            csrf_secret="E2E_Csrf_Hmac_Key_32_Bytes_Minimum_Value_335!",
            session_cookie_secure=False,
            oidc_enabled=False,
        )

        app_engine = create_db_engine(app_db_url)
        bootstrap_engine: Engine | None = None
        worker_proc: Any | None = None
        worker_log_fh: TextIO | None = None
        report_payload: dict[str, Any] = {}

        try:
            if db_mode == "postgresql":
                db_info = _verify_postgres_environment(
                    app_engine=app_engine,
                    worker_db_url=worker_db_url,
                    migration_db_url=migration_db_url,
                )
                bootstrap_engine = create_db_engine(migration_db_url)
                bootstrap_factory = create_session_factory(bootstrap_engine)
            else:
                Base.metadata.create_all(app_engine)
                bootstrap_factory = create_session_factory(app_engine)
                db_info = {
                    "db_mode": "sqlite_file",
                    "backend_db_user": "sqlite_local",
                    "worker_db_user": "sqlite_local",
                    "sqlite_file": (tmp_path / "inst_e2e.sqlite3").as_posix(),
                }

            app_factory = create_session_factory(app_engine)
            storage = LocalControlledSyntheticStorage(
                storage_dir,
                enabled=True,
                max_bytes=settings.max_document_bytes,
            )

            try:
                seeded = _seed_harness_data(
                    bootstrap_factory=bootstrap_factory,
                    app_factory=app_factory,
                    storage=storage,
                    settings=settings,
                    session_token=args.session_token,
                    csrf_token=args.csrf_token,
                    run_uid=run_uid,
                )
            finally:
                if bootstrap_engine is not None:
                    bootstrap_engine.dispose()
                    bootstrap_engine = None

            ctx: TenantContext = seeded["ctx"]
            case_a_id: str = seeded["case_a_id"]
            case_b_id: str = seeded["case_b_id"]

            # Start the single real worker subprocess (`python -m app.worker`)
            worker_proc, worker_log_fh = _start_worker_subprocess(
                app_db_url=app_db_url,
                worker_db_url=worker_db_url,
                storage_dir=storage_dir,
                settings=settings,
                worker_id=f"e2e-worker-{run_uid}",
                log_path=worker_log_path,
            )

            # Wait for the worker subprocess to drain initial seeded integrity + extraction + comparison runs
            initial_snap = wait_for_cases_queue_drained(
                app_factory=app_factory,
                ctx=ctx,
                case_expectations={
                    case_a_id: {
                        "case_code": "CASO-E2E-COERENTE-A",
                        "expected_docs": 2,
                        "min_assessments": 1,
                        "expected_readiness": "pendente",
                    },
                    case_b_id: {
                        "case_code": "CASO-E2E-CONFLITO-B",
                        "expected_docs": 2,
                        "min_assessments": 1,
                        "expected_readiness": "bloqueado",
                    },
                },
                worker_proc=worker_proc,
                worker_log_path=worker_log_path,
                timeout_seconds=args.drain_timeout,
                poll_interval_seconds=args.drain_interval,
            )

            post_e2e_expectations = {
                case_a_id: {
                    "case_code": "CASO-E2E-COERENTE-A",
                    "expected_docs": 2,
                    "min_assessments": 2,
                    "expected_readiness": "conferida",
                    "expected_human_review_completed": True,
                },
                case_b_id: {
                    "case_code": "CASO-E2E-CONFLITO-B",
                    "expected_docs": 2,
                    "min_assessments": 2,
                    "expected_readiness": "bloqueado",
                    "expected_human_review_completed": True,
                },
            }

            report_payload = {
                "stage": "initial_seed_drained",
                "run_uid": run_uid,
                "harness_pid": os.getpid(),
                "worker_pid": worker_proc.pid,
                "db_info": db_info,
                "organization_id": seeded["organization_id"],
                "reviewer_user_id": seeded["reviewer_user_id"],
                "session_token_hash": seeded["session_token_hash"],
                "case_a_id": case_a_id,
                "case_b_id": case_b_id,
                "initial_drain_ok": True,
                "e2e_cases_drained_verified": False,
                "worker_terminated_cleanly": False,
                "worker_exit_code": None,
                "cases_snapshot": initial_snap,
            }
            _write_report_file(report_path, report_payload)

            app = create_app(settings, engine=app_engine, storage=storage)

            @app.middleware("http")
            async def _track_queue_drainage_for_report(
                request: Request, call_next: Any
            ) -> Response:
                response: Response = await call_next(request)
                if not report_payload.get("e2e_cases_drained_verified"):
                    # When a human review POST completes on Case B, wait for the worker subprocess
                    # to drain any post-review comparison run if all 4 seeded versions are reviewed.
                    if (
                        request.method == "POST"
                        and "/human-reviews" in request.url.path
                        and response.status_code in (200, 201)
                    ):
                        chk_sess = app_factory()
                        both_cases_reviewed = False
                        try:
                            rev_a = InstitutionalService.list_case_human_reviews(
                                chk_sess, ctx, case_id=case_a_id
                            )
                            rev_b = InstitutionalService.list_case_human_reviews(
                                chk_sess, ctx, case_id=case_b_id
                            )
                            both_cases_reviewed = bool(
                                rev_a.human_review_completed and rev_b.human_review_completed
                            )
                        except Exception:
                            both_cases_reviewed = False
                        finally:
                            chk_sess.rollback()
                            chk_sess.close()

                        if both_cases_reviewed:
                            import asyncio

                            snap = await asyncio.to_thread(
                                wait_for_cases_queue_drained,
                                app_factory=app_factory,
                                ctx=ctx,
                                case_expectations=post_e2e_expectations,
                                worker_proc=worker_proc,
                                worker_log_path=worker_log_path,
                                timeout_seconds=args.drain_timeout,
                                poll_interval_seconds=args.drain_interval,
                            )
                            report_payload["stage"] = "e2e_cases_drained"
                            report_payload["e2e_cases_drained_verified"] = True
                            report_payload["cases_snapshot"] = snap
                            _write_report_file(report_path, report_payload)
                return response

            uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
        finally:
            if bootstrap_engine is not None:
                bootstrap_engine.dispose()

            # Attempt final queue drainage verification before stopping worker subprocess
            if report_payload and not report_payload.get("e2e_cases_drained_verified"):
                try:
                    final_snap = wait_for_cases_queue_drained(
                        app_factory=create_session_factory(app_engine),
                        ctx=seeded["ctx"],
                        case_expectations={
                            seeded["case_a_id"]: {
                                "case_code": "CASO-E2E-COERENTE-A",
                                "expected_docs": 2,
                                "min_assessments": 1,
                            },
                            seeded["case_b_id"]: {
                                "case_code": "CASO-E2E-CONFLITO-B",
                                "expected_docs": 2,
                                "min_assessments": 1,
                            },
                        },
                        worker_proc=worker_proc,
                        worker_log_path=worker_log_path,
                        timeout_seconds=min(args.drain_timeout, 10.0),
                        poll_interval_seconds=args.drain_interval,
                    )
                    report_payload["cases_snapshot"] = final_snap
                except Exception:
                    pass

            exit_code = _stop_worker_subprocess(worker_proc, worker_log_fh, timeout_seconds=5.0)
            if report_payload:
                report_payload["stage"] = "shutdown_complete"
                report_payload["worker_terminated_cleanly"] = exit_code is not None
                report_payload["worker_exit_code"] = exit_code
                _write_report_file(report_path, report_payload)

            app_engine.dispose()


if __name__ == "__main__":
    main()
