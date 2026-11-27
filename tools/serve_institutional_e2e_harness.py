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
import contextlib
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, TextIO
import urllib.request

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


class _GracefulShutdownInterrupted(Exception):
    """Raised when a termination signal arrives while waiting for queue drainage before HTTP server start."""


class _GracefulHarnessServer(uvicorn.Server):
    """Uvicorn Server subclass whose `capture_signals` does not call `signal.raise_signal(SIGTERM)`
    with `SIG_DFL` on exit, ensuring `server.run()` always returns to the caller's `finally:` block."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def _parse_linux_proc_stat_content(raw_stat: str) -> dict[str, Any] | None:
    """Parse `/proc/<pid>/stat` content safely even when `(comm)` contains spaces or parentheses."""
    text_val = raw_stat.strip()
    if not text_val:
        return None
    lpar = text_val.find("(")
    rpar = text_val.rfind(")")
    if lpar <= 0 or rpar <= lpar or rpar + 2 > len(text_val):
        return None
    try:
        pid_val = int(text_val[:lpar].strip())
        comm_val = text_val[lpar + 1 : rpar]
        rest = text_val[rpar + 2 :].split()
        if len(rest) < 20:
            return None
        state_code = rest[0]
        ppid_val = int(rest[1])
        starttime_ticks = int(rest[19])
        return {
            "pid": pid_val,
            "comm": comm_val,
            "state": state_code,
            "ppid": ppid_val,
            "starttime_ticks": starttime_ticks,
        }
    except Exception:
        return None


def _capture_pid_identity(
    pid: int | None,
    *,
    expected_cmdline_token: str | None = None,
    proc_root: Path | None = None,
) -> dict[str, Any]:
    """Capture immutable OS process identity attributes at startup to detect PID reuse later."""
    if pid is None or int(pid) <= 0:
        return {"pid": pid, "platform": sys.platform}
    target_pid = int(pid)
    identity: dict[str, Any] = {
        "pid": target_pid,
        "platform": sys.platform,
        "expected_cmdline_token": expected_cmdline_token,
        "proc_starttime_ticks": None,
        "proc_cmdline": None,
        "win32_creation_time": None,
    }
    effective_proc_root = proc_root if proc_root is not None else Path("/proc")
    if proc_root is not None or (
        sys.platform.startswith("linux") and effective_proc_root.is_dir()
    ):
        stat_path = effective_proc_root / str(target_pid) / "stat"
        cmdline_path = effective_proc_root / str(target_pid) / "cmdline"
        try:
            parsed = _parse_linux_proc_stat_content(
                stat_path.read_text(encoding="utf-8", errors="replace")
            )
            if parsed is not None:
                identity["proc_starttime_ticks"] = int(parsed["starttime_ticks"])
        except Exception:
            pass
        try:
            raw_cmd = cmdline_path.read_bytes()
            identity["proc_cmdline"] = (
                raw_cmd.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            )
        except Exception:
            pass
    elif sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, target_pid)
            if handle:
                try:
                    ct = ctypes.c_ulonglong(0)
                    et = ctypes.c_ulonglong(0)
                    kt = ctypes.c_ulonglong(0)
                    ut = ctypes.c_ulonglong(0)
                    if kernel32.GetProcessTimes(
                        handle,
                        ctypes.byref(ct),
                        ctypes.byref(et),
                        ctypes.byref(kt),
                        ctypes.byref(ut),
                    ):
                        identity["win32_creation_time"] = int(ct.value)
                finally:
                    kernel32.CloseHandle(handle)
        except Exception:
            pass
    return identity


def _inspect_pid_state(
    pid: int | None,
    expected_identity: dict[str, Any] | None = None,
    *,
    proc_root: Path | None = None,
) -> dict[str, Any]:
    """Inspect OS process state, differentiating active, zombie ('Z'), terminated, and reused PID."""
    if pid is None or int(pid) <= 0:
        return {
            "pid": pid,
            "classification": "terminated",
            "alive": False,
            "zombie": False,
            "pid_reused": False,
            "detail": "invalid_or_missing_pid",
        }
    target_pid = int(pid)
    effective_proc_root = proc_root if proc_root is not None else Path("/proc")
    use_procfs = proc_root is not None or (
        sys.platform.startswith("linux") and effective_proc_root.is_dir()
    )

    if use_procfs:
        stat_path = effective_proc_root / str(target_pid) / "stat"
        cmdline_path = effective_proc_root / str(target_pid) / "cmdline"
        try:
            raw_stat = stat_path.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, ProcessLookupError, NotADirectoryError):
            return {
                "pid": target_pid,
                "classification": "terminated",
                "alive": False,
                "zombie": False,
                "pid_reused": False,
                "detail": "proc_stat_not_found",
            }
        except PermissionError:
            pass
        else:
            parsed = _parse_linux_proc_stat_content(raw_stat)
            if parsed is None:
                return {
                    "pid": target_pid,
                    "classification": "terminated",
                    "alive": False,
                    "zombie": False,
                    "pid_reused": False,
                    "detail": "proc_stat_unparseable",
                }
            cmdline_val = ""
            try:
                raw_cmd = cmdline_path.read_bytes()
                cmdline_val = (
                    raw_cmd.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                )
            except Exception:
                cmdline_val = ""

            exp_start = (
                expected_identity.get("proc_starttime_ticks")
                if isinstance(expected_identity, dict)
                else None
            )
            if exp_start is not None and int(exp_start) != int(parsed["starttime_ticks"]):
                return {
                    "pid": target_pid,
                    "classification": "pid_reused",
                    "alive": False,
                    "zombie": False,
                    "pid_reused": True,
                    "proc_state": parsed["state"],
                    "ppid": parsed["ppid"],
                    "starttime_ticks": parsed["starttime_ticks"],
                    "expected_starttime_ticks": int(exp_start),
                    "cmdline": cmdline_val,
                }

            exp_token = (
                expected_identity.get("expected_cmdline_token")
                if isinstance(expected_identity, dict)
                else None
            )
            state_code = str(parsed["state"])
            if state_code == "Z":
                return {
                    "pid": target_pid,
                    "classification": "zombie",
                    "alive": False,
                    "zombie": True,
                    "pid_reused": False,
                    "proc_state": state_code,
                    "ppid": parsed["ppid"],
                    "starttime_ticks": parsed["starttime_ticks"],
                    "cmdline": cmdline_val,
                }
            if state_code in {"X", "x"}:
                return {
                    "pid": target_pid,
                    "classification": "terminated",
                    "alive": False,
                    "zombie": False,
                    "pid_reused": False,
                    "proc_state": state_code,
                    "ppid": parsed["ppid"],
                    "starttime_ticks": parsed["starttime_ticks"],
                }
            if exp_start is None and exp_token and cmdline_val and exp_token not in cmdline_val:
                return {
                    "pid": target_pid,
                    "classification": "pid_reused",
                    "alive": False,
                    "zombie": False,
                    "pid_reused": True,
                    "proc_state": state_code,
                    "ppid": parsed["ppid"],
                    "starttime_ticks": parsed["starttime_ticks"],
                    "cmdline": cmdline_val,
                }
            return {
                "pid": target_pid,
                "classification": "active",
                "alive": True,
                "zombie": False,
                "pid_reused": False,
                "proc_state": state_code,
                "ppid": parsed["ppid"],
                "starttime_ticks": parsed["starttime_ticks"],
                "cmdline": cmdline_val,
            }

    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            SYNCHRONIZE = 0x00100000
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, target_pid
            )
            if not handle:
                return {
                    "pid": target_pid,
                    "classification": "terminated",
                    "alive": False,
                    "zombie": False,
                    "pid_reused": False,
                    "detail": "win32_open_process_failed",
                }
            try:
                WAIT_OBJECT_0 = 0x00000000
                res = kernel32.WaitForSingleObject(handle, 0)
                if res == WAIT_OBJECT_0:
                    return {
                        "pid": target_pid,
                        "classification": "terminated",
                        "alive": False,
                        "zombie": False,
                        "pid_reused": False,
                        "detail": "win32_wait_signaled",
                    }
                ct = ctypes.c_ulonglong(0)
                et = ctypes.c_ulonglong(0)
                kt = ctypes.c_ulonglong(0)
                ut = ctypes.c_ulonglong(0)
                creation_time: int | None = None
                if kernel32.GetProcessTimes(
                    handle,
                    ctypes.byref(ct),
                    ctypes.byref(et),
                    ctypes.byref(kt),
                    ctypes.byref(ut),
                ):
                    creation_time = int(ct.value)
                exp_ct = (
                    expected_identity.get("win32_creation_time")
                    if isinstance(expected_identity, dict)
                    else None
                )
                if (
                    exp_ct is not None
                    and creation_time is not None
                    and int(exp_ct) != creation_time
                ):
                    return {
                        "pid": target_pid,
                        "classification": "pid_reused",
                        "alive": False,
                        "zombie": False,
                        "pid_reused": True,
                        "win32_creation_time": creation_time,
                        "expected_win32_creation_time": int(exp_ct),
                    }
                return {
                    "pid": target_pid,
                    "classification": "active",
                    "alive": True,
                    "zombie": False,
                    "pid_reused": False,
                    "win32_creation_time": creation_time,
                }
            finally:
                kernel32.CloseHandle(handle)
        except Exception as exc:
            return {
                "pid": target_pid,
                "classification": "terminated",
                "alive": False,
                "zombie": False,
                "pid_reused": False,
                "detail": f"win32_error:{exc}",
            }

    try:
        os.kill(target_pid, 0)
        return {
            "pid": target_pid,
            "classification": "active",
            "alive": True,
            "zombie": False,
            "pid_reused": False,
        }
    except ProcessLookupError:
        return {
            "pid": target_pid,
            "classification": "terminated",
            "alive": False,
            "zombie": False,
            "pid_reused": False,
        }
    except PermissionError:
        return {
            "pid": target_pid,
            "classification": "active",
            "alive": True,
            "zombie": False,
            "pid_reused": False,
        }


def _start_worker_subprocess(
    *,
    app_db_url: str,
    worker_db_url: str,
    storage_dir: Path,
    settings: Settings,
    worker_id: str,
    log_path: Path,
    poll_interval_seconds: float = 0.15,
) -> tuple[Any, TextIO, dict[str, Any]]:
    log_fh = open(log_path, "w+", encoding="utf-8")
    worker_env = _build_worker_subprocess_env(
        app_db_url=app_db_url,
        worker_db_url=worker_db_url,
        storage_dir=storage_dir,
        settings=settings,
        worker_id=worker_id,
    )
    worker_env["JYXIA_WORKER_POLL_INTERVAL_SECONDS"] = str(poll_interval_seconds)
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.worker"],
        cwd=str(BACKEND_DIR),
        env=worker_env,
        stdin=subprocess.DEVNULL,
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
    worker_identity = _capture_pid_identity(
        proc.pid,
        expected_cmdline_token="app.worker",
    )
    return proc, log_fh, worker_identity


def _stop_worker_subprocess(
    proc: Any | None,
    log_fh: TextIO | None,
    *,
    timeout_seconds: float = 5.0,
    kill_timeout_seconds: float = 3.0,
    expected_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    worker_pid: int | None = getattr(proc, "pid", None) if proc is not None else None
    result: dict[str, Any] = {
        "worker_pid": worker_pid,
        "worker_shutdown_requested": False,
        "worker_shutdown_confirmed": False,
        "worker_forced_kill": False,
        "worker_exit_code": None,
        "worker_process_alive": False,
        "worker_pid_state": "terminated",
    }
    try:
        if proc is not None:
            result["worker_shutdown_requested"] = True
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout_seconds)
                except Exception:
                    result["worker_forced_kill"] = True
                    proc.kill()
                    proc.wait(timeout=kill_timeout_seconds)

            exit_code = proc.poll()
            if exit_code is None:
                with contextlib.suppress(Exception):
                    proc.wait(timeout=1.0)
                exit_code = proc.poll()

            # Wait briefly for kernel process table / procfs entry to settle
            settle_deadline = time.monotonic() + 2.0
            pid_state = _inspect_pid_state(worker_pid, expected_identity)
            while (
                pid_state["alive"] or pid_state["zombie"]
            ) and time.monotonic() < settle_deadline:
                if hasattr(os, "waitpid") and worker_pid is not None:
                    with contextlib.suppress(Exception):
                        os.waitpid(int(worker_pid), getattr(os, "WNOHANG", 1))
                with contextlib.suppress(Exception):
                    proc.wait(timeout=0.1)
                time.sleep(0.05)
                pid_state = _inspect_pid_state(worker_pid, expected_identity)

            is_alive_or_zombie = bool(pid_state["alive"] or pid_state["zombie"])
            result["worker_exit_code"] = exit_code
            result["worker_pid_state"] = str(pid_state["classification"])
            result["worker_process_alive"] = is_alive_or_zombie
            result["worker_shutdown_confirmed"] = bool(
                exit_code is not None and not is_alive_or_zombie
            )
            if exit_code is None or is_alive_or_zombie:
                raise RuntimeError(
                    f"Worker subprocess PID {worker_pid} failed to terminate cleanly: "
                    f"result={result}, pid_state={pid_state}"
                )
    finally:
        if log_fh is not None:
            with contextlib.suppress(Exception):
                log_fh.flush()
                log_fh.close()
    return result


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
    should_abort: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Poll database until all expected case runs are terminal, lease-free, and assessments exist."""
    deadline = time.monotonic() + timeout_seconds
    last_snapshot: dict[str, Any] = {}

    while time.monotonic() < deadline:
        if should_abort is not None and should_abort():
            raise _GracefulShutdownInterrupted("Shutdown signal received while draining queue.")
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

        if should_abort is not None and should_abort():
            raise _GracefulShutdownInterrupted("Shutdown signal received while draining queue.")
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


def _is_pid_running(
    pid: int | None,
    expected_identity: dict[str, Any] | None = None,
) -> bool:
    info = _inspect_pid_state(pid, expected_identity)
    return bool(info.get("alive") or info.get("zombie"))


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
        worker_identity: dict[str, Any] | None = None
        stop_info: dict[str, Any] = {}
        try:
            worker_proc, worker_log_fh, worker_identity = _start_worker_subprocess(
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
            stop_info = _stop_worker_subprocess(
                worker_proc,
                worker_log_fh,
                timeout_seconds=5.0,
                expected_identity=worker_identity,
            )
            engine.dispose()

        assert stop_info["worker_shutdown_confirmed"] is True, (
            f"Worker did not stop cleanly: {stop_info}"
        )
        assert stop_info["worker_process_alive"] is False, f"Worker still alive: {stop_info}"
        assert not _is_pid_running(worker_pid, worker_identity), (
            f"Worker PID {worker_pid} still running after stop."
        )
        print(
            json.dumps(
                {
                    "status": "SQLITE_MULTIPROCESS_LIFECYCLE_OK",
                    "worker_pid": worker_pid,
                    "worker_exit_code": stop_info["worker_exit_code"],
                    "worker_shutdown_confirmed": stop_info["worker_shutdown_confirmed"],
                    "case_a_readiness": final_snap[case_a_id]["latest_readiness_state"],
                    "case_b_readiness": final_snap[case_b_id]["latest_readiness_state"],
                }
            )
        )


def _find_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _send_graceful_termination_to_harness_subprocess(proc: subprocess.Popen[Any]) -> str:
    """Send POSIX SIGTERM on Linux/macOS, or stdin SHUTDOWN / CTRL_BREAK_EVENT on Windows."""
    if sys.platform != "win32":
        proc.send_signal(signal.SIGTERM)
        return "SIGTERM"
    if proc.stdin is not None:
        with contextlib.suppress(Exception):
            proc.stdin.write(b"SHUTDOWN\n")
            proc.stdin.flush()
            proc.stdin.close()
            return "WIN32_STDIN_SHUTDOWN"
    ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
    if ctrl_break is not None:
        proc.send_signal(ctrl_break)
        return "CTRL_BREAK_EVENT"
    proc.terminate()
    return "WIN32_TERMINATE"


def _run_self_test_process_shutdown() -> None:
    """Mandatory regression test for POSIX SIGTERM / multiprocess shutdown lifecycle and edge cases:
    1. Linux `/proc/<pid>/stat` parser & PID state classification (`active`, `zombie`, `terminated`, `pid_reused`).
    2. Worker shutdown timeout & fallback to `kill()` (`SIGKILL`) when worker ignores `SIGTERM`.
    3. Shutdown during active queue processing (`stage='worker_started'`, before initial drain completes).
    4. Normal live HTTP harness + post-E2E-failure shutdown via `SIGTERM` (POSIX) / graceful signal (Windows),
       verifying `finally` execution, `worker_shutdown_confirmed=True`, `worker_process_alive=False`,
       zero orphan processes, and `_verify_post_e2e_report` validation.
    """
    # 1. Verify Linux /proc/<pid>/stat parser & PID classifier (active, zombie 'Z', pid_reused, terminated)
    with tempfile.TemporaryDirectory(
        prefix="jyxia-procfs-test-", ignore_cleanup_errors=True
    ) as ptmp:
        fake_proc = Path(ptmp)
        pid_dir = fake_proc / "4215"
        pid_dir.mkdir(parents=True, exist_ok=True)
        # Field 3 = state ('S'), Field 4 = ppid (4211), Field 22 = starttime (987654)
        stat_fields_after_comm = [
            "S", "4211", "4211", "4211", "0", "-1", "4194304",
            "120", "0", "0", "0", "15", "3", "0", "0", "20", "0", "1", "0", "987654",
            "12345678", "1024",
        ]
        (pid_dir / "stat").write_text(
            f"4215 (python -m (app.worker)) {' '.join(stat_fields_after_comm)}\n",
            encoding="utf-8",
        )
        (pid_dir / "cmdline").write_bytes(b"/usr/bin/python\x00-m\x00app.worker\x00")

        ident = _capture_pid_identity(
            4215,
            expected_cmdline_token="app.worker",
            proc_root=fake_proc,
        )
        assert ident["proc_starttime_ticks"] == 987654, ident

        st_active = _inspect_pid_state(4215, ident, proc_root=fake_proc)
        assert st_active["classification"] == "active" and st_active["alive"] is True, st_active

        # Simulate zombie ('Z') state for the same process starttime
        zombie_fields = list(stat_fields_after_comm)
        zombie_fields[0] = "Z"
        (pid_dir / "stat").write_text(
            f"4215 (python) {' '.join(zombie_fields)}\n",
            encoding="utf-8",
        )
        st_zombie = _inspect_pid_state(4215, ident, proc_root=fake_proc)
        assert st_zombie["classification"] == "zombie" and st_zombie["zombie"] is True, st_zombie
        assert st_zombie["alive"] is False, st_zombie

        # Simulate PID reuse (different starttime_ticks = 999999)
        reused_fields = list(stat_fields_after_comm)
        reused_fields[0] = "R"
        reused_fields[19] = "999999"
        (pid_dir / "stat").write_text(
            f"4215 (other_service) {' '.join(reused_fields)}\n",
            encoding="utf-8",
        )
        st_reused = _inspect_pid_state(4215, ident, proc_root=fake_proc)
        assert st_reused["classification"] == "pid_reused" and st_reused["pid_reused"] is True, (
            st_reused
        )
        assert st_reused["alive"] is False and st_reused["zombie"] is False, st_reused

        # Simulate terminated process (no /proc/4215/stat)
        (pid_dir / "stat").unlink()
        st_term = _inspect_pid_state(4215, ident, proc_root=fake_proc)
        assert st_term["classification"] == "terminated" and st_term["alive"] is False, st_term

    # 2. Verify worker shutdown timeout and fallback to kill() (SIGKILL) when worker ignores SIGTERM
    with tempfile.TemporaryDirectory(
        prefix="jyxia-kill-fallback-", ignore_cleanup_errors=True
    ) as ktmp:
        klog_path = Path(ktmp) / "stubborn_worker.log"
        klog_fh = open(klog_path, "w+", encoding="utf-8")
        stubborn_code = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "if hasattr(signal, 'SIGINT'): signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.2)\n"
        )
        stubborn_proc = subprocess.Popen(
            [sys.executable, "-c", stubborn_code],
            stdin=subprocess.DEVNULL,
            stdout=klog_fh,
            stderr=subprocess.STDOUT,
        )
        time.sleep(0.25)
        assert stubborn_proc.poll() is None, "Stubborn worker exited prematurely"
        stubborn_ident = _capture_pid_identity(stubborn_proc.pid)
        kill_res = _stop_worker_subprocess(
            stubborn_proc,
            klog_fh,
            timeout_seconds=0.35,
            kill_timeout_seconds=3.0,
            expected_identity=stubborn_ident,
        )
        assert kill_res["worker_shutdown_requested"] is True, kill_res
        assert kill_res["worker_shutdown_confirmed"] is True, kill_res
        assert kill_res["worker_process_alive"] is False, kill_res
        assert kill_res["worker_exit_code"] is not None, kill_res
        if sys.platform != "win32":
            assert kill_res["worker_forced_kill"] is True, (
                f"Expected worker_forced_kill=True on POSIX when SIGTERM is ignored, got: {kill_res}"
            )
        post_kill_state = _inspect_pid_state(stubborn_proc.pid, stubborn_ident)
        assert not (post_kill_state["alive"] or post_kill_state["zombie"]), post_kill_state

    # 3. Verify shutdown during active processing (before initial queue drain finishes)
    with tempfile.TemporaryDirectory(
        prefix="jyxia-midproc-shutdown-", ignore_cleanup_errors=True
    ) as mtmp:
        mreport_path = Path(mtmp) / "midproc_report.json"
        mout_path = Path(mtmp) / "midproc_harness.log"
        mport = _find_free_tcp_port()
        sub_env = dict(os.environ)
        sub_env.pop("JYXIA_DATABASE_URL", None)
        sub_env.pop("JYXIA_WORKER_DATABASE_URL", None)
        sub_env.pop("JYXIA_MIGRATION_DATABASE_URL", None)
        sub_env["JYXIA_E2E_REQUIRE_POSTGRES"] = "0"

        with open(mout_path, "w+", encoding="utf-8") as mout_fh:
            mproc = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--port",
                    str(mport),
                    "--report-file",
                    str(mreport_path),
                    "--worker-poll-interval",
                    "1.5",
                ],
                cwd=str(ROOT),
                env=sub_env,
                stdin=subprocess.PIPE if sys.platform == "win32" else subprocess.DEVNULL,
                stdout=mout_fh,
                stderr=subprocess.STDOUT,
            )
            try:
                appear_deadline = time.monotonic() + 15.0
                mid_report: dict[str, Any] = {}
                while time.monotonic() < appear_deadline:
                    if mreport_path.exists():
                        with contextlib.suppress(Exception):
                            mid_report = json.loads(mreport_path.read_text(encoding="utf-8"))
                            if mid_report.get("worker_process_started") is True:
                                break
                    if mproc.poll() is not None:
                        mout_fh.flush()
                        out = _read_worker_log_tail(mout_path)
                        raise RuntimeError(
                            f"Harness exited early during mid-processing test: {out}"
                        )
                    time.sleep(0.05)
                else:
                    mout_fh.flush()
                    out = _read_worker_log_tail(mout_path)
                    raise RuntimeError(
                        f"Timeout waiting for harness to start worker in mid-processing test:\n{out}"
                    )

                mid_worker_pid = mid_report["worker_pid"]
                mid_worker_ident = mid_report.get("worker_proc_identity")
                _send_graceful_termination_to_harness_subprocess(mproc)
                mproc.wait(timeout=12.0)
            finally:
                if mproc.poll() is None:
                    mproc.kill()
                    mproc.wait(timeout=3.0)

        final_mid_report = json.loads(mreport_path.read_text(encoding="utf-8"))
        assert final_mid_report.get("stage") == "shutdown_complete", final_mid_report
        assert final_mid_report.get("finally_block_executed") is True, final_mid_report
        assert final_mid_report.get("worker_shutdown_requested") is True, final_mid_report
        assert final_mid_report.get("worker_shutdown_confirmed") is True, final_mid_report
        assert final_mid_report.get("worker_process_alive") is False, final_mid_report
        assert final_mid_report.get("worker_exit_code") is not None, final_mid_report
        mid_w_state = _inspect_pid_state(mid_worker_pid, mid_worker_ident)
        assert not (mid_w_state["alive"] or mid_w_state["zombie"]), mid_w_state

    # 4. Verify live HTTP harness readiness + SIGTERM / post-E2E-failure shutdown + --verify-report
    with tempfile.TemporaryDirectory(
        prefix="jyxia-http-shutdown-", ignore_cleanup_errors=True
    ) as htmp:
        hreport_path = Path(htmp) / "http_shutdown_report.json"
        hout_path = Path(htmp) / "http_harness.log"
        hport = _find_free_tcp_port()
        sub_env = dict(os.environ)
        sub_env.pop("JYXIA_DATABASE_URL", None)
        sub_env.pop("JYXIA_WORKER_DATABASE_URL", None)
        sub_env.pop("JYXIA_MIGRATION_DATABASE_URL", None)
        sub_env["JYXIA_E2E_REQUIRE_POSTGRES"] = "0"

        sig_used = "UNKNOWN"
        with open(hout_path, "w+", encoding="utf-8") as hout_fh:
            hproc = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--port",
                    str(hport),
                    "--report-file",
                    str(hreport_path),
                ],
                cwd=str(ROOT),
                env=sub_env,
                stdin=subprocess.PIPE if sys.platform == "win32" else subprocess.DEVNULL,
                stdout=hout_fh,
                stderr=subprocess.STDOUT,
            )
            try:
                http_deadline = time.monotonic() + 30.0
                while time.monotonic() < http_deadline:
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{hport}/api/v1/health/live", timeout=1.5
                        ) as resp:
                            if resp.status == 200:
                                break
                    except Exception:
                        if hproc.poll() is not None:
                            hout_fh.flush()
                            out = _read_worker_log_tail(hout_path)
                            raise RuntimeError(
                                f"Harness exited early before HTTP readiness (code={hproc.returncode}):\n{out}"
                            )
                        time.sleep(0.15)
                else:
                    hout_fh.flush()
                    out = _read_worker_log_tail(hout_path)
                    raise RuntimeError(
                        f"Timeout waiting for harness HTTP readiness in shutdown test:\n{out}"
                    )

                live_report = json.loads(hreport_path.read_text(encoding="utf-8"))
                live_harness_pid = int(live_report["harness_pid"])
                live_worker_pid = int(live_report["worker_pid"])
                live_worker_ident = live_report.get("worker_proc_identity")
                live_harness_ident = live_report.get("harness_proc_identity")

                assert live_report.get("worker_process_started") is True, live_report
                assert live_report.get("worker_process_alive") is True, live_report
                assert live_report.get("worker_shutdown_confirmed") is False, live_report
                assert _inspect_pid_state(live_worker_pid, live_worker_ident)["alive"] is True

                # Send graceful termination signal (SIGTERM on POSIX) before human reviews (also covers E2E failure abort)
                sig_used = _send_graceful_termination_to_harness_subprocess(hproc)
                hproc.wait(timeout=12.0)
            finally:
                if hproc.poll() is None:
                    hproc.kill()
                    hproc.wait(timeout=3.0)

        assert hproc.returncode == 0, (
            f"Expected harness returncode 0 after {sig_used}, got {hproc.returncode}"
        )
        final_http_report = json.loads(hreport_path.read_text(encoding="utf-8"))
        assert final_http_report.get("stage") == "shutdown_complete", final_http_report
        assert final_http_report.get("finally_block_executed") is True, final_http_report
        assert final_http_report.get("worker_process_started") is True, final_http_report
        assert final_http_report.get("worker_shutdown_requested") is True, final_http_report
        assert final_http_report.get("worker_shutdown_confirmed") is True, final_http_report
        assert final_http_report.get("worker_process_alive") is False, final_http_report
        assert final_http_report.get("worker_exit_code") is not None, final_http_report

        w_final = _inspect_pid_state(live_worker_pid, live_worker_ident)
        h_final = _inspect_pid_state(live_harness_pid, live_harness_ident)
        assert not (w_final["alive"] or w_final["zombie"]), w_final
        assert not (h_final["alive"] or h_final["zombie"]), h_final

        # Also validate through _verify_post_e2e_report (with allow_unreviewed_cases=True)
        _verify_post_e2e_report(
            hreport_path,
            require_postgres=False,
            allow_unreviewed_cases=True,
        )

    print(
        json.dumps(
            {
                "status": "HARNESS_PROCESS_SHUTDOWN_SELF_TEST_OK",
                "platform": sys.platform,
                "signal_tested": sig_used,
                "scenarios_verified": [
                    "proc_stat_parser_active_zombie_reused_terminated",
                    "worker_sigterm_timeout_sigkill_fallback",
                    "shutdown_during_active_processing",
                    "normal_and_failed_e2e_http_harness_sigterm_shutdown",
                ],
            }
        )
    )


def _verify_post_e2e_report(
    report_path: Path,
    *,
    require_postgres: bool,
    drain_timeout: float = 15.0,
    drain_interval: float = 0.15,
    allow_unreviewed_cases: bool = False,
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
    worker_identity = report.get("worker_proc_identity")
    harness_identity = report.get("harness_proc_identity")

    # Wait for both harness and worker subprocess to exit completely and finalize report
    proc_deadline = time.monotonic() + 10.0
    while time.monotonic() < proc_deadline:
        w_state = _inspect_pid_state(worker_pid, worker_identity)
        h_state = _inspect_pid_state(harness_pid, harness_identity)
        with contextlib.suppress(Exception):
            report = json.loads(report_path.read_text(encoding="utf-8"))
        if (
            not (w_state["alive"] or w_state["zombie"])
            and not (h_state["alive"] or h_state["zombie"])
            and report.get("stage") == "shutdown_complete"
        ):
            break
        time.sleep(0.15)

    w_state = _inspect_pid_state(worker_pid, worker_identity)
    if w_state["alive"] or w_state["zombie"]:
        raise RuntimeError(
            f"Orphan worker subprocess PID {worker_pid} is still {w_state['classification']} "
            f"after E2E! Details: {json.dumps(w_state, ensure_ascii=False)}"
        )
    h_state = _inspect_pid_state(harness_pid, harness_identity)
    if h_state["alive"] or h_state["zombie"]:
        raise RuntimeError(
            f"Harness process PID {harness_pid} is still {h_state['classification']} "
            f"after E2E! Details: {json.dumps(h_state, ensure_ascii=False)}"
        )

    # Re-read report after processes have exited
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("worker_process_started") is not True:
        raise RuntimeError(
            f"Expected worker_process_started=True in report, got: {report.get('worker_process_started')}"
        )
    if report.get("worker_shutdown_requested") is not True:
        raise RuntimeError(
            f"Expected worker_shutdown_requested=True in report, got: {report.get('worker_shutdown_requested')}"
        )
    if report.get("worker_shutdown_confirmed") is not True:
        raise RuntimeError(
            f"Expected worker_shutdown_confirmed=True in report, got: {report.get('worker_shutdown_confirmed')}"
        )
    if report.get("worker_process_alive") is not False:
        raise RuntimeError(
            f"Expected worker_process_alive=False in report, got: {report.get('worker_process_alive')}"
        )
    if report.get("worker_exit_code") is None:
        raise RuntimeError("Expected non-null worker_exit_code in report after shutdown.")
    if report.get("finally_block_executed") is not True:
        raise RuntimeError("Harness finally block was not executed before exit.")
    if report.get("stage") != "shutdown_complete":
        raise RuntimeError(
            f"Expected final report stage='shutdown_complete', got '{report.get('stage')}'."
        )

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
        if not allow_unreviewed_cases:
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
                "worker_process_started": report.get("worker_process_started"),
                "worker_shutdown_requested": report.get("worker_shutdown_requested"),
                "worker_shutdown_confirmed": report.get("worker_shutdown_confirmed"),
                "worker_exit_code": report.get("worker_exit_code"),
                "worker_process_alive": False,
                "worker_pid_state": w_state["classification"],
                "harness_pid_state": h_state["classification"],
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
    parser.add_argument(
        "--worker-poll-interval",
        type=float,
        default=0.15,
    )
    parser.add_argument("--self-test-fail-closed", action="store_true")
    parser.add_argument("--self-test-sqlite-lifecycle", action="store_true")
    parser.add_argument("--self-test-process-shutdown", action="store_true")
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

    if args.self_test_process_shutdown:
        _run_self_test_process_shutdown()
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
    harness_pid = os.getpid()
    harness_identity = _capture_pid_identity(
        harness_pid,
        expected_cmdline_token="serve_institutional_e2e_harness.py",
    )

    shutdown_state: dict[str, Any] = {
        "signal_received": None,
        "phase": "startup",
        "server": None,
    }

    def _request_harness_shutdown(reason: str) -> None:
        if shutdown_state["signal_received"] is None:
            shutdown_state["signal_received"] = reason
        srv = shutdown_state.get("server")
        if srv is not None:
            srv.should_exit = True

    def _handle_termination_signal(signum: int, _frame: Any) -> None:
        try:
            sig_name = signal.Signals(signum).name
        except Exception:
            sig_name = f"SIG_{signum}"
        if shutdown_state.get("phase") == "cleanup":
            return
        _request_harness_shutdown(sig_name)

    handled_signals = [
        sig
        for sig in (
            getattr(signal, "SIGINT", None),
            getattr(signal, "SIGTERM", None),
            getattr(signal, "SIGBREAK", None),
        )
        if sig is not None
    ]
    original_signal_handlers: dict[int, Any] = {}
    for sig in handled_signals:
        with contextlib.suppress(Exception):
            original_signal_handlers[sig] = signal.signal(sig, _handle_termination_signal)

    if sys.platform == "win32":

        def _win32_stdin_shutdown_watcher() -> None:
            with contextlib.suppress(Exception):
                import ctypes
                from ctypes import wintypes
                import msvcrt

                h_stdin = msvcrt.get_osfhandle(sys.stdin.fileno())
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                buf = b""
                while shutdown_state.get("phase") != "cleanup":
                    avail = wintypes.DWORD(0)
                    ok = kernel32.PeekNamedPipe(
                        wintypes.HANDLE(h_stdin),
                        None,
                        0,
                        None,
                        ctypes.byref(avail),
                        None,
                    )
                    if not ok:
                        err = ctypes.get_last_error()
                        # ERROR_BROKEN_PIPE (109) means parent closed the stdin pipe
                        if err == 109 and buf:
                            _request_harness_shutdown("WIN32_STDIN_SHUTDOWN")
                        return
                    if avail.value > 0:
                        chunk = os.read(sys.stdin.fileno(), int(avail.value))
                        if not chunk:
                            return
                        buf += chunk
                        if b"SHUTDOWN" in buf.upper():
                            _request_harness_shutdown("WIN32_STDIN_SHUTDOWN")
                            return
                    time.sleep(0.1)

        threading.Thread(
            target=_win32_stdin_shutdown_watcher,
            name="jyxia-win32-stdin-shutdown",
            daemon=True,
        ).start()

    with tempfile.TemporaryDirectory(
        prefix="jyxia-inst-e2e-335-", ignore_cleanup_errors=True
    ) as tmp:
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
        worker_identity: dict[str, Any] | None = None
        seeded: dict[str, Any] | None = None
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
            worker_proc, worker_log_fh, worker_identity = _start_worker_subprocess(
                app_db_url=app_db_url,
                worker_db_url=worker_db_url,
                storage_dir=storage_dir,
                settings=settings,
                worker_id=f"e2e-worker-{run_uid}",
                log_path=worker_log_path,
                poll_interval_seconds=args.worker_poll_interval,
            )

            report_payload = {
                "stage": "worker_started",
                "run_uid": run_uid,
                "harness_pid": harness_pid,
                "harness_proc_identity": harness_identity,
                "worker_pid": worker_proc.pid,
                "worker_proc_identity": worker_identity,
                "worker_process_started": True,
                "worker_shutdown_requested": False,
                "worker_shutdown_confirmed": False,
                "worker_forced_kill": False,
                "worker_terminated_cleanly": False,
                "worker_exit_code": None,
                "worker_process_alive": True,
                "worker_pid_state": "active",
                "finally_block_executed": False,
                "harness_shutdown_signal": None,
                "db_info": db_info,
                "organization_id": seeded["organization_id"],
                "reviewer_user_id": seeded["reviewer_user_id"],
                "session_token_hash": seeded["session_token_hash"],
                "case_a_id": case_a_id,
                "case_b_id": case_b_id,
                "initial_drain_ok": False,
                "e2e_cases_drained_verified": False,
                "cases_snapshot": {},
            }
            _write_report_file(report_path, report_payload)

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
                should_abort=lambda: shutdown_state["signal_received"] is not None,
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

            report_payload["stage"] = "initial_seed_drained"
            report_payload["initial_drain_ok"] = True
            report_payload["cases_snapshot"] = initial_snap
            _write_report_file(report_path, report_payload)

            if shutdown_state["signal_received"] is not None:
                raise _GracefulShutdownInterrupted("Shutdown requested prior to HTTP server start.")

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
                                should_abort=lambda: shutdown_state["signal_received"] is not None,
                            )
                            report_payload["stage"] = "e2e_cases_drained"
                            report_payload["e2e_cases_drained_verified"] = True
                            report_payload["cases_snapshot"] = snap
                            _write_report_file(report_path, report_payload)
                return response

            config = uvicorn.Config(
                app,
                host="127.0.0.1",
                port=args.port,
                log_level="warning",
                timeout_graceful_shutdown=5,
            )
            server = _GracefulHarnessServer(config)
            shutdown_state["server"] = server
            shutdown_state["phase"] = "serving"
            if shutdown_state["signal_received"] is not None:
                server.should_exit = True
            else:
                server.run()
        except _GracefulShutdownInterrupted:
            pass
        finally:
            shutdown_state["phase"] = "cleanup"
            if bootstrap_engine is not None:
                with contextlib.suppress(Exception):
                    bootstrap_engine.dispose()

            # Capture a final non-blocking snapshot of case runs before stopping the worker
            if (
                report_payload
                and seeded is not None
                and not report_payload.get("e2e_cases_drained_verified")
            ):
                snap_sess = None
                try:
                    snap_sess = create_session_factory(app_engine)()
                    _, latest_snap = _inspect_cases_queue_snapshot(
                        snap_sess,
                        seeded["ctx"],
                        {
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
                    )
                    report_payload["cases_snapshot"] = latest_snap
                except Exception:
                    pass
                finally:
                    if snap_sess is not None:
                        with contextlib.suppress(Exception):
                            snap_sess.rollback()
                            snap_sess.close()

            stop_info = _stop_worker_subprocess(
                worker_proc,
                worker_log_fh,
                timeout_seconds=5.0,
                kill_timeout_seconds=3.0,
                expected_identity=worker_identity,
            )
            with contextlib.suppress(Exception):
                app_engine.dispose()

            if report_payload:
                report_payload["stage"] = "shutdown_complete"
                report_payload["finally_block_executed"] = True
                report_payload["harness_shutdown_signal"] = (
                    shutdown_state.get("signal_received") or "normal_return"
                )
                report_payload["worker_shutdown_requested"] = stop_info[
                    "worker_shutdown_requested"
                ]
                report_payload["worker_shutdown_confirmed"] = stop_info[
                    "worker_shutdown_confirmed"
                ]
                report_payload["worker_forced_kill"] = stop_info["worker_forced_kill"]
                report_payload["worker_terminated_cleanly"] = stop_info[
                    "worker_shutdown_confirmed"
                ]
                report_payload["worker_exit_code"] = stop_info["worker_exit_code"]
                report_payload["worker_process_alive"] = stop_info["worker_process_alive"]
                report_payload["worker_pid_state"] = stop_info["worker_pid_state"]
                _write_report_file(report_path, report_payload)

            for sig, orig_handler in original_signal_handlers.items():
                with contextlib.suppress(Exception):
                    signal.signal(sig, orig_handler)


if __name__ == "__main__":
    main()
