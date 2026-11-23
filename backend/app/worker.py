"""Standalone process entrypoint for the JYXIA durable processing worker."""

from __future__ import annotations

import argparse
import logging
import sys

from app.core.config import ConfigurationError, Settings, load_settings
from app.core.logging import LOGGER_NAME, build_safe_log_extra, configure_logging
from app.db.session import create_db_engine, create_session_factory
from app.services.processing_worker import ProcessingWorker
from app.services.storage import LocalControlledSyntheticStorage


def resolve_worker_database_url(settings: Settings) -> str:
    """Resolve the database URL required by the background worker with fail-closed staging/prod checks."""
    if settings.worker_database_url:
        return settings.worker_database_url
    if settings.env in {"production", "staging"}:
        raise ConfigurationError(
            f"{settings.env.capitalize()} worker requires explicit JYXIA_WORKER_DATABASE_URL."
        )
    if settings.database_url:
        return settings.database_url
    raise ConfigurationError(
        "JYXIA_WORKER_DATABASE_URL (or JYXIA_DATABASE_URL in dev/test) must be configured."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="JYXIA asynchronous document processing worker")
    parser.add_argument("--once", action="store_true", help="Run a single polling cycle and exit.")
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Optional bounded number of polling cycles before exit.",
    )
    args = parser.parse_args(argv)

    settings = load_settings(strict_database=False)
    configure_logging(settings.log_level)
    logger = logging.getLogger(LOGGER_NAME)

    if not settings.worker_enabled:
        logger.info("Worker disabled by JYXIA_WORKER_ENABLED=false; exiting cleanly.")
        return 0

    worker_db_url = resolve_worker_database_url(settings)
    engine = create_db_engine(worker_db_url, echo=settings.debug)
    session_factory = create_session_factory(engine)
    storage = LocalControlledSyntheticStorage(
        settings.storage_root,
        enabled=settings.allow_local_synthetic_storage,
        max_bytes=settings.max_document_bytes,
    )
    worker = ProcessingWorker(session_factory, storage, settings)
    max_cycles = 1 if args.once else args.max_cycles

    logger.info(
        "Starting JYXIA asynchronous processing worker.",
        extra=build_safe_log_extra(
            worker_id=worker.worker_id,
            env=settings.env,
            max_cycles=max_cycles,
        ),
    )
    try:
        summary = worker.run_loop(max_cycles=max_cycles, handle_signals=True)
        logger.info(
            "JYXIA processing worker stopped cleanly.",
            extra=build_safe_log_extra(
                worker_id=worker.worker_id,
                claimed=summary.claimed,
                succeeded=summary.succeeded,
                retried=summary.retried,
                failed=summary.failed,
                reclaimed_leases=summary.reclaimed_leases,
                lease_lost=summary.lease_lost,
            ),
        )
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
