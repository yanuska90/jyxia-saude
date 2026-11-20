"""Synchronize or verify backend requirements files from canonical backend/pyproject.toml."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = ROOT / "backend" / "pyproject.toml"
RUNTIME_REQ_PATH = ROOT / "backend" / "requirements.txt"
DEV_REQ_PATH = ROOT / "backend" / "requirements-dev.txt"

HEADER = (
    "# GENERATED DETERMINISTICALLY BY tools/sync_backend_deps.py "
    "FROM backend/pyproject.toml. DO NOT EDIT MANUALLY.\n"
)


def render_requirements() -> tuple[str, str]:
    data = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    project = data["project"]
    runtime_deps = sorted(set(project["dependencies"]), key=str.lower)
    dev_only = sorted(set(project.get("optional-dependencies", {}).get("dev", [])), key=str.lower)
    all_dev = sorted(set(runtime_deps) | set(dev_only), key=str.lower)

    runtime_text = HEADER + "\n".join(runtime_deps) + "\n"
    dev_text = HEADER + "\n".join(all_dev) + "\n"
    return runtime_text, dev_text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="Write generated requirements files.")
    mode.add_argument("--check", action="store_true", help="Verify requirements match pyproject.toml.")
    args = parser.parse_args()

    runtime_text, dev_text = render_requirements()

    if args.write:
        RUNTIME_REQ_PATH.write_bytes(runtime_text.encode("utf-8"))
        DEV_REQ_PATH.write_bytes(dev_text.encode("utf-8"))
        print("Wrote backend/requirements.txt and backend/requirements-dev.txt from pyproject.toml.")
        return 0

    mismatches: list[str] = []
    for path, expected in ((RUNTIME_REQ_PATH, runtime_text), (DEV_REQ_PATH, dev_text)):
        if not path.is_file():
            mismatches.append(f"Missing generated file: {path.relative_to(ROOT)}")
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            mismatches.append(f"Out of sync with pyproject.toml: {path.relative_to(ROOT)}")

    if mismatches:
        print("\n".join(mismatches), file=sys.stderr)
        return 1
    print("Backend requirements files match backend/pyproject.toml (single source of truth).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
