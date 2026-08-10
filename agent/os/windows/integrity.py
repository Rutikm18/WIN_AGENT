"""Install-manifest generation and fail-closed runtime verification."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Iterable

MANIFEST_NAME = "install-manifest.json"
MANIFEST_SCHEMA = 1


class IntegrityError(RuntimeError):
    """The installed package does not match its build manifest."""


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_manifest(
    root: str | os.PathLike[str],
    relative_paths: Iterable[str],
) -> dict[str, Any]:
    base = Path(root).resolve()
    files: dict[str, dict[str, Any]] = {}
    for relative in sorted({str(item).replace("\\", "/") for item in relative_paths}):
        candidate = (base / Path(relative)).resolve()
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise ValueError(f"manifest path escapes package root: {relative}") from exc
        stat = candidate.stat()
        files[relative] = {
            "sha256": sha256_file(candidate),
            "size": int(stat.st_size),
        }
    return {
        "schema": MANIFEST_SCHEMA,
        "generated_at": int(time.time()),
        "algorithm": "sha256",
        "files": files,
    }


def write_manifest_atomic(
    path: str | os.PathLike[str],
    manifest: dict[str, Any],
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_suffix(destination.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, sort_keys=True, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, destination)


def verify_manifest(
    manifest_path: str | os.PathLike[str],
    install_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path).resolve()
    base = Path(install_root).resolve() if install_root else manifest_file.parent
    try:
        raw = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IntegrityError(f"cannot read install manifest: {type(exc).__name__}") from exc
    if raw.get("schema") != MANIFEST_SCHEMA or raw.get("algorithm") != "sha256":
        raise IntegrityError("unsupported install manifest schema or algorithm")
    entries = raw.get("files")
    if not isinstance(entries, dict) or not entries:
        raise IntegrityError("install manifest contains no files")

    checked = 0
    for relative, expected in entries.items():
        if not isinstance(relative, str) or not isinstance(expected, dict):
            raise IntegrityError("malformed install manifest entry")
        candidate = (base / Path(relative)).resolve()
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise IntegrityError(f"manifest path escapes install root: {relative}") from exc
        if not candidate.is_file():
            raise IntegrityError(f"installed file is missing: {relative}")
        actual_size = candidate.stat().st_size
        if actual_size != int(expected.get("size", -1)):
            raise IntegrityError(f"installed file size mismatch: {relative}")
        actual_hash = sha256_file(candidate)
        if actual_hash.lower() != str(expected.get("sha256", "")).lower():
            raise IntegrityError(f"installed file checksum mismatch: {relative}")
        checked += 1
    return {
        "status": "verified",
        "checked_files": checked,
        "manifest": str(manifest_file),
    }


def locate_install_manifest(executable: str | None = None) -> Path | None:
    exe = Path(executable or sys.executable).resolve()
    candidates = [exe.parent / MANIFEST_NAME]
    candidates.extend(parent / MANIFEST_NAME for parent in list(exe.parents)[:4])
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def verify_current_install(executable: str | None = None) -> dict[str, Any]:
    manifest = locate_install_manifest(executable)
    if manifest is None:
        if bool(getattr(sys, "frozen", False)):
            raise IntegrityError(
                "packaged agent is missing install-manifest.json"
            )
        return {
            "status": "source_mode",
            "checked_files": 0,
            "manifest": None,
            "reason": "manifest verification applies to packaged installs",
        }
    return verify_manifest(manifest, manifest.parent)
