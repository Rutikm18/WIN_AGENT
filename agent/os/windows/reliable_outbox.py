"""Crash-safe encrypted delivery outbox for the Windows agent.

The manager rejects wire envelopes older than its replay window.  Persisting
those envelopes directly therefore cannot survive a long outage.  This module
stores the canonical inner message instead.  The sender creates a fresh
transport envelope for every attempt while preserving ``collected_at`` and a
stable ``delivery_id``.

SQLite is used as a transactional outbox:

* ``synchronous=FULL`` and WAL journaling make an acknowledged local enqueue
  survive a process or host crash.
* rows are deleted only after a positive manager acknowledgement.
* non-retryable rows become retained dead letters; they are never silently
  discarded.
* payload blobs are encrypted with a machine-local AES-256-GCM key that is
  independent of the manager API key, so manager key rotation does not make
  queued telemetry unreadable.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("agent.windows.reliable_outbox")

_DB_NAME = "delivery-outbox.sqlite3"
_KEY_NAME = "delivery-outbox.key"
_KEY_PREFIX_DPAPI = b"DPAPI1\x00"
_KEY_PREFIX_RAW = b"RAW1\x00"
_SCHEMA_VERSION = 1


class OutboxError(RuntimeError):
    """Raised when durable queue guarantees cannot be maintained."""


class OutboxCorruptionError(OutboxError):
    """Raised when a queued row cannot be authenticated or decoded."""


@dataclass(frozen=True)
class OutboxItem:
    row_id: int
    delivery_id: str
    section: str
    message: dict[str, Any]
    created_at: int
    attempts: int


def new_delivery_id() -> str:
    """Return an opaque, stable identifier suitable for idempotency headers."""
    return str(uuid.uuid4())


class _PayloadProtector:
    """AES-GCM protection using a machine-local, ACL-restricted key."""

    def __init__(
        self,
        security_dir: str,
        agent_id: str,
        *,
        allow_create: bool = True,
    ) -> None:
        self._security_dir = Path(security_dir)
        safe_agent = "".join(
            char if char.isalnum() or char in "-_." else "_"
            for char in agent_id
        )
        self._path = self._security_dir / f"{safe_agent}.{_KEY_NAME}"
        self._key = self._load_or_create(allow_create=allow_create)
        if len(self._key) != 32:
            raise OutboxError("delivery outbox key has an invalid length")

    def encrypt(self, delivery_id: str, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(
            nonce, plaintext, delivery_id.encode("utf-8")
        )
        return nonce + ciphertext

    def decrypt(self, delivery_id: str, protected: bytes) -> bytes:
        if len(protected) < 29:
            raise OutboxCorruptionError("protected payload is truncated")
        try:
            return AESGCM(self._key).decrypt(
                protected[:12],
                protected[12:],
                delivery_id.encode("utf-8"),
            )
        except Exception as exc:
            raise OutboxCorruptionError(
                "protected payload authentication failed"
            ) from exc

    def _load_or_create(self, *, allow_create: bool) -> bytes:
        self._security_dir.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            return self._decode_key_file(self._path.read_bytes())
        if not allow_create:
            raise OutboxError(
                "delivery outbox key is missing while an outbox database exists; "
                "refusing to replace the key and orphan queued telemetry"
            )

        key = secrets.token_bytes(32)
        encoded = self._encode_key_file(key)
        temp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            fd = os.open(
                temp_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
            self._repair_acl()
        except FileExistsError:
            # A concurrent first-start winner created the key.
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

        if not self._path.exists():
            raise OutboxError("delivery outbox key could not be created")
        return self._decode_key_file(self._path.read_bytes())

    @staticmethod
    def _encode_key_file(key: bytes) -> bytes:
        if os.name == "nt":
            try:
                import win32crypt

                protected = win32crypt.CryptProtectData(
                    key,
                    "AttackLens delivery outbox",
                    None,
                    None,
                    None,
                    0x4,  # CRYPTPROTECT_LOCAL_MACHINE
                )
                return _KEY_PREFIX_DPAPI + protected
            except Exception as exc:
                log.warning(
                    "DPAPI unavailable for delivery outbox key; "
                    "using ACL-protected fallback: %s",
                    type(exc).__name__,
                )
        return _KEY_PREFIX_RAW + key

    @staticmethod
    def _decode_key_file(raw: bytes) -> bytes:
        if raw.startswith(_KEY_PREFIX_DPAPI):
            try:
                import win32crypt

                _description, plaintext = win32crypt.CryptUnprotectData(
                    raw[len(_KEY_PREFIX_DPAPI):],
                    None,
                    None,
                    None,
                    0x4,
                )
                return bytes(plaintext)
            except Exception as exc:
                raise OutboxError(
                    "delivery outbox key cannot be decrypted with DPAPI"
                ) from exc
        if raw.startswith(_KEY_PREFIX_RAW):
            return raw[len(_KEY_PREFIX_RAW):]
        raise OutboxError("delivery outbox key file has an unknown format")

    def _repair_acl(self) -> None:
        try:
            from agent.os.windows.acl import repair_acl

            result = repair_acl(str(self._path), "key_file")
            if not result.skipped and not result.compliant:
                raise OutboxError(
                    f"delivery outbox key ACL is not compliant: {result.error}"
                )
        except ImportError:
            if os.name != "nt":
                os.chmod(self._path, 0o600)


class ReliableOutbox:
    """Thread-safe encrypted SQLite outbox with retained dead letters."""

    def __init__(
        self,
        spool_dir: str,
        security_dir: str,
        agent_id: str,
        *,
        busy_timeout_ms: int = 5000,
    ) -> None:
        self._dir = Path(spool_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / _DB_NAME
        self._lock = threading.RLock()
        self._protector = _PayloadProtector(
            security_dir,
            agent_id,
            allow_create=not self._path.exists(),
        )
        self._conn = sqlite3.connect(
            self._path,
            timeout=max(1.0, busy_timeout_ms / 1000.0),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._configure(busy_timeout_ms)
        self._create_schema()
        self._verify_integrity()

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                self._conn.close()

    def enqueue(
        self,
        message: dict[str, Any],
        *,
        state: str = "pending",
        error: str = "",
    ) -> str:
        """Durably enqueue one canonical message and return its delivery ID."""
        return self.enqueue_many(
            [message],
            state=state,
            error=error,
        )[0]

    def enqueue_many(
        self,
        messages: list[dict[str, Any]],
        *,
        state: str = "pending",
        error: str = "",
    ) -> list[str]:
        """Atomically enqueue a batch so cursor commits cannot expose partial data."""
        if state not in {"pending", "dead"}:
            raise ValueError(f"unsupported outbox state: {state}")
        if not messages:
            return []

        prepared: list[tuple[str, str, bytes]] = []
        for message in messages:
            delivery_id = str(message.get("delivery_id") or new_delivery_id())
            canonical = dict(message)
            canonical["delivery_id"] = delivery_id
            section = str(canonical.get("section") or "unknown")
            try:
                plaintext = json.dumps(
                    canonical,
                    separators=(",", ":"),
                    sort_keys=True,
                    ensure_ascii=False,
                    default=str,
                ).encode("utf-8")
            except Exception as exc:
                raise OutboxError(
                    f"message cannot be serialized: {type(exc).__name__}"
                ) from exc
            prepared.append(
                (
                    delivery_id,
                    section,
                    self._protector.encrypt(delivery_id, plaintext),
                )
            )
        now = int(time.time())

        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                for delivery_id, section, protected in prepared:
                    self._conn.execute(
                        """
                        INSERT OR IGNORE INTO outbox(
                            delivery_id, section, protected_payload, created_at,
                            state, next_attempt_at, last_error
                        ) VALUES(?,?,?,?,?,?,?)
                        """,
                        (
                            delivery_id,
                            section,
                            sqlite3.Binary(protected),
                            now,
                            state,
                            0.0,
                            error[:512],
                        ),
                    )
                self._conn.execute("COMMIT")
            except Exception as exc:
                self._rollback_quietly()
                raise OutboxError(
                    f"durable enqueue failed: {type(exc).__name__}: {exc}"
                ) from exc
        return [entry[0] for entry in prepared]

    def next_due(self, now: float | None = None) -> OutboxItem | None:
        """Return the oldest retryable row due for transmission."""
        due = time.time() if now is None else now
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, delivery_id, section, protected_payload,
                       created_at, attempts
                FROM outbox
                WHERE state='pending' AND next_attempt_at <= ?
                ORDER BY id
                LIMIT 1
                """,
                (due,),
            ).fetchone()
            if row is None:
                return None

            delivery_id = str(row["delivery_id"])
            try:
                plaintext = self._protector.decrypt(
                    delivery_id, bytes(row["protected_payload"])
                )
                message = json.loads(plaintext.decode("utf-8"))
                if not isinstance(message, dict):
                    raise ValueError("message root is not an object")
            except Exception as exc:
                self._conn.execute(
                    """
                    UPDATE outbox
                    SET state='dead', last_error=?, last_attempt_at=?
                    WHERE id=?
                    """,
                    (
                        f"local_payload_corrupt:{type(exc).__name__}"[:512],
                        int(time.time()),
                        int(row["id"]),
                    ),
                )
                log.error(
                    "outbox row %s retained as dead letter: local payload corrupt",
                    delivery_id,
                )
                return None

            return OutboxItem(
                row_id=int(row["id"]),
                delivery_id=delivery_id,
                section=str(row["section"]),
                message=message,
                created_at=int(row["created_at"]),
                attempts=int(row["attempts"]),
            )

    def acknowledge(self, item: OutboxItem) -> None:
        """Delete a row only after confirmed manager acceptance."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM outbox WHERE id=? AND delivery_id=?",
                (item.row_id, item.delivery_id),
            )

    def retry(
        self,
        item: OutboxItem,
        *,
        delay_sec: float,
        error: str,
        status_code: int | None = None,
    ) -> None:
        """Schedule a retry without altering the protected message."""
        with self._lock:
            self._conn.execute(
                """
                UPDATE outbox
                SET attempts=attempts+1, next_attempt_at=?,
                    last_attempt_at=?, last_status=?, last_error=?
                WHERE id=?
                """,
                (
                    time.time() + max(0.0, delay_sec),
                    int(time.time()),
                    status_code,
                    error[:512],
                    item.row_id,
                ),
            )

    def retain_dead_letter(
        self,
        item: OutboxItem,
        *,
        error: str,
        status_code: int | None = None,
    ) -> None:
        """Retain a non-retryable message for diagnosis/manual replay."""
        with self._lock:
            self._conn.execute(
                """
                UPDATE outbox
                SET state='dead', attempts=attempts+1, last_attempt_at=?,
                    last_status=?, last_error=?
                WHERE id=?
                """,
                (
                    int(time.time()),
                    status_code,
                    error[:512],
                    item.row_id,
                ),
            )

    def retry_dead_letters(self) -> int:
        """Move all retained dead letters back to the pending queue."""
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE outbox
                SET state='pending', next_attempt_at=0, last_error=''
                WHERE state='dead'
                """
            )
            return max(0, int(cursor.rowcount))

    def seconds_until_next(self, default: float = 30.0) -> float:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT MIN(next_attempt_at) AS next_at
                FROM outbox WHERE state='pending'
                """
            ).fetchone()
        if row is None or row["next_at"] is None:
            return default
        return max(0.0, min(default, float(row["next_at"]) - time.time()))

    def stats(self) -> dict[str, Any]:
        with self._lock:
            grouped = {
                str(row["state"]): {
                    "count": int(row["count"]),
                    "bytes": int(row["bytes"] or 0),
                    "oldest_at": (
                        int(row["oldest_at"]) if row["oldest_at"] is not None
                        else None
                    ),
                }
                for row in self._conn.execute(
                    """
                    SELECT state, COUNT(*) AS count,
                           SUM(LENGTH(protected_payload)) AS bytes,
                           MIN(created_at) AS oldest_at
                    FROM outbox GROUP BY state
                    """
                )
            }
            attempts = self._conn.execute(
                "SELECT COALESCE(SUM(attempts), 0) AS total FROM outbox"
            ).fetchone()
        pending = grouped.get("pending", {"count": 0, "bytes": 0, "oldest_at": None})
        dead = grouped.get("dead", {"count": 0, "bytes": 0, "oldest_at": None})
        oldest = pending["oldest_at"]
        return {
            "pending": pending["count"],
            "dead_letters": dead["count"],
            "bytes": pending["bytes"] + dead["bytes"],
            "oldest_age_sec": (
                max(0, int(time.time()) - int(oldest)) if oldest else 0
            ),
            "attempts": int(attempts["total"] if attempts else 0),
            "db": str(self._path),
        }

    def integrity_check(self) -> str:
        with self._lock:
            row = self._conn.execute("PRAGMA quick_check").fetchone()
        return str(row[0]) if row else "unknown"

    def _configure(self, busy_timeout_ms: int) -> None:
        with self._lock:
            self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA temp_store=MEMORY")
            self._conn.execute("PRAGMA foreign_keys=ON")

    def _create_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS outbox(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    delivery_id TEXT NOT NULL UNIQUE,
                    section TEXT NOT NULL,
                    protected_payload BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'pending'
                        CHECK(state IN ('pending', 'dead')),
                    last_attempt_at INTEGER,
                    last_status INTEGER,
                    last_error TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_outbox_due
                    ON outbox(state, next_attempt_at, id);
                CREATE TABLE IF NOT EXISTS outbox_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self._conn.execute(
                """
                INSERT INTO outbox_meta(key, value) VALUES('schema_version', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (str(_SCHEMA_VERSION),),
            )

    def _verify_integrity(self) -> None:
        result = self.integrity_check()
        if result.lower() != "ok":
            raise OutboxCorruptionError(
                f"delivery outbox database integrity check failed: {result}"
            )

    def _rollback_quietly(self) -> None:
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
