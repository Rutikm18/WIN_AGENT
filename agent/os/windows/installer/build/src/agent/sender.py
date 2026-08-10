"""
agent/sender.py — Encrypted HTTPS sender with resilient delivery.

Features:
  - Exponential backoff with jitter on transient failures
  - Disk spool: failed payloads written to disk, replayed on reconnect
  - Connectivity probe: fast manager reachability check before send
  - Auto-drain: spool flushed when manager comes back online
  - TLS 1.3 minimum
"""

import json
import logging
import os
import queue
import random
import ssl
import threading
import time
import urllib.request
import urllib.error

log = logging.getLogger("agent.sender")

# How many bytes the spool file may grow to before we drop oldest lines (~50 MB)
_SPOOL_MAX_BYTES = 50 * 1024 * 1024
# How often (seconds) to retry spool when manager is unreachable
_SPOOL_RETRY_INTERVAL = 30
# Connectivity probe timeout (seconds)
_PROBE_TIMEOUT = 5


class DiskSpool:
    """
    Append-only NDJSON spool file.  Thread-safe (one writer thread at a time).
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, envelope: dict) -> None:
        """Append one envelope to the spool."""
        line = json.dumps(envelope, separators=(",", ":")) + "\n"
        with self._lock:
            # Trim spool if too large (drop first ~10 % of lines = oldest)
            try:
                if os.path.getsize(self.path) > _SPOOL_MAX_BYTES:
                    self._trim()
            except FileNotFoundError:
                pass
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)

    def drain(self) -> list[dict]:
        """Read and clear all spooled envelopes.  Returns list of dicts."""
        with self._lock:
            try:
                with open(self.path, encoding="utf-8") as f:
                    lines = f.readlines()
                os.remove(self.path)
            except FileNotFoundError:
                return []
        out = []
        for l in lines:
            l = l.strip()
            if not l:
                continue
            try:
                out.append(json.loads(l))
            except json.JSONDecodeError:
                pass
        return out

    def size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except FileNotFoundError:
            return 0

    def _trim(self) -> None:
        """Drop the first 10 % of lines to make room (holding lock)."""
        try:
            with open(self.path, encoding="utf-8") as f:
                lines = f.readlines()
            drop = max(1, len(lines) // 10)
            with open(self.path, "w", encoding="utf-8") as f:
                f.writelines(lines[drop:])
            log.warning("Spool trimmed: dropped %d oldest entries (was %d lines)",
                        drop, len(lines))
        except Exception as exc:
            log.error("Spool trim failed: %s", exc)


class Sender:
    def __init__(self, config: dict, send_queue: queue.Queue):
        self.mgr        = config["manager"]
        self.url        = self.mgr["url"].rstrip("/") + "/api/v1/ingest"
        self.probe_url  = self.mgr["url"].rstrip("/") + "/health"
        self.timeout    = self.mgr.get("timeout_sec", 30)
        self.max_retry  = self.mgr.get("retry_attempts", 3)
        self.retry_del  = self.mgr.get("retry_delay_sec", 5)
        self.tls_verify = self.mgr.get("tls_verify", True)
        self.queue      = send_queue
        self._stop      = threading.Event()
        self._ctx       = self._build_ssl_ctx()
        self._online    = False   # tracks last known manager state

        # Disk spool — persists payloads when manager is unreachable.
        # NOTE: never derive this from __file__; PyInstaller bundles the module
        # inside a temp directory whose path changes between runs.
        import sys as _sys
        if _sys.platform == "darwin":
            _default_spool = "/Library/Jarvis/spool"
        elif _sys.platform == "win32":
            _default_spool = r"C:\Program Files (x86)\Jarvis\spool"
        else:
            _default_spool = "/var/lib/jarvis/spool"
        spool_dir = config.get("paths", {}).get("spool_dir", _default_spool)
        self._spool = DiskSpool(os.path.join(spool_dir, "unsent.ndjson"))

    # ── SSL ───────────────────────────────────────────────────────────────────

    def _build_ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            log.warning("TLS verification disabled — dev/self-signed cert mode")
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs()
        return ctx

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> threading.Thread:
        self._stop.clear()
        # Drain any spool from previous run immediately
        spooled = self._spool.drain()
        if spooled:
            log.info("Replaying %d spooled envelopes from previous run", len(spooled))
            for env in spooled:
                self.queue.put_nowait(env)

        t = threading.Thread(target=self._drain_loop, daemon=True, name="sender")
        t.start()
        return t

    def stop(self):
        self._stop.set()

    # ── Connectivity probe ────────────────────────────────────────────────────

    def _probe(self) -> bool:
        """Quick HEAD/GET to /health to check manager reachability."""
        try:
            req = urllib.request.Request(self.probe_url, method="GET")
            with urllib.request.urlopen(req, context=self._ctx,
                                        timeout=_PROBE_TIMEOUT):
                return True
        except Exception:
            return False

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _drain_loop(self):
        spool_check = 0.0
        while not self._stop.is_set():
            # Periodically retry spool when we know we're offline
            now = time.time()
            if not self._online and (now - spool_check) >= _SPOOL_RETRY_INTERVAL:
                spool_check = now
                if self._probe():
                    log.info("Manager back online — draining spool")
                    self._online = True
                    spooled = self._spool.drain()
                    for env in spooled:
                        self.queue.put_nowait(env)
                else:
                    log.debug("Manager still unreachable — spool has %d bytes",
                              self._spool.size())

            try:
                envelope = self.queue.get(timeout=1)
            except queue.Empty:
                continue

            success = self._send_with_retry(envelope)
            if not success:
                log.warning("Spooling %s to disk", envelope.get("section"))
                self._spool.write(envelope)
                self._online = False

    # ── Send with retry ───────────────────────────────────────────────────────

    def _send_with_retry(self, envelope: dict) -> bool:
        """
        Try to POST envelope to manager.
        Returns True on success, False if all attempts failed.
        4xx client errors are dropped (not retried, not spooled).
        """
        body  = json.dumps(envelope).encode()
        delay = self.retry_del

        for attempt in range(1, self.max_retry + 1):
            try:
                req = urllib.request.Request(
                    self.url,
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Agent-ID":   envelope.get("agent_id", ""),
                        "X-Section":    envelope.get("section", ""),
                        "User-Agent":   "mac_intel-agent/1.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, context=self._ctx,
                                            timeout=self.timeout) as resp:
                    if resp.status == 200:
                        if not self._online:
                            log.info("Manager connection restored")
                        self._online = True
                        log.debug("Sent %s → 200", envelope.get("section"))
                        return True
                    elif 400 <= resp.status < 500:
                        # Client error — bad payload, not a connectivity issue
                        log.error("Manager rejected (HTTP %d) section=%s — dropping",
                                  resp.status, envelope.get("section"))
                        return True   # "handled" — don't spool
                    else:
                        log.warning("Manager HTTP %d (attempt %d/%d)",
                                    resp.status, attempt, self.max_retry)

            except urllib.error.HTTPError as exc:
                if 400 <= exc.code < 500:
                    log.error("Manager rejected (HTTP %d) section=%s — dropping",
                              exc.code, envelope.get("section"))
                    return True
                log.warning("HTTP error %d (attempt %d/%d): %s",
                            exc.code, attempt, self.max_retry, exc)
            except Exception as exc:
                log.warning("Send failed (attempt %d/%d): %s",
                            attempt, self.max_retry, exc)

            if attempt < self.max_retry:
                jitter = random.uniform(0, delay * 0.3)
                time.sleep(min(delay + jitter, 60))
                delay *= 2

        return False   # all retries exhausted — caller will spool to disk
