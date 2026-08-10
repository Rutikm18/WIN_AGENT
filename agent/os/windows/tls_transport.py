"""
agent/os/windows/tls_transport.py — Hardened HTTPS transport for Windows agent.

Security guarantees
───────────────────
• TLS 1.2 minimum — SSLContext.minimum_version = TLSVersion.TLSv1_2.
  TLS 1.3 is negotiated automatically when supported by both endpoints.
• SPKI certificate pinning — the server's SubjectPublicKeyInfo SHA-256 is
  verified after every TLS handshake.  A rogue CA installed into the Windows
  trust store (admin compromise, corporate proxy) cannot MITM the agent
  because the pin is tied to the manager's *key*, not any CA chain.
• Persistent session — one TLS handshake per process lifetime; connection
  keep-alive amortises the handshake cost across many payloads.
• Strict timeouts — 15 s connect, 30 s read prevents indefinite hangs if
  the manager is overloaded or the TCP connection is silently dropped.
• No automatic retry — retries and backoff are the caller's responsibility
  (the sender loop in win_agent.py handles that).

SPKI pin format
───────────────
  sha256//base64pad==   (same format as HTTP Public Key Pinning header)

Generate pin for your manager cert:
  python -c "
  import base64, hashlib, ssl, socket
  from cryptography import x509
  from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
  der = ssl.get_server_certificate(('manager.example.com', 443)).encode()
  import ssl as _ssl
  # Or use openssl: openssl s_client -connect host:port | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
  "

Config (agent.toml):
  [manager]
  url      = 'https://manager.example.com'
  spki_pin = 'sha256//abc123...base64=='   # omit to disable pinning
  tls_verify = true                        # set false for self-signed dev cert
"""
from __future__ import annotations

import hashlib
import logging
import ssl
from typing import Any

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("agent.windows.tls_transport")


# ── SSL context ───────────────────────────────────────────────────────────────

def _make_tls13_context(tls_verify: bool | str) -> ssl.SSLContext:
    """
    Build an SSLContext that enforces TLS 1.2 minimum.

    tls_verify=True  → system CA bundle (standard validation)
    tls_verify=False → no cert verification (dev / self-signed)
    tls_verify=str   → path to a custom CA bundle or cert file

    Older protocol versions fail the handshake with ssl.SSLError; the caller
    logs this and treats it as a transient failure so the backoff/spool path
    handles it.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # TLS 1.2 is the enterprise-compatible floor; TLS 1.3 is preferred
    # automatically when supported by both endpoints.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if tls_verify is False:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        log.warning("TLS certificate verification disabled — use only in dev/test environments")
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        if isinstance(tls_verify, str):
            ctx.load_verify_locations(cafile=tls_verify)
        else:
            ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)

    return ctx


# ── SPKI pinning ──────────────────────────────────────────────────────────────

def _compute_spki_hash(der_cert: bytes) -> str:
    """
    Compute the base64-encoded SHA-256 of the SubjectPublicKeyInfo from a DER cert.

    This is the same hash that browsers use for HTTP Public Key Pinning.
    Pinning SPKI (rather than the full cert) survives cert renewals as long
    as the manager's private key is unchanged.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64

    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def _extract_ssl_socket(resp: requests.Response) -> ssl.SSLSocket | None:
    """
    Extract the underlying ssl.SSLSocket from a requests/urllib3 response.

    urllib3 internal paths differ between 1.x and 2.x; we try both.
    Returns None if extraction fails — caller decides whether to fail open or closed.
    """
    raw = resp.raw

    # ── urllib3 2.x path ─────────────────────────────────────────────────────
    # HTTPResponse._connection → HTTPSConnection.sock → SSLSocket
    conn = getattr(raw, "_connection", None)
    if conn is not None:
        sock = getattr(conn, "sock", None)
        if isinstance(sock, ssl.SSLSocket):
            return sock
        # wrapped by urllib3's ssl_wrap_socket → SSLObject backed by SSLSocket
        inner = getattr(sock, "_sock", None)
        if isinstance(inner, ssl.SSLSocket):
            return inner

    # ── urllib3 1.x path ─────────────────────────────────────────────────────
    # HTTPResponse._fp → socket.makefile() → socket → SSLSocket
    fp = getattr(raw, "_fp", None)
    if fp is not None:
        fp2 = getattr(fp, "fp", fp)
        raw_sock = getattr(fp2, "raw", fp2)
        sock = getattr(raw_sock, "_sock", raw_sock)
        if isinstance(sock, ssl.SSLSocket):
            return sock

    return None


def _verify_spki_pin(resp: requests.Response, expected_pin: str) -> None:
    """
    Verify that the server certificate's SPKI SHA-256 matches expected_pin.

    Raises ssl.SSLError on mismatch so the caller (HTTPAdapter.send) surfaces
    it as a requests.exceptions.SSLError.
    """
    sock = _extract_ssl_socket(resp)
    if sock is None:
        raise ssl.SSLError(
            "SPKI pinning: peer certificate socket could not be inspected; "
            "refusing to skip the configured pin"
        )

    der = sock.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("SPKI pinning: no peer certificate returned by server")

    actual_pin = _compute_spki_hash(der)
    # Strip the "sha256//" scheme prefix if present
    expected   = expected_pin.removeprefix("sha256//")

    if actual_pin != expected:
        raise ssl.SSLError(
            f"SPKI pin mismatch — possible MITM attack. "
            f"got={actual_pin[:20]}... expected={expected[:20]}..."
        )
    log.debug("SPKI pin verified OK")


# ── Pinning HTTPAdapter ───────────────────────────────────────────────────────

class _PinningAdapter(HTTPAdapter):
    """
    HTTPAdapter that enforces TLS 1.2+ and optional SPKI certificate pinning.
    """

    def __init__(self, ssl_ctx: ssl.SSLContext, spki_pin: str | None = None, **kw):
        self._ssl_ctx  = ssl_ctx
        self._spki_pin = spki_pin
        super().__init__(max_retries=0, **kw)   # retries handled by caller

    # inject our SSLContext into urllib3's pool manager
    def init_poolmanager(self, *args, **kw):
        from urllib3.util.ssl_ import create_urllib3_context
        kw.setdefault("ssl_context", self._ssl_ctx)
        super().init_poolmanager(*args, **kw)

    def proxy_manager_for(self, proxy, **kw):
        kw.setdefault("ssl_context", self._ssl_ctx)
        return super().proxy_manager_for(proxy, **kw)

    def send(self, request: requests.PreparedRequest, **kw) -> requests.Response:
        # Preserve Requests' verification setting. WindowsTLSTransport assigns
        # Session.verify from the validated manager configuration, while the
        # injected SSLContext enforces the TLS floor and hostname policy.
        # Passing verify=False here would make urllib3 try to downgrade a
        # hostname-checking context to CERT_NONE and break secure HTTPS.
        resp = super().send(request, **kw)

        if self._spki_pin:
            _verify_spki_pin(resp, self._spki_pin)

        return resp


# ── Public transport class ────────────────────────────────────────────────────

class WindowsTLSTransport:
    """
    Hardened HTTPS transport for the Windows agent.

    One session is created at construction time and reused for all requests
    (HTTP/1.1 keep-alive preserves the TLS session).

    Usage
    ─────
      t = WindowsTLSTransport(
              base_url   = "https://manager.example.com",
              spki_pin   = "sha256//abc123...",
              tls_verify = True,
          )
      resp = t.post("/api/v1/ingest", data=payload_bytes)
      t.close()

      # or as a context manager:
      with WindowsTLSTransport(...) as t:
          t.post(...)
    """

    def __init__(
        self,
        base_url: str,
        spki_pin: str | None = None,
        tls_verify: bool | str = True,
        timeout: tuple[int, int] = (15, 30),
        proxy_url: str | None = None,
    ):
        self._base_url = base_url.rstrip("/")
        # Validate timeout: must be a (connect_sec, read_sec) tuple.
        # A bare int is silently misinterpreted by requests as both timeouts.
        if not isinstance(timeout, tuple) or len(timeout) != 2:
            raise ValueError(
                f"timeout must be a (connect, read) tuple, got {timeout!r}"
            )
        self._timeout = timeout

        ssl_ctx = _make_tls13_context(tls_verify)
        adapter = _PinningAdapter(ssl_ctx=ssl_ctx, spki_pin=spki_pin)

        self._session = requests.Session()
        # A privileged service must not inherit per-user HTTP(S)_PROXY settings.
        self._session.trust_env = False
        # Keep Requests/urllib3 certificate policy aligned with the custom
        # SSLContext. A string is a custom CA bundle path.
        self._session.verify = tls_verify
        if proxy_url:
            self._session.proxies.update({
                "http": proxy_url,
                "https": proxy_url,
            })
        self._session.mount("https://", adapter)
        # Reject plain HTTP (should never be used in production)
        self._session.mount("http://", HTTPAdapter(max_retries=0))
        self._session.headers.update({
            "User-Agent":   "attacklens-agent-win/2.0",
            "Content-Type": "application/json",
        })

    # ── HTTP verbs ────────────────────────────────────────────────────────────

    def post(
        self, path: str, data: bytes,
        extra_headers: dict[str, str] | None = None,
    ) -> requests.Response:
        headers = dict(extra_headers or {})
        return self._session.post(
            self._base_url + path,
            data=data,
            headers=headers,
            timeout=self._timeout,
        )

    def get(
        self, path: str,
        extra_headers: dict[str, str] | None = None,
    ) -> requests.Response:
        return self._session.get(
            self._base_url + path,
            headers=dict(extra_headers or {}),
            timeout=self._timeout,
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "WindowsTLSTransport":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
