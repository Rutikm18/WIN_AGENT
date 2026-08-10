"""Broader release-candidate tests for Windows-agent boundary behavior."""
from __future__ import annotations

import copy
import base64
import datetime
import json
import ssl
import re
import sqlite3
import tempfile
import threading
import time
import unittest
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from urllib3.exceptions import InsecureRequestWarning

from agent.agent.crypto import derive_keys
from agent.os.windows.collectors.eventlog import (
    _classify_eventlog_error,
    _parse_event_xml,
)
from agent.os.windows.config_model import (
    ConfigValidationError,
    load_config_dict,
)
from agent.os.windows.diagnostics import connectivity_test
from agent.os.windows.integrity import (
    IntegrityError,
    create_manifest,
    verify_manifest,
    write_manifest_atomic,
)
from agent.os.windows.normalizer import _NORMALIZERS, normalize
from agent.os.windows.reliable_outbox import ReliableOutbox
from agent.os.windows.sca.engine import _apply_matcher, _numeric_compare
from agent.os.windows.tls_transport import (
    WindowsTLSTransport,
    _compute_spki_hash,
    _make_tls13_context,
)
from agent.os.windows.win_agent import WindowsAgent


def _valid_config() -> dict:
    return {
        "agent": {"id": "qa-agent", "name": "QA Agent"},
        "manager": {
            "url": "https://manager.example",
            "tls_verify": True,
        },
        "enrollment": {"token": ""},
        "paths": {
            "config_dir": "C:/ProgramData/AttackLens/config",
            "security_dir": "C:/ProgramData/AttackLens/security",
            "log_dir": "C:/ProgramData/AttackLens/logs",
            "spool_dir": "C:/ProgramData/AttackLens/spool",
            "data_dir": "C:/ProgramData/AttackLens/data",
        },
        "logging": {"level": "INFO", "max_mb": 10, "backups": 5},
        "collection": {
            "sections": {
                "metrics": {"enabled": True, "interval_sec": 60},
            },
        },
        "transport": {},
    }


class ConfigurationQATests(unittest.TestCase):
    def test_http_manager_defaults_are_explicitly_enabled(self) -> None:
        cfg = _valid_config()
        cfg["manager"] = {"url": "http://manager.example:8080"}
        manager = load_config_dict(cfg).to_dict()["manager"]
        self.assertIs(manager["tls_verify"], False)
        self.assertIs(manager["allow_insecure_transport"], True)

    def test_valid_configuration_round_trips(self) -> None:
        result = load_config_dict(_valid_config()).to_dict()
        self.assertEqual(result["manager"]["url"], "https://manager.example")
        self.assertEqual(
            result["collection"]["sections"]["metrics"]["interval_sec"],
            60,
        )

    def test_invalid_configuration_matrix_is_rejected(self) -> None:
        cases = [
            (
                "missing agent id",
                lambda cfg: cfg["agent"].__setitem__("id", ""),
                "[agent] id is required",
            ),
            (
                "invalid agent id",
                lambda cfg: cfg["agent"].__setitem__("id", "bad id"),
                "unsupported characters",
            ),
            (
                "unsupported manager scheme",
                lambda cfg: cfg["manager"].__setitem__(
                    "url", "ftp://127.0.0.1"
                ),
                "must use http:// or https://",
            ),
            (
                "URL credentials",
                lambda cfg: cfg["manager"].__setitem__(
                    "url", "https://user:pass@example.test"
                ),
                "must not contain username",
            ),
            (
                "quoted TLS boolean",
                lambda cfg: cfg["manager"].__setitem__(
                    "tls_verify", "false"
                ),
                "not a quoted string",
            ),
            (
                "CA with disabled verification",
                lambda cfg: cfg["manager"].update({
                    "tls_verify": False,
                    "ca_bundle": "C:/ca.pem",
                }),
                "cannot be combined",
            ),
            (
                "bad SPKI pin",
                lambda cfg: cfg["manager"].__setitem__("spki_pin", "bad"),
                "sha256//",
            ),
            (
                "bad API key",
                lambda cfg: cfg["manager"].__setitem__("api_key", "1234"),
                "64-character hexadecimal",
            ),
            (
                "relative path",
                lambda cfg: cfg["paths"].__setitem__(
                    "spool_dir", "relative/spool"
                ),
                "absolute Windows path",
            ),
            (
                "unknown collector",
                lambda cfg: cfg["collection"]["sections"].__setitem__(
                    "bogus", {}
                ),
                "not a supported Windows collector",
            ),
            (
                "invalid interval",
                lambda cfg: cfg["collection"]["sections"]["metrics"].__setitem__(
                    "interval_sec", 0
                ),
                "between 1 and 604800",
            ),
            (
                "backoff inversion",
                lambda cfg: cfg["transport"].update({
                    "initial_backoff_sec": 60,
                    "max_backoff_sec": 5,
                }),
                "greater than or equal",
            ),
            (
                "unsafe automatic reenrollment",
                lambda cfg: cfg["transport"].__setitem__(
                    "auto_reenroll", True
                ),
                "requires a non-empty",
            ),
            (
                "unsupported transport key",
                lambda cfg: cfg["transport"].__setitem__("mystery", 1),
                "unsupported key",
            ),
            (
                "unsupported proxy",
                lambda cfg: cfg["manager"].__setitem__(
                    "proxy_url", "socks5://proxy"
                ),
                "must use http:// or https://",
            ),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                cfg = copy.deepcopy(_valid_config())
                mutate(cfg)
                with self.assertRaisesRegex(
                    ConfigValidationError,
                    re.escape(expected),
                ):
                    load_config_dict(cfg)

    def test_connectivity_failures_always_include_top_level_ok(self) -> None:
        cfg = load_config_dict(_valid_config()).to_dict()
        with mock.patch(
            "agent.os.windows.diagnostics.socket.getaddrinfo",
            side_effect=OSError("dns unavailable"),
        ):
            dns_failure = connectivity_test(cfg)
        self.assertIs(dns_failure["ok"], False)
        self.assertIs(dns_failure["dns"]["ok"], False)

        with (
            mock.patch(
                "agent.os.windows.diagnostics.socket.getaddrinfo",
                return_value=[(None, None, None, None, ("127.0.0.1", 443))],
            ),
            mock.patch(
                "agent.os.windows.diagnostics.socket.create_connection",
                side_effect=OSError("tcp unavailable"),
            ),
        ):
            tcp_failure = connectivity_test(cfg)
        self.assertIs(tcp_failure["ok"], False)
        self.assertIs(tcp_failure["dns"]["ok"], True)
        self.assertIs(tcp_failure["tcp"]["ok"], False)


class NormalizationQATests(unittest.TestCase):
    def test_every_normalizer_tolerates_wrong_root_types(self) -> None:
        for section in _NORMALIZERS:
            for malformed in (None, 7, "bad", object()):
                with self.subTest(section=section, value=type(malformed).__name__):
                    normalize(section, malformed)

    def test_process_normalization_filters_invalid_rows_and_coerces_types(
        self,
    ) -> None:
        result = normalize(
            "processes",
            [
                None,
                {
                    "pid": "42",
                    "ppid": "7",
                    "name": "proc.exe",
                    "cpu_pct": "1.5",
                    "mem_pct": "2.25",
                    "cmdline": "proc.exe --safe",
                },
            ],
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["pid"], 42)
        self.assertEqual(result[0]["ppid"], 7)
        self.assertEqual(result[0]["cpu_pct"], 1.5)

    def test_eventlog_normalization_drops_invalid_records(self) -> None:
        result = normalize(
            "eventlog",
            [
                {},
                "invalid",
                {
                    "event_id": "4688",
                    "channel": "Security",
                    "detail": {"NewProcessName": "C:/test.exe"},
                },
            ],
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["event_id"], 4688)


class EventLogQATests(unittest.TestCase):
    def test_security_process_xml_produces_canonical_entity(self) -> None:
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>4688</EventID><EventRecordID>99</EventRecordID>
            <TimeCreated SystemTime="2026-07-27T01:02:03.1234567Z"/>
            <Computer>qa-host</Computer>
          </System>
          <EventData>
            <Data Name="NewProcessId">0x2a</Data>
            <Data Name="NewProcessName">C:\\Windows\\test.exe</Data>
            <Data Name="ParentProcessName">C:\\Windows\\parent.exe</Data>
            <Data Name="CommandLine">test.exe --safe</Data>
            <Data Name="SubjectUserName">qa-user</Data>
          </EventData>
        </Event>"""
        record = _parse_event_xml(xml, "Security")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["record_id"], 99)
        self.assertEqual(record["entity"]["kind"], "process")
        self.assertEqual(record["entity"]["pid"], 42)
        self.assertEqual(record["entity"]["user"], "qa-user")

    def test_generic_event_fields_exclude_secret_named_values(self) -> None:
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="QA"/><EventID>9999</EventID>
            <EventRecordID>1</EventRecordID><Computer>qa</Computer></System>
          <EventData>
            <Data Name="SafeField">visible</Data>
            <Data Name="AccessToken">must-not-ship</Data>
            <Data Name="PasswordValue">must-not-ship</Data>
          </EventData>
        </Event>"""
        record = _parse_event_xml(xml, "Application")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["detail"], {"SafeField": "visible"})

    def test_eventlog_error_codes_are_stable(self) -> None:
        for code, expected in (
            (5, "access_denied"),
            (15007, "channel_unavailable"),
            (15011, "query_result_stale"),
        ):
            exc = OSError(code, "qa")
            exc.winerror = code
            self.assertEqual(_classify_eventlog_error(exc), expected)


class IntegrityQATests(unittest.TestCase):
    def test_manifest_creation_rejects_root_escape(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            outside = Path(root).parent / "outside.bin"
            outside.write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "escapes package root"):
                create_manifest(root, ["../outside.bin"])
            outside.unlink(missing_ok=True)

    def test_atomic_manifest_round_trip_and_schema_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            payload = base / "bin" / "agent.exe"
            payload.parent.mkdir()
            payload.write_bytes(b"qa-payload")
            manifest = create_manifest(base, ["bin/agent.exe"])
            manifest_path = base / "install-manifest.json"
            write_manifest_atomic(manifest_path, manifest)
            self.assertEqual(
                verify_manifest(manifest_path, base)["checked_files"],
                1,
            )
            malformed = json.loads(manifest_path.read_text(encoding="utf-8"))
            malformed["schema"] = 999
            manifest_path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaisesRegex(IntegrityError, "unsupported"):
                verify_manifest(manifest_path, base)


class OutboxQATests(unittest.TestCase):
    def _new_outbox(self, root: str) -> ReliableOutbox:
        patcher = mock.patch(
            "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        outbox = ReliableOutbox(
            str(Path(root) / "spool"),
            str(Path(root) / "security"),
            "qa-agent",
        )
        return outbox

    def test_concurrent_enqueues_do_not_lose_rows(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            outbox = self._new_outbox(root)
            try:
                failures: list[Exception] = []

                def writer(worker: int) -> None:
                    try:
                        for item in range(25):
                            outbox.enqueue({
                                "delivery_id": f"{worker:02d}-{item:02d}",
                                "section": "metrics",
                                "payload": {"worker": worker, "item": item},
                            })
                    except Exception as exc:  # pragma: no cover - assertion path
                        failures.append(exc)

                threads = [
                    threading.Thread(target=writer, args=(worker,))
                    for worker in range(6)
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)
                self.assertFalse(failures)
                self.assertTrue(
                    all(not thread.is_alive() for thread in threads)
                )
                self.assertEqual(outbox.stats()["pending"], 150)
                self.assertEqual(outbox.integrity_check().lower(), "ok")
            finally:
                outbox.close()

    def test_duplicate_delivery_id_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            outbox = self._new_outbox(root)
            try:
                message = {
                    "delivery_id": "stable-id",
                    "section": "metrics",
                    "payload": {"value": 1},
                }
                outbox.enqueue(message)
                outbox.enqueue(message)
                self.assertEqual(outbox.stats()["pending"], 1)
            finally:
                outbox.close()

    def test_corrupt_payload_is_retained_as_dead_letter(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            outbox = self._new_outbox(root)
            try:
                outbox.enqueue({
                    "delivery_id": "corrupt-me",
                    "section": "metrics",
                    "payload": {"marker": "plaintext-marker"},
                })
                connection = sqlite3.connect(outbox.path)
                try:
                    protected = connection.execute(
                        "SELECT protected_payload FROM outbox"
                    ).fetchone()[0]
                    self.assertNotIn(b"plaintext-marker", bytes(protected))
                    connection.execute(
                        "UPDATE outbox SET protected_payload=?",
                        (sqlite3.Binary(b"truncated"),),
                    )
                    connection.commit()
                finally:
                    connection.close()
                self.assertIsNone(outbox.next_due())
                self.assertEqual(outbox.stats()["dead_letters"], 1)
            finally:
                outbox.close()

    def test_retry_delay_and_attempt_counter(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            outbox = self._new_outbox(root)
            try:
                outbox.enqueue({
                    "delivery_id": "retry-me",
                    "section": "metrics",
                    "payload": {},
                })
                item = outbox.next_due()
                self.assertIsNotNone(item)
                assert item is not None
                outbox.retry(
                    item,
                    delay_sec=60,
                    error="temporary",
                    status_code=503,
                )
                self.assertIsNone(outbox.next_due(now=time.time()))
                self.assertEqual(outbox.stats()["attempts"], 1)
                self.assertGreater(outbox.seconds_until_next(), 0)
            finally:
                outbox.close()

    def test_legacy_spool_migrates_without_losing_collection_time(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = load_config_dict(_valid_config()).to_dict()
            cfg["paths"] = {
                key: str(Path(root) / key)
                for key in (
                    "config_dir",
                    "security_dir",
                    "log_dir",
                    "spool_dir",
                    "data_dir",
                )
            }
            agent = WindowsAgent(cfg)
            agent._enc_key, agent._mac_key = derive_keys("b" * 64)
            agent._agent_number = "qa-001"
            outbox = self._new_outbox(root)
            agent._outbox = outbox
            legacy = Path(cfg["paths"]["spool_dir"]) / "win_agent.spool.ndjson"
            legacy.parent.mkdir(parents=True, exist_ok=True)
            original = agent._new_message(
                "metrics",
                {"sample": 1},
                collected_at=123456,
            )
            legacy.write_text(
                base64.b64encode(
                    agent._wire_for_message(original)
                ).decode("ascii") + "\n",
                encoding="ascii",
            )
            try:
                agent._migrate_legacy_spool()
                self.assertFalse(legacy.exists())
                self.assertEqual(outbox.stats()["pending"], 1)
                item = outbox.next_due()
                self.assertIsNotNone(item)
                assert item is not None
                self.assertEqual(item.message["collected_at"], 123456)
                self.assertTrue(
                    item.message["delivery_id"].startswith("legacy-")
                )
                preserved = list(
                    legacy.parent.glob("win_agent.spool.ndjson.migrated-*")
                )
                self.assertEqual(len(preserved), 1)
            finally:
                outbox.close()

    def test_bad_legacy_spool_is_retained_for_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = load_config_dict(_valid_config()).to_dict()
            cfg["paths"] = {
                key: str(Path(root) / key)
                for key in (
                    "config_dir",
                    "security_dir",
                    "log_dir",
                    "spool_dir",
                    "data_dir",
                )
            }
            agent = WindowsAgent(cfg)
            agent._enc_key, agent._mac_key = derive_keys("c" * 64)
            outbox = self._new_outbox(root)
            agent._outbox = outbox
            legacy = Path(cfg["paths"]["spool_dir"]) / "win_agent.spool.ndjson"
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text("not-valid-base64\n", encoding="ascii")
            try:
                agent._migrate_legacy_spool()
                self.assertTrue(legacy.exists())
                self.assertEqual(outbox.stats()["pending"], 0)
            finally:
                outbox.close()


class TransportAndScaQATests(unittest.TestCase):
    def test_self_signed_server_is_rejected_when_verification_is_enabled(
        self,
    ) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def log_message(self, *_: object) -> None:
                return

        with tempfile.TemporaryDirectory() as root:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("localhost"),
                    ]),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(key, hashes.SHA256())
            )
            cert_path = Path(root) / "cert.pem"
            key_path = Path(root) / "key.pem"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
            server.socket = server_context.wrap_socket(
                server.socket,
                server_side=True,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            transport = WindowsTLSTransport(
                f"https://127.0.0.1:{server.server_port}",
                tls_verify=True,
                timeout=(2, 2),
            )
            try:
                with self.assertRaises(requests.exceptions.SSLError):
                    transport.get("/")
            finally:
                transport.close()

            trusted = WindowsTLSTransport(
                f"https://localhost:{server.server_port}",
                tls_verify=str(cert_path),
                timeout=(2, 2),
            )
            try:
                self.assertEqual(trusted.get("/").status_code, 200)
            finally:
                trusted.close()

            hostname_mismatch = WindowsTLSTransport(
                f"https://127.0.0.1:{server.server_port}",
                tls_verify=str(cert_path),
                timeout=(2, 2),
            )
            try:
                with self.assertRaises(requests.exceptions.SSLError):
                    hostname_mismatch.get("/")
            finally:
                hostname_mismatch.close()

            pin = _compute_spki_hash(
                cert.public_bytes(serialization.Encoding.DER)
            )
            pinned = WindowsTLSTransport(
                f"https://localhost:{server.server_port}",
                tls_verify=str(cert_path),
                spki_pin=f"sha256//{pin}",
                timeout=(2, 2),
            )
            try:
                self.assertEqual(pinned.get("/").status_code, 200)
            finally:
                pinned.close()

            wrong_pin = WindowsTLSTransport(
                f"https://localhost:{server.server_port}",
                tls_verify=str(cert_path),
                spki_pin="sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                timeout=(2, 2),
            )
            try:
                with self.assertRaises(ssl.SSLError):
                    wrong_pin.get("/")
            finally:
                wrong_pin.close()

            explicitly_insecure = WindowsTLSTransport(
                f"https://127.0.0.1:{server.server_port}",
                tls_verify=False,
                timeout=(2, 2),
            )
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                    self.assertEqual(
                        explicitly_insecure.get("/").status_code,
                        200,
                    )
            finally:
                explicitly_insecure.close()

            try:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            except Exception:
                server.server_close()
                raise

    def test_transport_rejects_ambiguous_timeout_and_ignores_environment_proxy(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "timeout must be"):
            WindowsTLSTransport("https://manager.example", timeout=30)  # type: ignore[arg-type]
        transport = WindowsTLSTransport(
            "https://manager.example/",
            tls_verify=False,
            proxy_url="http://proxy.example:8080",
        )
        self.addCleanup(transport.close)
        self.assertFalse(transport._session.trust_env)
        self.assertEqual(
            transport._session.proxies["https"],
            "http://proxy.example:8080",
        )
        self.assertEqual(transport._base_url, "https://manager.example")

    def test_tls_context_has_secure_floor_and_hostname_policy(self) -> None:
        import ssl

        secure = _make_tls13_context(True)
        self.assertGreaterEqual(
            secure.minimum_version,
            ssl.TLSVersion.TLSv1_2,
        )
        self.assertTrue(secure.check_hostname)
        insecure = _make_tls13_context(False)
        self.assertFalse(insecure.check_hostname)
        self.assertEqual(insecure.verify_mode, ssl.CERT_NONE)

    def test_sca_regex_numeric_and_invalid_matchers(self) -> None:
        self.assertTrue(_apply_matcher(r"r:enabled\s*=\s*true", "Enabled = TRUE"))
        self.assertTrue(_apply_matcher(r"n:value=(\d+) compare >= 10", "value=12"))
        self.assertIsNone(_apply_matcher("r:[", "anything"))
        self.assertTrue(_numeric_compare(10, ">=", 10))
        self.assertFalse(_numeric_compare(9, ">=", 10))


if __name__ == "__main__":
    unittest.main()
