"""
shared/crypto.py — AES-256-GCM + HKDF + HMAC-SHA256

Security design:
  - HKDF-SHA256 derives two domain-separated keys from the master API key:
      enc_key  (for AES-256-GCM encryption)
      mac_key  (for HMAC-SHA256 over the full envelope — defense in depth)
  - AES-256-GCM provides both confidentiality and authentication (GCM tag).
  - HMAC covers agent_id + timestamp + nonce + ciphertext to prevent
    field-substitution attacks even if the GCM tag is somehow bypassed.
  - Random 96-bit nonce per message → no nonce reuse under normal operation.
  - Timestamp + nonce dedup on the manager side → replay prevention.

Used by: agent/sender.py  and  manager/security/verifier.py
"""

import gzip
import hmac
import json
import os
import hashlib
import base64
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ── Constants ─────────────────────────────────────────────────────────────────
NONCE_BYTES     = 12          # 96-bit GCM nonce (NIST recommended)
KEY_BYTES       = 32          # AES-256
HKDF_SALT       = b"mac_intel_2026_salt_v1"
HKDF_INFO_ENC   = b"mac_intel_enc_v1"
HKDF_INFO_MAC   = b"mac_intel_mac_v1"
REPLAY_WINDOW_S = 300         # ±5 minutes


def derive_keys(api_key: str) -> Tuple[bytes, bytes]:
    """
    Derive enc_key and mac_key from a master API key using HKDF-SHA256.
    Domain-separated via different 'info' strings.
    Both parties (agent + manager) call this once at startup.
    """
    raw = api_key.encode("utf-8")

    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=HKDF_SALT,
        info=HKDF_INFO_ENC,
    ).derive(raw)

    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=HKDF_SALT,
        info=HKDF_INFO_MAC,
    ).derive(raw)

    return enc_key, mac_key


def encrypt(plaintext_dict: dict, enc_key: bytes, mac_key: bytes,
            agent_id: str, timestamp: int) -> dict:
    """
    Compress → AES-256-GCM encrypt → HMAC-sign a payload dict.

    Returns a wire-format dict ready for JSON serialisation:
      {
        "v":         1,
        "agent_id":  str,
        "timestamp": int,
        "nonce":     base64,
        "ct":        base64,   # ciphertext (GCM tag appended by AESGCM)
        "hmac":      hex
      }
    """
    nonce = os.urandom(NONCE_BYTES)
    compressed = gzip.compress(
        json.dumps(plaintext_dict, separators=(",", ":"), default=str).encode(),
        compresslevel=6,
    )

    aesgcm = AESGCM(enc_key)
    ct_with_tag = aesgcm.encrypt(nonce, compressed, None)

    nonce_b64 = base64.b64encode(nonce).decode()
    ct_b64    = base64.b64encode(ct_with_tag).decode()

    # HMAC over everything that must not be tampered with
    mac = _compute_hmac(mac_key, agent_id, timestamp, nonce_b64, ct_b64)

    return {
        "v":         1,
        "agent_id":  agent_id,
        "timestamp": timestamp,
        "nonce":     nonce_b64,
        "ct":        ct_b64,
        "hmac":      mac,
    }


def decrypt(envelope: dict, enc_key: bytes, mac_key: bytes) -> dict:
    """
    Verify HMAC → AES-256-GCM decrypt → decompress → return payload dict.
    Raises ValueError on any verification or decryption failure.
    Caller is responsible for timestamp and nonce-dedup checks BEFORE calling this.
    """
    required = {"v", "agent_id", "timestamp", "nonce", "ct", "hmac"}
    missing  = required - set(envelope)
    if missing:
        raise ValueError(f"Envelope missing fields: {missing}")

    if envelope["v"] != 1:
        raise ValueError(f"Unsupported envelope version: {envelope['v']}")

    ts = int(float(envelope["timestamp"]))

    # 1. Verify HMAC (constant-time)
    expected_mac = _compute_hmac(
        mac_key,
        envelope["agent_id"],
        ts,
        envelope["nonce"],
        envelope["ct"],
    )
    if not hmac.compare_digest(expected_mac, envelope["hmac"]):
        raise ValueError("HMAC verification failed")

    # 2. Decrypt + verify GCM tag
    nonce        = base64.b64decode(envelope["nonce"])
    ct_with_tag  = base64.b64decode(envelope["ct"])

    aesgcm = AESGCM(enc_key)
    try:
        compressed = aesgcm.decrypt(nonce, ct_with_tag, None)
    except Exception as exc:
        raise ValueError(f"GCM decryption failed: {exc}") from exc

    # 3. Decompress + parse
    return json.loads(gzip.decompress(compressed))


# ── Internal ──────────────────────────────────────────────────────────────────

def _compute_hmac(mac_key: bytes, agent_id: str, timestamp: int,
                  nonce: str, ct: str) -> str:
    """HMAC-SHA256 over the concatenation of all tamper-sensitive fields."""
    msg = f"{agent_id}:{timestamp}:{nonce}:{ct}".encode("utf-8")
    return hmac.new(mac_key, msg, hashlib.sha256).hexdigest()
