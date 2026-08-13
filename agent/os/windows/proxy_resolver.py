"""Native Windows proxy discovery for the LocalSystem agent transport.

Precedence is explicit configuration, machine WinHTTP static configuration,
then an explicitly configured PAC URL or opt-in WPAD auto-discovery. User
WinINET settings are deliberately excluded: a service must not borrow an
interactive user's network identity or registry profile without impersonation.
"""
from __future__ import annotations

import ctypes
import fnmatch
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


WINHTTP_ACCESS_TYPE_NO_PROXY = 1
WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002
WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002


class _WINHTTP_PROXY_INFO(ctypes.Structure):
    _fields_ = [
        ("dwAccessType", ctypes.c_uint32),
        ("lpszProxy", ctypes.c_void_p),
        ("lpszProxyBypass", ctypes.c_void_p),
    ]


class _WINHTTP_AUTOPROXY_OPTIONS(ctypes.Structure):
    _fields_ = [
        ("dwFlags", ctypes.c_uint32),
        ("dwAutoDetectFlags", ctypes.c_uint32),
        ("lpszAutoConfigUrl", ctypes.c_wchar_p),
        ("lpvReserved", ctypes.c_void_p),
        ("dwReserved", ctypes.c_uint32),
        ("fAutoLogonIfChallenged", ctypes.c_int),
    ]


@dataclass(frozen=True)
class NativeProxyInfo:
    access_type: int
    proxy: str | None = None
    bypass: str | None = None


@dataclass(frozen=True)
class ProxyResolution:
    proxy_url: str | None
    source: str
    bypassed: bool = False


class WinHttpApi:
    """Small ownership-safe ctypes wrapper around WinHTTP proxy APIs."""

    def __init__(self, *, winhttp: Any | None = None, kernel32: Any | None = None):
        if os.name != "nt" and winhttp is None:
            raise OSError("WinHTTP is available only on Windows")
        self._winhttp = winhttp or ctypes.WinDLL("winhttp", use_last_error=True)
        self._kernel32 = kernel32 or ctypes.WinDLL("kernel32", use_last_error=True)
        if winhttp is None:
            self._configure_signatures()

    def _configure_signatures(self) -> None:
        self._winhttp.WinHttpGetDefaultProxyConfiguration.argtypes = [
            ctypes.POINTER(_WINHTTP_PROXY_INFO)
        ]
        self._winhttp.WinHttpGetDefaultProxyConfiguration.restype = ctypes.c_int
        self._winhttp.WinHttpOpen.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        self._winhttp.WinHttpOpen.restype = ctypes.c_void_p
        self._winhttp.WinHttpGetProxyForUrl.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(_WINHTTP_AUTOPROXY_OPTIONS),
            ctypes.POINTER(_WINHTTP_PROXY_INFO),
        ]
        self._winhttp.WinHttpGetProxyForUrl.restype = ctypes.c_int
        self._winhttp.WinHttpCloseHandle.argtypes = [ctypes.c_void_p]
        self._winhttp.WinHttpCloseHandle.restype = ctypes.c_int
        self._kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.GlobalFree.restype = ctypes.c_void_p

    def _consume_info(self, info: _WINHTTP_PROXY_INFO) -> NativeProxyInfo:
        try:
            proxy = ctypes.wstring_at(info.lpszProxy) if info.lpszProxy else None
            bypass = (
                ctypes.wstring_at(info.lpszProxyBypass)
                if info.lpszProxyBypass
                else None
            )
            return NativeProxyInfo(int(info.dwAccessType), proxy, bypass)
        finally:
            for pointer in (info.lpszProxy, info.lpszProxyBypass):
                if pointer:
                    self._kernel32.GlobalFree(pointer)

    def get_default(self) -> NativeProxyInfo | None:
        info = _WINHTTP_PROXY_INFO()
        ctypes.set_last_error(0)
        if not self._winhttp.WinHttpGetDefaultProxyConfiguration(ctypes.byref(info)):
            return None
        return self._consume_info(info)

    def get_auto(
        self,
        target_url: str,
        *,
        pac_url: str | None,
        auto_detect: bool,
    ) -> NativeProxyInfo | None:
        flags = 0
        detect_flags = 0
        if pac_url:
            flags |= WINHTTP_AUTOPROXY_CONFIG_URL
        if auto_detect:
            flags |= WINHTTP_AUTOPROXY_AUTO_DETECT
            detect_flags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
        if not flags:
            return None

        session = self._winhttp.WinHttpOpen(
            "AttackLensAgent/2",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            None,
            None,
            0,
        )
        if not session:
            return None
        options = _WINHTTP_AUTOPROXY_OPTIONS(
            dwFlags=flags,
            dwAutoDetectFlags=detect_flags,
            lpszAutoConfigUrl=pac_url,
            lpvReserved=None,
            dwReserved=0,
            # Never send the machine account automatically while downloading PAC.
            fAutoLogonIfChallenged=0,
        )
        info = _WINHTTP_PROXY_INFO()
        try:
            ctypes.set_last_error(0)
            if not self._winhttp.WinHttpGetProxyForUrl(
                session,
                target_url,
                ctypes.byref(options),
                ctypes.byref(info),
            ):
                return None
            return self._consume_info(info)
        finally:
            self._winhttp.WinHttpCloseHandle(session)


def _select_proxy(proxy_list: str | None, scheme: str) -> str | None:
    if not proxy_list:
        return None
    selected: str | None = None
    generic: str | None = None
    for raw_entry in proxy_list.replace(",", ";").split(";"):
        entry = raw_entry.strip()
        if not entry:
            continue
        if "=" in entry:
            key, value = (part.strip() for part in entry.split("=", 1))
            if key.lower() == scheme.lower():
                selected = value
                break
            continue
        if generic is None:
            generic = entry
    value = selected or generic
    if not value:
        return None
    upper = value.upper()
    if upper == "DIRECT" or upper.startswith("SOCKS"):
        return None
    if upper.startswith("PROXY "):
        value = value[6:].strip()
    first = value.split()[0]
    if "://" not in first:
        first = f"http://{first}"
    parsed = urlsplit(first)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return first


def _is_bypassed(target_url: str, bypass_list: str | None) -> bool:
    host = (urlsplit(target_url).hostname or "").lower()
    if not host or not bypass_list:
        return False
    for raw_pattern in bypass_list.replace(",", ";").split(";"):
        pattern = raw_pattern.strip().lower()
        if not pattern:
            continue
        if pattern == "<local>" and "." not in host:
            return True
        pattern = pattern.split(":", 1)[0]
        if fnmatch.fnmatchcase(host, pattern):
            return True
    return False


def resolve_windows_proxy(
    target_url: str,
    *,
    explicit_proxy: str | None = None,
    pac_url: str | None = None,
    auto_detect: bool = True,
    api: Any | None = None,
) -> ProxyResolution:
    """Resolve a requests-compatible proxy without reading process environment."""
    if explicit_proxy:
        return ProxyResolution(explicit_proxy, "explicit")
    if api is None and os.name != "nt":
        return ProxyResolution(None, "direct")

    native = api or WinHttpApi()
    try:
        default = native.get_default()
    except Exception:
        default = None
    if default and default.access_type == WINHTTP_ACCESS_TYPE_NAMED_PROXY:
        if _is_bypassed(target_url, default.bypass):
            return ProxyResolution(None, "winhttp_static", bypassed=True)
        proxy = _select_proxy(default.proxy, urlsplit(target_url).scheme)
        if proxy:
            return ProxyResolution(proxy, "winhttp_static")

    try:
        automatic = native.get_auto(
            target_url,
            pac_url=pac_url,
            auto_detect=auto_detect,
        )
    except Exception:
        automatic = None
    if automatic and automatic.access_type == WINHTTP_ACCESS_TYPE_NAMED_PROXY:
        if _is_bypassed(target_url, automatic.bypass):
            return ProxyResolution(
                None,
                "pac" if pac_url else "wpad",
                bypassed=True,
            )
        proxy = _select_proxy(automatic.proxy, urlsplit(target_url).scheme)
        if proxy:
            return ProxyResolution(proxy, "pac" if pac_url else "wpad")
    return ProxyResolution(None, "direct")
