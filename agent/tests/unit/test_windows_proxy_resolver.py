"""Unit and transport-integration tests for native Windows proxy discovery."""
from __future__ import annotations

from agent.os.windows.proxy_resolver import (
    NativeProxyInfo,
    ProxyResolution,
    WINHTTP_ACCESS_TYPE_NAMED_PROXY,
    WINHTTP_ACCESS_TYPE_NO_PROXY,
    resolve_windows_proxy,
)


class FakeApi:
    def __init__(self, default=None, automatic=None):
        self.default = default
        self.automatic = automatic
        self.default_calls = 0
        self.auto_calls = []

    def get_default(self):
        self.default_calls += 1
        return self.default

    def get_auto(self, target_url, *, pac_url, auto_detect):
        self.auto_calls.append((target_url, pac_url, auto_detect))
        return self.automatic


def test_explicit_proxy_has_precedence_without_native_discovery():
    api = FakeApi()
    result = resolve_windows_proxy(
        "https://manager.example.test",
        explicit_proxy="http://explicit.proxy:8080",
        api=api,
    )
    assert result == ProxyResolution("http://explicit.proxy:8080", "explicit")
    assert api.default_calls == 0
    assert api.auto_calls == []


def test_machine_winhttp_proxy_selects_target_scheme():
    api = FakeApi(default=NativeProxyInfo(
        WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        "http=plain.proxy:8080;https=secure.proxy:8443",
        "localhost;*.internal.example",
    ))
    result = resolve_windows_proxy("https://manager.example.test", api=api)
    assert result == ProxyResolution("http://secure.proxy:8443", "winhttp_static")
    assert api.auto_calls == []


def test_machine_bypass_prevents_proxy_and_pac_fallback():
    api = FakeApi(default=NativeProxyInfo(
        WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        "proxy.example:8080",
        "<local>;*.internal.example",
    ))
    result = resolve_windows_proxy("https://manager.internal.example", api=api)
    assert result.proxy_url is None
    assert result.source == "winhttp_static"
    assert result.bypassed is True
    assert api.auto_calls == []


def test_pac_is_used_after_direct_machine_configuration():
    api = FakeApi(
        default=NativeProxyInfo(WINHTTP_ACCESS_TYPE_NO_PROXY),
        automatic=NativeProxyInfo(
            WINHTTP_ACCESS_TYPE_NAMED_PROXY,
            "PROXY pac.proxy:3128",
        ),
    )
    result = resolve_windows_proxy(
        "https://manager.example.test",
        pac_url="https://config.example.test/proxy.pac",
        auto_detect=False,
        api=api,
    )
    assert result == ProxyResolution("http://pac.proxy:3128", "pac")
    assert api.auto_calls == [(
        "https://manager.example.test",
        "https://config.example.test/proxy.pac",
        False,
    )]


def test_wpad_direct_result_remains_direct():
    api = FakeApi(
        default=NativeProxyInfo(WINHTTP_ACCESS_TYPE_NO_PROXY),
        automatic=NativeProxyInfo(WINHTTP_ACCESS_TYPE_NO_PROXY),
    )
    result = resolve_windows_proxy(
        "https://manager.example.test",
        auto_detect=True,
        api=api,
    )
    assert result == ProxyResolution(None, "direct")


def test_transport_uses_resolved_proxy_without_trusting_environment(monkeypatch):
    from agent.os.windows import proxy_resolver
    from agent.os.windows.tls_transport import WindowsTLSTransport

    monkeypatch.setattr(
        proxy_resolver,
        "resolve_windows_proxy",
        lambda *_args, **_kwargs: ProxyResolution(
            "http://resolved.proxy:8080",
            "winhttp_static",
        ),
    )
    transport = WindowsTLSTransport(
        "https://manager.example.test",
        proxy_auto_detect=True,
    )
    try:
        assert transport.proxy_source == "winhttp_static"
        assert transport._session.trust_env is False
        assert transport._session.proxies == {
            "http": "http://resolved.proxy:8080",
            "https": "http://resolved.proxy:8080",
        }
    finally:
        transport.close()
