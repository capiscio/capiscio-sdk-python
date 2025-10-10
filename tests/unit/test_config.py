"""Tests for configuration."""
from capiscio_a2a_security.config import (
    SecurityConfig,
    DownstreamConfig,
    UpstreamConfig,
)


def test_default_config():
    """Test default configuration."""
    config = SecurityConfig()
    assert config.downstream.validate_schema
    assert config.fail_mode == "block"


def test_development_preset():
    """Test development preset."""
    config = SecurityConfig.development()
    assert not config.downstream.require_signatures
    assert not config.downstream.enable_rate_limiting
    assert config.fail_mode == "log"


def test_production_preset():
    """Test production preset."""
    config = SecurityConfig.production()
    assert config.downstream.enable_rate_limiting
    assert config.fail_mode == "block"
    assert not config.downstream.require_signatures


def test_strict_preset():
    """Test strict preset."""
    config = SecurityConfig.strict()
    assert config.downstream.require_signatures
    assert config.upstream.require_signatures
    assert config.strict_mode
    assert config.fail_mode == "block"


def test_from_env(monkeypatch):
    """Test loading from environment."""
    monkeypatch.setenv("CAPISCIO_FAIL_MODE", "monitor")
    monkeypatch.setenv("CAPISCIO_RATE_LIMIT_RPM", "120")
    monkeypatch.setenv("CAPISCIO_REQUIRE_SIGNATURES", "true")

    config = SecurityConfig.from_env()
    assert config.fail_mode == "monitor"
    assert config.downstream.rate_limit_requests_per_minute == 120
    assert config.downstream.require_signatures


def test_custom_downstream_config():
    """Test custom downstream configuration."""
    config = SecurityConfig(
        downstream=DownstreamConfig(
            validate_schema=False, rate_limit_requests_per_minute=200
        )
    )
    assert not config.downstream.validate_schema
    assert config.downstream.rate_limit_requests_per_minute == 200


def test_custom_upstream_config():
    """Test custom upstream configuration."""
    config = SecurityConfig(
        upstream=UpstreamConfig(test_endpoints=True, cache_timeout=7200)
    )
    assert config.upstream.test_endpoints
    assert config.upstream.cache_timeout == 7200
