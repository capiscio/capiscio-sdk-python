"""Configuration for Capiscio Python SDK."""
import os
from typing import Literal
from pydantic import BaseModel, Field


class DownstreamConfig(BaseModel):
    """Configuration for downstream protection (agents calling you)."""

    validate_schema: bool = True
    verify_signatures: bool = True
    require_signatures: bool = False
    check_protocol_compliance: bool = True
    enable_rate_limiting: bool = True
    rate_limit_requests_per_minute: int = 60


class UpstreamConfig(BaseModel):
    """Configuration for upstream protection (calling other agents)."""

    validate_agent_cards: bool = True
    verify_signatures: bool = True
    require_signatures: bool = False
    test_endpoints: bool = False  # Performance impact
    cache_validation: bool = True
    cache_timeout: int = 3600  # seconds


class SecurityConfig(BaseModel):
    """Main security configuration."""

    downstream: DownstreamConfig = Field(default_factory=DownstreamConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    strict_mode: bool = False
    fail_mode: Literal["block", "monitor", "log"] = "block"
    log_validation_failures: bool = True
    timeout_ms: int = 5000

    @classmethod
    def development(cls) -> "SecurityConfig":
        """Development preset - permissive."""
        return cls(
            downstream=DownstreamConfig(
                require_signatures=False,
                enable_rate_limiting=False,
            ),
            upstream=UpstreamConfig(
                require_signatures=False,
                test_endpoints=False,
            ),
            strict_mode=False,
            fail_mode="log",
        )

    @classmethod
    def production(cls) -> "SecurityConfig":
        """Production preset - balanced."""
        return cls(
            downstream=DownstreamConfig(
                require_signatures=False,
                enable_rate_limiting=True,
            ),
            upstream=UpstreamConfig(
                require_signatures=False,
                test_endpoints=False,
            ),
            strict_mode=False,
            fail_mode="block",
        )

    @classmethod
    def strict(cls) -> "SecurityConfig":
        """Strict preset - maximum security."""
        return cls(
            downstream=DownstreamConfig(
                require_signatures=True,
                enable_rate_limiting=True,
            ),
            upstream=UpstreamConfig(
                require_signatures=True,
                test_endpoints=True,
            ),
            strict_mode=True,
            fail_mode="block",
        )

    @classmethod
    def from_env(cls) -> "SecurityConfig":
        """Load configuration from environment variables."""
        return cls(
            downstream=DownstreamConfig(
                validate_schema=os.getenv("CAPISCIO_VALIDATE_SCHEMA", "true").lower()
                == "true",
                verify_signatures=os.getenv("CAPISCIO_VERIFY_SIGNATURES", "true").lower()
                == "true",
                require_signatures=os.getenv("CAPISCIO_REQUIRE_SIGNATURES", "false").lower()
                == "true",
                enable_rate_limiting=os.getenv("CAPISCIO_RATE_LIMITING", "true").lower()
                == "true",
                rate_limit_requests_per_minute=int(os.getenv("CAPISCIO_RATE_LIMIT_RPM", "60")),
            ),
            upstream=UpstreamConfig(
                validate_agent_cards=os.getenv("CAPISCIO_VALIDATE_UPSTREAM", "true").lower()
                == "true",
                verify_signatures=os.getenv(
                    "CAPISCIO_VERIFY_UPSTREAM_SIGNATURES", "true"
                ).lower()
                == "true",
                cache_validation=os.getenv("CAPISCIO_CACHE_VALIDATION", "true").lower()
                == "true",
            ),
            fail_mode=os.getenv("CAPISCIO_FAIL_MODE", "block"),  # type: ignore
            timeout_ms=int(os.getenv("CAPISCIO_TIMEOUT_MS", "5000")),
        )
