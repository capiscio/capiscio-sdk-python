"""Error types for Capiscio Python SDK."""
from typing import Optional, List, Dict, Any
from .types import ValidationResult


class CapiscioSecurityError(Exception):
    """Base error for Capiscio security."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class CapiscioValidationError(CapiscioSecurityError):
    """Schema or protocol validation failed."""

    def __init__(
        self,
        message: str,
        validation_result: ValidationResult,
        errors: Optional[List[str]] = None,
    ):
        super().__init__(message)
        self.validation_result = validation_result
        self.errors = errors or [issue.message for issue in validation_result.errors]


class CapiscioSignatureError(CapiscioSecurityError):
    """Signature verification failed."""

    def __init__(self, message: str, agent_url: str, reason: str):
        super().__init__(message)
        self.agent_url = agent_url
        self.reason = reason


class CapiscioRateLimitError(CapiscioSecurityError):
    """Rate limit exceeded."""

    def __init__(self, message: str, retry_after_seconds: int):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class CapiscioUpstreamError(CapiscioSecurityError):
    """Upstream agent validation failed."""

    def __init__(
        self,
        message: str,
        agent_url: str,
        validation_result: ValidationResult,
    ):
        super().__init__(message)
        self.agent_url = agent_url
        self.validation_result = validation_result


class CapiscioConfigError(CapiscioSecurityError):
    """Configuration error."""

    pass


class CapiscioTimeoutError(CapiscioSecurityError):
    """Operation timed out."""

    pass


class ConfigurationError(CapiscioSecurityError):
    """Missing keys or invalid paths (SimpleGuard)."""
    pass


class VerificationError(CapiscioSecurityError):
    """Invalid signature, expired token, or untrusted key (SimpleGuard)."""
    pass
