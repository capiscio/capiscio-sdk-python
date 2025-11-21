"""Capiscio SDK - Runtime security middleware for A2A agents.

This package provides always-on protection for A2A protocol agents through
validation, signature verification, and protocol compliance checking.

Example:
    >>> from capiscio_sdk import secure
    >>> agent = secure(MyAgentExecutor())
"""

__version__ = "0.1.0"

# Core exports
from .executor import CapiscioSecurityExecutor, secure, secure_agent
from .config import SecurityConfig, DownstreamConfig, UpstreamConfig
from .errors import (
    CapiscioSecurityError,
    CapiscioValidationError,
    CapiscioSignatureError,
    CapiscioRateLimitError,
    CapiscioUpstreamError,
)
from .types import ValidationResult, ValidationIssue, ValidationSeverity

__all__ = [
    "__version__",
    "CapiscioSecurityExecutor",
    "secure",
    "secure_agent",
    "SecurityConfig",
    "DownstreamConfig",
    "UpstreamConfig",
    "CapiscioSecurityError",
    "CapiscioValidationError",
    "CapiscioSignatureError",
    "CapiscioRateLimitError",
    "CapiscioUpstreamError",
    "ValidationResult",
    "ValidationIssue",
    "ValidationSeverity",
]

