"""Capiscio SDK - Runtime security middleware for A2A agents.

This package provides always-on protection for A2A protocol agents through
validation, signature verification, and protocol compliance checking.

Example:
    >>> from capiscio_sdk import secure
    >>> agent = secure(MyAgentExecutor())
    
    >>> from capiscio_sdk.badge import verify_badge
    >>> result = verify_badge(token, trusted_issuers=["https://registry.capisc.io"])
    
    >>> from capiscio_sdk import validate_agent_card
    >>> result = validate_agent_card(card_dict)  # Uses Go core
"""

__version__ = "2.3.1"

# Core exports
from .executor import CapiscioSecurityExecutor, secure, secure_agent
from .simple_guard import SimpleGuard
from .config import SecurityConfig, DownstreamConfig, UpstreamConfig
from .errors import (
    CapiscioSecurityError,
    CapiscioValidationError,
    CapiscioSignatureError,
    CapiscioRateLimitError,
    CapiscioUpstreamError,
)
from .types import ValidationResult, ValidationIssue, ValidationSeverity

# Go core-backed validation (RECOMMENDED)
from .validators import CoreValidator, validate_agent_card

# Trust Badge API
from .badge import (
    verify_badge,
    parse_badge,
    request_badge,
    request_badge_sync,
    request_pop_badge,
    request_pop_badge_sync,
    start_badge_keeper,
    BadgeClaims,
    VerifyOptions,
    VerifyResult,
    VerifyMode,
    TrustLevel,
)

# Badge lifecycle management
from .badge_keeper import BadgeKeeper, BadgeKeeperConfig

# Domain Validation (DV) API
from .dv import (
    create_dv_order,
    get_dv_order,
    finalize_dv_order,
    DVOrder,
    DVGrant,
)

# Easy connect API ("Let's Encrypt" style)
from .connect import CapiscIO, connect, from_env, AgentIdentity

# Event emission
from .events import EventEmitter

__all__ = [
    "__version__",
    # Security middleware
    "CapiscioSecurityExecutor",
    "SimpleGuard",
    "secure",
    "secure_agent",
    # Configuration
    "SecurityConfig",
    "DownstreamConfig",
    "UpstreamConfig",
    # Errors
    "CapiscioSecurityError",
    "CapiscioValidationError",
    "CapiscioSignatureError",
    "CapiscioRateLimitError",
    "CapiscioUpstreamError",
    # Types
    "ValidationResult",
    "ValidationIssue",
    "ValidationSeverity",
    # Validation (Go core-backed)
    "CoreValidator",
    "validate_agent_card",
    # Trust Badge API
    "verify_badge",
    "parse_badge",
    "request_badge",
    "request_badge_sync",
    "request_pop_badge",
    "request_pop_badge_sync",
    "start_badge_keeper",
    "BadgeClaims",
    "VerifyOptions",
    "VerifyResult",
    "VerifyMode",
    "TrustLevel",
    # Badge lifecycle management
    "BadgeKeeper",
    "BadgeKeeperConfig",
    # Domain Validation (DV) API
    "create_dv_order",
    "get_dv_order",
    "finalize_dv_order",
    "DVOrder",
    "DVGrant",
    # Easy Connect API ("Let's Encrypt" style)
    "CapiscIO",
    "connect",
    "from_env",
    "AgentIdentity",
    # Event emission
    "EventEmitter",
]

