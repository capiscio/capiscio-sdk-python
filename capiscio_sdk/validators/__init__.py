"""Validators for A2A message components.

This module provides validation for A2A protocol messages and Agent Cards.

RECOMMENDED: Use `CoreValidator` for Agent Card validation - it delegates
to Go core for consistent behavior across all CapiscIO SDKs.

The pure Python validators (AgentCardValidator, MessageValidator, etc.) are
DEPRECATED and will be removed in a future version. They are maintained for
backward compatibility only.

Example:
    # Recommended: Use Go core-backed validator
    from capiscio_sdk.validators import CoreValidator, validate_agent_card
    
    result = validate_agent_card(card_dict)
    # Or for repeated validations:
    with CoreValidator() as validator:
        result = validator.validate_agent_card(card_dict)
    
    # Deprecated: Pure Python validator
    from capiscio_sdk.validators import AgentCardValidator
    validator = AgentCardValidator()  # Will show deprecation warning
"""
import warnings as _warnings

# Go core-backed validators (RECOMMENDED)
from ._core import CoreValidator, validate_agent_card

# Legacy pure Python validators (DEPRECATED)
# These are imported with deprecation tracking
from .message import MessageValidator
from .protocol import ProtocolValidator
from .url_security import URLSecurityValidator
from .signature import SignatureValidator
from .semver import SemverValidator
from .agent_card import AgentCardValidator as _LegacyAgentCardValidator
from .certificate import CertificateValidator


class AgentCardValidator(_LegacyAgentCardValidator):
    """Agent Card validator (DEPRECATED - use CoreValidator instead).
    
    This class is deprecated. Use `CoreValidator` for Go core-backed
    validation with consistent behavior across all CapiscIO SDKs.
    
    .. deprecated:: 0.3.0
        Use :class:`CoreValidator` instead. This pure Python implementation
        will be removed in version 1.0.0.
    """
    
    def __init__(self, *args, **kwargs):
        _warnings.warn(
            "AgentCardValidator is deprecated and will be removed in v1.0.0. "
            "Use CoreValidator for Go core-backed validation: "
            "from capiscio_sdk.validators import CoreValidator, validate_agent_card",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(*args, **kwargs)


__all__ = [
    # Recommended (Go core-backed)
    "CoreValidator",
    "validate_agent_card",
    # Legacy (deprecated)
    "MessageValidator",
    "ProtocolValidator",
    "URLSecurityValidator",
    "SignatureValidator",
    "SemverValidator",
    "AgentCardValidator",
    "CertificateValidator",
]
