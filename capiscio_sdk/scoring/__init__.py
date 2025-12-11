"""Multi-dimensional scoring system for A2A validation.

.. deprecated:: 0.3.0
    The pure Python scoring module is deprecated. Scoring is now handled by
    capiscio-core via gRPC. Use :func:`capiscio_sdk.validate_agent_card` for
    Agent Card validation with scoring, which delegates to Go core.

This module provides three independent scoring dimensions:
- Compliance: Protocol specification adherence (0-100)
- Trust: Security and authenticity signals (0-100)  
- Availability: Operational readiness (0-100)

Each dimension has its own rating scale and breakdown structure,
allowing users to make nuanced decisions based on their priorities.

NOTE: The types in this module are still used for API compatibility.
The scorer classes (ComplianceScorer, TrustScorer, AvailabilityScorer)
are deprecated and should not be used directly.
"""

import warnings as _warnings

from .types import (
    ComplianceScore,
    TrustScore,
    AvailabilityScore,
    ComplianceBreakdown,
    TrustBreakdown,
    AvailabilityBreakdown,
    ComplianceRating,
    TrustRating,
    AvailabilityRating,
    ScoringContext,
)

# Import deprecated scorers with warnings
from .compliance import ComplianceScorer as _LegacyComplianceScorer
from .trust import TrustScorer as _LegacyTrustScorer
from .availability import AvailabilityScorer as _LegacyAvailabilityScorer


class ComplianceScorer(_LegacyComplianceScorer):
    """Compliance scorer (DEPRECATED - scoring now handled by Go core).
    
    .. deprecated:: 0.3.0
        Use :func:`capiscio_sdk.validate_agent_card` which delegates
        scoring to capiscio-core. This class will be removed in v1.0.0.
    """
    
    def __init__(self, *args, **kwargs):
        _warnings.warn(
            "ComplianceScorer is deprecated. Scoring is now handled by Go core. "
            "Use capiscio_sdk.validate_agent_card() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(*args, **kwargs)


class TrustScorer(_LegacyTrustScorer):
    """Trust scorer (DEPRECATED - scoring now handled by Go core).
    
    .. deprecated:: 0.3.0
        Use :func:`capiscio_sdk.validate_agent_card` which delegates
        scoring to capiscio-core. This class will be removed in v1.0.0.
    """
    
    def __init__(self, *args, **kwargs):
        _warnings.warn(
            "TrustScorer is deprecated. Scoring is now handled by Go core. "
            "Use capiscio_sdk.validate_agent_card() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(*args, **kwargs)


class AvailabilityScorer(_LegacyAvailabilityScorer):
    """Availability scorer (DEPRECATED - scoring now handled by Go core).
    
    .. deprecated:: 0.3.0
        Use :func:`capiscio_sdk.validate_agent_card` which delegates
        scoring to capiscio-core. This class will be removed in v1.0.0.
    """
    
    def __init__(self, *args, **kwargs):
        _warnings.warn(
            "AvailabilityScorer is deprecated. Scoring is now handled by Go core. "
            "Use capiscio_sdk.validate_agent_card() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(*args, **kwargs)


__all__ = [
    # Types (still used)
    "ComplianceScore",
    "TrustScore",
    "AvailabilityScore",
    "ComplianceBreakdown",
    "TrustBreakdown",
    "AvailabilityBreakdown",
    "ComplianceRating",
    "TrustRating",
    "AvailabilityRating",
    "ScoringContext",
    # Deprecated scorers (kept for backward compatibility)
    "ComplianceScorer",
    "TrustScorer",
    "AvailabilityScorer",
]
