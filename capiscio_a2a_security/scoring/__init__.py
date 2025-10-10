"""Multi-dimensional scoring system for A2A validation.

This module provides three independent scoring dimensions:
- Compliance: Protocol specification adherence (0-100)
- Trust: Security and authenticity signals (0-100)  
- Availability: Operational readiness (0-100)

Each dimension has its own rating scale and breakdown structure,
allowing users to make nuanced decisions based on their priorities.
"""

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
from .compliance import ComplianceScorer
from .trust import TrustScorer
from .availability import AvailabilityScorer

__all__ = [
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
    "ComplianceScorer",
    "TrustScorer",
    "AvailabilityScorer",
]
