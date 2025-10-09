"""Core types for Capiscio A2A Security."""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum


class ValidationSeverity(str, Enum):
    """Severity level for validation issues."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationIssue(BaseModel):
    """A single validation issue."""

    severity: ValidationSeverity
    code: str
    message: str
    path: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ValidationResult(BaseModel):
    """Result of a validation operation."""

    success: bool
    score: int = Field(ge=0, le=100)
    issues: List[ValidationIssue] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def errors(self) -> List[ValidationIssue]:
        """Get only error-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> List[ValidationIssue]:
        """Get only warning-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]


class CacheEntry(BaseModel):
    """Cached validation result with TTL."""

    result: ValidationResult
    cached_at: float  # Unix timestamp
    ttl: int  # Seconds


class RateLimitInfo(BaseModel):
    """Rate limit information."""

    requests_allowed: int
    requests_used: int
    reset_at: float  # Unix timestamp

    @property
    def requests_remaining(self) -> int:
        """Remaining requests."""
        return max(0, self.requests_allowed - self.requests_used)
