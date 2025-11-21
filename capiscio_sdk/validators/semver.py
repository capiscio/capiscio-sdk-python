"""Semantic version validation and comparison."""
import re
from typing import Optional, Tuple

from ..types import ValidationResult, ValidationIssue, ValidationSeverity, create_simple_validation_result


class SemverValidator:
    """Validates and compares semantic versions."""

    # Semver regex pattern (simplified but covers most cases)
    SEMVER_PATTERN = re.compile(
        r'^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)'
        r'(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)'
        r'(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?'
        r'(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'
    )

    def validate_version(self, version: str, field_name: str = "version") -> ValidationResult:
        """
        Validate semantic version format.

        Args:
            version: Version string to validate
            field_name: Name of the field being validated

        Returns:
            ValidationResult
        """
        issues = []
        score = 100

        if not version:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_VERSION",
                    message=f"{field_name}: Version is required",
                    path=field_name,
                )
            )
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="compliance"
            )

        if not isinstance(version, str):
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_VERSION_TYPE",
                    message=f"{field_name}: Version must be a string",
                    path=field_name,
                )
            )
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="compliance"
            )

        # Validate semver format
        match = self.SEMVER_PATTERN.match(version)
        if not match:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_SEMVER_FORMAT",
                    message=f"{field_name}: Version must follow semantic versioning (e.g., 1.0.0)",
                    path=field_name,
                    details={"version": version},
                )
            )
            return create_simple_validation_result(
                success=False,
                issues=issues,
                simple_score=0,
                dimension="compliance"
            )

        # Extract version parts
        major = int(match.group('major'))
        minor = int(match.group('minor'))
        patch = int(match.group('patch'))
        prerelease = match.group('prerelease')

        # Warn about pre-release versions in production
        if prerelease:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="PRERELEASE_VERSION",
                    message=f"{field_name}: Pre-release version detected ({version})",
                    path=field_name,
                    details={"prerelease": prerelease},
                )
            )
            score -= 10

        # Warn about 0.x versions
        if major == 0:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    code="DEVELOPMENT_VERSION",
                    message=f"{field_name}: Development version (0.x.x) - not stable",
                    path=field_name,
                )
            )

        result = create_simple_validation_result(
            success=True,
            issues=issues,
            simple_score=score,
            dimension="compliance"
        )
        result.metadata = {
            "major": major,
            "minor": minor,
            "patch": patch,
            "prerelease": prerelease,
        }
        return result

    def parse_version(self, version: str) -> Optional[Tuple[int, int, int]]:
        """
        Parse semantic version into (major, minor, patch) tuple.

        Args:
            version: Version string to parse

        Returns:
            Tuple of (major, minor, patch) or None if invalid
        """
        match = self.SEMVER_PATTERN.match(version)
        if not match:
            return None

        return (
            int(match.group('major')),
            int(match.group('minor')),
            int(match.group('patch'))
        )

    def compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two semantic versions.

        Args:
            version1: First version
            version2: Second version

        Returns:
            -1 if version1 < version2
             0 if version1 == version2
             1 if version1 > version2
        """
        v1 = self.parse_version(version1)
        v2 = self.parse_version(version2)

        if v1 is None or v2 is None:
            raise ValueError(f"Invalid version format: {version1} or {version2}")

        # Compare major, minor, patch
        if v1[0] != v2[0]:
            return 1 if v1[0] > v2[0] else -1
        if v1[1] != v2[1]:
            return 1 if v1[1] > v2[1] else -1
        if v1[2] != v2[2]:
            return 1 if v1[2] > v2[2] else -1

        return 0

    def is_compatible(self, version: str, required: str) -> bool:
        """
        Check if version is compatible with required version.

        Compatible means version >= required for same major version.

        Args:
            version: Actual version
            required: Required minimum version

        Returns:
            True if compatible
        """
        try:
            comparison = self.compare_versions(version, required)
            v1 = self.parse_version(version)
            v2 = self.parse_version(required)

            # Must be same major version
            if v1 and v2 and v1[0] != v2[0]:
                return False

            # Must be greater than or equal
            return comparison >= 0
        except ValueError:
            return False
