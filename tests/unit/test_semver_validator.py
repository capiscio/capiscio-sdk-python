"""Tests for semver validator."""
import pytest
from capiscio_a2a_security.validators.semver import SemverValidator


@pytest.fixture
def validator():
    """Create semver validator instance."""
    return SemverValidator()


def test_validate_valid_version(validator):
    """Test validation of valid semver."""
    result = validator.validate_version("1.0.0")
    assert result.success
    assert result.score == 100
    assert result.metadata["major"] == 1
    assert result.metadata["minor"] == 0
    assert result.metadata["patch"] == 0


def test_validate_development_version(validator):
    """Test validation of 0.x version."""
    result = validator.validate_version("0.3.0")
    assert result.success
    assert any(i.code == "DEVELOPMENT_VERSION" for i in result.issues)


def test_validate_prerelease_version(validator):
    """Test validation of pre-release version."""
    result = validator.validate_version("1.0.0-beta.1")
    assert result.success
    assert any(i.code == "PRERELEASE_VERSION" for i in result.warnings)


def test_validate_invalid_format(validator):
    """Test validation of invalid version format."""
    result = validator.validate_version("1.0")
    assert not result.success
    assert any(i.code == "INVALID_SEMVER_FORMAT" for i in result.errors)


def test_validate_missing_version(validator):
    """Test validation with missing version."""
    result = validator.validate_version("")
    assert not result.success
    assert any(i.code == "MISSING_VERSION" for i in result.errors)


def test_parse_version(validator):
    """Test version parsing."""
    parsed = validator.parse_version("1.2.3")
    assert parsed == (1, 2, 3)


def test_parse_invalid_version(validator):
    """Test parsing invalid version."""
    parsed = validator.parse_version("invalid")
    assert parsed is None


def test_compare_versions_equal(validator):
    """Test comparing equal versions."""
    result = validator.compare_versions("1.0.0", "1.0.0")
    assert result == 0


def test_compare_versions_greater(validator):
    """Test comparing greater version."""
    result = validator.compare_versions("1.1.0", "1.0.0")
    assert result == 1


def test_compare_versions_lesser(validator):
    """Test comparing lesser version."""
    result = validator.compare_versions("1.0.0", "1.1.0")
    assert result == -1


def test_is_compatible_same_major(validator):
    """Test compatibility with same major version."""
    assert validator.is_compatible("1.2.0", "1.0.0")
    assert validator.is_compatible("1.1.0", "1.1.0")


def test_is_compatible_different_major(validator):
    """Test incompatibility with different major version."""
    assert not validator.is_compatible("2.0.0", "1.0.0")
    assert not validator.is_compatible("1.0.0", "2.0.0")


def test_is_compatible_older_minor(validator):
    """Test incompatibility with older minor version."""
    assert not validator.is_compatible("1.0.0", "1.1.0")
