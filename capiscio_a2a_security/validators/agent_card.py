"""Agent Card validation for A2A protocol.

This module provides validation for Agent Card discovery documents as specified
in the A2A protocol. It validates schema structure, required fields, capabilities,
skills, and provider information.

Validates:
- Schema structure and required fields
- URL validity and security
- Protocol version compatibility
- Capabilities configuration
- Skills definitions
- Provider information
- Transport configuration
"""

from typing import Any, Dict, List, Optional
import httpx
from ..types import ValidationResult, ValidationIssue, ValidationSeverity
from .url_security import URLSecurityValidator
from .semver import SemverValidator


class AgentCardValidator:
    """Validates Agent Card discovery documents per A2A specification.
    
    Agent Cards are static metadata documents used for agent discovery.
    This validator checks schema compliance, security requirements, and
    configuration correctness.
    """
    
    # Required fields per A2A specification
    REQUIRED_FIELDS = [
        "name",
        "description", 
        "url",
        "version",
        "protocolVersion",
        "preferredTransport",
        "capabilities",
        "provider",
        "skills"
    ]
    
    # Valid transport protocols per A2A spec
    VALID_TRANSPORTS = ["JSONRPC", "GRPC", "HTTP+JSON"]
    
    def __init__(
        self,
        http_client: Optional[httpx.AsyncClient] = None,
        url_validator: Optional[URLSecurityValidator] = None,
        semver_validator: Optional[SemverValidator] = None
    ):
        """Initialize agent card validator.
        
        Args:
            http_client: Optional HTTP client for fetching cards
            url_validator: Optional URL security validator
            semver_validator: Optional semantic version validator
        """
        self.http_client = http_client or httpx.AsyncClient(timeout=10.0)
        self.url_validator = url_validator or URLSecurityValidator()
        self.semver_validator = semver_validator or SemverValidator()
    
    async def fetch_and_validate(self, agent_url: str) -> ValidationResult:
        """Fetch agent card from URL and validate it.
        
        Args:
            agent_url: Base URL of the agent
            
        Returns:
            ValidationResult with issues and score
        """
        issues: List[ValidationIssue] = []
        
        try:
            # Validate the agent URL first
            url_result = self.url_validator.validate_url(agent_url, field_name="agent_url", require_https=True)
            if not url_result.success:
                issues.extend(url_result.issues)
                return ValidationResult(success=False, score=0, issues=issues)
            
            # Fetch agent card from well-known location
            card_url = f"{agent_url.rstrip('/')}/.well-known/agent-card.json"
            response = await self.http_client.get(card_url)
            response.raise_for_status()
            
            card_data = response.json()
            
            # Validate the fetched card
            return self.validate_agent_card(card_data)
            
        except httpx.HTTPStatusError as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="AGENT_CARD_HTTP_ERROR",
                message=f"Failed to fetch agent card (HTTP {e.response.status_code}): {str(e)}",
                path="agent_card"
            ))
            return ValidationResult(success=False, score=0, issues=issues)
        except httpx.RequestError as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="AGENT_CARD_FETCH_FAILED",
                message=f"Failed to fetch agent card: {str(e)}",
                path="agent_card"
            ))
            return ValidationResult(success=False, score=0, issues=issues)
        except Exception as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="AGENT_CARD_VALIDATION_ERROR",
                message=f"Agent card validation error: {str(e)}",
                path="agent_card"
            ))
            return ValidationResult(success=False, score=0, issues=issues)
    
    def validate_agent_card(self, card: Dict[str, Any]) -> ValidationResult:
        """Validate agent card structure and content.
        
        Args:
            card: Agent card dictionary
            
        Returns:
            ValidationResult with validation issues and score
        """
        issues: List[ValidationIssue] = []
        
        # 1. Validate required fields
        issues.extend(self._validate_required_fields(card))
        
        # 2. Validate URL
        if "url" in card:
            url_result = self.url_validator.validate_url(card["url"], field_name="agent_card.url", require_https=True)
            issues.extend(url_result.issues)
        
        # 3. Validate protocol version
        if "protocolVersion" in card:
            version_result = self.semver_validator.validate_version(card["protocolVersion"])
            issues.extend(version_result.issues)
        
        # 4. Validate transport
        if "preferredTransport" in card:
            issues.extend(self._validate_transport(card["preferredTransport"]))
        
        # 5. Validate capabilities
        if "capabilities" in card:
            issues.extend(self._validate_capabilities(card["capabilities"]))
        
        # 6. Validate provider
        if "provider" in card:
            issues.extend(self._validate_provider(card["provider"]))
        
        # 7. Validate skills
        if "skills" in card:
            issues.extend(self._validate_skills(card["skills"]))
        
        # 8. Validate additional interfaces (if present)
        if "additionalInterfaces" in card:
            issues.extend(self._validate_additional_interfaces(card["additionalInterfaces"], card))
        
        # Calculate score
        error_count = sum(1 for i in issues if i.severity == ValidationSeverity.ERROR)
        warning_count = sum(1 for i in issues if i.severity == ValidationSeverity.WARNING)
        score = max(0, 100 - (error_count * 15) - (warning_count * 5))
        
        return ValidationResult(
            success=error_count == 0,
            score=score,
            issues=issues
        )
    
    def _validate_required_fields(self, card: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate that all required fields are present."""
        issues: List[ValidationIssue] = []
        
        for field in self.REQUIRED_FIELDS:
            if field not in card or card[field] is None:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_REQUIRED_FIELD",
                    message=f"Agent card missing required field: {field}",
                    path=f"agent_card.{field}"
                ))
            elif isinstance(card[field], str) and not card[field].strip():
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="EMPTY_REQUIRED_FIELD",
                    message=f"Agent card required field is empty: {field}",
                    path=f"agent_card.{field}"
                ))
        
        return issues
    
    def _validate_transport(self, transport: str) -> List[ValidationIssue]:
        """Validate transport protocol."""
        issues: List[ValidationIssue] = []
        
        if transport not in self.VALID_TRANSPORTS:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="INVALID_TRANSPORT",
                message=f"Invalid transport protocol: {transport}. Valid options: {', '.join(self.VALID_TRANSPORTS)}",
                path="agent_card.preferredTransport"
            ))
        
        return issues
    
    def _validate_capabilities(self, capabilities: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate agent capabilities."""
        issues: List[ValidationIssue] = []
        
        if not isinstance(capabilities, dict):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="INVALID_CAPABILITIES_TYPE",
                message="Capabilities must be an object",
                path="agent_card.capabilities"
            ))
            return issues
        
        # Validate boolean capability flags
        boolean_capabilities = ["streaming", "pushNotifications", "batchProcessing"]
        for cap in boolean_capabilities:
            if cap in capabilities and not isinstance(capabilities[cap], bool):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="INVALID_CAPABILITY_TYPE",
                    message=f"Capability {cap} should be boolean",
                    path=f"agent_card.capabilities.{cap}"
                ))
        
        # Check for empty capabilities
        if not capabilities:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="EMPTY_CAPABILITIES",
                message="Agent card has empty capabilities object",
                path="agent_card.capabilities"
            ))
        
        return issues
    
    def _validate_provider(self, provider: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate provider information."""
        issues: List[ValidationIssue] = []
        
        if not isinstance(provider, dict):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="INVALID_PROVIDER_TYPE",
                message="Provider must be an object",
                path="agent_card.provider"
            ))
            return issues
        
        # Check required provider fields
        required_provider_fields = ["name"]
        for field in required_provider_fields:
            if field not in provider or not provider[field]:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_PROVIDER_FIELD",
                    message=f"Provider missing required field: {field}",
                    path=f"agent_card.provider.{field}"
                ))
        
        # Validate provider URL if present
        if "url" in provider and provider["url"]:
            url_result = self.url_validator.validate_url(provider["url"], field_name="agent_card.provider.url", require_https=False)
            for issue in url_result.issues:
                issues.append(ValidationIssue(
                    severity=issue.severity,
                    code=issue.code,
                    message=f"Provider URL: {issue.message}",
                    path=f"agent_card.provider.url"
                ))
        
        return issues
    
    def _validate_skills(self, skills: List[Dict[str, Any]]) -> List[ValidationIssue]:
        """Validate skills array."""
        issues: List[ValidationIssue] = []
        
        if not isinstance(skills, list):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="INVALID_SKILLS_TYPE",
                message="Skills must be an array",
                path="agent_card.skills"
            ))
            return issues
        
        if not skills:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="EMPTY_SKILLS",
                message="Agent card has empty skills array",
                path="agent_card.skills"
            ))
            return issues
        
        # Validate each skill
        for idx, skill in enumerate(skills):
            if not isinstance(skill, dict):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_SKILL_TYPE",
                    message=f"Skill at index {idx} must be an object",
                    path=f"agent_card.skills[{idx}]"
                ))
                continue
            
            # Check required skill fields
            if "name" not in skill or not skill["name"]:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_SKILL_NAME",
                    message=f"Skill at index {idx} missing name",
                    path=f"agent_card.skills[{idx}].name"
                ))
            
            if "description" not in skill or not skill["description"]:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="MISSING_SKILL_DESCRIPTION",
                    message=f"Skill '{skill.get('name', idx)}' missing description",
                    path=f"agent_card.skills[{idx}].description"
                ))
        
        return issues
    
    def _validate_additional_interfaces(
        self,
        interfaces: List[Dict[str, Any]],
        card: Dict[str, Any]
    ) -> List[ValidationIssue]:
        """Validate additional interfaces configuration."""
        issues: List[ValidationIssue] = []
        
        if not isinstance(interfaces, list):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="INVALID_INTERFACES_TYPE",
                message="additionalInterfaces must be an array",
                path="agent_card.additionalInterfaces"
            ))
            return issues
        
        # Track URLs and transports to detect conflicts
        url_transport_map: Dict[str, str] = {}
        main_url = card.get("url", "")
        preferred_transport = card.get("preferredTransport", "JSONRPC")
        
        if main_url:
            url_transport_map[main_url] = preferred_transport
        
        for idx, interface in enumerate(interfaces):
            if not isinstance(interface, dict):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_INTERFACE_TYPE",
                    message=f"Interface at index {idx} must be an object",
                    path=f"agent_card.additionalInterfaces[{idx}]"
                ))
                continue
            
            # Validate required interface fields
            if "url" not in interface or not interface["url"]:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_INTERFACE_URL",
                    message=f"Interface at index {idx} missing URL",
                    path=f"agent_card.additionalInterfaces[{idx}].url"
                ))
            else:
                # Validate interface URL
                url_result = self.url_validator.validate_url(interface["url"], field_name=f"agent_card.additionalInterfaces[{idx}].url", require_https=True)
                issues.extend(url_result.issues)
            
            if "transport" not in interface or not interface["transport"]:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_INTERFACE_TRANSPORT",
                    message=f"Interface at index {idx} missing transport",
                    path=f"agent_card.additionalInterfaces[{idx}].transport"
                ))
            else:
                # Validate transport
                transport_issues = self._validate_transport(interface["transport"])
                issues.extend(transport_issues)
                
                # Check for transport conflicts on same URL
                url = interface.get("url", "")
                transport = interface["transport"]
                if url and url in url_transport_map:
                    if url_transport_map[url] != transport:
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.ERROR,
                            code="TRANSPORT_URL_CONFLICT",
                            message=f"Conflicting transport protocols for URL {url}: {url_transport_map[url]} vs {transport}",
                            path=f"agent_card.additionalInterfaces[{idx}]"
                        ))
                elif url:
                    url_transport_map[url] = transport
        
        return issues
