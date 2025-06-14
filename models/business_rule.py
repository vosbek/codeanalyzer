"""
Business Rule Data Model
========================

This module defines the core data structures for representing business rules
extracted from Struts applications. Business rules are the key focus of the
analysis as they represent the critical business logic that must be preserved
during migration.

Author: Claude Code Assistant
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from enum import Enum, auto
from datetime import datetime
import hashlib


class BusinessRuleType(Enum):
    """Enumeration of business rule types."""
    VALIDATION = "validation"
    WORKFLOW = "workflow"
    SECURITY = "security"
    DATA = "data"
    UI = "ui"
    INTEGRATION = "integration"
    BUSINESS_LOGIC = "business_logic"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class BusinessRuleComplexity(Enum):
    """Enumeration of business rule complexity levels."""
    SIMPLE = auto()      # Basic validation or simple logic
    MODERATE = auto()    # Multiple conditions or moderate complexity
    COMPLEX = auto()     # Complex business logic with multiple dependencies
    CRITICAL = auto()    # Mission-critical rules with high complexity


class BusinessRuleSource(Enum):
    """Enumeration of sources where business rules can be found."""
    STRUTS_CONFIG = "struts_config"
    VALIDATION_XML = "validation_xml"
    ACTION_CLASS = "action_class"
    JSP_FILE = "jsp_file"
    FORM_BEAN = "form_bean"
    INTERCEPTOR = "interceptor"
    COMMENT = "comment"
    METHOD_BODY = "method_body"
    ANNOTATION = "annotation"


@dataclass(frozen=True, eq=True)
class BusinessRuleLocation:
    """Represents the exact location of a business rule in the codebase."""
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    element_xpath: Optional[str] = None  # For XML elements
    
    def __str__(self) -> str:
        """String representation of the location."""
        location_parts = [self.file_path]
        
        if self.class_name:
            location_parts.append(f"class={self.class_name}")
        if self.method_name:
            location_parts.append(f"method={self.method_name}")
        if self.line_number:
            location_parts.append(f"line={self.line_number}")
        if self.element_xpath:
            location_parts.append(f"xpath={self.element_xpath}")
            
        return " | ".join(location_parts)


@dataclass
class BusinessRuleEvidence:
    """Evidence supporting the identification of a business rule."""
    code_snippet: str
    context: str
    confidence_score: float = 1.0  # 0.0 to 1.0
    extraction_method: str = "manual"
    
    def __post_init__(self):
        """Validate evidence data."""
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError("Confidence score must be between 0.0 and 1.0")


@dataclass
class BusinessRuleImpact:
    """Represents the business impact of a rule."""
    affected_users: Set[str] = field(default_factory=set)
    business_processes: Set[str] = field(default_factory=set)
    data_entities: Set[str] = field(default_factory=set)
    external_systems: Set[str] = field(default_factory=set)
    compliance_requirements: Set[str] = field(default_factory=set)
    
    @property
    def total_impact_score(self) -> int:
        """Calculate total impact score based on affected areas."""
        return (
            len(self.affected_users) +
            len(self.business_processes) * 2 +  # Processes weighted more heavily
            len(self.data_entities) +
            len(self.external_systems) * 3 +    # External systems critical
            len(self.compliance_requirements) * 4  # Compliance most critical
        )


@dataclass
class BusinessRule:
    """
    Comprehensive representation of a business rule extracted from Struts applications.
    
    This is the core data structure for business rule analysis and migration planning.
    Each business rule represents a discrete piece of business logic that must be
    understood and preserved during migration.
    """
    
    # Core identification
    id: str
    name: str
    description: str
    rule_type: BusinessRuleType
    
    # Source information
    source: BusinessRuleSource
    location: BusinessRuleLocation
    evidence: BusinessRuleEvidence
    
    # Business context
    business_domain: str = "unknown"
    business_context: str = ""
    business_rationale: str = ""
    impact: BusinessRuleImpact = field(default_factory=BusinessRuleImpact)
    
    # Technical details
    complexity: BusinessRuleComplexity = BusinessRuleComplexity.MODERATE
    dependencies: Set[str] = field(default_factory=set)
    affected_components: Set[str] = field(default_factory=set)
    
    # Migration information
    migration_risk: str = "medium"  # low, medium, high, critical
    migration_effort_hours: Optional[int] = None
    migration_notes: str = ""
    modernization_recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    extracted_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    version: str = "1.0"
    tags: Set[str] = field(default_factory=set)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and processing."""
        # Validate required fields
        if not self.id:
            raise ValueError("Business rule ID cannot be empty")
        if not self.name:
            raise ValueError("Business rule name cannot be empty")
        if not self.description:
            raise ValueError("Business rule description cannot be empty")
            
        # Auto-generate ID if needed
        if self.id == "auto":
            self.id = self._generate_id()
            
        # Ensure timestamps are set
        if not self.extracted_at:
            self.extracted_at = datetime.now()
        if not self.last_updated:
            self.last_updated = datetime.now()
    
    def _generate_id(self) -> str:
        """Generate a unique ID for the business rule."""
        # Create hash from key attributes
        hash_input = f"{self.name}_{self.location.file_path}_{self.rule_type.value}"
        return f"br_{hashlib.md5(hash_input.encode()).hexdigest()[:12]}"
    
    @property
    def complexity_score(self) -> int:
        """Calculate numeric complexity score."""
        base_scores = {
            BusinessRuleComplexity.SIMPLE: 1,
            BusinessRuleComplexity.MODERATE: 3,
            BusinessRuleComplexity.COMPLEX: 7,
            BusinessRuleComplexity.CRITICAL: 15
        }
        
        base_score = base_scores[self.complexity]
        
        # Add complexity for dependencies
        dependency_score = len(self.dependencies) * 2
        
        # Add complexity for affected components
        component_score = len(self.affected_components)
        
        return base_score + dependency_score + component_score
    
    @property
    def is_high_impact(self) -> bool:
        """Determine if this is a high-impact business rule."""
        return (
            self.impact.total_impact_score > 10 or
            self.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL] or
            self.migration_risk in ["high", "critical"]
        )
    
    def add_dependency(self, dependency_id: str) -> None:
        """Add a dependency to this business rule."""
        self.dependencies.add(dependency_id)
        self.last_updated = datetime.now()
    
    def add_affected_component(self, component_name: str) -> None:
        """Add an affected component to this business rule."""
        self.affected_components.add(component_name)
        self.last_updated = datetime.now()
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to this business rule."""
        self.tags.add(tag.lower())
        self.last_updated = datetime.now()
    
    def update_migration_assessment(self,
                                  risk: str,
                                  effort_hours: Optional[int] = None,
                                  notes: str = "",
                                  recommendations: Optional[List[str]] = None) -> None:
        """Update migration assessment information."""
        if risk not in ["low", "medium", "high", "critical"]:
            raise ValueError("Migration risk must be one of: low, medium, high, critical")
            
        self.migration_risk = risk
        if effort_hours is not None:
            self.migration_effort_hours = effort_hours
        if notes:
            self.migration_notes = notes
        if recommendations:
            self.modernization_recommendations.extend(recommendations)
        
        self.last_updated = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert business rule to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type.value,
            "source": self.source.value,
            "location": {
                "file_path": self.location.file_path,
                "line_number": self.location.line_number,
                "column_number": self.location.column_number,
                "method_name": self.location.method_name,
                "class_name": self.location.class_name,
                "element_xpath": self.location.element_xpath
            },
            "evidence": {
                "code_snippet": self.evidence.code_snippet,
                "context": self.evidence.context,
                "confidence_score": self.evidence.confidence_score,
                "extraction_method": self.evidence.extraction_method
            },
            "business_domain": self.business_domain,
            "business_context": self.business_context,
            "business_rationale": self.business_rationale,
            "impact": {
                "affected_users": list(self.impact.affected_users),
                "business_processes": list(self.impact.business_processes),
                "data_entities": list(self.impact.data_entities),
                "external_systems": list(self.impact.external_systems),
                "compliance_requirements": list(self.impact.compliance_requirements),
                "total_impact_score": self.impact.total_impact_score
            },
            "complexity": self.complexity.name,
            "complexity_score": self.complexity_score,
            "dependencies": list(self.dependencies),
            "affected_components": list(self.affected_components),
            "migration_risk": self.migration_risk,
            "migration_effort_hours": self.migration_effort_hours,
            "migration_notes": self.migration_notes,
            "modernization_recommendations": self.modernization_recommendations,
            "extracted_at": self.extracted_at.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "version": self.version,
            "tags": list(self.tags),
            "custom_attributes": self.custom_attributes,
            "is_high_impact": self.is_high_impact
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BusinessRule":
        """Create BusinessRule instance from dictionary."""
        # Parse location
        location_data = data.get("location", {})
        location = BusinessRuleLocation(
            file_path=location_data.get("file_path", ""),
            line_number=location_data.get("line_number"),
            column_number=location_data.get("column_number"),
            method_name=location_data.get("method_name"),
            class_name=location_data.get("class_name"),
            element_xpath=location_data.get("element_xpath")
        )
        
        # Parse evidence
        evidence_data = data.get("evidence", {})
        evidence = BusinessRuleEvidence(
            code_snippet=evidence_data.get("code_snippet", ""),
            context=evidence_data.get("context", ""),
            confidence_score=evidence_data.get("confidence_score", 1.0),
            extraction_method=evidence_data.get("extraction_method", "manual")
        )
        
        # Parse impact
        impact_data = data.get("impact", {})
        impact = BusinessRuleImpact(
            affected_users=set(impact_data.get("affected_users", [])),
            business_processes=set(impact_data.get("business_processes", [])),
            data_entities=set(impact_data.get("data_entities", [])),
            external_systems=set(impact_data.get("external_systems", [])),
            compliance_requirements=set(impact_data.get("compliance_requirements", []))
        )
        
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            rule_type=BusinessRuleType(data["rule_type"]),
            source=BusinessRuleSource(data["source"]),
            location=location,
            evidence=evidence,
            business_domain=data.get("business_domain", "unknown"),
            business_context=data.get("business_context", ""),
            business_rationale=data.get("business_rationale", ""),
            impact=impact,
            complexity=BusinessRuleComplexity[data.get("complexity", "MODERATE")],
            dependencies=set(data.get("dependencies", [])),
            affected_components=set(data.get("affected_components", [])),
            migration_risk=data.get("migration_risk", "medium"),
            migration_effort_hours=data.get("migration_effort_hours"),
            migration_notes=data.get("migration_notes", ""),
            modernization_recommendations=data.get("modernization_recommendations", []),
            extracted_at=datetime.fromisoformat(data.get("extracted_at", datetime.now().isoformat())),
            last_updated=datetime.fromisoformat(data.get("last_updated", datetime.now().isoformat())),
            version=data.get("version", "1.0"),
            tags=set(data.get("tags", [])),
            custom_attributes=data.get("custom_attributes", {})
        )
    
    def __str__(self) -> str:
        """String representation of the business rule."""
        return f"BusinessRule(id={self.id}, name='{self.name}', type={self.rule_type.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"BusinessRule(id='{self.id}', name='{self.name}', "
            f"type={self.rule_type.value}, complexity={self.complexity.name}, "
            f"location='{self.location.file_path}')"
        )