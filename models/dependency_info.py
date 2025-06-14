"""
Dependency Information Data Model
=================================

This module defines data structures for representing dependencies between
components in Struts applications. Dependencies are critical for understanding
system architecture and planning migration strategies.

Author: Claude Code Assistant
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from enum import Enum, auto
from datetime import datetime


class DependencyType(Enum):
    """Enumeration of dependency types."""
    INHERITANCE = "inheritance"          # Class inheritance relationship
    COMPOSITION = "composition"          # Strong composition relationship
    AGGREGATION = "aggregation"          # Weak aggregation relationship
    ASSOCIATION = "association"          # General association
    IMPLEMENTATION = "implementation"    # Interface implementation
    METHOD_CALL = "method_call"         # Method invocation dependency
    FIELD_ACCESS = "field_access"       # Field access dependency
    ANNOTATION = "annotation"           # Annotation usage
    IMPORT = "import"                   # Import statement dependency
    STRUTS_CONFIG = "struts_config"     # Struts configuration dependency
    ACTION_FORWARD = "action_forward"   # Action forward dependency
    FORM_BINDING = "form_binding"       # Form bean binding
    VALIDATION = "validation"           # Validation rule dependency
    INTERCEPTOR = "interceptor"         # Interceptor chain dependency
    JSP_INCLUDE = "jsp_include"         # JSP inclusion dependency
    TILE_DEFINITION = "tile_definition" # Tiles framework dependency
    EXTERNAL_LIB = "external_lib"       # External library dependency
    DATABASE = "database"               # Database dependency
    WEB_SERVICE = "web_service"         # Web service dependency
    MESSAGE_RESOURCE = "message_resource" # Message resource dependency
    UNKNOWN = "unknown"


class DependencyStrength(Enum):
    """Enumeration of dependency strength levels."""
    WEAK = auto()        # Loose coupling, easy to modify
    MODERATE = auto()    # Some coupling, moderate modification effort
    STRONG = auto()      # Tight coupling, difficult to modify
    CRITICAL = auto()    # Critical dependency, very difficult to modify


class DependencyDirection(Enum):
    """Enumeration of dependency directions."""
    OUTGOING = "outgoing"  # This component depends on another
    INCOMING = "incoming"  # Another component depends on this
    BIDIRECTIONAL = "bidirectional"  # Mutual dependency


@dataclass
class DependencyContext:
    """Context information for a dependency relationship."""
    usage_context: str = ""           # How the dependency is used
    business_context: str = ""        # Business reason for the dependency
    architectural_layer: str = ""     # Which architectural layer (presentation, business, data)
    coupling_reason: str = ""         # Why these components are coupled
    migration_impact: str = "medium"  # Impact on migration (low, medium, high, critical)


@dataclass
class DependencyMetrics:
    """Metrics related to dependency analysis."""
    usage_frequency: int = 0          # How often this dependency is used
    fan_in: int = 0                   # Number of components depending on this
    fan_out: int = 0                  # Number of components this depends on
    instability: float = 0.0          # Instability metric (fan_out / (fan_in + fan_out))
    abstractness: float = 0.0         # How abstract the dependency is
    distance_from_main: float = 0.0   # Distance from main sequence
    
    @property
    def stability_score(self) -> float:
        """Calculate stability score (1 - instability)."""
        return 1.0 - self.instability
    
    @property
    def is_stable(self) -> bool:
        """Check if this dependency is stable."""
        return self.instability < 0.3


@dataclass
class DependencyInfo:
    """
    Comprehensive information about a dependency relationship between components.
    
    This model captures detailed information about how components depend on each
    other, which is crucial for understanding system architecture and planning
    migration strategies.
    """
    
    # Core identification
    id: str
    source_component: str              # Component that has the dependency
    target_component: str              # Component that is depended upon
    dependency_type: DependencyType
    
    # Dependency characteristics
    strength: DependencyStrength = DependencyStrength.MODERATE
    direction: DependencyDirection = DependencyDirection.OUTGOING
    is_transitive: bool = False        # Whether this is a transitive dependency
    is_optional: bool = False          # Whether this dependency is optional
    is_runtime: bool = True            # Whether this is a runtime dependency
    
    # Context and location
    context: DependencyContext = field(default_factory=DependencyContext)
    source_location: str = ""          # Where in the source this dependency occurs
    line_number: Optional[int] = None
    method_context: Optional[str] = None
    
    # Metrics and analysis
    metrics: DependencyMetrics = field(default_factory=DependencyMetrics)
    
    # Business impact
    business_criticality: str = "medium"  # low, medium, high, critical
    affects_business_logic: bool = False
    affects_data_integrity: bool = False
    affects_user_experience: bool = False
    affects_security: bool = False
    
    # Migration information
    migration_complexity: str = "medium"   # low, medium, high, critical
    migration_strategy: str = ""           # Recommended migration approach
    breaking_change_risk: str = "medium"   # Risk of breaking changes
    modernization_recommendations: List[str] = field(default_factory=list)
    
    # Alternative implementations
    alternative_implementations: List[str] = field(default_factory=list)
    spring_boot_equivalents: List[str] = field(default_factory=list)
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    last_analyzed: datetime = field(default_factory=datetime.now)
    confidence_score: float = 1.0         # Confidence in dependency detection (0.0-1.0)
    analysis_method: str = "static"       # How this dependency was discovered
    version: str = "1.0"
    tags: Set[str] = field(default_factory=set)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and processing."""
        if not self.id:
            raise ValueError("Dependency ID cannot be empty")
        if not self.source_component:
            raise ValueError("Source component cannot be empty")
        if not self.target_component:
            raise ValueError("Target component cannot be empty")
        if self.source_component == self.target_component:
            raise ValueError("Source and target components cannot be the same")
            
        # Validate confidence score
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError("Confidence score must be between 0.0 and 1.0")
            
        # Auto-generate ID if needed
        if self.id == "auto":
            self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate a unique ID for the dependency."""
        import hashlib
        hash_input = f"{self.source_component}_{self.target_component}_{self.dependency_type.value}"
        return f"dep_{hashlib.md5(hash_input.encode()).hexdigest()[:12]}"
    
    @property
    def is_high_impact(self) -> bool:
        """Check if this is a high-impact dependency."""
        return (
            self.strength in [DependencyStrength.STRONG, DependencyStrength.CRITICAL] or
            self.business_criticality in ["high", "critical"] or
            self.migration_complexity in ["high", "critical"] or
            any([
                self.affects_business_logic,
                self.affects_data_integrity,
                self.affects_security
            ])
        )
    
    @property
    def is_struts_specific(self) -> bool:
        """Check if this dependency is Struts-specific."""
        struts_types = [
            DependencyType.STRUTS_CONFIG,
            DependencyType.ACTION_FORWARD,
            DependencyType.FORM_BINDING,
            DependencyType.VALIDATION,
            DependencyType.INTERCEPTOR,
            DependencyType.TILE_DEFINITION
        ]
        return self.dependency_type in struts_types
    
    @property
    def migration_priority_score(self) -> int:
        """Calculate migration priority score."""
        score = 0
        
        # Base score from strength
        strength_scores = {
            DependencyStrength.WEAK: 1,
            DependencyStrength.MODERATE: 3,
            DependencyStrength.STRONG: 7,
            DependencyStrength.CRITICAL: 15
        }
        score += strength_scores[self.strength]
        
        # Add score for business impact
        if self.business_criticality == "critical":
            score += 20
        elif self.business_criticality == "high":
            score += 10
        elif self.business_criticality == "medium":
            score += 5
        
        # Add score for affected areas
        if self.affects_business_logic:
            score += 10
        if self.affects_data_integrity:
            score += 15
        if self.affects_security:
            score += 12
        if self.affects_user_experience:
            score += 5
        
        # Add score for Struts-specific dependencies
        if self.is_struts_specific:
            score += 8
        
        # Add score for migration complexity
        complexity_scores = {
            "low": 1,
            "medium": 3,
            "high": 7,
            "critical": 15
        }
        score += complexity_scores.get(self.migration_complexity, 3)
        
        return score
    
    def update_metrics(self, **kwargs) -> None:
        """Update dependency metrics."""
        for key, value in kwargs.items():
            if hasattr(self.metrics, key):
                setattr(self.metrics, key, value)
        
        # Recalculate derived metrics
        total_deps = self.metrics.fan_in + self.metrics.fan_out
        if total_deps > 0:
            self.metrics.instability = self.metrics.fan_out / total_deps
    
    def add_alternative_implementation(self, implementation: str) -> None:
        """Add an alternative implementation approach."""
        if implementation not in self.alternative_implementations:
            self.alternative_implementations.append(implementation)
    
    def add_spring_boot_equivalent(self, equivalent: str) -> None:
        """Add a Spring Boot equivalent for this dependency."""
        if equivalent not in self.spring_boot_equivalents:
            self.spring_boot_equivalents.append(equivalent)
    
    def add_modernization_recommendation(self, recommendation: str) -> None:
        """Add a modernization recommendation."""
        if recommendation not in self.modernization_recommendations:
            self.modernization_recommendations.append(recommendation)
    
    def update_business_impact(self, 
                             criticality: Optional[str] = None,
                             affects_business_logic: Optional[bool] = None,
                             affects_data_integrity: Optional[bool] = None,
                             affects_user_experience: Optional[bool] = None,
                             affects_security: Optional[bool] = None) -> None:
        """Update business impact assessment."""
        if criticality is not None:
            if criticality not in ["low", "medium", "high", "critical"]:
                raise ValueError("Criticality must be one of: low, medium, high, critical")
            self.business_criticality = criticality
        
        if affects_business_logic is not None:
            self.affects_business_logic = affects_business_logic
        if affects_data_integrity is not None:
            self.affects_data_integrity = affects_data_integrity
        if affects_user_experience is not None:
            self.affects_user_experience = affects_user_experience
        if affects_security is not None:
            self.affects_security = affects_security
        
        self.last_analyzed = datetime.now()
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to this dependency."""
        self.tags.add(tag.lower())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert dependency info to dictionary representation."""
        return {
            "id": self.id,
            "source_component": self.source_component,
            "target_component": self.target_component,
            "dependency_type": self.dependency_type.value,
            "strength": self.strength.name,
            "direction": self.direction.value,
            "is_transitive": self.is_transitive,
            "is_optional": self.is_optional,
            "is_runtime": self.is_runtime,
            "context": {
                "usage_context": self.context.usage_context,
                "business_context": self.context.business_context,
                "architectural_layer": self.context.architectural_layer,
                "coupling_reason": self.context.coupling_reason,
                "migration_impact": self.context.migration_impact
            },
            "source_location": self.source_location,
            "line_number": self.line_number,
            "method_context": self.method_context,
            "metrics": {
                "usage_frequency": self.metrics.usage_frequency,
                "fan_in": self.metrics.fan_in,
                "fan_out": self.metrics.fan_out,
                "instability": self.metrics.instability,
                "abstractness": self.metrics.abstractness,
                "distance_from_main": self.metrics.distance_from_main,
                "stability_score": self.metrics.stability_score,
                "is_stable": self.metrics.is_stable
            },
            "business_criticality": self.business_criticality,
            "affects_business_logic": self.affects_business_logic,
            "affects_data_integrity": self.affects_data_integrity,
            "affects_user_experience": self.affects_user_experience,
            "affects_security": self.affects_security,
            "migration_complexity": self.migration_complexity,
            "migration_strategy": self.migration_strategy,
            "breaking_change_risk": self.breaking_change_risk,
            "migration_priority_score": self.migration_priority_score,
            "modernization_recommendations": self.modernization_recommendations,
            "alternative_implementations": self.alternative_implementations,
            "spring_boot_equivalents": self.spring_boot_equivalents,
            "is_high_impact": self.is_high_impact,
            "is_struts_specific": self.is_struts_specific,
            "discovered_at": self.discovered_at.isoformat(),
            "last_analyzed": self.last_analyzed.isoformat(),
            "confidence_score": self.confidence_score,
            "analysis_method": self.analysis_method,
            "version": self.version,
            "tags": list(self.tags),
            "custom_attributes": self.custom_attributes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DependencyInfo":
        """Create DependencyInfo instance from dictionary."""
        # Parse context
        context_data = data.get("context", {})
        context = DependencyContext(
            usage_context=context_data.get("usage_context", ""),
            business_context=context_data.get("business_context", ""),
            architectural_layer=context_data.get("architectural_layer", ""),
            coupling_reason=context_data.get("coupling_reason", ""),
            migration_impact=context_data.get("migration_impact", "medium")
        )
        
        # Parse metrics
        metrics_data = data.get("metrics", {})
        metrics = DependencyMetrics(
            usage_frequency=metrics_data.get("usage_frequency", 0),
            fan_in=metrics_data.get("fan_in", 0),
            fan_out=metrics_data.get("fan_out", 0),
            instability=metrics_data.get("instability", 0.0),
            abstractness=metrics_data.get("abstractness", 0.0),
            distance_from_main=metrics_data.get("distance_from_main", 0.0)
        )
        
        return cls(
            id=data["id"],
            source_component=data["source_component"],
            target_component=data["target_component"],
            dependency_type=DependencyType(data["dependency_type"]),
            strength=DependencyStrength[data.get("strength", "MODERATE")],
            direction=DependencyDirection(data.get("direction", "outgoing")),
            is_transitive=data.get("is_transitive", False),
            is_optional=data.get("is_optional", False),
            is_runtime=data.get("is_runtime", True),
            context=context,
            source_location=data.get("source_location", ""),
            line_number=data.get("line_number"),
            method_context=data.get("method_context"),
            metrics=metrics,
            business_criticality=data.get("business_criticality", "medium"),
            affects_business_logic=data.get("affects_business_logic", False),
            affects_data_integrity=data.get("affects_data_integrity", False),
            affects_user_experience=data.get("affects_user_experience", False),
            affects_security=data.get("affects_security", False),
            migration_complexity=data.get("migration_complexity", "medium"),
            migration_strategy=data.get("migration_strategy", ""),
            breaking_change_risk=data.get("breaking_change_risk", "medium"),
            modernization_recommendations=data.get("modernization_recommendations", []),
            alternative_implementations=data.get("alternative_implementations", []),
            spring_boot_equivalents=data.get("spring_boot_equivalents", []),
            discovered_at=datetime.fromisoformat(data.get("discovered_at", datetime.now().isoformat())),
            last_analyzed=datetime.fromisoformat(data.get("last_analyzed", datetime.now().isoformat())),
            confidence_score=data.get("confidence_score", 1.0),
            analysis_method=data.get("analysis_method", "static"),
            version=data.get("version", "1.0"),
            tags=set(data.get("tags", [])),
            custom_attributes=data.get("custom_attributes", {})
        )
    
    def __str__(self) -> str:
        """String representation of the dependency info."""
        return f"DependencyInfo({self.source_component} -> {self.target_component}, {self.dependency_type.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"DependencyInfo(id='{self.id}', source='{self.source_component}', "
            f"target='{self.target_component}', type={self.dependency_type.value}, "
            f"strength={self.strength.name})"
        )