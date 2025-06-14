"""
Class Information Data Model
============================

This module defines data structures for representing Java class information
extracted during Struts application analysis. This includes class metadata,
complexity metrics, and relationships.

Author: Claude Code Assistant
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from enum import Enum, auto
from datetime import datetime
from pathlib import Path


class ClassType(Enum):
    """Enumeration of class types in Struts applications."""
    ACTION = "action"
    FORM_BEAN = "form_bean"
    INTERCEPTOR = "interceptor"
    SERVICE = "service"
    DAO = "dao"
    UTILITY = "utility"
    EXCEPTION = "exception"
    INTERFACE = "interface"
    ABSTRACT_CLASS = "abstract_class"
    ENUM = "enum"
    ANNOTATION = "annotation"
    UNKNOWN = "unknown"


class ClassComplexity(Enum):
    """Enumeration of class complexity levels."""
    SIMPLE = auto()      # Few methods, simple logic
    MODERATE = auto()    # Multiple methods, moderate complexity
    COMPLEX = auto()     # Many methods, complex business logic
    CRITICAL = auto()    # Very complex, mission-critical functionality


@dataclass
class ClassMetrics:
    """Metrics for class complexity analysis."""
    lines_of_code: int = 0
    number_of_methods: int = 0
    number_of_fields: int = 0
    cyclomatic_complexity: int = 0
    cognitive_complexity: int = 0
    inheritance_depth: int = 0
    coupling_factor: int = 0
    cohesion_score: float = 0.0
    
    @property
    def overall_complexity_score(self) -> int:
        """Calculate overall complexity score."""
        # Weighted combination of metrics
        score = (
            (self.lines_of_code // 10) +
            (self.number_of_methods * 2) +
            (self.number_of_fields) +
            (self.cyclomatic_complexity * 3) +
            (self.cognitive_complexity * 2) +
            (self.inheritance_depth * 5) +
            (self.coupling_factor * 2) +
            max(0, int((1.0 - self.cohesion_score) * 10))  # Lower cohesion = higher complexity
        )
        return max(0, score)


@dataclass
class ClassRelationship:
    """Represents a relationship between classes."""
    target_class: str
    relationship_type: str  # inheritance, composition, aggregation, dependency
    strength: int = 1  # How strong the relationship is
    description: str = ""


@dataclass
class MethodSignature:
    """Represents a method signature within a class."""
    name: str
    return_type: str
    parameters: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    is_abstract: bool = False
    is_static: bool = False
    is_final: bool = False
    
    @property
    def signature_string(self) -> str:
        """Generate string representation of method signature."""
        modifiers_str = " ".join(self.modifiers) if self.modifiers else ""
        params_str = ", ".join(self.parameters)
        annotations_str = " ".join(f"@{ann}" for ann in self.annotations)
        
        parts = [annotations_str, modifiers_str, self.return_type, f"{self.name}({params_str})"]
        return " ".join(part for part in parts if part)


@dataclass
class ClassInfo:
    """
    Comprehensive information about a Java class in a Struts application.
    
    This model captures all relevant information about a class including its
    metadata, relationships, complexity metrics, and business significance.
    """
    
    # Core identification
    name: str
    package: str
    file_path: str
    class_type: ClassType = ClassType.UNKNOWN
    
    # Class structure
    superclass: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    inner_classes: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    
    # Methods and fields
    methods: List[MethodSignature] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    constructors: List[MethodSignature] = field(default_factory=list)
    
    # Relationships
    dependencies: Set[str] = field(default_factory=set)  # Classes this class depends on
    dependents: Set[str] = field(default_factory=set)    # Classes that depend on this class
    relationships: List[ClassRelationship] = field(default_factory=list)
    
    # Metrics and analysis
    metrics: ClassMetrics = field(default_factory=ClassMetrics)
    complexity: ClassComplexity = ClassComplexity.MODERATE
    
    # Business context
    business_purpose: str = ""
    business_domain: str = "unknown"
    struts_role: str = ""  # action, form, interceptor, etc.
    migration_priority: str = "medium"  # low, medium, high, critical
    
    # Struts-specific information
    action_mappings: List[str] = field(default_factory=list)  # For Action classes
    form_properties: List[str] = field(default_factory=list)  # For Form beans
    validation_rules: List[str] = field(default_factory=list)
    
    # Migration information
    migration_recommendations: List[str] = field(default_factory=list)
    modernization_notes: str = ""
    equivalent_spring_patterns: List[str] = field(default_factory=list)
    
    # Metadata
    analyzed_at: datetime = field(default_factory=datetime.now)
    last_modified: Optional[datetime] = None
    version: str = "1.0"
    tags: Set[str] = field(default_factory=set)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and processing."""
        if not self.name:
            raise ValueError("Class name cannot be empty")
        if not self.file_path:
            raise ValueError("File path cannot be empty")
            
        # Auto-detect class type from name patterns
        if self.class_type == ClassType.UNKNOWN:
            self.class_type = self._detect_class_type()
            
        # Set file modification time if available
        try:
            file_path = Path(self.file_path)
            if file_path.exists():
                self.last_modified = datetime.fromtimestamp(file_path.stat().st_mtime)
        except Exception:
            pass  # Ignore if file doesn't exist or can't be accessed
    
    def _detect_class_type(self) -> ClassType:
        """Auto-detect class type based on naming patterns and inheritance."""
        name_lower = self.name.lower()
        
        # Check inheritance patterns
        if self.superclass:
            superclass_lower = self.superclass.lower()
            if "action" in superclass_lower:
                return ClassType.ACTION
            elif "form" in superclass_lower or "bean" in superclass_lower:
                return ClassType.FORM_BEAN
            elif "interceptor" in superclass_lower:
                return ClassType.INTERCEPTOR
            elif "exception" in superclass_lower:
                return ClassType.EXCEPTION
            elif "dao" in superclass_lower or "repository" in superclass_lower:
                return ClassType.DAO
            elif "service" in superclass_lower:
                return ClassType.SERVICE
        
        # Check interface implementations
        for interface in self.interfaces:
            interface_lower = interface.lower()
            if "action" in interface_lower:
                return ClassType.ACTION
            elif "interceptor" in interface_lower:
                return ClassType.INTERCEPTOR
        
        # Check class name patterns
        if "action" in name_lower:
            return ClassType.ACTION
        elif "form" in name_lower or "bean" in name_lower:
            return ClassType.FORM_BEAN
        elif "interceptor" in name_lower:
            return ClassType.INTERCEPTOR
        elif "service" in name_lower:
            return ClassType.SERVICE
        elif "dao" in name_lower or "repository" in name_lower:
            return ClassType.DAO
        elif "util" in name_lower or "helper" in name_lower:
            return ClassType.UTILITY
        elif "exception" in name_lower or "error" in name_lower:
            return ClassType.EXCEPTION
        elif "abstract" in " ".join(self.modifiers).lower():
            return ClassType.ABSTRACT_CLASS
        elif "interface" in " ".join(self.modifiers).lower():
            return ClassType.INTERFACE
        elif "enum" in " ".join(self.modifiers).lower():
            return ClassType.ENUM
        elif any("@" in ann for ann in self.annotations):
            return ClassType.ANNOTATION
        
        return ClassType.UNKNOWN
    
    @property
    def fully_qualified_name(self) -> str:
        """Get the fully qualified class name."""
        if self.package:
            return f"{self.package}.{self.name}"
        return self.name
    
    @property
    def is_struts_component(self) -> bool:
        """Check if this class is a Struts-specific component."""
        return self.class_type in [
            ClassType.ACTION,
            ClassType.FORM_BEAN,
            ClassType.INTERCEPTOR
        ]
    
    @property
    def complexity_level(self) -> ClassComplexity:
        """Determine complexity level based on metrics."""
        score = self.metrics.overall_complexity_score
        
        if score >= 100:
            return ClassComplexity.CRITICAL
        elif score >= 50:
            return ClassComplexity.COMPLEX
        elif score >= 20:
            return ClassComplexity.MODERATE
        else:
            return ClassComplexity.SIMPLE
    
    @property
    def migration_complexity_score(self) -> int:
        """Calculate migration complexity score."""
        base_score = self.metrics.overall_complexity_score
        
        # Add complexity for Struts-specific features
        if self.is_struts_component:
            base_score += 10
        
        # Add complexity for business logic
        if self.business_purpose and "business" in self.business_purpose.lower():
            base_score += 5
        
        # Add complexity for dependencies
        base_score += len(self.dependencies) * 2
        base_score += len(self.dependents)
        
        return base_score
    
    def add_method(self, method: MethodSignature) -> None:
        """Add a method to this class."""
        self.methods.append(method)
        self.metrics.number_of_methods = len(self.methods)
    
    def add_dependency(self, class_name: str) -> None:
        """Add a dependency to another class."""
        self.dependencies.add(class_name)
    
    def add_dependent(self, class_name: str) -> None:
        """Add a class that depends on this class."""
        self.dependents.add(class_name)
    
    def add_relationship(self, target_class: str, relationship_type: str, 
                        strength: int = 1, description: str = "") -> None:
        """Add a relationship to another class."""
        relationship = ClassRelationship(
            target_class=target_class,
            relationship_type=relationship_type,
            strength=strength,
            description=description
        )
        self.relationships.append(relationship)
    
    def update_metrics(self, **kwargs) -> None:
        """Update class metrics."""
        for key, value in kwargs.items():
            if hasattr(self.metrics, key):
                setattr(self.metrics, key, value)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to this class."""
        self.tags.add(tag.lower())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert class info to dictionary representation."""
        return {
            "name": self.name,
            "package": self.package,
            "file_path": self.file_path,
            "fully_qualified_name": self.fully_qualified_name,
            "class_type": self.class_type.value,
            "superclass": self.superclass,
            "interfaces": self.interfaces,
            "inner_classes": self.inner_classes,
            "annotations": self.annotations,
            "modifiers": self.modifiers,
            "methods": [
                {
                    "name": method.name,
                    "return_type": method.return_type,
                    "parameters": method.parameters,
                    "modifiers": method.modifiers,
                    "annotations": method.annotations,
                    "signature": method.signature_string
                }
                for method in self.methods
            ],
            "fields": self.fields,
            "constructors": [
                {
                    "parameters": ctor.parameters,
                    "modifiers": ctor.modifiers,
                    "signature": ctor.signature_string
                }
                for ctor in self.constructors
            ],
            "dependencies": list(self.dependencies),
            "dependents": list(self.dependents),
            "relationships": [
                {
                    "target": rel.target_class,
                    "type": rel.relationship_type,
                    "strength": rel.strength,
                    "description": rel.description
                }
                for rel in self.relationships
            ],
            "metrics": {
                "lines_of_code": self.metrics.lines_of_code,
                "number_of_methods": self.metrics.number_of_methods,
                "number_of_fields": self.metrics.number_of_fields,
                "cyclomatic_complexity": self.metrics.cyclomatic_complexity,
                "cognitive_complexity": self.metrics.cognitive_complexity,
                "inheritance_depth": self.metrics.inheritance_depth,
                "coupling_factor": self.metrics.coupling_factor,
                "cohesion_score": self.metrics.cohesion_score,
                "overall_complexity_score": self.metrics.overall_complexity_score
            },
            "complexity": self.complexity.name,
            "complexity_level": self.complexity_level.name,
            "business_purpose": self.business_purpose,
            "business_domain": self.business_domain,
            "struts_role": self.struts_role,
            "migration_priority": self.migration_priority,
            "migration_complexity_score": self.migration_complexity_score,
            "action_mappings": self.action_mappings,
            "form_properties": self.form_properties,
            "validation_rules": self.validation_rules,
            "migration_recommendations": self.migration_recommendations,
            "modernization_notes": self.modernization_notes,
            "equivalent_spring_patterns": self.equivalent_spring_patterns,
            "is_struts_component": self.is_struts_component,
            "analyzed_at": self.analyzed_at.isoformat(),
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "version": self.version,
            "tags": list(self.tags),
            "custom_attributes": self.custom_attributes
        }
    
    def __str__(self) -> str:
        """String representation of the class info."""
        return f"ClassInfo(name={self.name}, type={self.class_type.value}, package={self.package})"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"ClassInfo(name='{self.name}', package='{self.package}', "
            f"type={self.class_type.value}, complexity={self.complexity.name}, "
            f"methods={len(self.methods)}, dependencies={len(self.dependencies)})"
        )