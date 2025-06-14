"""
Method Information Data Model
============================

This module defines data structures for representing Java method information
extracted during Struts application analysis. This includes method metadata,
complexity metrics, business logic patterns, and migration assessments.

Author: Claude Code Assistant
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set, Tuple
from enum import Enum, auto
from datetime import datetime


class MethodType(Enum):
    """Enumeration of method types in Struts applications."""
    EXECUTE = "execute"              # Main action execution method
    PERFORM = "perform"              # Legacy Struts 1.x action method
    VALIDATE = "validate"            # Validation method
    RESET = "reset"                  # Form reset method
    GETTER = "getter"                # Property getter method
    SETTER = "setter"                # Property setter method
    BUSINESS_LOGIC = "business_logic"  # Business logic method
    UTILITY = "utility"              # Utility/helper method
    CONSTRUCTOR = "constructor"      # Constructor method
    INTERCEPTOR = "interceptor"      # Interceptor method
    DAO_METHOD = "dao_method"        # Data access method
    SERVICE_METHOD = "service_method"  # Service layer method
    CALLBACK = "callback"            # Callback method
    UNKNOWN = "unknown"


class MethodComplexity(Enum):
    """Enumeration of method complexity levels."""
    TRIVIAL = auto()     # Simple getter/setter or one-liner
    SIMPLE = auto()      # Basic logic, few branches
    MODERATE = auto()    # Multiple conditions, some complexity
    COMPLEX = auto()     # Complex business logic, many branches
    CRITICAL = auto()    # Very complex, mission-critical logic


@dataclass
class MethodMetrics:
    """Metrics for method complexity analysis."""
    lines_of_code: int = 0
    cyclomatic_complexity: int = 0
    cognitive_complexity: int = 0
    nesting_depth: int = 0
    number_of_parameters: int = 0
    number_of_local_variables: int = 0
    number_of_method_calls: int = 0
    number_of_conditionals: int = 0
    number_of_loops: int = 0
    number_of_exceptions: int = 0
    halstead_volume: float = 0.0
    
    @property
    def overall_complexity_score(self) -> int:
        """Calculate overall complexity score for the method."""
        score = (
            (self.lines_of_code // 5) +
            (self.cyclomatic_complexity * 4) +
            (self.cognitive_complexity * 3) +
            (self.nesting_depth * 3) +
            (self.number_of_parameters * 2) +
            (self.number_of_local_variables) +
            (self.number_of_method_calls) +
            (self.number_of_conditionals * 2) +
            (self.number_of_loops * 2) +
            (self.number_of_exceptions * 3) +
            int(self.halstead_volume // 10)
        )
        return max(0, score)


@dataclass
class BusinessLogicPattern:
    """Represents a business logic pattern found in a method."""
    pattern_type: str  # validation, workflow, calculation, integration, etc.
    description: str
    code_snippet: str
    confidence: float = 1.0  # 0.0 to 1.0
    business_impact: str = "medium"  # low, medium, high, critical
    migration_notes: str = ""


@dataclass
class MethodCall:
    """Represents a method call within the analyzed method."""
    target_class: Optional[str]
    method_name: str
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    is_external: bool = False
    is_business_logic: bool = False
    line_number: Optional[int] = None


@dataclass
class ConditionalLogic:
    """Represents conditional logic within a method."""
    condition_type: str  # if, switch, ternary, etc.
    condition: str
    line_number: Optional[int] = None
    nesting_level: int = 0
    business_significance: str = ""
    else_branches: List[str] = field(default_factory=list)


@dataclass
class LoopLogic:
    """Represents loop logic within a method."""
    loop_type: str  # for, while, do-while, enhanced-for
    condition: str
    line_number: Optional[int] = None
    nesting_level: int = 0
    business_purpose: str = ""
    estimated_iterations: Optional[str] = None


@dataclass
class ExceptionHandling:
    """Represents exception handling within a method."""
    exception_type: str
    handling_strategy: str  # catch, throw, finally
    line_number: Optional[int] = None
    business_context: str = ""
    recovery_strategy: str = ""


@dataclass
class DataAccess:
    """Represents data access patterns within a method."""
    access_type: str  # read, write, update, delete
    data_source: str  # database, file, web service, etc.
    entity_type: Optional[str] = None
    sql_queries: List[str] = field(default_factory=list)
    business_entity: str = ""


@dataclass
class MethodInfo:
    """
    Comprehensive information about a Java method in a Struts application.
    
    This model captures detailed information about methods including their
    signature, complexity, business logic patterns, and migration considerations.
    """
    
    # Core identification
    name: str
    class_name: str
    file_path: str
    method_type: MethodType = MethodType.UNKNOWN
    
    # Method signature
    return_type: str = "void"
    parameters: List[Tuple[str, str]] = field(default_factory=list)  # (type, name) pairs
    modifiers: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    generic_types: List[str] = field(default_factory=list)
    
    # Code location
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    
    # Metrics and complexity
    metrics: MethodMetrics = field(default_factory=MethodMetrics)
    complexity: MethodComplexity = MethodComplexity.MODERATE
    
    # Business logic analysis
    business_logic_patterns: List[BusinessLogicPattern] = field(default_factory=list)
    business_purpose: str = ""
    business_domain: str = "unknown"
    
    # Code structure analysis
    method_calls: List[MethodCall] = field(default_factory=list)
    conditional_logic: List[ConditionalLogic] = field(default_factory=list)
    loop_logic: List[LoopLogic] = field(default_factory=list)
    exception_handling: List[ExceptionHandling] = field(default_factory=list)
    data_access: List[DataAccess] = field(default_factory=list)
    
    # Dependencies
    called_methods: Set[str] = field(default_factory=set)
    used_classes: Set[str] = field(default_factory=set)
    accessed_fields: Set[str] = field(default_factory=set)
    
    # Struts-specific information
    action_forwards: List[str] = field(default_factory=list)  # For action methods
    form_validations: List[str] = field(default_factory=list)  # For validation methods
    struts_annotations: List[str] = field(default_factory=list)
    
    # Migration information
    migration_risk: str = "medium"  # low, medium, high, critical
    migration_effort_hours: Optional[int] = None
    migration_strategy: str = ""
    modernization_recommendations: List[str] = field(default_factory=list)
    spring_boot_equivalent: str = ""
    
    # Quality indicators
    is_tested: bool = False
    test_coverage: float = 0.0
    code_smells: List[str] = field(default_factory=list)
    refactoring_suggestions: List[str] = field(default_factory=list)
    
    # Metadata
    analyzed_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0"
    tags: Set[str] = field(default_factory=set)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and processing."""
        if not self.name:
            raise ValueError("Method name cannot be empty")
        if not self.class_name:
            raise ValueError("Class name cannot be empty")
            
        # Auto-detect method type
        if self.method_type == MethodType.UNKNOWN:
            self.method_type = self._detect_method_type()
            
        # Update metrics from parameters
        self.metrics.number_of_parameters = len(self.parameters)
    
    def _detect_method_type(self) -> MethodType:
        """Auto-detect method type based on name and signature."""
        name_lower = self.name.lower()
        
        # Check for Struts-specific patterns
        if name_lower == "execute":
            return MethodType.EXECUTE
        elif name_lower == "perform":
            return MethodType.PERFORM
        elif name_lower == "validate":
            return MethodType.VALIDATE
        elif name_lower == "reset":
            return MethodType.RESET
        elif name_lower.startswith("get") and len(self.parameters) == 0:
            return MethodType.GETTER
        elif name_lower.startswith("set") and len(self.parameters) == 1:
            return MethodType.SETTER
        elif name_lower.startswith("is") and len(self.parameters) == 0:
            return MethodType.GETTER
        elif self.name == self.class_name:  # Constructor
            return MethodType.CONSTRUCTOR
        elif "intercept" in name_lower:
            return MethodType.INTERCEPTOR
        elif any(dao_pattern in name_lower for dao_pattern in ["find", "save", "delete", "update", "create"]):
            return MethodType.DAO_METHOD
        elif any(service_pattern in name_lower for service_pattern in ["process", "handle", "manage", "calculate"]):
            return MethodType.SERVICE_METHOD
        elif name_lower.endswith("callback") or "callback" in name_lower:
            return MethodType.CALLBACK
        elif any(util_pattern in name_lower for util_pattern in ["util", "helper", "format", "parse", "convert"]):
            return MethodType.UTILITY
        else:
            # Check if method contains business logic patterns
            if self.business_logic_patterns or "business" in self.business_purpose.lower():
                return MethodType.BUSINESS_LOGIC
            return MethodType.UNKNOWN
    
    @property
    def signature(self) -> str:
        """Generate method signature string."""
        modifiers_str = " ".join(self.modifiers) if self.modifiers else ""
        annotations_str = " ".join(f"@{ann}" for ann in self.annotations)
        params_str = ", ".join(f"{param_type} {param_name}" for param_type, param_name in self.parameters)
        
        parts = [annotations_str, modifiers_str, self.return_type, f"{self.name}({params_str})"]
        return " ".join(part for part in parts if part)
    
    @property
    def complexity_level(self) -> MethodComplexity:
        """Determine complexity level based on metrics."""
        score = self.metrics.overall_complexity_score
        
        if score >= 50:
            return MethodComplexity.CRITICAL
        elif score >= 25:
            return MethodComplexity.COMPLEX
        elif score >= 10:
            return MethodComplexity.MODERATE
        elif score >= 3:
            return MethodComplexity.SIMPLE
        else:
            return MethodComplexity.TRIVIAL
    
    @property
    def is_business_critical(self) -> bool:
        """Check if this method contains business-critical logic."""
        return (
            self.method_type in [MethodType.EXECUTE, MethodType.PERFORM, MethodType.BUSINESS_LOGIC] or
            any(pattern.business_impact in ["high", "critical"] for pattern in self.business_logic_patterns) or
            self.complexity_level in [MethodComplexity.COMPLEX, MethodComplexity.CRITICAL] or
            self.migration_risk in ["high", "critical"]
        )
    
    @property
    def migration_complexity_score(self) -> int:
        """Calculate migration complexity score."""
        base_score = self.metrics.overall_complexity_score
        
        # Add complexity for Struts-specific features
        if self.method_type in [MethodType.EXECUTE, MethodType.PERFORM]:
            base_score += 10
        
        # Add complexity for business logic patterns
        base_score += len(self.business_logic_patterns) * 3
        
        # Add complexity for data access
        base_score += len(self.data_access) * 5
        
        # Add complexity for exception handling
        base_score += len(self.exception_handling) * 2
        
        return base_score
    
    def add_business_logic_pattern(self, pattern_type: str, description: str, 
                                 code_snippet: str, confidence: float = 1.0,
                                 business_impact: str = "medium") -> None:
        """Add a business logic pattern to this method."""
        pattern = BusinessLogicPattern(
            pattern_type=pattern_type,
            description=description,
            code_snippet=code_snippet,
            confidence=confidence,
            business_impact=business_impact
        )
        self.business_logic_patterns.append(pattern)
    
    def add_method_call(self, target_class: Optional[str], method_name: str,
                       parameters: Optional[List[str]] = None,
                       is_business_logic: bool = False) -> None:
        """Add a method call to the analysis."""
        call = MethodCall(
            target_class=target_class,
            method_name=method_name,
            parameters=parameters or [],
            is_business_logic=is_business_logic
        )
        self.method_calls.append(call)
        
        # Update called methods set
        if target_class:
            self.called_methods.add(f"{target_class}.{method_name}")
            self.used_classes.add(target_class)
        else:
            self.called_methods.add(method_name)
    
    def add_conditional_logic(self, condition_type: str, condition: str,
                            nesting_level: int = 0, business_significance: str = "") -> None:
        """Add conditional logic to the analysis."""
        conditional = ConditionalLogic(
            condition_type=condition_type,
            condition=condition,
            nesting_level=nesting_level,
            business_significance=business_significance
        )
        self.conditional_logic.append(conditional)
        self.metrics.number_of_conditionals = len(self.conditional_logic)
        self.metrics.nesting_depth = max(self.metrics.nesting_depth, nesting_level)
    
    def add_loop_logic(self, loop_type: str, condition: str,
                      nesting_level: int = 0, business_purpose: str = "") -> None:
        """Add loop logic to the analysis."""
        loop = LoopLogic(
            loop_type=loop_type,
            condition=condition,
            nesting_level=nesting_level,
            business_purpose=business_purpose
        )
        self.loop_logic.append(loop)
        self.metrics.number_of_loops = len(self.loop_logic)
        self.metrics.nesting_depth = max(self.metrics.nesting_depth, nesting_level)
    
    def add_exception_handling(self, exception_type: str, handling_strategy: str,
                             business_context: str = "") -> None:
        """Add exception handling to the analysis."""
        exception = ExceptionHandling(
            exception_type=exception_type,
            handling_strategy=handling_strategy,
            business_context=business_context
        )
        self.exception_handling.append(exception)
        self.metrics.number_of_exceptions = len(self.exception_handling)
    
    def add_data_access(self, access_type: str, data_source: str,
                       entity_type: Optional[str] = None, business_entity: str = "") -> None:
        """Add data access pattern to the analysis."""
        access = DataAccess(
            access_type=access_type,
            data_source=data_source,
            entity_type=entity_type,
            business_entity=business_entity
        )
        self.data_access.append(access)
    
    def update_metrics(self, **kwargs) -> None:
        """Update method metrics."""
        for key, value in kwargs.items():
            if hasattr(self.metrics, key):
                setattr(self.metrics, key, value)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to this method."""
        self.tags.add(tag.lower())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert method info to dictionary representation."""
        return {
            "name": self.name,
            "class_name": self.class_name,
            "file_path": self.file_path,
            "method_type": self.method_type.value,
            "return_type": self.return_type,
            "parameters": [{"type": ptype, "name": pname} for ptype, pname in self.parameters],
            "modifiers": self.modifiers,
            "annotations": self.annotations,
            "generic_types": self.generic_types,
            "signature": self.signature,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "metrics": {
                "lines_of_code": self.metrics.lines_of_code,
                "cyclomatic_complexity": self.metrics.cyclomatic_complexity,
                "cognitive_complexity": self.metrics.cognitive_complexity,
                "nesting_depth": self.metrics.nesting_depth,
                "number_of_parameters": self.metrics.number_of_parameters,
                "number_of_local_variables": self.metrics.number_of_local_variables,
                "number_of_method_calls": self.metrics.number_of_method_calls,
                "number_of_conditionals": self.metrics.number_of_conditionals,
                "number_of_loops": self.metrics.number_of_loops,
                "number_of_exceptions": self.metrics.number_of_exceptions,
                "halstead_volume": self.metrics.halstead_volume,
                "overall_complexity_score": self.metrics.overall_complexity_score
            },
            "complexity": self.complexity.name,
            "complexity_level": self.complexity_level.name,
            "business_logic_patterns": [
                {
                    "pattern_type": pattern.pattern_type,
                    "description": pattern.description,
                    "code_snippet": pattern.code_snippet,
                    "confidence": pattern.confidence,
                    "business_impact": pattern.business_impact,
                    "migration_notes": pattern.migration_notes
                }
                for pattern in self.business_logic_patterns
            ],
            "business_purpose": self.business_purpose,
            "business_domain": self.business_domain,
            "method_calls": [
                {
                    "target_class": call.target_class,
                    "method_name": call.method_name,
                    "parameters": call.parameters,
                    "return_type": call.return_type,
                    "is_external": call.is_external,
                    "is_business_logic": call.is_business_logic,
                    "line_number": call.line_number
                }
                for call in self.method_calls
            ],
            "conditional_logic": [
                {
                    "condition_type": cond.condition_type,
                    "condition": cond.condition,
                    "line_number": cond.line_number,
                    "nesting_level": cond.nesting_level,
                    "business_significance": cond.business_significance,
                    "else_branches": cond.else_branches
                }
                for cond in self.conditional_logic
            ],
            "loop_logic": [
                {
                    "loop_type": loop.loop_type,
                    "condition": loop.condition,
                    "line_number": loop.line_number,
                    "nesting_level": loop.nesting_level,
                    "business_purpose": loop.business_purpose,
                    "estimated_iterations": loop.estimated_iterations
                }
                for loop in self.loop_logic
            ],
            "exception_handling": [
                {
                    "exception_type": exc.exception_type,
                    "handling_strategy": exc.handling_strategy,
                    "line_number": exc.line_number,
                    "business_context": exc.business_context,
                    "recovery_strategy": exc.recovery_strategy
                }
                for exc in self.exception_handling
            ],
            "data_access": [
                {
                    "access_type": access.access_type,
                    "data_source": access.data_source,
                    "entity_type": access.entity_type,
                    "sql_queries": access.sql_queries,
                    "business_entity": access.business_entity
                }
                for access in self.data_access
            ],
            "called_methods": list(self.called_methods),
            "used_classes": list(self.used_classes),
            "accessed_fields": list(self.accessed_fields),
            "action_forwards": self.action_forwards,
            "form_validations": self.form_validations,
            "struts_annotations": self.struts_annotations,
            "migration_risk": self.migration_risk,
            "migration_effort_hours": self.migration_effort_hours,
            "migration_strategy": self.migration_strategy,
            "migration_complexity_score": self.migration_complexity_score,
            "modernization_recommendations": self.modernization_recommendations,
            "spring_boot_equivalent": self.spring_boot_equivalent,
            "is_business_critical": self.is_business_critical,
            "is_tested": self.is_tested,
            "test_coverage": self.test_coverage,
            "code_smells": self.code_smells,
            "refactoring_suggestions": self.refactoring_suggestions,
            "analyzed_at": self.analyzed_at.isoformat(),
            "version": self.version,
            "tags": list(self.tags),
            "custom_attributes": self.custom_attributes
        }
    
    def __str__(self) -> str:
        """String representation of the method info."""
        return f"MethodInfo(name={self.name}, class={self.class_name}, type={self.method_type.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"MethodInfo(name='{self.name}', class='{self.class_name}', "
            f"type={self.method_type.value}, complexity={self.complexity.name}, "
            f"loc={self.metrics.lines_of_code}, calls={len(self.method_calls)})"
        )