"""
Data Models Package
==================

This package contains all data models and domain objects used throughout
the Struts analysis system. All models use dataclasses with proper typing
and validation.

Models included:
- BusinessRule: Represents extracted business rules
- ClassInfo: Java class metadata and analysis results
- MethodInfo: Method-level analysis data
- DependencyInfo: Dependency relationship information
- MigrationInfo: Migration planning and assessment data
"""

from .business_rule import BusinessRule, BusinessRuleType, BusinessRuleComplexity
from .class_info import ClassInfo, ClassType, ClassComplexity
from .method_info import MethodInfo, MethodType, MethodComplexity
from .dependency_info import DependencyInfo, DependencyType, DependencyStrength
from .migration_info import MigrationInfo, MigrationRisk, MigrationEffort

__all__ = [
    # Business Rule models
    "BusinessRule",
    "BusinessRuleType", 
    "BusinessRuleComplexity",
    
    # Class models
    "ClassInfo",
    "ClassType",
    "ClassComplexity",
    
    # Method models
    "MethodInfo",
    "MethodType",
    "MethodComplexity",
    
    # Dependency models
    "DependencyInfo",
    "DependencyType",
    "DependencyStrength",
    
    # Migration models
    "MigrationInfo",
    "MigrationRisk",
    "MigrationEffort"
]