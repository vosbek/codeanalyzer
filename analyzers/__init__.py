"""
Analyzers Package
=================

This package contains specialized analyzers for different components of Struts applications.
Each analyzer focuses on a specific aspect of the codebase and implements the BaseAnalyzer
interface for consistency and extensibility.

Analyzers included:
- BaseAnalyzer: Abstract base class for all analyzers
- StrutsConfigAnalyzer: Analyzes struts-config.xml and related configuration
- ValidationAnalyzer: Analyzes validation.xml and validation rules
- JavaActionAnalyzer: Analyzes Java Action classes and business logic
- JSPAnalyzer: Analyzes JSP files for UI business rules
- DependencyAnalyzer: Analyzes dependencies and builds dependency graphs
- BusinessLogicAnalyzer: Extracts and categorizes business rules
- ComplexityAnalyzer: Calculates complexity metrics and technical debt
- MigrationAnalyzer: Provides migration-specific analysis and recommendations

Author: Claude Code Assistant
"""

from .base_analyzer import BaseAnalyzer, AnalysisResult, AnalysisContext
from .struts_config_analyzer import StrutsConfigAnalyzer
from .validation_analyzer import ValidationAnalyzer
from .java_action_analyzer import JavaActionAnalyzer
from .jsp_analyzer import JSPAnalyzer
from .dependency_analyzer import DependencyAnalyzer
# from .business_logic_analyzer import BusinessLogicAnalyzer
# from .complexity_analyzer import ComplexityAnalyzer
# from .migration_analyzer import MigrationAnalyzer

__all__ = [
    # Base classes
    "BaseAnalyzer",
    "AnalysisResult",
    "AnalysisContext",
    
    # Specialized analyzers
    "StrutsConfigAnalyzer",
    "ValidationAnalyzer", 
    "JavaActionAnalyzer",
    "JSPAnalyzer",
    "DependencyAnalyzer",
    # "BusinessLogicAnalyzer",
    # "ComplexityAnalyzer", 
    # "MigrationAnalyzer"
]