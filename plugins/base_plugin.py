"""
Base Plugin Interface
=====================

This module defines the base interface and contracts for all plugins in the
Struts analyzer system. Plugins extend the analyzer's capabilities with
custom functionality, framework-specific analysis, or integration features.

Author: Claude Code Assistant
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Type
from pathlib import Path
from datetime import datetime
from enum import Enum, auto

from models.business_rule import BusinessRule


class PluginType(Enum):
    """Types of plugins supported by the system."""
    ANALYZER = auto()           # Custom analyzers for specific file types
    FRAMEWORK = auto()          # Framework-specific analysis (Spring, Hibernate, etc.)
    MIGRATION = auto()          # Migration strategy and recommendations
    DOCUMENTATION = auto()      # Custom documentation generators
    INTEGRATION = auto()        # External tool integrations
    VALIDATION = auto()         # Custom validation and quality checks
    REPORTING = auto()          # Custom reporting and metrics


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    dependencies: List[str] = field(default_factory=list)
    supported_file_types: Set[str] = field(default_factory=set)
    configuration_schema: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    priority: int = 50  # 0-100, higher = higher priority
    
    def __post_init__(self):
        """Validate metadata."""
        if not self.name:
            raise ValueError("Plugin name cannot be empty")
        if not self.version:
            raise ValueError("Plugin version cannot be empty")


@dataclass
class PluginResult:
    """Result from plugin execution."""
    plugin_name: str
    success: bool
    execution_time_ms: int
    business_rules: List[BusinessRule] = field(default_factory=list)
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_business_rule(self, rule: BusinessRule) -> None:
        """Add a business rule to the result."""
        self.business_rules.append(rule)
    
    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)
        self.success = False
    
    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)
    
    def add_recommendation(self, recommendation: str) -> None:
        """Add a migration or improvement recommendation."""
        self.recommendations.append(recommendation)


class BasePlugin(ABC):
    """
    Abstract base class for all plugins.
    
    Plugins extend the analyzer's functionality by providing:
    - Custom analysis for specific frameworks or file types
    - Specialized business rule extraction
    - Migration strategies and recommendations
    - Integration with external tools
    - Custom documentation generation
    """
    
    def __init__(self, configuration: Optional[Dict[str, Any]] = None):
        """
        Initialize the plugin.
        
        Args:
            configuration: Plugin-specific configuration
        """
        self.configuration = configuration or {}
        self.metadata = self._get_metadata()
        self._validate_dependencies()
    
    @abstractmethod
    def _get_metadata(self) -> PluginMetadata:
        """
        Get plugin metadata.
        
        Returns:
            PluginMetadata describing this plugin
        """
        pass
    
    @abstractmethod
    def can_handle(self, context: Dict[str, Any]) -> bool:
        """
        Check if this plugin can handle the given context.
        
        Args:
            context: Analysis context including files, configuration, etc.
            
        Returns:
            True if this plugin can process the context, False otherwise
        """
        pass
    
    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> PluginResult:
        """
        Execute the plugin's main functionality.
        
        Args:
            context: Analysis context
            
        Returns:
            PluginResult containing the plugin's output
        """
        pass
    
    def initialize(self) -> bool:
        """
        Initialize the plugin (called once during system startup).
        
        Returns:
            True if initialization successful, False otherwise
        """
        return True
    
    def cleanup(self) -> None:
        """Clean up plugin resources (called during system shutdown)."""
        pass
    
    def validate_configuration(self) -> List[str]:
        """
        Validate plugin configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required configuration keys from schema
        schema = self.metadata.configuration_schema
        for key, config in schema.items():
            if config.get('required', False) and key not in self.configuration:
                errors.append(f"Required configuration key '{key}' is missing")
        
        return errors
    
    def get_supported_file_extensions(self) -> Set[str]:
        """Get file extensions this plugin can analyze."""
        return self.metadata.supported_file_types
    
    def get_priority(self) -> int:
        """Get plugin priority (higher = runs first)."""
        return self.metadata.priority
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled."""
        return self.metadata.enabled
    
    def _validate_dependencies(self) -> None:
        """Validate that plugin dependencies are available."""
        for dependency in self.metadata.dependencies:
            try:
                __import__(dependency)
            except ImportError as e:
                raise ImportError(
                    f"Plugin {self.metadata.name} requires dependency '{dependency}' "
                    f"which is not available: {e}"
                )
    
    def _create_business_rule_from_plugin(self,
                                        rule_id: str,
                                        name: str,
                                        description: str,
                                        **kwargs) -> BusinessRule:
        """
        Helper method to create business rules with plugin attribution.
        
        Args:
            rule_id: Unique rule identifier
            name: Rule name
            description: Rule description
            **kwargs: Additional BusinessRule parameters
            
        Returns:
            BusinessRule instance with plugin metadata
        """
        from models.business_rule import (
            BusinessRule, BusinessRuleType, BusinessRuleSource,
            BusinessRuleLocation, BusinessRuleEvidence
        )
        
        # Set defaults
        rule_type = kwargs.get('rule_type', BusinessRuleType.BUSINESS_LOGIC)
        source = kwargs.get('source', BusinessRuleSource.ANNOTATION)
        
        # Create evidence with plugin attribution
        evidence = kwargs.get('evidence', BusinessRuleEvidence(
            code_snippet=kwargs.get('code_snippet', ''),
            context=kwargs.get('context', ''),
            confidence_score=kwargs.get('confidence_score', 0.8),
            extraction_method=f"plugin_{self.metadata.name}"
        ))
        
        # Create location
        location = kwargs.get('location', BusinessRuleLocation(
            file_path=kwargs.get('file_path', '')
        ))
        
        rule = BusinessRule(
            id=rule_id,
            name=name,
            description=description,
            rule_type=rule_type,
            source=source,
            location=location,
            evidence=evidence,
            **{k: v for k, v in kwargs.items() 
               if k not in ['rule_type', 'source', 'location', 'evidence', 
                           'code_snippet', 'context', 'confidence_score', 'file_path']}
        )
        
        # Add plugin attribution
        rule.add_tag(f"plugin_{self.metadata.name}")
        rule.add_tag(f"plugin_type_{self.metadata.plugin_type.name.lower()}")
        
        return rule
    
    def __str__(self) -> str:
        """String representation of the plugin."""
        return f"{self.metadata.name} v{self.metadata.version}"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"{self.__class__.__name__}("
            f"name='{self.metadata.name}', "
            f"version='{self.metadata.version}', "
            f"type={self.metadata.plugin_type.name}, "
            f"enabled={self.metadata.enabled})"
        )


class AnalyzerPlugin(BasePlugin):
    """Base class for analyzer plugins that process specific file types."""
    
    @abstractmethod
    def analyze_file(self, file_path: Path, context: Dict[str, Any]) -> PluginResult:
        """
        Analyze a specific file.
        
        Args:
            file_path: Path to file to analyze
            context: Analysis context
            
        Returns:
            PluginResult with analysis findings
        """
        pass
    
    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this plugin can analyze the given file."""
        extension = file_path.suffix.lower()
        return extension in self.get_supported_file_extensions()


class FrameworkPlugin(BasePlugin):
    """Base class for framework-specific analysis plugins."""
    
    @abstractmethod
    def detect_framework(self, project_path: Path) -> bool:
        """
        Detect if the framework is used in the project.
        
        Args:
            project_path: Path to project root
            
        Returns:
            True if framework is detected, False otherwise
        """
        pass
    
    @abstractmethod
    def analyze_framework_usage(self, project_path: Path, 
                              context: Dict[str, Any]) -> PluginResult:
        """
        Analyze framework usage and extract business rules.
        
        Args:
            project_path: Path to project root
            context: Analysis context
            
        Returns:
            PluginResult with framework-specific findings
        """
        pass


class MigrationPlugin(BasePlugin):
    """Base class for migration strategy plugins."""
    
    @abstractmethod
    def generate_migration_recommendations(self, 
                                         business_rules: List[BusinessRule],
                                         context: Dict[str, Any]) -> PluginResult:
        """
        Generate migration recommendations for business rules.
        
        Args:
            business_rules: List of identified business rules
            context: Analysis context
            
        Returns:
            PluginResult with migration recommendations
        """
        pass
    
    @abstractmethod
    def estimate_migration_effort(self, business_rules: List[BusinessRule]) -> Dict[str, Any]:
        """
        Estimate effort required for migration.
        
        Args:
            business_rules: List of business rules to migrate
            
        Returns:
            Dictionary with effort estimates and metrics
        """
        pass


class DocumentationPlugin(BasePlugin):
    """Base class for custom documentation generation plugins."""
    
    @abstractmethod
    def generate_documentation(self,
                             business_rules: List[BusinessRule],
                             analysis_results: Dict[str, Any],
                             output_path: Path) -> PluginResult:
        """
        Generate custom documentation.
        
        Args:
            business_rules: List of business rules
            analysis_results: Complete analysis results
            output_path: Path to write documentation
            
        Returns:
            PluginResult with generation status
        """
        pass
    
    @abstractmethod
    def get_output_formats(self) -> List[str]:
        """
        Get supported output formats.
        
        Returns:
            List of supported formats (e.g., ['pdf', 'docx', 'html'])
        """
        pass


class IntegrationPlugin(BasePlugin):
    """Base class for external tool integration plugins."""
    
    @abstractmethod
    def integrate_with_tool(self,
                          business_rules: List[BusinessRule],
                          context: Dict[str, Any]) -> PluginResult:
        """
        Integrate with external tool.
        
        Args:
            business_rules: List of business rules
            context: Analysis context
            
        Returns:
            PluginResult with integration status and data
        """
        pass
    
    @abstractmethod
    def export_data(self, data: Dict[str, Any], format: str) -> str:
        """
        Export data in format required by external tool.
        
        Args:
            data: Data to export
            format: Export format
            
        Returns:
            Exported data as string
        """
        pass