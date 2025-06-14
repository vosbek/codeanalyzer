"""
Plugin Manager
==============

This module manages the loading, execution, and lifecycle of plugins in the
Struts analyzer system. It provides a centralized interface for plugin
discovery, dependency resolution, and execution coordination.

Author: Claude Code Assistant
"""

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Type, Tuple
import logging
from datetime import datetime

from plugins.base_plugin import (
    BasePlugin, PluginResult, PluginType, PluginMetadata,
    AnalyzerPlugin, FrameworkPlugin, MigrationPlugin, 
    DocumentationPlugin, IntegrationPlugin
)
from models.business_rule import BusinessRule


class PluginManager:
    """
    Manages plugins for the Struts analyzer system.
    
    Responsibilities:
    - Plugin discovery and loading
    - Dependency resolution
    - Execution coordination
    - Plugin lifecycle management
    - Configuration management
    """
    
    def __init__(self, plugin_dirs: Optional[List[Path]] = None,
                 configuration: Optional[Dict[str, Any]] = None):
        """
        Initialize the plugin manager.
        
        Args:
            plugin_dirs: Directories to search for plugins
            configuration: Global plugin configuration
        """
        self.plugin_dirs = plugin_dirs or []
        self.configuration = configuration or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Plugin registry
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_metadata: Dict[str, PluginMetadata] = {}
        self.plugins_by_type: Dict[PluginType, List[BasePlugin]] = {}
        
        # Execution state
        self.initialized = False
        self.execution_order: List[str] = []
        
        # Built-in plugins
        self._register_builtin_plugins()
    
    def discover_plugins(self) -> int:
        """
        Discover and load plugins from configured directories.
        
        Returns:
            Number of plugins discovered
        """
        discovered_count = 0
        
        # Discover from plugin directories
        for plugin_dir in self.plugin_dirs:
            if plugin_dir.exists():
                discovered_count += self._discover_plugins_in_directory(plugin_dir)
        
        # Discover from current package
        discovered_count += self._discover_builtin_plugins()
        
        self.logger.info(f"Discovered {discovered_count} plugins")
        return discovered_count
    
    def register_plugin(self, plugin: BasePlugin, 
                       plugin_config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Register a plugin instance.
        
        Args:
            plugin: Plugin instance to register
            plugin_config: Plugin-specific configuration
            
        Returns:
            True if registration successful, False otherwise
        """
        try:
            # Validate plugin
            if not isinstance(plugin, BasePlugin):
                self.logger.error(f"Invalid plugin type: {type(plugin)}")
                return False
            
            metadata = plugin.metadata
            plugin_name = metadata.name
            
            # Check for conflicts
            if plugin_name in self.plugins:
                self.logger.warning(f"Plugin '{plugin_name}' already registered, skipping")
                return False
            
            # Validate configuration
            config_errors = plugin.validate_configuration()
            if config_errors:
                self.logger.error(f"Plugin '{plugin_name}' configuration errors: {config_errors}")
                return False
            
            # Register plugin
            self.plugins[plugin_name] = plugin
            self.plugin_metadata[plugin_name] = metadata
            
            # Add to type registry
            plugin_type = metadata.plugin_type
            if plugin_type not in self.plugins_by_type:
                self.plugins_by_type[plugin_type] = []
            self.plugins_by_type[plugin_type].append(plugin)
            
            self.logger.info(f"Registered plugin: {plugin_name} v{metadata.version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error registering plugin: {e}")
            return False
    
    def initialize_plugins(self) -> bool:
        """
        Initialize all registered plugins.
        
        Returns:
            True if all plugins initialized successfully, False otherwise
        """
        if self.initialized:
            return True
        
        success_count = 0
        total_count = len(self.plugins)
        
        # Sort plugins by priority for initialization order
        sorted_plugins = sorted(
            self.plugins.items(),
            key=lambda item: item[1].get_priority(),
            reverse=True
        )
        
        for plugin_name, plugin in sorted_plugins:
            try:
                if plugin.is_enabled():
                    if plugin.initialize():
                        success_count += 1
                        self.execution_order.append(plugin_name)
                        self.logger.debug(f"Initialized plugin: {plugin_name}")
                    else:
                        self.logger.error(f"Failed to initialize plugin: {plugin_name}")
                else:
                    self.logger.info(f"Plugin disabled, skipping: {plugin_name}")
                    
            except Exception as e:
                self.logger.error(f"Error initializing plugin '{plugin_name}': {e}")
        
        self.initialized = success_count == total_count
        if self.initialized:
            self.logger.info(f"Successfully initialized {success_count}/{total_count} plugins")
        else:
            self.logger.warning(f"Initialized {success_count}/{total_count} plugins")
        
        return self.initialized
    
    def execute_analyzer_plugins(self, file_path: Path, 
                                context: Dict[str, Any]) -> List[PluginResult]:
        """
        Execute analyzer plugins for a specific file.
        
        Args:
            file_path: File to analyze
            context: Analysis context
            
        Returns:
            List of plugin results
        """
        results = []
        analyzer_plugins = self.get_plugins_by_type(PluginType.ANALYZER)
        
        for plugin in analyzer_plugins:
            if isinstance(plugin, AnalyzerPlugin) and plugin.can_analyze_file(file_path):
                try:
                    start_time = datetime.now()
                    result = plugin.analyze_file(file_path, context)
                    end_time = datetime.now()
                    
                    result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
                    results.append(result)
                    
                except Exception as e:
                    error_result = PluginResult(
                        plugin_name=plugin.metadata.name,
                        success=False,
                        execution_time_ms=0
                    )
                    error_result.add_error(f"Plugin execution failed: {e}")
                    results.append(error_result)
        
        return results
    
    def execute_framework_plugins(self, project_path: Path,
                                 context: Dict[str, Any]) -> List[PluginResult]:
        """
        Execute framework detection and analysis plugins.
        
        Args:
            project_path: Path to project root
            context: Analysis context
            
        Returns:
            List of plugin results
        """
        results = []
        framework_plugins = self.get_plugins_by_type(PluginType.FRAMEWORK)
        
        for plugin in framework_plugins:
            if isinstance(plugin, FrameworkPlugin):
                try:
                    # First detect if framework is present
                    if plugin.detect_framework(project_path):
                        start_time = datetime.now()
                        result = plugin.analyze_framework_usage(project_path, context)
                        end_time = datetime.now()
                        
                        result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
                        results.append(result)
                        
                        self.logger.info(f"Framework plugin '{plugin.metadata.name}' found applicable framework")
                    else:
                        self.logger.debug(f"Framework plugin '{plugin.metadata.name}' - framework not detected")
                        
                except Exception as e:
                    error_result = PluginResult(
                        plugin_name=plugin.metadata.name,
                        success=False,
                        execution_time_ms=0
                    )
                    error_result.add_error(f"Framework plugin execution failed: {e}")
                    results.append(error_result)
        
        return results
    
    def execute_migration_plugins(self, business_rules: List[BusinessRule],
                                 context: Dict[str, Any]) -> List[PluginResult]:
        """
        Execute migration strategy plugins.
        
        Args:
            business_rules: List of identified business rules
            context: Analysis context
            
        Returns:
            List of plugin results with migration recommendations
        """
        results = []
        migration_plugins = self.get_plugins_by_type(PluginType.MIGRATION)
        
        for plugin in migration_plugins:
            if isinstance(plugin, MigrationPlugin):
                try:
                    start_time = datetime.now()
                    result = plugin.generate_migration_recommendations(business_rules, context)
                    end_time = datetime.now()
                    
                    result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
                    
                    # Add effort estimates
                    effort_estimates = plugin.estimate_migration_effort(business_rules)
                    result.metadata['effort_estimates'] = effort_estimates
                    
                    results.append(result)
                    
                except Exception as e:
                    error_result = PluginResult(
                        plugin_name=plugin.metadata.name,
                        success=False,
                        execution_time_ms=0
                    )
                    error_result.add_error(f"Migration plugin execution failed: {e}")
                    results.append(error_result)
        
        return results
    
    def execute_documentation_plugins(self, business_rules: List[BusinessRule],
                                    analysis_results: Dict[str, Any],
                                    output_path: Path) -> List[PluginResult]:
        """
        Execute documentation generation plugins.
        
        Args:
            business_rules: List of business rules
            analysis_results: Complete analysis results
            output_path: Path to write documentation
            
        Returns:
            List of plugin results
        """
        results = []
        doc_plugins = self.get_plugins_by_type(PluginType.DOCUMENTATION)
        
        for plugin in doc_plugins:
            if isinstance(plugin, DocumentationPlugin):
                try:
                    start_time = datetime.now()
                    result = plugin.generate_documentation(business_rules, analysis_results, output_path)
                    end_time = datetime.now()
                    
                    result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
                    results.append(result)
                    
                except Exception as e:
                    error_result = PluginResult(
                        plugin_name=plugin.metadata.name,
                        success=False,
                        execution_time_ms=0
                    )
                    error_result.add_error(f"Documentation plugin execution failed: {e}")
                    results.append(error_result)
        
        return results
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[BasePlugin]:
        """Get all plugins of a specific type."""
        return self.plugins_by_type.get(plugin_type, [])
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name."""
        return self.plugins.get(name)
    
    def get_enabled_plugins(self) -> List[BasePlugin]:
        """Get all enabled plugins."""
        return [plugin for plugin in self.plugins.values() if plugin.is_enabled()]
    
    def get_plugin_summary(self) -> Dict[str, Any]:
        """Get summary of registered plugins."""
        summary = {
            'total_plugins': len(self.plugins),
            'enabled_plugins': len(self.get_enabled_plugins()),
            'plugins_by_type': {},
            'plugin_list': []
        }
        
        # Count by type
        for plugin_type in PluginType:
            type_plugins = self.get_plugins_by_type(plugin_type)
            summary['plugins_by_type'][plugin_type.name] = len(type_plugins)
        
        # Plugin details
        for name, plugin in self.plugins.items():
            metadata = plugin.metadata
            summary['plugin_list'].append({
                'name': name,
                'version': metadata.version,
                'type': metadata.plugin_type.name,
                'enabled': metadata.enabled,
                'description': metadata.description
            })
        
        return summary
    
    def cleanup_plugins(self) -> None:
        """Clean up all plugins."""
        for plugin_name, plugin in self.plugins.items():
            try:
                plugin.cleanup()
                self.logger.debug(f"Cleaned up plugin: {plugin_name}")
            except Exception as e:
                self.logger.error(f"Error cleaning up plugin '{plugin_name}': {e}")
    
    def _discover_plugins_in_directory(self, plugin_dir: Path) -> int:
        """Discover plugins in a specific directory."""
        discovered = 0
        
        for py_file in plugin_dir.glob("**/*.py"):
            if py_file.name.startswith("__"):
                continue
                
            try:
                # Import module
                module_name = py_file.stem
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find plugin classes
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, BasePlugin) and 
                        obj != BasePlugin and 
                        not inspect.isabstract(obj)):
                        
                        # Instantiate and register plugin
                        plugin_config = self.configuration.get(name, {})
                        plugin_instance = obj(plugin_config)
                        
                        if self.register_plugin(plugin_instance, plugin_config):
                            discovered += 1
                            
            except Exception as e:
                self.logger.error(f"Error loading plugin from {py_file}: {e}")
        
        return discovered
    
    def _discover_builtin_plugins(self) -> int:
        """Discover built-in plugins in the current package."""
        discovered = 0
        
        try:
            # Import plugin modules
            from plugins import framework_plugins, migration_plugins, documentation_plugins
            
            plugin_modules = [framework_plugins, migration_plugins, documentation_plugins]
            
            for module in plugin_modules:
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, BasePlugin) and 
                        obj != BasePlugin and 
                        not inspect.isabstract(obj)):
                        
                        # Instantiate and register plugin
                        plugin_config = self.configuration.get(name, {})
                        plugin_instance = obj(plugin_config)
                        
                        if self.register_plugin(plugin_instance, plugin_config):
                            discovered += 1
                            
        except ImportError as e:
            self.logger.warning(f"Could not import built-in plugins: {e}")
        except Exception as e:
            self.logger.error(f"Error discovering built-in plugins: {e}")
        
        return discovered
    
    def _register_builtin_plugins(self) -> None:
        """Register built-in plugins that are always available."""
        # This method can be extended to register core plugins
        # that should always be available
        pass
    
    def __enter__(self):
        """Context manager entry."""
        self.discover_plugins()
        self.initialize_plugins()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup_plugins()