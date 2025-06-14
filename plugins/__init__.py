"""
Plugin Framework
================

This module provides a pluggable extension framework for the Struts analyzer.
Plugins can extend functionality for specific frameworks, custom analyzers,
or integration with external tools.

The plugin framework supports:
- Custom business rule extractors
- Framework-specific analyzers (Spring, Hibernate, etc.)
- External tool integrations
- Custom documentation generators
- Migration strategy plugins

Author: Claude Code Assistant
"""

from plugins.plugin_manager import PluginManager
from plugins.base_plugin import BasePlugin, PluginMetadata
from plugins.framework_plugins import SpringIntegrationPlugin, HibernateAnalysisPlugin
from plugins.migration_plugins import GraphQLMigrationPlugin, AngularMigrationPlugin
from plugins.documentation_plugins import CustomDocumentationPlugin

__all__ = [
    'PluginManager',
    'BasePlugin',
    'PluginMetadata',
    'SpringIntegrationPlugin',
    'HibernateAnalysisPlugin', 
    'GraphQLMigrationPlugin',
    'AngularMigrationPlugin',
    'CustomDocumentationPlugin'
]