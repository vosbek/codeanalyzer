"""
Configuration Management Utilities
===================================

This module provides configuration management functionality for the Struts analysis system.
It handles loading, merging, and accessing configuration settings from various sources
including YAML files, JSON files, and environment variables.

Features:
- Hierarchical configuration with defaults and user overrides
- Environment variable substitution
- Configuration validation
- Dot notation access for nested values
- Configuration change notification

Author: Claude Code Assistant
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field
from copy import deepcopy


logger = logging.getLogger(__name__)


@dataclass
class ConfigurationSource:
    """Represents a configuration source."""
    name: str
    path: Optional[Path] = None
    data: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0  # Higher priority overrides lower priority
    is_default: bool = False


class ConfigurationError(Exception):
    """Raised when configuration operations fail."""
    pass


class ConfigurationManager:
    """
    Manages configuration settings for the Struts analysis system.
    
    Supports loading configuration from multiple sources with proper
    precedence handling, environment variable substitution, and
    validation.
    """
    
    def __init__(self, config_file: Optional[Union[str, Path]] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Optional path to user configuration file
        """
        self.sources: List[ConfigurationSource] = []
        self.merged_config: Dict[str, Any] = {}
        self._env_prefix = "STRUTS_ANALYZER_"
        
        # Load default configuration
        self._load_default_config()
        
        # Load user configuration if provided
        if config_file:
            self.load_config_file(config_file)
        
        # Load environment variables
        self._load_environment_config()
        
        # Merge all configurations
        self._merge_configurations()
    
    def _load_default_config(self) -> None:
        """Load default configuration settings."""
        default_config = {
            'analysis': {
                'max_file_size_mb': 10,
                'skip_test_files': True,
                'parallel_enabled': True,
                'parallel_workers': 4,
                'min_files_for_parallel': 10,
                'cache_enabled': True,
                'deep_analysis': True,
                'timeout_seconds': 300
            },
            'struts': {
                'config_files': ['struts-config.xml', 'struts.xml'],
                'validation_files': ['validation.xml', 'validator-rules.xml'],
                'supported_versions': ['1.x', '2.x'],
                'action_extensions': ['.java'],
                'jsp_extensions': ['.jsp', '.jspx']
            },
            'output': {
                'format': 'markdown',
                'include_diagrams': True,
                'stakeholder_friendly': True,
                'generate_migration_plan': True,
                'output_directory': './analysis_output',
                'create_timestamp_dirs': True
            },
            'business_rules': {
                'extract_from_comments': True,
                'infer_from_patterns': True,
                'include_ui_rules': True,
                'categorize_by_domain': True,
                'confidence_threshold': 0.7
            },
            'migration': {
                'target_framework': 'spring_boot',
                'include_graphql_recommendations': True,
                'include_angular_recommendations': True,
                'generate_modernization_plan': True,
                'risk_assessment_enabled': True
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file_enabled': True,
                'console_enabled': True,
                'max_file_size_mb': 10,
                'backup_count': 5
            },
            'performance': {
                'enable_monitoring': True,
                'enable_profiling': False,
                'memory_limit_mb': 2048,
                'gc_frequency': 100
            }
        }
        
        source = ConfigurationSource(
            name="default",
            data=default_config,
            priority=0,
            is_default=True
        )
        self.sources.append(source)
    
    def load_config_file(self, config_file: Union[str, Path]) -> None:
        """
        Load configuration from a file.
        
        Args:
            config_file: Path to configuration file (YAML or JSON)
        """
        config_path = Path(config_file)
        
        if not config_path.exists():
            logger.warning(f"Configuration file not found: {config_path}")
            return
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                if config_path.suffix.lower() in ['.yaml', '.yml']:
                    data = yaml.safe_load(f)
                elif config_path.suffix.lower() == '.json':
                    data = json.load(f)
                else:
                    raise ConfigurationError(f"Unsupported configuration file format: {config_path.suffix}")
            
            if data is None:
                data = {}
            
            source = ConfigurationSource(
                name=f"file:{config_path.name}",
                path=config_path,
                data=data,
                priority=10  # User files have higher priority than defaults
            )
            self.sources.append(source)
            
            logger.info(f"Loaded configuration from {config_path}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration file {config_path}: {e}")
            raise ConfigurationError(f"Failed to load configuration file: {e}")
    
    def _load_environment_config(self) -> None:
        """Load configuration from environment variables."""
        env_config = {}
        
        for key, value in os.environ.items():
            if key.startswith(self._env_prefix):
                # Convert environment variable to config key
                config_key = key[len(self._env_prefix):].lower().replace('_', '.')
                
                # Try to parse as JSON first, then as string
                try:
                    parsed_value = json.loads(value)
                except (json.JSONDecodeError, ValueError):
                    parsed_value = value
                
                # Set nested value
                self._set_nested_value(env_config, config_key, parsed_value)
        
        if env_config:
            source = ConfigurationSource(
                name="environment",
                data=env_config,
                priority=20  # Environment variables have highest priority
            )
            self.sources.append(source)
            
            logger.info("Loaded configuration from environment variables")
    
    def _set_nested_value(self, config: Dict[str, Any], key_path: str, value: Any) -> None:
        """Set a value in nested dictionary using dot notation."""
        keys = key_path.split('.')
        current = config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _merge_configurations(self) -> None:
        """Merge all configuration sources based on priority."""
        self.merged_config = {}
        
        # Sort sources by priority (lower numbers first)
        sorted_sources = sorted(self.sources, key=lambda s: s.priority)
        
        for source in sorted_sources:
            self._deep_merge(self.merged_config, source.data)
        
        # Perform environment variable substitution
        self._substitute_environment_variables(self.merged_config)
        
        logger.debug("Configuration merged from all sources")
    
    def _deep_merge(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Deep merge source dictionary into target dictionary."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = deepcopy(value)
    
    def _substitute_environment_variables(self, config: Dict[str, Any]) -> None:
        """Substitute environment variables in configuration values."""
        for key, value in config.items():
            if isinstance(value, dict):
                self._substitute_environment_variables(value)
            elif isinstance(value, str):
                # Simple environment variable substitution: ${VAR_NAME}
                import re
                pattern = r'\$\{([^}]+)\}'
                
                def replace_env_var(match):
                    env_var = match.group(1)
                    return os.environ.get(env_var, match.group(0))
                
                config[key] = re.sub(pattern, replace_env_var, value)
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to configuration value (e.g., 'analysis.max_file_size_mb')
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.merged_config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to configuration value
            value: Value to set
        """
        self._set_nested_value(self.merged_config, key_path, value)
        logger.debug(f"Configuration updated: {key_path} = {value}")
    
    def has(self, key_path: str) -> bool:
        """
        Check if configuration key exists.
        
        Args:
            key_path: Dot-separated path to configuration value
            
        Returns:
            True if key exists, False otherwise
        """
        return self.get(key_path, None) is not None
    
    def get_section(self, section_path: str) -> Dict[str, Any]:
        """
        Get entire configuration section.
        
        Args:
            section_path: Dot-separated path to configuration section
            
        Returns:
            Configuration section as dictionary
        """
        section = self.get(section_path, {})
        if not isinstance(section, dict):
            return {}
        return deepcopy(section)
    
    def update_from_dict(self, config_dict: Dict[str, Any]) -> None:
        """
        Update configuration from dictionary.
        
        Args:
            config_dict: Dictionary containing configuration updates
        """
        source = ConfigurationSource(
            name="runtime_update",
            data=config_dict,
            priority=30  # Runtime updates have highest priority
        )
        self.sources.append(source)
        self._merge_configurations()
        
        logger.info("Configuration updated from dictionary")
    
    def validate_config(self) -> List[str]:
        """
        Validate configuration settings.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Validate analysis settings
        max_file_size = self.get('analysis.max_file_size_mb')
        if not isinstance(max_file_size, (int, float)) or max_file_size <= 0:
            errors.append("analysis.max_file_size_mb must be a positive number")
        
        parallel_workers = self.get('analysis.parallel_workers')
        if not isinstance(parallel_workers, int) or parallel_workers < 1:
            errors.append("analysis.parallel_workers must be a positive integer")
        
        timeout_seconds = self.get('analysis.timeout_seconds')
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            errors.append("analysis.timeout_seconds must be a positive number")
        
        # Validate output settings
        output_dir = self.get('output.output_directory')
        if not isinstance(output_dir, str) or not output_dir.strip():
            errors.append("output.output_directory must be a non-empty string")
        
        # Validate logging settings
        log_level = self.get('logging.level')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level not in valid_levels:
            errors.append(f"logging.level must be one of: {valid_levels}")
        
        return errors
    
    def save_to_file(self, file_path: Union[str, Path], 
                    include_defaults: bool = False) -> None:
        """
        Save current configuration to file.
        
        Args:
            file_path: Path where to save configuration
            include_defaults: Whether to include default values
        """
        output_path = Path(file_path)
        
        if include_defaults:
            config_to_save = self.merged_config
        else:
            # Only save non-default configurations
            config_to_save = {}
            for source in self.sources:
                if not source.is_default:
                    self._deep_merge(config_to_save, source.data)
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                if output_path.suffix.lower() in ['.yaml', '.yml']:
                    yaml.dump(config_to_save, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_to_save, f, indent=2, default=str)
            
            logger.info(f"Configuration saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration to {output_path}: {e}")
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def get_effective_config(self) -> Dict[str, Any]:
        """
        Get the effective configuration (merged from all sources).
        
        Returns:
            Complete merged configuration
        """
        return deepcopy(self.merged_config)
    
    def list_sources(self) -> List[Dict[str, Any]]:
        """
        List all configuration sources.
        
        Returns:
            List of configuration source information
        """
        return [
            {
                'name': source.name,
                'path': str(source.path) if source.path else None,
                'priority': source.priority,
                'is_default': source.is_default,
                'keys': list(source.data.keys()) if source.data else []
            }
            for source in self.sources
        ]
    
    def __str__(self) -> str:
        """String representation of configuration manager."""
        return f"ConfigurationManager(sources={len(self.sources)})"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        source_names = [source.name for source in self.sources]
        return f"ConfigurationManager(sources={source_names})"