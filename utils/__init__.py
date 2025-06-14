"""
Utilities Package
=================

This package contains utility modules that provide common functionality
across the Struts analysis system. These utilities handle configuration,
logging, performance monitoring, validation, and other cross-cutting concerns.

Utilities included:
- config_utils: Configuration management and settings
- logging_utils: Centralized logging configuration
- performance_utils: Performance monitoring and optimization
- validation_utils: Input validation and error checking
- file_utils: File system operations and path handling
- cache_utils: Caching mechanisms for improved performance

Author: Claude Code Assistant
"""

from .config_utils import ConfigurationManager
from .logging_utils import get_logger, setup_logging
from .performance_utils import PerformanceMonitor, performance_timer
from .validation_utils import ValidationError, validate_file_path, validate_directory
from .file_utils import FileUtils, find_files_by_pattern
from .cache_utils import CacheManager

__all__ = [
    # Configuration
    "ConfigurationManager",
    
    # Logging
    "get_logger",
    "setup_logging",
    
    # Performance
    "PerformanceMonitor",
    "performance_timer",
    
    # Validation
    "ValidationError",
    "validate_file_path",
    "validate_directory",
    
    # File operations
    "FileUtils",
    "find_files_by_pattern",
    
    # Caching
    "CacheManager"
]