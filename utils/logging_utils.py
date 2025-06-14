"""
Logging Utilities
=================

This module provides centralized logging configuration and utilities for the 
Struts analysis system. It supports multiple output formats, log rotation,
and context-aware logging.

Features:
- Structured logging with context information
- Multiple output handlers (console, file, rotating file)
- Performance-aware logging (minimal overhead in production)
- Custom formatters for different output types
- Log level management per module

Author: Claude Code Assistant
"""

import logging
import logging.handlers
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional, Union
from datetime import datetime
import json


class ContextFilter(logging.Filter):
    """Filter that adds context information to log records."""
    
    def __init__(self, context: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.context = context or {}
    
    def filter(self, record):
        """Add context information to the log record."""
        for key, value in self.context.items():
            setattr(record, key, value)
        return True


class JSONFormatter(logging.Formatter):
    """Formatter that outputs log records as JSON."""
    
    def format(self, record):
        """Format log record as JSON."""
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'message']:
                log_entry[key] = str(value)
        
        return json.dumps(log_entry)


class ColoredFormatter(logging.Formatter):
    """Formatter that adds colors to console output."""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        """Format log record with colors."""
        # Get the base formatted message
        message = super().format(record)
        
        # Add color if outputting to a terminal
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            reset = self.COLORS['RESET']
            return f"{color}{message}{reset}"
        
        return message


class PerformanceFormatter(logging.Formatter):
    """Lightweight formatter optimized for performance."""
    
    def format(self, record):
        """Fast formatting for high-volume logging."""
        return f"{record.levelname[0]}|{record.name}|{record.getMessage()}"


def setup_logging(config: Optional[Dict[str, Any]] = None) -> None:
    """
    Set up logging configuration for the entire application.
    
    Args:
        config: Logging configuration dictionary
    """
    if config is None:
        config = get_default_logging_config()
    
    # Clear any existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set root logger level
    log_level = getattr(logging, config.get('level', 'INFO').upper())
    root_logger.setLevel(log_level)
    
    # Create formatters
    formatters = _create_formatters(config)
    
    # Set up console handler
    if config.get('console_enabled', True):
        console_handler = _create_console_handler(config, formatters)
        root_logger.addHandler(console_handler)
    
    # Set up file handler
    if config.get('file_enabled', True):
        file_handler = _create_file_handler(config, formatters)
        if file_handler:
            root_logger.addHandler(file_handler)
    
    # Set up rotating file handler for long-running processes
    if config.get('rotating_file_enabled', False):
        rotating_handler = _create_rotating_file_handler(config, formatters)
        if rotating_handler:
            root_logger.addHandler(rotating_handler)
    
    # Set up JSON file handler for structured logging
    if config.get('json_file_enabled', False):
        json_handler = _create_json_file_handler(config, formatters)
        if json_handler:
            root_logger.addHandler(json_handler)
    
    # Configure specific logger levels
    logger_levels = config.get('logger_levels', {})
    for logger_name, level in logger_levels.items():
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, level.upper()))
    
    # Suppress noisy third-party loggers
    _suppress_noisy_loggers(config)


def _create_formatters(config: Dict[str, Any]) -> Dict[str, logging.Formatter]:
    """Create logging formatters based on configuration."""
    formatters = {}
    
    # Standard formatter
    standard_format = config.get('format', 
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatters['standard'] = logging.Formatter(standard_format)
    
    # Colored formatter for console
    formatters['colored'] = ColoredFormatter(standard_format)
    
    # JSON formatter for structured logging
    formatters['json'] = JSONFormatter()
    
    # Performance formatter for high-volume logging
    formatters['performance'] = PerformanceFormatter()
    
    # Detailed formatter with more context
    detailed_format = (
        '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s'
    )
    formatters['detailed'] = logging.Formatter(detailed_format)
    
    return formatters


def _create_console_handler(config: Dict[str, Any], 
                          formatters: Dict[str, logging.Formatter]) -> logging.Handler:
    """Create console handler."""
    handler = logging.StreamHandler(sys.stdout)
    
    # Use colored formatter for console if available
    formatter_name = config.get('console_formatter', 'colored')
    handler.setFormatter(formatters.get(formatter_name, formatters['standard']))
    
    # Set console-specific log level
    console_level = config.get('console_level', config.get('level', 'INFO'))
    handler.setLevel(getattr(logging, console_level.upper()))
    
    return handler


def _create_file_handler(config: Dict[str, Any], 
                        formatters: Dict[str, logging.Formatter]) -> Optional[logging.Handler]:
    """Create file handler."""
    log_file = config.get('log_file', 'struts_analyzer.log')
    
    try:
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        handler = logging.FileHandler(log_file, encoding='utf-8')
        
        # Use detailed formatter for file logging
        formatter_name = config.get('file_formatter', 'detailed')
        handler.setFormatter(formatters.get(formatter_name, formatters['detailed']))
        
        # Set file-specific log level
        file_level = config.get('file_level', config.get('level', 'INFO'))
        handler.setLevel(getattr(logging, file_level.upper()))
        
        return handler
        
    except Exception as e:
        print(f"Warning: Could not create file handler for {log_file}: {e}")
        return None


def _create_rotating_file_handler(config: Dict[str, Any], 
                                formatters: Dict[str, logging.Formatter]) -> Optional[logging.Handler]:
    """Create rotating file handler."""
    log_file = config.get('rotating_log_file', 'struts_analyzer_rotating.log')
    max_bytes = config.get('max_file_size_mb', 10) * 1024 * 1024
    backup_count = config.get('backup_count', 5)
    
    try:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=max_bytes, 
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        formatter_name = config.get('rotating_file_formatter', 'detailed')
        handler.setFormatter(formatters.get(formatter_name, formatters['detailed']))
        
        rotating_level = config.get('rotating_file_level', config.get('level', 'INFO'))
        handler.setLevel(getattr(logging, rotating_level.upper()))
        
        return handler
        
    except Exception as e:
        print(f"Warning: Could not create rotating file handler for {log_file}: {e}")
        return None


def _create_json_file_handler(config: Dict[str, Any], 
                            formatters: Dict[str, logging.Formatter]) -> Optional[logging.Handler]:
    """Create JSON file handler for structured logging."""
    json_log_file = config.get('json_log_file', 'struts_analyzer.json.log')
    
    try:
        log_path = Path(json_log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        handler = logging.FileHandler(json_log_file, encoding='utf-8')
        handler.setFormatter(formatters['json'])
        
        json_level = config.get('json_file_level', config.get('level', 'INFO'))
        handler.setLevel(getattr(logging, json_level.upper()))
        
        return handler
        
    except Exception as e:
        print(f"Warning: Could not create JSON file handler for {json_log_file}: {e}")
        return None


def _suppress_noisy_loggers(config: Dict[str, Any]) -> None:
    """Suppress noisy third-party loggers."""
    suppress_loggers = config.get('suppress_loggers', [
        'urllib3.connectionpool',
        'requests.packages.urllib3',
        'matplotlib',
        'PIL'
    ])
    
    for logger_name in suppress_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def get_logger(name: str, context: Optional[Dict[str, Any]] = None) -> logging.Logger:
    """
    Get a logger with optional context information.
    
    Args:
        name: Logger name (usually module name)
        context: Optional context information to add to all log messages
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Add context filter if provided
    if context:
        context_filter = ContextFilter(context)
        logger.addFilter(context_filter)
    
    return logger


def get_default_logging_config() -> Dict[str, Any]:
    """Get default logging configuration."""
    return {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'console_enabled': True,
        'console_formatter': 'colored',
        'console_level': 'INFO',
        'file_enabled': True,
        'file_formatter': 'detailed',
        'file_level': 'DEBUG',
        'log_file': 'struts_analyzer.log',
        'rotating_file_enabled': False,
        'rotating_file_formatter': 'detailed',
        'rotating_file_level': 'INFO',
        'max_file_size_mb': 10,
        'backup_count': 5,
        'json_file_enabled': False,
        'json_file_level': 'INFO',
        'json_log_file': 'struts_analyzer.json.log',
        'logger_levels': {
            'javalang': 'WARNING',
            'networkx': 'WARNING',
            'tqdm': 'WARNING'
        },
        'suppress_loggers': [
            'urllib3.connectionpool',
            'requests.packages.urllib3',
            'matplotlib',
            'PIL'
        ]
    }


def configure_performance_logging() -> None:
    """Configure high-performance logging for production use."""
    config = {
        'level': 'WARNING',
        'format': '%(levelname)s:%(name)s:%(message)s',
        'console_enabled': True,
        'console_formatter': 'performance',
        'file_enabled': False,
        'rotating_file_enabled': True,
        'rotating_file_formatter': 'performance',
        'max_file_size_mb': 50,
        'backup_count': 3
    }
    setup_logging(config)


def configure_debug_logging() -> None:
    """Configure detailed logging for debugging."""
    config = {
        'level': 'DEBUG',
        'console_enabled': True,
        'console_formatter': 'colored',
        'console_level': 'DEBUG',
        'file_enabled': True,
        'file_formatter': 'detailed',
        'file_level': 'DEBUG',
        'json_file_enabled': True,
        'json_file_level': 'DEBUG',
        'logger_levels': {}  # Don't suppress any loggers in debug mode
    }
    setup_logging(config)


class LoggerContextManager:
    """Context manager for temporary logger configuration."""
    
    def __init__(self, logger_name: str, level: Union[str, int], 
                 context: Optional[Dict[str, Any]] = None):
        """
        Initialize context manager.
        
        Args:
            logger_name: Name of logger to configure
            level: Temporary log level
            context: Optional context to add
        """
        self.logger_name = logger_name
        self.new_level = level if isinstance(level, int) else getattr(logging, level.upper())
        self.context = context
        self.original_level = None
        self.context_filter = None
    
    def __enter__(self):
        """Enter context and apply temporary configuration."""
        logger = logging.getLogger(self.logger_name)
        self.original_level = logger.level
        logger.setLevel(self.new_level)
        
        if self.context:
            self.context_filter = ContextFilter(self.context)
            logger.addFilter(self.context_filter)
        
        return logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original configuration."""
        logger = logging.getLogger(self.logger_name)
        logger.setLevel(self.original_level)
        
        if self.context_filter:
            logger.removeFilter(self.context_filter)


# Convenience function for temporary logger configuration
def with_logger_config(logger_name: str, level: Union[str, int], 
                      context: Optional[Dict[str, Any]] = None):
    """
    Context manager for temporary logger configuration.
    
    Usage:
        with with_logger_config('my.logger', 'DEBUG', {'component': 'parser'}):
            # Logger is temporarily configured
            logger.debug("This will be logged")
    """
    return LoggerContextManager(logger_name, level, context)