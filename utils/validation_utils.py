"""
Validation Utilities
====================

This module provides validation utilities for the Struts analysis system.
It includes input validation, error checking, and data integrity verification
to ensure robust and reliable analysis operations.

Features:
- File and directory validation
- Configuration validation  
- Data structure validation
- Custom validation rules
- Detailed error reporting

Author: Claude Code Assistant
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Pattern, Callable
from dataclasses import dataclass
import logging


logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, 
                 value: Any = None, suggestions: Optional[List[str]] = None):
        """
        Initialize validation error.
        
        Args:
            message: Error message
            field: Field name that failed validation
            value: Value that failed validation
            suggestions: Suggested corrections
        """
        super().__init__(message)
        self.field = field
        self.value = value
        self.suggestions = suggestions or []
    
    def __str__(self) -> str:
        """String representation of validation error."""
        msg = super().__str__()
        if self.field:
            msg = f"Field '{self.field}': {msg}"
        if self.suggestions:
            msg += f"\nSuggestions: {', '.join(self.suggestions)}"
        return msg


@dataclass
class ValidationResult:
    """Result of a validation operation."""
    is_valid: bool
    errors: List[ValidationError]
    warnings: List[str]
    
    def add_error(self, message: str, field: Optional[str] = None, 
                  value: Any = None, suggestions: Optional[List[str]] = None) -> None:
        """Add a validation error."""
        self.errors.append(ValidationError(message, field, value, suggestions))
        self.is_valid = False
    
    def add_warning(self, message: str) -> None:
        """Add a validation warning."""
        self.warnings.append(message)
    
    def merge(self, other: 'ValidationResult') -> None:
        """Merge another validation result."""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if not other.is_valid:
            self.is_valid = False


class Validator:
    """Base class for validators."""
    
    def __init__(self, name: str):
        """Initialize validator with a name."""
        self.name = name
    
    def validate(self, value: Any) -> ValidationResult:
        """Validate a value and return result."""
        result = ValidationResult(is_valid=True, errors=[], warnings=[])
        self._validate_impl(value, result)
        return result
    
    def _validate_impl(self, value: Any, result: ValidationResult) -> None:
        """Implementation of validation logic."""
        raise NotImplementedError("Subclasses must implement _validate_impl")


class FilePathValidator(Validator):
    """Validator for file paths."""
    
    def __init__(self, must_exist: bool = True, must_be_file: bool = True,
                 allowed_extensions: Optional[List[str]] = None):
        """
        Initialize file path validator.
        
        Args:
            must_exist: Whether file must exist
            must_be_file: Whether path must be a file (not directory)
            allowed_extensions: List of allowed file extensions
        """
        super().__init__("file_path")
        self.must_exist = must_exist
        self.must_be_file = must_be_file
        self.allowed_extensions = allowed_extensions or []
    
    def _validate_impl(self, value: Any, result: ValidationResult) -> None:
        """Validate file path."""
        if not isinstance(value, (str, Path)):
            result.add_error("Value must be a string or Path object", value=value)
            return
        
        path = Path(value)
        
        # Check if path exists
        if self.must_exist and not path.exists():
            result.add_error(f"Path does not exist: {path}", value=value,
                           suggestions=["Check if the path is correct", "Ensure the file exists"])
            return
        
        # Check if it's a file
        if self.must_be_file and path.exists() and not path.is_file():
            result.add_error(f"Path is not a file: {path}", value=value)
            return
        
        # Check file extension
        if self.allowed_extensions and path.suffix.lower() not in self.allowed_extensions:
            result.add_error(
                f"File extension '{path.suffix}' not allowed. "
                f"Allowed extensions: {self.allowed_extensions}",
                value=value
            )
        
        # Check file size (warn if very large)
        if path.exists() and path.is_file():
            size_mb = path.stat().st_size / 1024 / 1024
            if size_mb > 100:  # Warn for files larger than 100MB
                result.add_warning(f"Large file detected: {size_mb:.1f}MB")
        
        # Check file permissions
        if path.exists() and not os.access(path, os.R_OK):
            result.add_error(f"No read permission for file: {path}", value=value)


class DirectoryValidator(Validator):
    """Validator for directory paths."""
    
    def __init__(self, must_exist: bool = True, must_be_writable: bool = False):
        """
        Initialize directory validator.
        
        Args:
            must_exist: Whether directory must exist
            must_be_writable: Whether directory must be writable
        """
        super().__init__("directory")
        self.must_exist = must_exist
        self.must_be_writable = must_be_writable
    
    def _validate_impl(self, value: Any, result: ValidationResult) -> None:
        """Validate directory path."""
        if not isinstance(value, (str, Path)):
            result.add_error("Value must be a string or Path object", value=value)
            return
        
        path = Path(value)
        
        # Check if directory exists
        if self.must_exist and not path.exists():
            result.add_error(f"Directory does not exist: {path}", value=value,
                           suggestions=["Check if the path is correct", "Create the directory"])
            return
        
        # Check if it's a directory
        if path.exists() and not path.is_dir():
            result.add_error(f"Path is not a directory: {path}", value=value)
            return
        
        # Check write permissions
        if self.must_be_writable:
            if path.exists() and not os.access(path, os.W_OK):
                result.add_error(f"No write permission for directory: {path}", value=value)
            elif not path.exists():
                # Check if parent directory is writable
                parent = path.parent
                if parent.exists() and not os.access(parent, os.W_OK):
                    result.add_error(f"Cannot create directory - no write permission in parent: {parent}",
                                   value=value)


class RegexValidator(Validator):
    """Validator using regular expressions."""
    
    def __init__(self, pattern: Union[str, Pattern], name: str = "regex",
                 error_message: Optional[str] = None):
        """
        Initialize regex validator.
        
        Args:
            pattern: Regular expression pattern
            name: Name of the validator
            error_message: Custom error message
        """
        super().__init__(name)
        self.pattern = re.compile(pattern) if isinstance(pattern, str) else pattern
        self.error_message = error_message or f"Value does not match pattern: {pattern}"
    
    def _validate_impl(self, value: Any, result: ValidationResult) -> None:
        """Validate using regex pattern."""
        if not isinstance(value, str):
            result.add_error("Value must be a string", value=value)
            return
        
        if not self.pattern.match(value):
            result.add_error(self.error_message, value=value)


class RangeValidator(Validator):
    """Validator for numeric ranges."""
    
    def __init__(self, min_value: Optional[Union[int, float]] = None,
                 max_value: Optional[Union[int, float]] = None,
                 name: str = "range"):
        """
        Initialize range validator.
        
        Args:
            min_value: Minimum allowed value
            max_value: Maximum allowed value
            name: Name of the validator
        """
        super().__init__(name)
        self.min_value = min_value
        self.max_value = max_value
    
    def _validate_impl(self, value: Any, result: ValidationResult) -> None:
        """Validate numeric range."""
        if not isinstance(value, (int, float)):
            result.add_error("Value must be a number", value=value)
            return
        
        if self.min_value is not None and value < self.min_value:
            result.add_error(f"Value {value} is below minimum {self.min_value}", value=value)
        
        if self.max_value is not None and value > self.max_value:
            result.add_error(f"Value {value} is above maximum {self.max_value}", value=value)


class ChoiceValidator(Validator):
    """Validator for choice fields."""
    
    def __init__(self, choices: List[Any], name: str = "choice",
                 case_sensitive: bool = True):
        """
        Initialize choice validator.
        
        Args:
            choices: List of valid choices
            name: Name of the validator
            case_sensitive: Whether comparison is case-sensitive
        """
        super().__init__(name)
        self.choices = choices
        self.case_sensitive = case_sensitive
    
    def _validate_impl(self, value: Any, result: ValidationResult) -> None:
        """Validate choice."""
        if self.case_sensitive:
            valid = value in self.choices
        else:
            # Case-insensitive comparison for strings
            if isinstance(value, str):
                valid = any(isinstance(choice, str) and choice.lower() == value.lower() 
                          for choice in self.choices)
            else:
                valid = value in self.choices
        
        if not valid:
            result.add_error(f"Invalid choice '{value}'. Valid choices: {self.choices}",
                           value=value, suggestions=self.choices)


class CompositeValidator(Validator):
    """Validator that combines multiple validators."""
    
    def __init__(self, validators: List[Validator], name: str = "composite",
                 require_all: bool = True):
        """
        Initialize composite validator.
        
        Args:
            validators: List of validators to apply
            name: Name of the validator
            require_all: Whether all validators must pass (AND) or any (OR)
        """
        super().__init__(name)
        self.validators = validators
        self.require_all = require_all
    
    def _validate_impl(self, value: Any, result: ValidationResult) -> None:
        """Validate using all validators."""
        results = [validator.validate(value) for validator in self.validators]
        
        if self.require_all:
            # All validators must pass
            for val_result in results:
                result.merge(val_result)
        else:
            # At least one validator must pass
            if not any(r.is_valid for r in results):
                # All failed, merge all errors
                for val_result in results:
                    result.merge(val_result)


# Convenience functions for common validations

def validate_file_path(file_path: Union[str, Path], must_exist: bool = True,
                      allowed_extensions: Optional[List[str]] = None) -> None:
    """
    Validate a file path.
    
    Args:
        file_path: Path to validate
        must_exist: Whether file must exist
        allowed_extensions: List of allowed extensions
        
    Raises:
        ValidationError: If validation fails
    """
    validator = FilePathValidator(must_exist=must_exist, allowed_extensions=allowed_extensions)
    result = validator.validate(file_path)
    
    if not result.is_valid:
        raise result.errors[0]


def validate_directory(directory_path: Union[str, Path], must_exist: bool = True,
                      must_be_writable: bool = False) -> None:
    """
    Validate a directory path.
    
    Args:
        directory_path: Directory path to validate
        must_exist: Whether directory must exist
        must_be_writable: Whether directory must be writable
        
    Raises:
        ValidationError: If validation fails
    """
    validator = DirectoryValidator(must_exist=must_exist, must_be_writable=must_be_writable)
    result = validator.validate(directory_path)
    
    if not result.is_valid:
        raise result.errors[0]


def validate_configuration(config: Dict[str, Any]) -> ValidationResult:
    """
    Validate configuration dictionary.
    
    Args:
        config: Configuration to validate
        
    Returns:
        ValidationResult with validation outcome
    """
    result = ValidationResult(is_valid=True, errors=[], warnings=[])
    
    # Validate analysis settings
    if 'analysis' in config:
        analysis_config = config['analysis']
        
        # Validate max_file_size_mb
        if 'max_file_size_mb' in analysis_config:
            validator = RangeValidator(min_value=0.1, max_value=1000, name="max_file_size_mb")
            size_result = validator.validate(analysis_config['max_file_size_mb'])
            result.merge(size_result)
        
        # Validate parallel_workers
        if 'parallel_workers' in analysis_config:
            validator = RangeValidator(min_value=1, max_value=64, name="parallel_workers")
            workers_result = validator.validate(analysis_config['parallel_workers'])
            result.merge(workers_result)
        
        # Validate timeout_seconds
        if 'timeout_seconds' in analysis_config:
            validator = RangeValidator(min_value=1, max_value=3600, name="timeout_seconds")
            timeout_result = validator.validate(analysis_config['timeout_seconds'])
            result.merge(timeout_result)
    
    # Validate output settings
    if 'output' in config:
        output_config = config['output']
        
        # Validate format
        if 'format' in output_config:
            validator = ChoiceValidator(['markdown', 'json', 'yaml', 'html'], name="output_format")
            format_result = validator.validate(output_config['format'])
            result.merge(format_result)
        
        # Validate output directory
        if 'output_directory' in output_config:
            try:
                validate_directory(output_config['output_directory'], must_exist=False, must_be_writable=True)
            except ValidationError as e:
                result.add_error(str(e), field="output_directory")
    
    # Validate logging settings
    if 'logging' in config:
        logging_config = config['logging']
        
        # Validate log level
        if 'level' in logging_config:
            validator = ChoiceValidator(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                                      name="log_level", case_sensitive=False)
            level_result = validator.validate(logging_config['level'])
            result.merge(level_result)
    
    return result


def validate_struts_project(project_path: Union[str, Path]) -> ValidationResult:
    """
    Validate that a directory contains a Struts project.
    
    Args:
        project_path: Path to potential Struts project
        
    Returns:
        ValidationResult with validation outcome
    """
    result = ValidationResult(is_valid=True, errors=[], warnings=[])
    path = Path(project_path)
    
    # Check if directory exists
    if not path.exists():
        result.add_error(f"Project directory does not exist: {path}")
        return result
    
    if not path.is_dir():
        result.add_error(f"Project path is not a directory: {path}")
        return result
    
    # Look for Struts indicators
    struts_indicators = []
    
    # Check for struts configuration files
    config_files = ['struts-config.xml', 'struts.xml']
    for config_file in config_files:
        if (path / config_file).exists():
            struts_indicators.append(f"Found {config_file}")
    
    # Check for WEB-INF directory
    web_inf = path / 'WEB-INF'
    if web_inf.exists():
        struts_indicators.append("Found WEB-INF directory")
        
        # Check for web.xml
        web_xml = web_inf / 'web.xml'
        if web_xml.exists():
            struts_indicators.append("Found web.xml")
            
            # Check web.xml content for Struts references
            try:
                with open(web_xml, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'struts' in content.lower():
                        struts_indicators.append("Found Struts references in web.xml")
            except Exception:
                pass
    
    # Check for validation files
    validation_files = ['validation.xml', 'validator-rules.xml']
    for val_file in validation_files:
        if (path / val_file).exists() or (web_inf / val_file).exists():
            struts_indicators.append(f"Found {val_file}")
    
    # Check for Java source files with Action pattern
    java_files = list(path.rglob('*.java'))
    action_files = [f for f in java_files if 'action' in f.name.lower()]
    if action_files:
        struts_indicators.append(f"Found {len(action_files)} potential Action files")
    
    # Check for JSP files
    jsp_files = list(path.rglob('*.jsp'))
    if jsp_files:
        struts_indicators.append(f"Found {len(jsp_files)} JSP files")
    
    # Evaluate results
    if not struts_indicators:
        result.add_error("No Struts project indicators found in directory")
        result.add_warning("This may not be a Struts project or may be missing key files")
    elif len(struts_indicators) < 2:
        result.add_warning("Only minimal Struts indicators found - project may be incomplete")
    
    # Add informational warnings
    for indicator in struts_indicators:
        result.add_warning(f"✓ {indicator}")
    
    return result


class ValidationContext:
    """Context for validation operations with custom rules."""
    
    def __init__(self):
        """Initialize validation context."""
        self.custom_validators: Dict[str, Validator] = {}
        self.global_rules: List[Callable[[Any], ValidationResult]] = []
    
    def register_validator(self, name: str, validator: Validator) -> None:
        """Register a custom validator."""
        self.custom_validators[name] = validator
    
    def add_global_rule(self, rule: Callable[[Any], ValidationResult]) -> None:
        """Add a global validation rule."""
        self.global_rules.append(rule)
    
    def validate(self, value: Any, validator_names: List[str]) -> ValidationResult:
        """Validate using specified validators."""
        result = ValidationResult(is_valid=True, errors=[], warnings=[])
        
        # Apply custom validators
        for name in validator_names:
            if name in self.custom_validators:
                validator_result = self.custom_validators[name].validate(value)
                result.merge(validator_result)
        
        # Apply global rules
        for rule in self.global_rules:
            rule_result = rule(value)
            result.merge(rule_result)
        
        return result


# Create a global validation context
validation_context = ValidationContext()