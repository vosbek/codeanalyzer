"""
Base Parser Interface
=====================

This module defines the base interface and common functionality for all
file parsers in the Struts analysis system. It provides a consistent
contract for parsing different file types and extracting business rules.

Author: Claude Code Assistant
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import hashlib

from models.business_rule import BusinessRule, BusinessRuleType, BusinessRuleSource


@dataclass
class ParseResult:
    """Represents the result of parsing a file."""
    file_path: str
    parser_name: str
    success: bool
    parse_time_ms: int
    business_rules: List[BusinessRule] = field(default_factory=list)
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_business_rule(self, rule: BusinessRule) -> None:
        """Add a business rule to the parse result."""
        self.business_rules.append(rule)
    
    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)
        self.success = False
    
    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)
    
    def add_extracted_data(self, key: str, data: Any) -> None:
        """Add extracted data with a key."""
        self.extracted_data[key] = data


class BaseParser(ABC):
    """
    Abstract base class for all file parsers.
    
    Parsers are responsible for:
    - Determining if they can parse a given file
    - Extracting structured data from the file
    - Creating business rule objects from the data
    - Providing metadata about the parsing process
    """
    
    def __init__(self):
        """Initialize the parser."""
        self.supported_extensions: Set[str] = set()
        self.supported_patterns: List[str] = []
        self.parser_name = self.__class__.__name__
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """
        Determine if this parser can handle the given file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if this parser can handle the file, False otherwise
        """
        pass
    
    @abstractmethod
    def parse_file(self, file_path: Path) -> ParseResult:
        """
        Parse the given file and extract business rules and data.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            ParseResult containing extracted data and business rules
        """
        pass
    
    def get_priority(self) -> int:
        """
        Get the priority of this parser when multiple parsers can handle a file.
        Higher numbers indicate higher priority.
        
        Returns:
            Priority level (0-100)
        """
        return 50  # Default priority
    
    def supports_extension(self, extension: str) -> bool:
        """Check if this parser supports the given file extension."""
        return extension.lower() in self.supported_extensions
    
    def supports_filename_pattern(self, filename: str) -> bool:
        """Check if this parser supports files matching the given pattern."""
        filename_lower = filename.lower()
        return any(pattern in filename_lower for pattern in self.supported_patterns)
    
    def _create_business_rule(self, 
                            rule_id: str,
                            name: str, 
                            description: str,
                            rule_type: BusinessRuleType,
                            source: BusinessRuleSource,
                            file_path: Path,
                            **kwargs) -> BusinessRule:
        """
        Helper method to create a business rule with common attributes.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name
            description: Detailed description
            rule_type: Type of business rule
            source: Source where the rule was found
            file_path: File containing the rule
            **kwargs: Additional attributes for BusinessRule
            
        Returns:
            Configured BusinessRule instance
        """
        from ..models.business_rule import BusinessRuleLocation, BusinessRuleEvidence
        
        # Set default values
        location = BusinessRuleLocation(file_path=str(file_path))
        evidence = BusinessRuleEvidence(
            code_snippet=kwargs.get('code_snippet', ''),
            context=kwargs.get('context', ''),
            confidence_score=kwargs.get('confidence_score', 0.8)
        )
        
        # Override with provided values
        if 'location' in kwargs:
            location = kwargs['location']
        if 'evidence' in kwargs:
            evidence = kwargs['evidence']
        
        return BusinessRule(
            id=rule_id,
            name=name,
            description=description,
            rule_type=rule_type,
            source=source,
            location=location,
            evidence=evidence,
            business_domain=kwargs.get('business_domain', 'unknown'),
            business_context=kwargs.get('business_context', ''),
            **{k: v for k, v in kwargs.items() 
               if k not in ['location', 'evidence', 'code_snippet', 'context', 'confidence_score']}
        )
    
    def _generate_rule_id(self, *components: str) -> str:
        """
        Generate a unique rule ID from components.
        
        Args:
            *components: Components to include in the ID
            
        Returns:
            Unique rule ID
        """
        content = "_".join(str(comp) for comp in components)
        hash_part = hashlib.md5(content.encode()).hexdigest()[:12]
        return f"{self.parser_name.lower()}_{hash_part}"
    
    def _extract_business_context_from_comments(self, text: str) -> List[str]:
        """
        Extract business context hints from comments in the text.
        
        Args:
            text: Text content to analyze
            
        Returns:
            List of business context hints found in comments
        """
        import re
        
        # Patterns for different comment styles
        comment_patterns = [
            r'/\*\*(.*?)\*/',  # Javadoc comments
            r'/\*(.*?)\*/',    # Multi-line comments
            r'//\s*(.*?)$',    # Single-line comments
            r'#\s*(.*?)$',     # Properties comments
            r'<%--\s*(.*?)\s*--%>'  # JSP comments
        ]
        
        business_indicators = [
            'business rule', 'requirement', 'must', 'should', 'shall',
            'validation', 'constraint', 'policy', 'process', 'workflow'
        ]
        
        business_contexts = []
        
        for pattern in comment_patterns:
            matches = re.findall(pattern, text, re.DOTALL | re.MULTILINE | re.IGNORECASE)
            for match in matches:
                comment_text = match.strip()
                if any(indicator in comment_text.lower() for indicator in business_indicators):
                    business_contexts.append(comment_text)
        
        return business_contexts
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate MD5 hash of file contents for change detection."""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception:
            return ""
    
    def __str__(self) -> str:
        """String representation of the parser."""
        return f"{self.parser_name}(extensions={self.supported_extensions})"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"{self.parser_name}("
            f"extensions={self.supported_extensions}, "
            f"patterns={self.supported_patterns})"
        )