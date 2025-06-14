"""
Parser Framework
================

This module provides a pluggable parser framework for different file types
in Struts applications. Each parser is responsible for extracting structured
data from specific file formats.

The parser framework supports:
- XML configuration files (struts-config.xml, validation.xml, etc.)
- Java source files with business logic
- JSP/JSPX template files
- Properties files for messages and configuration
- Web.xml deployment descriptors
- Spring configuration files (for hybrid applications)

Author: Claude Code Assistant
"""

from .base_parser import BaseParser, ParseResult
from .xml_parser import XMLConfigurationParser
from .java_parser import JavaSourceParser
from .jsp_parser import JSPTemplateParser
from .properties_parser import PropertiesFileParser

__all__ = [
    'BaseParser',
    'ParseResult', 
    'XMLConfigurationParser',
    'JavaSourceParser', 
    'JSPTemplateParser',
    'PropertiesFileParser'
]