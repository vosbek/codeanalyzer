"""
Documentation Generators
========================

This module provides documentation generation functionality for the
Struts analyzer, including enhanced HTML, PDF, and interactive reports.

Author: Claude Code Assistant
"""

# Import will be done dynamically when needed to avoid import issues
__all__ = [
    'EnhancedDocumentationGenerator'
]

def __getattr__(name):
    if name == 'EnhancedDocumentationGenerator':
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from generators.enhanced_documentation_generator import EnhancedDocumentationGenerator
        return EnhancedDocumentationGenerator
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")