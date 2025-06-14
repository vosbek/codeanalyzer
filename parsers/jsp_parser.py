"""
JSP Template Parser
==================

This parser handles JavaServer Pages (JSP) templates, extracting UI business rules,
validation logic, and presentation patterns for migration to Angular components.

Features:
- JSP tag analysis for business logic extraction
- Form validation and binding patterns
- UI business rules identification
- Angular component mapping recommendations
- Template structure analysis

Author: Claude Code Assistant
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from xml.etree import ElementTree as ET

from parsers.base_parser import BaseParser, ParseResult
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource,
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)


class JSPTemplateParser(BaseParser):
    """Parser for JSP template files in Struts applications."""
    
    def __init__(self):
        """Initialize JSP parser."""
        super().__init__()
        self.supported_extensions = {'.jsp', '.jspx'}
        
        # JSP/Struts tag patterns
        self.struts_tags = {
            'form_tags': ['html:form', 'html:text', 'html:password', 'html:hidden', 
                         'html:textarea', 'html:select', 'html:submit', 'html:cancel'],
            'logic_tags': ['logic:iterate', 'logic:if', 'logic:equal', 'logic:notEqual',
                          'logic:present', 'logic:notPresent', 'logic:match'],
            'bean_tags': ['bean:write', 'bean:message', 'bean:define'],
            'validation_tags': ['html:errors', 'html:messages']
        }
        
        # Business logic indicators in JSP
        self.business_indicators = [
            'validate', 'required', 'format', 'pattern', 'maxlength',
            'business rule', 'constraint', 'workflow', 'process'
        ]
        
        # Common JSP scriptlet patterns
        self.scriptlet_patterns = {
            'java_code': r'<%\s*([^%]+)\s*%>',
            'expression': r'<%=\s*([^%]+)\s*%>',
            'declaration': r'<%!\s*([^%]+)\s*%>',
            'directive': r'<%@\s*([^%]+)\s*%>'
        }
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the JSP file."""
        return self.supports_extension(file_path.suffix)
    
    def get_priority(self) -> int:
        """JSP parser has high priority for JSP files."""
        return 80
    
    def parse_file(self, file_path: Path) -> ParseResult:
        """Parse JSP template file."""
        start_time = datetime.now()
        result = ParseResult(
            file_path=str(file_path),
            parser_name=self.parser_name,
            success=True,
            parse_time_ms=0
        )
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract JSP structure
            jsp_structure = self._extract_jsp_structure(content, file_path)
            result.add_extracted_data('jsp_structure', jsp_structure)
            
            # Extract Struts tags
            struts_tags = self._extract_struts_tags(content, file_path)
            result.add_extracted_data('struts_tags', struts_tags)
            
            # Extract scriptlets
            scriptlets = self._extract_scriptlets(content, file_path)
            result.add_extracted_data('scriptlets', scriptlets)
            
            # Extract business rules
            self._extract_business_rules_from_jsp(content, file_path, result)
            
            # Calculate parsing time
            end_time = datetime.now()
            result.parse_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
        except Exception as e:
            result.add_error(f"Error parsing JSP file: {e}")
        
        return result
    
    def _extract_jsp_structure(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Extract overall JSP structure and metadata."""
        structure = {
            'directives': [],
            'includes': [],
            'taglib_declarations': [],
            'form_count': 0,
            'table_count': 0,
            'has_validation': False,
            'has_javascript': False
        }
        
        # Extract page directives
        directive_pattern = r'<%@\s*(\w+)\s+([^%]+)%>'
        for match in re.finditer(directive_pattern, content):
            directive_type = match.group(1)
            attributes = match.group(2)
            structure['directives'].append({
                'type': directive_type,
                'attributes': attributes.strip()
            })
        
        # Extract taglib declarations
        taglib_pattern = r'<%@\s*taglib\s+([^%]+)%>'
        for match in re.finditer(taglib_pattern, content):
            structure['taglib_declarations'].append(match.group(1).strip())
        
        # Extract includes
        include_pattern = r'<%@\s*include\s+file\s*=\s*["\']([^"\'>]+)["\']'
        for match in re.finditer(include_pattern, content):
            structure['includes'].append(match.group(1))
        
        # Count forms and tables
        structure['form_count'] = len(re.findall(r'<(?:html:)?form', content, re.IGNORECASE))
        structure['table_count'] = len(re.findall(r'<table', content, re.IGNORECASE))
        
        # Check for validation and JavaScript
        structure['has_validation'] = bool(re.search(r'html:errors|validate|required', content, re.IGNORECASE))
        structure['has_javascript'] = bool(re.search(r'<script|javascript:', content, re.IGNORECASE))
        
        return structure
    
    def _extract_struts_tags(self, content: str, file_path: Path) -> Dict[str, List[Dict[str, Any]]]:
        """Extract Struts tag usage patterns."""
        tags_found = {
            'form_tags': [],
            'logic_tags': [],
            'bean_tags': [],
            'validation_tags': []
        }
        
        for category, tag_list in self.struts_tags.items():
            for tag in tag_list:
                pattern = rf'<{re.escape(tag)}([^>]*)(?:/>|>.*?</{re.escape(tag)}>)'
                for match in re.finditer(pattern, content, re.DOTALL | re.IGNORECASE):
                    attributes = self._parse_tag_attributes(match.group(1))
                    tags_found[category].append({
                        'tag': tag,
                        'attributes': attributes,
                        'full_match': match.group(0)[:200] + '...' if len(match.group(0)) > 200 else match.group(0)
                    })
        
        return tags_found
    
    def _extract_scriptlets(self, content: str, file_path: Path) -> Dict[str, List[Dict[str, Any]]]:
        """Extract JSP scriptlets and embedded Java code."""
        scriptlets = {
            'java_code': [],
            'expressions': [],
            'declarations': [],
            'directives': []
        }
        
        # Extract Java code scriptlets
        for match in re.finditer(self.scriptlet_patterns['java_code'], content, re.DOTALL):
            java_code = match.group(1).strip()
            if java_code:
                scriptlets['java_code'].append({
                    'code': java_code,
                    'has_business_logic': self._contains_business_logic(java_code),
                    'complexity': self._assess_code_complexity(java_code)
                })
        
        # Extract expressions
        for match in re.finditer(self.scriptlet_patterns['expression'], content):
            expression = match.group(1).strip()
            if expression:
                scriptlets['expressions'].append({
                    'expression': expression,
                    'is_bean_property': '.' in expression and any(word in expression for word in ['bean', 'form', 'request', 'session'])
                })
        
        # Extract declarations
        for match in re.finditer(self.scriptlet_patterns['declaration'], content, re.DOTALL):
            declaration = match.group(1).strip()
            if declaration:
                scriptlets['declarations'].append({
                    'declaration': declaration,
                    'type': self._identify_declaration_type(declaration)
                })
        
        return scriptlets
    
    def _extract_business_rules_from_jsp(self, content: str, file_path: Path, result: ParseResult):
        """Extract business rules from JSP content."""
        
        # Extract form validation rules
        self._extract_form_validation_rules(content, file_path, result)
        
        # Extract conditional display logic
        self._extract_conditional_logic_rules(content, file_path, result)
        
        # Extract data display patterns
        self._extract_data_display_rules(content, file_path, result)
        
        # Extract JavaScript validation
        self._extract_javascript_validation_rules(content, file_path, result)
        
        # Extract business logic from scriptlets
        self._extract_scriptlet_business_rules(content, file_path, result)
    
    def _extract_form_validation_rules(self, content: str, file_path: Path, result: ParseResult):
        """Extract form validation rules from HTML and Struts form tags."""
        
        # Find all form elements with validation attributes
        form_validation_pattern = r'<(?:html:|input|select|textarea)([^>]*(?:required|maxlength|pattern|validate)[^>]*)>'
        
        for i, match in enumerate(re.finditer(form_validation_pattern, content, re.IGNORECASE)):
            attributes_str = match.group(1)
            attributes = self._parse_tag_attributes(attributes_str)
            
            # Check for validation attributes
            validation_attrs = {}
            for attr in ['required', 'maxlength', 'pattern', 'validate']:
                if attr in attributes_str.lower():
                    validation_attrs[attr] = attributes.get(attr, 'true')
            
            if validation_attrs:
                rule_id = self._generate_rule_id('form_validation', str(i))
                
                field_name = attributes.get('name', attributes.get('property', f'field_{i}'))
                
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"Form Validation: {field_name}",
                    description=f"Input validation for field '{field_name}' with constraints: {', '.join(validation_attrs.keys())}",
                    rule_type=BusinessRuleType.VALIDATION,
                    source=BusinessRuleSource.UI_COMPONENT,
                    file_path=file_path,
                    business_context="User input validation and data integrity",
                    code_snippet=match.group(0),
                    complexity=BusinessRuleComplexity.SIMPLE
                )
                
                rule.add_tag('form_validation')
                rule.add_tag('ui_constraint')
                rule.add_tag('data_integrity')
                
                for attr in validation_attrs.keys():
                    rule.add_tag(f'validation_{attr}')
                
                result.add_business_rule(rule)
    
    def _extract_conditional_logic_rules(self, content: str, file_path: Path, result: ParseResult):
        """Extract conditional display logic using Struts logic tags."""
        
        logic_patterns = {
            'logic:if': r'<logic:if\s+([^>]+)>(.*?)</logic:if>',
            'logic:equal': r'<logic:equal\s+([^>]+)>(.*?)</logic:equal>',
            'logic:present': r'<logic:present\s+([^>]+)>(.*?)</logic:present>',
            'logic:iterate': r'<logic:iterate\s+([^>]+)>(.*?)</logic:iterate>'
        }
        
        for tag_name, pattern in logic_patterns.items():
            for i, match in enumerate(re.finditer(pattern, content, re.DOTALL | re.IGNORECASE)):
                attributes_str = match.group(1)
                content_block = match.group(2)
                
                attributes = self._parse_tag_attributes(attributes_str)
                
                rule_id = self._generate_rule_id('conditional_logic', tag_name, str(i))
                
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"Conditional Display: {tag_name}",
                    description=f"Conditional UI logic using {tag_name} with attributes: {', '.join(attributes.keys())}",
                    rule_type=BusinessRuleType.UI_BEHAVIOR,
                    source=BusinessRuleSource.UI_COMPONENT,
                    file_path=file_path,
                    business_context=self._infer_conditional_business_context(attributes, content_block),
                    code_snippet=match.group(0)[:300] + '...' if len(match.group(0)) > 300 else match.group(0),
                    complexity=self._assess_conditional_complexity(attributes, content_block)
                )
                
                rule.add_tag('conditional_logic')
                rule.add_tag('ui_behavior')
                rule.add_tag(tag_name.replace(':', '_'))
                
                result.add_business_rule(rule)
    
    def _extract_data_display_rules(self, content: str, file_path: Path, result: ParseResult):
        """Extract data display patterns using bean:write and similar tags."""
        
        # Find bean:write tags
        bean_write_pattern = r'<bean:write\s+([^>]+)\s*/?>'
        
        for i, match in enumerate(re.finditer(bean_write_pattern, content, re.IGNORECASE)):
            attributes_str = match.group(1)
            attributes = self._parse_tag_attributes(attributes_str)
            
            property_name = attributes.get('name', attributes.get('property', f'property_{i}'))
            
            rule_id = self._generate_rule_id('data_display', property_name)
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Data Display: {property_name}",
                description=f"Display business data property '{property_name}' with formatting rules",
                rule_type=BusinessRuleType.DATA,
                source=BusinessRuleSource.UI_COMPONENT,
                file_path=file_path,
                business_context=self._infer_data_display_context(property_name, attributes),
                code_snippet=match.group(0),
                complexity=BusinessRuleComplexity.SIMPLE
            )
            
            rule.add_tag('data_display')
            rule.add_tag('bean_property')
            
            # Add formatting tags if present
            if 'format' in attributes:
                rule.add_tag('formatted_output')
            if 'filter' in attributes:
                rule.add_tag('filtered_output')
            
            result.add_business_rule(rule)
    
    def _extract_javascript_validation_rules(self, content: str, file_path: Path, result: ParseResult):
        """Extract client-side JavaScript validation rules."""
        
        # Find JavaScript blocks
        js_pattern = r'<script[^>]*>(.*?)</script>'
        
        for i, match in enumerate(re.finditer(js_pattern, content, re.DOTALL | re.IGNORECASE)):
            js_content = match.group(1)
            
            # Look for validation functions
            if any(keyword in js_content.lower() for keyword in ['validate', 'check', 'verify', 'required']):
                
                # Extract function names
                function_pattern = r'function\s+(\w*validate\w*)\s*\('
                functions = re.findall(function_pattern, js_content, re.IGNORECASE)
                
                for func_name in functions:
                    rule_id = self._generate_rule_id('js_validation', func_name)
                    
                    rule = self._create_business_rule(
                        rule_id=rule_id,
                        name=f"JavaScript Validation: {func_name}",
                        description=f"Client-side validation function '{func_name}'",
                        rule_type=BusinessRuleType.VALIDATION,
                        source=BusinessRuleSource.CLIENT_SCRIPT,
                        file_path=file_path,
                        business_context="Client-side data validation and user experience",
                        code_snippet=js_content[:200] + '...' if len(js_content) > 200 else js_content,
                        complexity=BusinessRuleComplexity.MODERATE
                    )
                    
                    rule.add_tag('javascript_validation')
                    rule.add_tag('client_side')
                    rule.add_tag('user_experience')
                    
                    result.add_business_rule(rule)
    
    def _extract_scriptlet_business_rules(self, content: str, file_path: Path, result: ParseResult):
        """Extract business rules from JSP scriptlets."""
        
        # Extract Java code from scriptlets
        for i, match in enumerate(re.finditer(self.scriptlet_patterns['java_code'], content, re.DOTALL)):
            java_code = match.group(1).strip()
            
            if self._contains_business_logic(java_code):
                rule_id = self._generate_rule_id('scriptlet_business_logic', str(i))
                
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"Scriptlet Business Logic {i+1}",
                    description=f"Business logic embedded in JSP scriptlet",
                    rule_type=BusinessRuleType.BUSINESS_LOGIC,
                    source=BusinessRuleSource.JSP_SCRIPTLET,
                    file_path=file_path,
                    business_context="Embedded presentation-layer business logic",
                    code_snippet=java_code[:200] + '...' if len(java_code) > 200 else java_code,
                    complexity=self._assess_code_complexity(java_code)
                )
                
                rule.add_tag('scriptlet')
                rule.add_tag('embedded_logic')
                rule.add_tag('presentation_layer')
                
                # Add specific logic type tags
                if 'if' in java_code.lower():
                    rule.add_tag('conditional_logic')
                if 'for' in java_code.lower() or 'while' in java_code.lower():
                    rule.add_tag('iterative_logic')
                if any(word in java_code.lower() for word in ['validate', 'check', 'verify']):
                    rule.add_tag('validation_logic')
                
                result.add_business_rule(rule)
    
    def _parse_tag_attributes(self, attributes_str: str) -> Dict[str, str]:
        """Parse HTML/JSP tag attributes."""
        attributes = {}
        
        # Simple attribute parsing
        attr_pattern = r'(\w+)\s*=\s*["\']([^"\'>]*)["\']'
        for match in re.finditer(attr_pattern, attributes_str):
            attributes[match.group(1)] = match.group(2)
        
        return attributes
    
    def _contains_business_logic(self, code: str) -> bool:
        """Check if code contains business logic indicators."""
        business_keywords = [
            'if', 'else', 'for', 'while', 'switch',
            'calculate', 'validate', 'process', 'check',
            'business', 'rule', 'policy', 'constraint'
        ]
        
        code_lower = code.lower()
        return any(keyword in code_lower for keyword in business_keywords)
    
    def _assess_code_complexity(self, code: str) -> BusinessRuleComplexity:
        """Assess complexity of code snippet."""
        complexity_score = 0
        
        # Count control structures
        complexity_score += code.count('if')
        complexity_score += code.count('for')
        complexity_score += code.count('while')
        complexity_score += code.count('switch')
        complexity_score += code.count('try')
        
        # Count method calls
        complexity_score += len(re.findall(r'\w+\s*\(', code))
        
        if complexity_score <= 2:
            return BusinessRuleComplexity.SIMPLE
        elif complexity_score <= 5:
            return BusinessRuleComplexity.MODERATE
        elif complexity_score <= 10:
            return BusinessRuleComplexity.COMPLEX
        else:
            return BusinessRuleComplexity.CRITICAL
    
    def _assess_conditional_complexity(self, attributes: Dict[str, str], content_block: str) -> BusinessRuleComplexity:
        """Assess complexity of conditional logic."""
        complexity_score = 1  # Base complexity
        
        # Add for nested conditions
        if 'logic:' in content_block:
            complexity_score += content_block.count('logic:')
        
        # Add for multiple attributes
        complexity_score += len(attributes)
        
        if complexity_score <= 2:
            return BusinessRuleComplexity.SIMPLE
        elif complexity_score <= 4:
            return BusinessRuleComplexity.MODERATE
        else:
            return BusinessRuleComplexity.COMPLEX
    
    def _identify_declaration_type(self, declaration: str) -> str:
        """Identify the type of JSP declaration."""
        if 'method' in declaration.lower() or '(' in declaration:
            return 'method'
        elif 'class' in declaration.lower():
            return 'class'
        elif '=' in declaration:
            return 'variable'
        else:
            return 'unknown'
    
    def _infer_conditional_business_context(self, attributes: Dict[str, str], content_block: str) -> str:
        """Infer business context from conditional logic."""
        # Check attribute names for business context clues
        attr_names = ' '.join(attributes.keys()).lower()
        
        if any(word in attr_names for word in ['user', 'customer', 'account']):
            return "User Access and Personalization"
        elif any(word in attr_names for word in ['order', 'purchase', 'transaction']):
            return "Order Processing and Commerce"
        elif any(word in attr_names for word in ['role', 'permission', 'access']):
            return "Security and Authorization"
        elif any(word in attr_names for word in ['status', 'state', 'condition']):
            return "Business State Management"
        else:
            return "Conditional Business Logic"
    
    def _infer_data_display_context(self, property_name: str, attributes: Dict[str, str]) -> str:
        """Infer business context from data display patterns."""
        prop_lower = property_name.lower()
        
        if any(word in prop_lower for word in ['user', 'customer', 'person']):
            return "User Information Display"
        elif any(word in prop_lower for word in ['order', 'purchase', 'transaction']):
            return "Order and Transaction Display"
        elif any(word in prop_lower for word in ['product', 'item', 'catalog']):
            return "Product Information Display"
        elif any(word in prop_lower for word in ['price', 'amount', 'total', 'cost']):
            return "Financial Data Display"
        elif any(word in prop_lower for word in ['date', 'time', 'created', 'updated']):
            return "Temporal Data Display"
        else:
            return f"Business Data Display: {property_name}"
