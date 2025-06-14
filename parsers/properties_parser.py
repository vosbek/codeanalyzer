"""
Properties File Parser
=====================

This parser handles Java properties files, extracting internationalization patterns,
configuration settings, and validation messages for migration analysis.

Features:
- Property analysis for business context
- Validation message extraction
- Internationalization pattern identification
- Configuration rule extraction
- Angular i18n mapping recommendations

Author: Claude Code Assistant
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime

from parsers.base_parser import BaseParser, ParseResult
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource,
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)


class PropertiesFileParser(BaseParser):
    """Parser for Java properties files in Struts applications."""
    
    def __init__(self):
        """Initialize properties parser."""
        super().__init__()
        self.supported_extensions = {'.properties'}
        
        # Property categorization patterns
        self.property_categories = {
            'validation': [
                'error', 'invalid', 'required', 'format', 'length',
                'validate', 'constraint', 'rule'
            ],
            'labels': [
                'label', 'title', 'caption', 'header', 'name'
            ],
            'messages': [
                'message', 'msg', 'text', 'description', 'info'
            ],
            'configuration': [
                'config', 'setting', 'property', 'param', 'value'
            ],
            'business': [
                'business', 'rule', 'policy', 'process', 'workflow'
            ]
        }
        
        # Common validation message patterns
        self.validation_patterns = {
            'required': r'(?:required|mandatory|must|cannot be empty)',
            'format': r'(?:format|pattern|invalid format)',
            'length': r'(?:length|minimum|maximum|too long|too short)',
            'range': r'(?:range|between|minimum|maximum)',
            'email': r'(?:email|e-mail|invalid email)',
            'numeric': r'(?:numeric|number|digit|integer)',
            'date': r'(?:date|time|invalid date)'
        }
        
        # Business context indicators
        self.business_indicators = [
            'user', 'customer', 'order', 'product', 'payment',
            'account', 'transaction', 'business', 'rule', 'policy'
        ]
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the properties file."""
        return self.supports_extension(file_path.suffix)
    
    def get_priority(self) -> int:
        """Properties parser has moderate priority."""
        return 60
    
    def parse_file(self, file_path: Path) -> ParseResult:
        """Parse properties file."""
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
            
            # Parse properties
            properties = self._parse_properties(content)
            result.add_extracted_data('properties', properties)
            
            # Categorize properties
            categorized = self._categorize_properties(properties)
            result.add_extracted_data('categorized_properties', categorized)
            
            # Extract validation patterns
            validation_analysis = self._analyze_validation_messages(properties)
            result.add_extracted_data('validation_analysis', validation_analysis)
            
            # Extract business rules
            self._extract_business_rules_from_properties(properties, file_path, result)
            
            # Calculate parsing time
            end_time = datetime.now()
            result.parse_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
        except Exception as e:
            result.add_error(f"Error parsing properties file: {e}")
        
        return result
    
    def _parse_properties(self, content: str) -> List[Dict[str, Any]]:
        """Parse properties file content."""
        properties = []
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # Handle multi-line properties (ending with \)
            while line.endswith('\\') and line_num < len(lines):
                line = line[:-1] + lines[line_num].strip()
                line_num += 1
            
            # Parse key=value pairs
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                property_data = {
                    'key': key,
                    'value': value,
                    'line_number': line_num,
                    'category': self._categorize_property_key(key),
                    'business_context': self._extract_business_context(key, value),
                    'is_validation': self._is_validation_property(key, value),
                    'is_internationalization': self._is_i18n_property(key, value),
                    'complexity': self._assess_property_complexity(key, value)
                }
                
                properties.append(property_data)
        
        return properties
    
    def _categorize_properties(self, properties: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize properties by type."""
        categorized = {
            'validation': [],
            'labels': [],
            'messages': [],
            'configuration': [],
            'business': [],
            'other': []
        }
        
        for prop in properties:
            category = prop['category']
            if category in categorized:
                categorized[category].append(prop)
            else:
                categorized['other'].append(prop)
        
        return categorized
    
    def _analyze_validation_messages(self, properties: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze validation message patterns."""
        analysis = {
            'validation_types': {},
            'field_validations': {},
            'common_patterns': [],
            'business_constraints': []
        }
        
        validation_props = [p for p in properties if p['is_validation']]
        
        for prop in validation_props:
            key = prop['key']
            value = prop['value']
            
            # Identify validation type
            for val_type, pattern in self.validation_patterns.items():
                if re.search(pattern, value, re.IGNORECASE):
                    if val_type not in analysis['validation_types']:
                        analysis['validation_types'][val_type] = []
                    analysis['validation_types'][val_type].append({
                        'key': key,
                        'value': value,
                        'field': self._extract_field_name(key)
                    })
            
            # Extract field name
            field_name = self._extract_field_name(key)
            if field_name:
                if field_name not in analysis['field_validations']:
                    analysis['field_validations'][field_name] = []
                analysis['field_validations'][field_name].append({
                    'key': key,
                    'value': value,
                    'validation_type': self._identify_validation_type(value)
                })
            
            # Check for business constraints
            if any(indicator in value.lower() for indicator in self.business_indicators):
                analysis['business_constraints'].append({
                    'key': key,
                    'value': value,
                    'business_context': prop['business_context']
                })
        
        return analysis
    
    def _extract_business_rules_from_properties(self, properties: List[Dict[str, Any]], 
                                              file_path: Path, result: ParseResult):
        """Extract business rules from properties."""
        
        # Extract validation rules
        self._extract_validation_rules(properties, file_path, result)
        
        # Extract business constraint rules
        self._extract_business_constraint_rules(properties, file_path, result)
        
        # Extract internationalization rules
        self._extract_i18n_rules(properties, file_path, result)
        
        # Extract configuration rules
        self._extract_configuration_rules(properties, file_path, result)
    
    def _extract_validation_rules(self, properties: List[Dict[str, Any]], 
                                file_path: Path, result: ParseResult):
        """Extract validation business rules."""
        
        validation_props = [p for p in properties if p['is_validation']]
        
        for prop in validation_props:
            key = prop['key']
            value = prop['value']
            field_name = self._extract_field_name(key)
            
            rule_id = self._generate_rule_id('validation_message', key)
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Validation Rule: {field_name or key}",
                description=f"Validation message for field '{field_name or key}': {value}",
                rule_type=BusinessRuleType.VALIDATION,
                source=BusinessRuleSource.PROPERTIES_FILE,
                file_path=file_path,
                business_context=prop['business_context'],
                code_snippet=f"{key}={value}",
                complexity=prop['complexity'],
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    line_number=prop['line_number']
                )
            )
            
            rule.add_tag('validation_message')
            rule.add_tag('properties_file')
            
            if field_name:
                rule.add_tag(f'field_{field_name}')
            
            # Add validation type tags
            validation_type = self._identify_validation_type(value)
            if validation_type:
                rule.add_tag(f'validation_{validation_type}')
            
            result.add_business_rule(rule)
    
    def _extract_business_constraint_rules(self, properties: List[Dict[str, Any]], 
                                         file_path: Path, result: ParseResult):
        """Extract business constraint rules."""
        
        business_props = [p for p in properties if p['category'] == 'business' or 
                         any(indicator in p['value'].lower() for indicator in self.business_indicators)]
        
        for prop in business_props:
            key = prop['key']
            value = prop['value']
            
            rule_id = self._generate_rule_id('business_constraint', key)
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Business Constraint: {key}",
                description=f"Business constraint or policy message: {value}",
                rule_type=BusinessRuleType.BUSINESS_LOGIC,
                source=BusinessRuleSource.PROPERTIES_FILE,
                file_path=file_path,
                business_context=prop['business_context'],
                code_snippet=f"{key}={value}",
                complexity=prop['complexity'],
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    line_number=prop['line_number']
                )
            )
            
            rule.add_tag('business_constraint')
            rule.add_tag('policy_message')
            rule.add_tag('properties_file')
            
            result.add_business_rule(rule)
    
    def _extract_i18n_rules(self, properties: List[Dict[str, Any]], 
                          file_path: Path, result: ParseResult):
        """Extract internationalization rules."""
        
        i18n_props = [p for p in properties if p['is_internationalization']]
        
        if len(i18n_props) > 5:  # Only create rule if significant i18n content
            rule_id = self._generate_rule_id('internationalization', file_path.stem)
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Internationalization: {file_path.stem}",
                description=f"Internationalization rules with {len(i18n_props)} translated messages",
                rule_type=BusinessRuleType.UI_BEHAVIOR,
                source=BusinessRuleSource.PROPERTIES_FILE,
                file_path=file_path,
                business_context="User interface internationalization and localization",
                code_snippet=f"# {len(i18n_props)} internationalization properties",
                complexity=BusinessRuleComplexity.MODERATE
            )
            
            rule.add_tag('internationalization')
            rule.add_tag('localization')
            rule.add_tag('ui_text')
            rule.add_tag('properties_file')
            
            result.add_business_rule(rule)
    
    def _extract_configuration_rules(self, properties: List[Dict[str, Any]], 
                                   file_path: Path, result: ParseResult):
        """Extract configuration rules."""
        
        config_props = [p for p in properties if p['category'] == 'configuration']
        
        for prop in config_props:
            key = prop['key']
            value = prop['value']
            
            # Only create rules for business-relevant configuration
            if any(indicator in key.lower() for indicator in ['business', 'rule', 'policy', 'workflow']):
                rule_id = self._generate_rule_id('configuration', key)
                
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"Configuration: {key}",
                    description=f"Business configuration setting: {key} = {value}",
                    rule_type=BusinessRuleType.CONFIGURATION,
                    source=BusinessRuleSource.PROPERTIES_FILE,
                    file_path=file_path,
                    business_context="Business configuration and settings",
                    code_snippet=f"{key}={value}",
                    complexity=BusinessRuleComplexity.SIMPLE,
                    location=BusinessRuleLocation(
                        file_path=str(file_path),
                        line_number=prop['line_number']
                    )
                )
                
                rule.add_tag('configuration')
                rule.add_tag('business_setting')
                rule.add_tag('properties_file')
                
                result.add_business_rule(rule)
    
    def _categorize_property_key(self, key: str) -> str:
        """Categorize property key by type."""
        key_lower = key.lower()
        
        for category, keywords in self.property_categories.items():
            if any(keyword in key_lower for keyword in keywords):
                return category
        
        return 'other'
    
    def _extract_business_context(self, key: str, value: str) -> str:
        """Extract business context from property key and value."""
        combined = (key + ' ' + value).lower()
        
        if any(word in combined for word in ['user', 'customer', 'person', 'account']):
            return "User Management and Authentication"
        elif any(word in combined for word in ['order', 'purchase', 'transaction']):
            return "Order Processing and Commerce"
        elif any(word in combined for word in ['product', 'item', 'catalog']):
            return "Product Management"
        elif any(word in combined for word in ['payment', 'billing', 'invoice']):
            return "Payment and Financial Processing"
        elif any(word in combined for word in ['error', 'invalid', 'required']):
            return "Data Validation and Quality"
        elif any(word in combined for word in ['message', 'label', 'title']):
            return "User Interface and Experience"
        else:
            return "General Business Configuration"
    
    def _is_validation_property(self, key: str, value: str) -> bool:
        """Check if property represents a validation rule."""
        combined = (key + ' ' + value).lower()
        validation_indicators = [
            'error', 'invalid', 'required', 'format', 'length',
            'validate', 'constraint', 'must', 'cannot', 'minimum', 'maximum'
        ]
        
        return any(indicator in combined for indicator in validation_indicators)
    
    def _is_i18n_property(self, key: str, value: str) -> bool:
        """Check if property is for internationalization."""
        # Check for common i18n patterns
        i18n_patterns = [
            r'\w+\.\w+\.label$',
            r'\w+\.\w+\.title$',
            r'\w+\.\w+\.message$',
            r'\w+\.\w+\.text$'
        ]
        
        return any(re.search(pattern, key) for pattern in i18n_patterns)
    
    def _assess_property_complexity(self, key: str, value: str) -> BusinessRuleComplexity:
        """Assess complexity of a property."""
        complexity_score = 0
        
        # Length of value
        if len(value) > 100:
            complexity_score += 2
        elif len(value) > 50:
            complexity_score += 1
        
        # Number of parameters in value
        param_count = len(re.findall(r'\{\d+\}', value))
        complexity_score += param_count
        
        # Complexity of validation logic
        if any(word in value.lower() for word in ['and', 'or', 'if', 'when', 'must']):
            complexity_score += 1
        
        if complexity_score <= 1:
            return BusinessRuleComplexity.SIMPLE
        elif complexity_score <= 3:
            return BusinessRuleComplexity.MODERATE
        else:
            return BusinessRuleComplexity.COMPLEX
    
    def _extract_field_name(self, key: str) -> Optional[str]:
        """Extract field name from property key."""
        # Common patterns for field names in property keys
        patterns = [
            r'error\.([\w.]+)',
            r'([\w.]+)\.error',
            r'([\w.]+)\.required',
            r'([\w.]+)\.invalid',
            r'([\w.]+)\.format',
            r'([\w.]+)\.length'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, key)
            if match:
                return match.group(1)
        
        return None
    
    def _identify_validation_type(self, value: str) -> Optional[str]:
        """Identify the type of validation from the message."""
        value_lower = value.lower()
        
        for val_type, pattern in self.validation_patterns.items():
            if re.search(pattern, value_lower):
                return val_type
        
        return None
