import sys
sys.path.append('..')

"""
Properties File Analyzer
=========================

This module analyzes Java properties files, particularly those used for
internationalization (i18n), messages, and configuration in Struts applications.
It extracts business context from message keys, validation messages, and
configuration properties.

Features:
- Message bundle analysis with business context extraction
- Validation message mapping to business rules
- Configuration property analysis
- Internationalization pattern detection
- Business language identification from messages
- GraphQL schema and error message migration recommendations

Author: Claude Code Assistant
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
import hashlib

from analyzers.base_analyzer import BaseAnalyzer, AnalysisContext
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource, 
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)
from utils.logging_utils import get_logger


logger = get_logger(__name__)


@dataclass
class MessageEntry:
    """Represents a message entry from properties file."""
    key: str
    value: str
    file_path: str
    line_number: int = 0
    is_validation_message: bool = False
    is_error_message: bool = False
    is_business_message: bool = False
    business_context: str = ""
    referenced_fields: List[str] = field(default_factory=list)
    message_parameters: List[str] = field(default_factory=list)
    severity: str = "info"  # info, warning, error
    i18n_locale: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'key': self.key,
            'value': self.value,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'is_validation_message': self.is_validation_message,
            'is_error_message': self.is_error_message,
            'is_business_message': self.is_business_message,
            'business_context': self.business_context,
            'referenced_fields': self.referenced_fields,
            'message_parameters': self.message_parameters,
            'severity': self.severity,
            'i18n_locale': self.i18n_locale
        }


@dataclass
class PropertyGroup:
    """Represents a logical group of related properties."""
    prefix: str
    properties: List[MessageEntry] = field(default_factory=list)
    business_purpose: str = ""
    feature_area: str = ""
    migration_strategy: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'prefix': self.prefix,
            'properties': [prop.to_dict() for prop in self.properties],
            'business_purpose': self.business_purpose,
            'feature_area': self.feature_area,
            'migration_strategy': self.migration_strategy
        }


class PropertiesAnalyzer(BaseAnalyzer):
    """
    Analyzer for Java properties files in Struts applications.
    """
    
    def _initialize_analyzer(self) -> None:
        """Initialize properties analyzer settings."""
        self._supported_extensions = {'.properties'}
        self._required_patterns = []
        
        # Business message patterns
        self._business_patterns = {
            'validation': [
                r'error\.', r'validation\.', r'invalid\.', r'required\.',
                r'\.error$', r'\.validation$', r'\.invalid$', r'\.required$'
            ],
            'success': [
                r'success\.', r'confirm\.', r'complete\.',
                r'\.success$', r'\.confirm$', r'\.complete$'
            ],
            'business_process': [
                r'process\.', r'workflow\.', r'business\.',
                r'order\.', r'customer\.', r'product\.'
            ],
            'security': [
                r'security\.', r'permission\.', r'access\.',
                r'login\.', r'auth\.', r'unauthorized\.'
            ]
        }
        
        # Severity indicators
        self._severity_patterns = {
            'error': [r'error', r'invalid', r'fail', r'exception', r'denied'],
            'warning': [r'warning', r'warn', r'caution', r'notice'],
            'info': [r'info', r'message', r'note', r'confirm', r'success']
        }
    
    def can_analyze(self, file_path: Path) -> bool:
        """Check if this is a properties file."""
        return file_path.suffix.lower() == '.properties'
    
    def _analyze_file(self, file_path: Path, context: AnalysisContext) -> Dict[str, Any]:
        """Analyze a properties file and extract message information."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse properties
            message_entries = self._parse_properties(content, file_path)
            
            # Group related properties
            property_groups = self._group_properties(message_entries)
            
            # Extract business rules from messages
            business_rules = self._extract_business_rules_from_messages(
                message_entries, file_path
            )
            
            # Analyze internationalization patterns
            i18n_analysis = self._analyze_i18n_patterns(file_path, message_entries)
            
            return {
                'file_path': str(file_path),
                'message_entries': [entry.to_dict() for entry in message_entries],
                'property_groups': [group.to_dict() for group in property_groups],
                'business_rules': [rule.to_dict() for rule in business_rules],
                'i18n_analysis': i18n_analysis,
                'total_messages': len(message_entries),
                'validation_messages': len([e for e in message_entries if e.is_validation_message]),
                'business_messages': len([e for e in message_entries if e.is_business_message])
            }
            
        except Exception as e:
            logger.error(f"Error analyzing properties file {file_path}: {e}")
            return {}
    
    def _parse_properties(self, content: str, file_path: Path) -> List[MessageEntry]:
        """Parse properties file content into message entries."""
        entries = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # Parse key=value pairs
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key and value:
                    entry = MessageEntry(
                        key=key,
                        value=value,
                        file_path=str(file_path),
                        line_number=line_num
                    )
                    
                    # Classify message type
                    self._classify_message(entry)
                    
                    # Extract business context
                    entry.business_context = self._infer_business_context(entry)
                    
                    # Extract message parameters
                    entry.message_parameters = self._extract_message_parameters(value)
                    
                    # Determine severity
                    entry.severity = self._determine_severity(key, value)
                    
                    # Extract i18n locale if present
                    entry.i18n_locale = self._extract_locale_from_filename(file_path)
                    
                    entries.append(entry)
        
        return entries
    
    def _classify_message(self, entry: MessageEntry) -> None:
        """Classify the message type based on key patterns."""
        key_lower = entry.key.lower()
        value_lower = entry.value.lower()
        
        # Check for validation messages
        for pattern in self._business_patterns['validation']:
            if re.search(pattern, key_lower) or re.search(pattern, value_lower):
                entry.is_validation_message = True
                break
        
        # Check for error messages
        if any(word in key_lower or word in value_lower 
               for word in ['error', 'invalid', 'fail', 'exception']):
            entry.is_error_message = True
        
        # Check for business messages
        for category_patterns in self._business_patterns.values():
            for pattern in category_patterns:
                if re.search(pattern, key_lower):
                    entry.is_business_message = True
                    break
            if entry.is_business_message:
                break
    
    def _infer_business_context(self, entry: MessageEntry) -> str:
        """Infer business context from message key and value."""
        key_parts = entry.key.split('.')
        context_clues = []
        
        # Analyze key segments
        for part in key_parts:
            part_lower = part.lower()
            if part_lower in ['user', 'customer', 'account']:
                context_clues.append("User Management")
            elif part_lower in ['order', 'purchase', 'cart', 'payment']:
                context_clues.append("Order Processing")
            elif part_lower in ['product', 'item', 'catalog', 'inventory']:
                context_clues.append("Product Management")
            elif part_lower in ['login', 'auth', 'security', 'permission']:
                context_clues.append("Security and Authentication")
            elif part_lower in ['validation', 'error', 'required']:
                context_clues.append("Data Validation")
            elif part_lower in ['report', 'analytics', 'dashboard']:
                context_clues.append("Reporting and Analytics")
        
        # Analyze message content
        value_lower = entry.value.lower()
        if any(word in value_lower for word in ['must', 'required', 'cannot be empty']):
            context_clues.append("Business Constraint")
        elif any(word in value_lower for word in ['successfully', 'completed', 'saved']):
            context_clues.append("Process Confirmation")
        elif any(word in value_lower for word in ['unauthorized', 'permission denied', 'access']):
            context_clues.append("Access Control")
        
        return " | ".join(context_clues) if context_clues else "General Application Message"
    
    def _extract_message_parameters(self, value: str) -> List[str]:
        """Extract message parameters from value (e.g., {0}, {1})."""
        # Find placeholders like {0}, {1}, etc.
        numeric_params = re.findall(r'\{(\d+)\}', value)
        
        # Find named placeholders like {fieldName}
        named_params = re.findall(r'\{([a-zA-Z][a-zA-Z0-9]*)\}', value)
        
        return numeric_params + named_params
    
    def _determine_severity(self, key: str, value: str) -> str:
        """Determine message severity based on content."""
        key_lower = key.lower()
        value_lower = value.lower()
        
        for severity, patterns in self._severity_patterns.items():
            if any(pattern in key_lower or pattern in value_lower 
                   for pattern in patterns):
                return severity
        
        return "info"
    
    def _extract_locale_from_filename(self, file_path: Path) -> str:
        """Extract locale from filename (e.g., messages_en_US.properties)."""
        filename = file_path.stem
        
        # Look for locale patterns like _en_US, _fr_FR, etc.
        locale_match = re.search(r'_([a-z]{2}_[A-Z]{2})$', filename)
        if locale_match:
            return locale_match.group(1)
        
        # Look for language-only patterns like _en, _fr, etc.
        lang_match = re.search(r'_([a-z]{2})$', filename)
        if lang_match:
            return lang_match.group(1)
        
        return "default"
    
    def _group_properties(self, entries: List[MessageEntry]) -> List[PropertyGroup]:
        """Group related properties by common prefixes."""
        groups_dict = {}
        
        for entry in entries:
            # Find the common prefix (first two parts of the key)
            key_parts = entry.key.split('.')
            if len(key_parts) >= 2:
                prefix = '.'.join(key_parts[:2])
            else:
                prefix = key_parts[0] if key_parts else 'misc'
            
            if prefix not in groups_dict:
                groups_dict[prefix] = PropertyGroup(prefix=prefix)
            
            groups_dict[prefix].properties.append(entry)
        
        # Analyze each group
        groups = list(groups_dict.values())
        for group in groups:
            group.business_purpose = self._infer_group_purpose(group)
            group.feature_area = self._infer_feature_area(group)
            group.migration_strategy = self._recommend_migration_strategy(group)
        
        return groups
    
    def _infer_group_purpose(self, group: PropertyGroup) -> str:
        """Infer the business purpose of a property group."""
        prefix_lower = group.prefix.lower()
        
        if 'error' in prefix_lower or 'validation' in prefix_lower:
            return "Data validation and error handling"
        elif 'success' in prefix_lower or 'confirm' in prefix_lower:
            return "Process confirmation messages"
        elif 'user' in prefix_lower or 'account' in prefix_lower:
            return "User account management"
        elif 'order' in prefix_lower or 'purchase' in prefix_lower:
            return "Order processing workflow"
        elif 'product' in prefix_lower or 'item' in prefix_lower:
            return "Product catalog management"
        elif 'security' in prefix_lower or 'auth' in prefix_lower:
            return "Security and authentication"
        else:
            return f"Business functionality related to {group.prefix}"
    
    def _infer_feature_area(self, group: PropertyGroup) -> str:
        """Infer the feature area for a property group."""
        prefix_parts = group.prefix.split('.')
        if len(prefix_parts) >= 2:
            return prefix_parts[0].title()
        return "Core"
    
    def _recommend_migration_strategy(self, group: PropertyGroup) -> str:
        """Recommend migration strategy for a property group."""
        if any(prop.is_validation_message for prop in group.properties):
            return "Migrate to GraphQL schema validation with custom error messages"
        elif any(prop.is_error_message for prop in group.properties):
            return "Implement as GraphQL error extensions with structured error codes"
        elif len(group.properties) > 10:
            return "Create dedicated message service with internationalization support"
        else:
            return "Integrate into frontend component-level message handling"
    
    def _extract_business_rules_from_messages(self, entries: List[MessageEntry], 
                                            file_path: Path) -> List[BusinessRule]:
        """Extract business rules from message entries."""
        business_rules = []
        
        # Group validation messages by field/entity
        validation_groups = {}
        for entry in entries:
            if entry.is_validation_message:
                # Extract field name from key
                field_match = re.search(r'\.([^.]+)\.(?:error|invalid|required)$', entry.key)
                if field_match:
                    field_name = field_match.group(1)
                    if field_name not in validation_groups:
                        validation_groups[field_name] = []
                    validation_groups[field_name].append(entry)
        
        # Create business rules for validation groups
        for field_name, field_entries in validation_groups.items():
            rule_id = f"validation_{hashlib.md5(f'{file_path}_{field_name}'.encode()).hexdigest()[:12]}"
            
            descriptions = []
            constraints = []
            for entry in field_entries:
                descriptions.append(f"{entry.key}: {entry.value}")
                if 'required' in entry.key.lower():
                    constraints.append(f"{field_name} is mandatory")
                elif 'invalid' in entry.key.lower():
                    constraints.append(f"{field_name} format validation")
            
            business_rule = BusinessRule(
                id=rule_id,
                name=f"Field Validation: {field_name}",
                description=f"Validation rules for field {field_name}: " + "; ".join(constraints),
                rule_type=BusinessRuleType.VALIDATION,
                source=BusinessRuleSource.VALIDATION_XML,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    line_number=field_entries[0].line_number
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet="\n".join(descriptions),
                    context=f"Validation messages for {field_name}",
                    confidence_score=0.9
                ),
                business_context=field_entries[0].business_context,
                complexity=BusinessRuleComplexity.SIMPLE if len(field_entries) <= 2 else BusinessRuleComplexity.MODERATE
            )
            
            business_rule.add_tag("validation")
            business_rule.add_tag("messages")
            business_rule.add_tag(field_name)
            
            business_rules.append(business_rule)
        
        # Create business rules for business message groups
        business_message_groups = {}
        for entry in entries:
            if entry.is_business_message and not entry.is_validation_message:
                prefix = entry.key.split('.')[0]
                if prefix not in business_message_groups:
                    business_message_groups[prefix] = []
                business_message_groups[prefix].append(entry)
        
        for prefix, entries in business_message_groups.items():
            if len(entries) >= 3:  # Only create rules for significant message groups
                rule_id = f"business_messages_{hashlib.md5(f'{file_path}_{prefix}'.encode()).hexdigest()[:12]}"
                
                business_rule = BusinessRule(
                    id=rule_id,
                    name=f"Business Messages: {prefix}",
                    description=f"Business messaging for {prefix} functionality",
                    rule_type=BusinessRuleType.BUSINESS_LOGIC,
                    source=BusinessRuleSource.VALIDATION_XML,
                    location=BusinessRuleLocation(
                        file_path=str(file_path),
                        line_number=entries[0].line_number
                    ),
                    evidence=BusinessRuleEvidence(
                        code_snippet=f"Message group with {len(entries)} messages",
                        context=f"Business messaging context for {prefix}",
                        confidence_score=0.7
                    ),
                    business_context=entries[0].business_context,
                    complexity=BusinessRuleComplexity.SIMPLE
                )
                
                business_rule.add_tag("messaging")
                business_rule.add_tag("business_logic")
                business_rule.add_tag(prefix)
                
                business_rules.append(business_rule)
        
        return business_rules
    
    def _analyze_i18n_patterns(self, file_path: Path, entries: List[MessageEntry]) -> Dict[str, Any]:
        """Analyze internationalization patterns."""
        return {
            'has_locale_suffix': bool(re.search(r'_[a-z]{2}(_[A-Z]{2})?\.properties$', str(file_path))),
            'default_locale': entries[0].i18n_locale if entries else "default",
            'total_messages': len(entries),
            'parameterized_messages': len([e for e in entries if e.message_parameters]),
            'validation_messages': len([e for e in entries if e.is_validation_message]),
            'business_messages': len([e for e in entries if e.is_business_message]),
            'message_complexity': {
                'simple': len([e for e in entries if len(e.message_parameters) == 0]),
                'parameterized': len([e for e in entries if 0 < len(e.message_parameters) <= 2]),
                'complex': len([e for e in entries if len(e.message_parameters) > 2])
            }
        }
    
    def _post_process_results(self, results: List[Dict[str, Any]], 
                            context: AnalysisContext) -> Dict[str, Any]:
        """Post-process properties analysis results."""
        all_messages = []
        all_groups = []
        all_business_rules = []
        i18n_summary = {}
        
        for result in results:
            if result:
                all_messages.extend(result.get('message_entries', []))
                all_groups.extend(result.get('property_groups', []))
                all_business_rules.extend(result.get('business_rules', []))
        
        # Summarize i18n patterns
        locales = set()
        for result in results:
            if result and 'i18n_analysis' in result:
                locale = result['i18n_analysis'].get('default_locale', 'default')
                locales.add(locale)
        
        return {
            'message_entries': all_messages,
            'property_groups': all_groups,
            'business_rules': all_business_rules,
            'summary': {
                'total_files': len(results),
                'total_messages': len(all_messages),
                'total_groups': len(all_groups),
                'total_business_rules': len(all_business_rules),
                'locales_detected': list(locales),
                'validation_messages': len([m for m in all_messages if m.get('is_validation_message')]),
                'business_messages': len([m for m in all_messages if m.get('is_business_message')])
            }
        }