#!/usr/bin/env python3
"""
Struts Legacy Business Rules Analyzer
=====================================

A comprehensive tool for extracting business rules, dependencies, and architectural
complexity from Struts legacy applications to inform GraphQL/Angular migration strategies.

This analyzer focuses on:
- Extracting ALL business rules from Struts configurations
- Mapping action flows and user journeys  
- Identifying cross-dependencies and architectural complexity
- Generating stakeholder-friendly documentation
- Providing migration risk assessments

Author: Claude Code Assistant
Version: 2.0.0
"""

import os
import sys
import json
import yaml
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import re
import ast
import javalang
import networkx as nx
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import configparser
from datetime import datetime
import hashlib
import pickle
from tqdm import tqdm


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('struts_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class BusinessRule:
    """Represents a single business rule extracted from the codebase."""
    id: str
    name: str
    description: str
    type: str  # validation, workflow, security, data, ui
    source_file: str
    source_location: str
    complexity: int = 1
    dependencies: List[str] = field(default_factory=list)
    impact_areas: List[str] = field(default_factory=list)
    migration_risk: str = "medium"  # low, medium, high, critical
    business_context: str = ""
    technical_context: str = ""
    examples: List[str] = field(default_factory=list)


@dataclass
class ActionMapping:
    """Represents a Struts action mapping with all its business context."""
    path: str
    name: str
    action_class: str
    form_bean: Optional[str] = None
    forwards: Dict[str, str] = field(default_factory=dict)
    exceptions: Dict[str, str] = field(default_factory=dict)
    validation_rules: List[BusinessRule] = field(default_factory=list)
    business_purpose: str = ""
    user_journey_step: str = ""
    config_file: str = ""
    line_number: int = 0


@dataclass
class ValidationRule:
    """Represents a validation rule with business context."""
    field: str
    rule_type: str  # required, mask, range, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    message_key: str = ""
    business_reason: str = ""
    form_name: str = ""
    source: str = ""  # xml, annotation, code


@dataclass
class FormBean:
    """Represents a Struts form bean with validation and business context."""
    name: str
    type: str
    file_path: str = ""
    fields: List[str] = field(default_factory=list)
    validation_rules: List[ValidationRule] = field(default_factory=list)
    business_purpose: str = ""


@dataclass
class DependencyRelation:
    """Represents a dependency relationship between components."""
    source: str
    target: str
    relation_type: str  # action_forward, form_validation, class_inheritance, etc.
    strength: int = 1
    business_impact: str = ""


@dataclass
class MigrationAssessment:
    """Assessment of migration complexity and risks."""
    component_name: str
    component_type: str
    complexity_score: int
    risk_level: str
    migration_effort: str  # hours/days estimate
    blockers: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class ConfigurationManager:
    """Manages analyzer configuration and settings."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_default_config()
        if config_file and Path(config_file).exists():
            self._load_user_config(config_file)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration settings."""
        return {
            'analysis': {
                'max_file_size_mb': 10,
                'skip_test_files': True,
                'parallel_workers': 4,
                'cache_enabled': True,
                'deep_analysis': True
            },
            'struts': {
                'config_files': ['struts-config.xml', 'struts.xml'],
                'validation_files': ['validation.xml', 'validator-rules.xml'],
                'supported_versions': ['1.x', '2.x']
            },
            'output': {
                'format': 'markdown',
                'include_diagrams': True,
                'stakeholder_friendly': True,
                'generate_migration_plan': True
            },
            'business_rules': {
                'extract_from_comments': True,
                'infer_from_patterns': True,
                'include_ui_rules': True,
                'categorize_by_domain': True
            }
        }
    
    def _load_user_config(self, config_file: str):
        """Load user configuration from file."""
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    user_config = yaml.safe_load(f)
                else:
                    user_config = json.load(f)
            self._merge_config(user_config)
        except Exception as e:
            logger.warning(f"Failed to load user config {config_file}: {e}")
    
    def _merge_config(self, user_config: Dict[str, Any]):
        """Merge user configuration with defaults."""
        def merge_dict(base: Dict, overlay: Dict):
            for key, value in overlay.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge_dict(base[key], value)
                else:
                    base[key] = value
        
        merge_dict(self.config, user_config)
    
    def get(self, key_path: str, default=None):
        """Get configuration value using dot notation (e.g., 'analysis.max_file_size_mb')."""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value


class CacheManager:
    """Manages caching of analysis results for performance."""
    
    def __init__(self, cache_dir: str = ".struts_analyzer_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.enabled = True
    
    def _get_cache_key(self, file_path: str, content_hash: str) -> str:
        """Generate cache key for a file."""
        return f"{hashlib.md5(file_path.encode()).hexdigest()}_{content_hash}"
    
    def _get_content_hash(self, file_path: Path) -> str:
        """Get content hash for cache validation."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""
    
    def get(self, file_path: str) -> Optional[Any]:
        """Get cached result for a file."""
        if not self.enabled:
            return None
        
        try:
            path = Path(file_path)
            content_hash = self._get_content_hash(path)
            cache_key = self._get_cache_key(file_path, content_hash)
            cache_file = self.cache_dir / f"{cache_key}.pkl"
            
            if cache_file.exists():
                with open(cache_file, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            logger.debug(f"Cache read error for {file_path}: {e}")
        
        return None
    
    def set(self, file_path: str, data: Any):
        """Cache result for a file."""
        if not self.enabled:
            return
        
        try:
            path = Path(file_path)
            content_hash = self._get_content_hash(path)
            cache_key = self._get_cache_key(file_path, content_hash)
            cache_file = self.cache_dir / f"{cache_key}.pkl"
            
            with open(cache_file, 'wb') as f:
                pickle.dump(data, f)
        except Exception as e:
            logger.debug(f"Cache write error for {file_path}: {e}")


class BaseParser(ABC):
    """Abstract base class for all parsers."""
    
    def __init__(self, config: ConfigurationManager, cache: CacheManager):
        self.config = config
        self.cache = cache
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file."""
        pass
    
    @abstractmethod
    def parse(self, file_path: Path) -> Dict[str, Any]:
        """Parse the file and extract relevant information."""
        pass
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on configuration."""
        if self.config.get('analysis.skip_test_files', True):
            if any(test_indicator in str(file_path).lower() 
                   for test_indicator in ['test', 'spec', 'mock']):
                return True
        
        max_size_mb = self.config.get('analysis.max_file_size_mb', 10)
        if file_path.stat().st_size > max_size_mb * 1024 * 1024:
            self.logger.warning(f"Skipping large file: {file_path}")
            return True
        
        return False


class StrutsConfigParser(BaseParser):
    """Parser for struts-config.xml and related configuration files."""
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Struts configuration file."""
        filename = file_path.name.lower()
        return any(config_name in filename for config_name in 
                  self.config.get('struts.config_files', ['struts-config.xml', 'struts.xml']))
    
    def parse(self, file_path: Path) -> Dict[str, Any]:
        """Parse Struts configuration file and extract business rules."""
        if self._should_skip_file(file_path):
            return {}
        
        # Check cache first
        cached_result = self.cache.get(str(file_path))
        if cached_result:
            return cached_result
        
        try:
            result = {
                'action_mappings': [],
                'form_beans': [],
                'global_forwards': [],
                'business_rules': [],
                'file_path': str(file_path)
            }
            
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Extract action mappings
            result['action_mappings'] = self._extract_action_mappings(root, file_path)
            
            # Extract form beans
            result['form_beans'] = self._extract_form_beans(root, file_path)
            
            # Extract global forwards
            result['global_forwards'] = self._extract_global_forwards(root)
            
            # Extract business rules from configuration
            result['business_rules'] = self._extract_config_business_rules(root, file_path)
            
            # Cache the result
            self.cache.set(str(file_path), result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
            return {}
    
    def _extract_action_mappings(self, root: ET.Element, file_path: Path) -> List[ActionMapping]:
        """Extract action mappings with business context."""
        actions = []
        
        for action in root.findall('.//action'):
            try:
                action_mapping = ActionMapping(
                    path=action.get('path', ''),
                    name=action.get('name', ''),
                    action_class=action.get('type', ''),
                    form_bean=action.get('name'),
                    config_file=str(file_path),
                    line_number=getattr(action, 'sourceline', 0)
                )
                
                # Extract forwards
                for forward in action.findall('forward'):
                    name = forward.get('name', '')
                    path = forward.get('path', '')
                    if name and path:
                        action_mapping.forwards[name] = path
                
                # Extract exceptions
                for exception in action.findall('exception'):
                    key = exception.get('key', '')
                    path = exception.get('path', '')
                    if key and path:
                        action_mapping.exceptions[key] = path
                
                # Infer business purpose from path and class name
                action_mapping.business_purpose = self._infer_business_purpose(action_mapping)
                
                actions.append(action_mapping)
                
            except Exception as e:
                self.logger.warning(f"Error parsing action mapping: {e}")
        
        return actions
    
    def _extract_form_beans(self, root: ET.Element, file_path: Path) -> List[FormBean]:
        """Extract form bean definitions."""
        forms = []
        
        for form in root.findall('.//form-bean'):
            try:
                form_bean = FormBean(
                    name=form.get('name', ''),
                    type=form.get('type', ''),
                    file_path=str(file_path)
                )
                
                # Infer business purpose from name and type
                form_bean.business_purpose = self._infer_form_purpose(form_bean)
                
                forms.append(form_bean)
                
            except Exception as e:
                self.logger.warning(f"Error parsing form bean: {e}")
        
        return forms
    
    def _extract_global_forwards(self, root: ET.Element) -> Dict[str, str]:
        """Extract global forward mappings."""
        forwards = {}
        
        for forward in root.findall('.//global-forwards/forward'):
            name = forward.get('name', '')
            path = forward.get('path', '')
            if name and path:
                forwards[name] = path
        
        return forwards
    
    def _extract_config_business_rules(self, root: ET.Element, file_path: Path) -> List[BusinessRule]:
        """Extract business rules from configuration patterns."""
        rules = []
        
        # Rule: Action paths indicate business processes
        for action in root.findall('.//action'):
            path = action.get('path', '')
            if path:
                rule = BusinessRule(
                    id=f"action_path_{hashlib.md5(path.encode()).hexdigest()[:8]}",
                    name=f"Action Path: {path}",
                    description=f"Business process accessible via path {path}",
                    type="workflow",
                    source_file=str(file_path),
                    source_location=f"action[path='{path}']",
                    business_context=self._analyze_path_business_context(path)
                )
                rules.append(rule)
        
        # Rule: Form validation requirements
        for form in root.findall('.//form-bean'):
            name = form.get('name', '')
            if name:
                rule = BusinessRule(
                    id=f"form_bean_{hashlib.md5(name.encode()).hexdigest()[:8]}",
                    name=f"Form Bean: {name}",
                    description=f"Data collection form with validation requirements",
                    type="data",
                    source_file=str(file_path),
                    source_location=f"form-bean[name='{name}']",
                    business_context=self._analyze_form_business_context(name)
                )
                rules.append(rule)
        
        return rules
    
    def _infer_business_purpose(self, action: ActionMapping) -> str:
        """Infer business purpose from action mapping details."""
        path = action.path.lower()
        class_name = action.action_class.lower()
        
        # Common business patterns
        if 'login' in path or 'login' in class_name:
            return "User Authentication"
        elif 'search' in path or 'search' in class_name:
            return "Data Search and Retrieval"
        elif 'create' in path or 'save' in path or 'add' in path:
            return "Data Creation"
        elif 'update' in path or 'edit' in path or 'modify' in path:
            return "Data Modification"
        elif 'delete' in path or 'remove' in path:
            return "Data Deletion"
        elif 'report' in path or 'report' in class_name:
            return "Reporting and Analytics"
        elif 'admin' in path or 'admin' in class_name:
            return "Administrative Functions"
        else:
            return "Business Process"
    
    def _infer_form_purpose(self, form: FormBean) -> str:
        """Infer business purpose from form bean details."""
        name = form.name.lower()
        type_name = form.type.lower()
        
        if 'login' in name or 'auth' in name:
            return "User Authentication Form"
        elif 'search' in name or 'filter' in name:
            return "Search and Filter Form"
        elif 'user' in name or 'person' in name:
            return "User Information Form"
        elif 'product' in name or 'item' in name:
            return "Product/Item Management Form"
        elif 'order' in name or 'purchase' in name:
            return "Order Processing Form"
        else:
            return "Data Entry Form"
    
    def _analyze_path_business_context(self, path: str) -> str:
        """Analyze business context from action path."""
        segments = path.strip('/').split('/')
        context_clues = []
        
        for segment in segments:
            if segment.lower() in ['admin', 'management', 'config']:
                context_clues.append("Administrative operations")
            elif segment.lower() in ['user', 'customer', 'client']:
                context_clues.append("User-facing operations")
            elif segment.lower() in ['report', 'analytics', 'dashboard']:
                context_clues.append("Reporting and analysis")
            elif segment.lower() in ['api', 'service', 'rest']:
                context_clues.append("Service layer operations")
        
        return " | ".join(context_clues) if context_clues else "General business operations"
    
    def _analyze_form_business_context(self, form_name: str) -> str:
        """Analyze business context from form name."""
        name = form_name.lower()
        
        if 'dto' in name or 'vo' in name:
            return "Data transfer object for service layer communication"
        elif 'form' in name:
            return "User input validation and data binding"
        elif 'bean' in name:
            return "Business entity representation"
        else:
            return "Data structure for business operations"


class ValidationParser(BaseParser):
    """Parser for validation.xml and validation rules."""
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a validation configuration file."""
        filename = file_path.name.lower()
        return any(val_file in filename for val_file in 
                  self.config.get('struts.validation_files', ['validation.xml', 'validator-rules.xml']))
    
    def parse(self, file_path: Path) -> Dict[str, Any]:
        """Parse validation configuration and extract business rules."""
        if self._should_skip_file(file_path):
            return {}
        
        cached_result = self.cache.get(str(file_path))
        if cached_result:
            return cached_result
        
        try:
            result = {
                'validation_rules': [],
                'validator_definitions': [],
                'business_rules': [],
                'file_path': str(file_path)
            }
            
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Extract validation rules
            result['validation_rules'] = self._extract_validation_rules(root)
            
            # Extract validator definitions
            result['validator_definitions'] = self._extract_validator_definitions(root)
            
            # Generate business rules from validation patterns
            result['business_rules'] = self._generate_validation_business_rules(
                result['validation_rules'], file_path)
            
            self.cache.set(str(file_path), result)
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing validation file {file_path}: {e}")
            return {}
    
    def _extract_validation_rules(self, root: ET.Element) -> List[ValidationRule]:
        """Extract individual validation rules."""
        rules = []
        
        for form in root.findall('.//form'):
            form_name = form.get('name', '')
            
            for field in form.findall('.//field'):
                field_name = field.get('property', '')
                
                for validator in field.findall('depends'):
                    rule = ValidationRule(
                        field=field_name,
                        rule_type=validator.text or '',
                        form_name=form_name,
                        source='xml'
                    )
                    
                    # Extract parameters
                    for var in field.findall('var'):
                        var_name = var.find('var-name')
                        var_value = var.find('var-value')
                        if var_name is not None and var_value is not None:
                            rule.parameters[var_name.text] = var_value.text
                    
                    # Extract message key
                    msg = field.find('msg')
                    if msg is not None:
                        rule.message_key = msg.get('key', '')
                    
                    # Infer business reason
                    rule.business_reason = self._infer_validation_business_reason(rule)
                    
                    rules.append(rule)
        
        return rules
    
    def _extract_validator_definitions(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Extract validator definitions."""
        validators = []
        
        for validator in root.findall('.//validator'):
            validator_def = {
                'name': validator.get('name', ''),
                'classname': validator.get('classname', ''),
                'method': validator.get('method', ''),
                'javascript': validator.get('javascript', '')
            }
            validators.append(validator_def)
        
        return validators
    
    def _generate_validation_business_rules(self, validation_rules: List[ValidationRule], 
                                          file_path: Path) -> List[BusinessRule]:
        """Generate business rules from validation patterns."""
        business_rules = []
        
        # Group rules by form
        form_rules = defaultdict(list)
        for rule in validation_rules:
            form_rules[rule.form_name].append(rule)
        
        # Generate business rules for each form
        for form_name, rules in form_rules.items():
            rule_id = f"validation_form_{hashlib.md5(form_name.encode()).hexdigest()[:8]}"
            
            rule_descriptions = []
            for rule in rules:
                desc = f"{rule.field} must {rule.rule_type}"
                if rule.parameters:
                    param_desc = ", ".join([f"{k}={v}" for k, v in rule.parameters.items()])
                    desc += f" ({param_desc})"
                rule_descriptions.append(desc)
            
            business_rule = BusinessRule(
                id=rule_id,
                name=f"Form Validation: {form_name}",
                description=f"Validation requirements for {form_name}: " + "; ".join(rule_descriptions),
                type="validation",
                source_file=str(file_path),
                source_location=f"form[name='{form_name}']",
                complexity=len(rules),
                business_context=self._analyze_form_validation_context(form_name, rules)
            )
            business_rules.append(business_rule)
        
        return business_rules
    
    def _infer_validation_business_reason(self, rule: ValidationRule) -> str:
        """Infer business reason for validation rule."""
        field_name = rule.field.lower()
        rule_type = rule.rule_type.lower()
        
        if rule_type == 'required':
            return f"Field {rule.field} is mandatory for business process completion"
        elif rule_type == 'email':
            return f"Field {rule.field} must be valid email for communication purposes"
        elif rule_type in ['minlength', 'maxlength']:
            return f"Field {rule.field} length constraints ensure data quality and system compatibility"
        elif rule_type in ['range', 'min', 'max']:
            return f"Field {rule.field} value constraints ensure business rule compliance"
        elif rule_type == 'date':
            return f"Field {rule.field} must be valid date for temporal business logic"
        elif rule_type == 'mask':
            return f"Field {rule.field} format constraints ensure data consistency"
        else:
            return f"Field {rule.field} validation ensures business data integrity"
    
    def _analyze_form_validation_context(self, form_name: str, rules: List[ValidationRule]) -> str:
        """Analyze business context of form validation."""
        contexts = []
        
        # Analyze field patterns
        field_patterns = Counter()
        for rule in rules:
            field_lower = rule.field.lower()
            if 'email' in field_lower:
                field_patterns['communication'] += 1
            elif 'phone' in field_lower or 'tel' in field_lower:
                field_patterns['communication'] += 1
            elif 'address' in field_lower:
                field_patterns['location'] += 1
            elif 'date' in field_lower or 'time' in field_lower:
                field_patterns['temporal'] += 1
            elif 'amount' in field_lower or 'price' in field_lower:
                field_patterns['financial'] += 1
            elif 'password' in field_lower:
                field_patterns['security'] += 1
        
        # Build context description
        if field_patterns['communication'] > 0:
            contexts.append("Communication data validation")
        if field_patterns['financial'] > 0:
            contexts.append("Financial data integrity")
        if field_patterns['security'] > 0:
            contexts.append("Security and authentication")
        if field_patterns['temporal'] > 0:
            contexts.append("Date/time business logic")
        
        return " | ".join(contexts) if contexts else "General data validation"


class JSPAnalyzer(BaseParser):
    """Analyzer for JSP files to extract UI business rules and conditional logic."""
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a JSP file."""
        return file_path.suffix.lower() in ['.jsp', '.jspx']
    
    def parse(self, file_path: Path) -> Dict[str, Any]:
        """Parse JSP file and extract UI business rules."""
        if self._should_skip_file(file_path):
            return {}
        
        cached_result = self.cache.get(str(file_path))
        if cached_result:
            return cached_result
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            result = {
                'ui_business_rules': [],
                'conditional_logic': [],
                'form_bindings': [],
                'navigation_elements': [],
                'file_path': str(file_path)
            }
            
            # Extract UI business rules
            result['ui_business_rules'] = self._extract_ui_business_rules(content, file_path)
            
            # Extract conditional logic (c:if, c:choose, etc.)
            result['conditional_logic'] = self._extract_conditional_logic(content)
            
            # Extract form bindings and validation
            result['form_bindings'] = self._extract_form_bindings(content)
            
            # Extract navigation elements
            result['navigation_elements'] = self._extract_navigation_elements(content)
            
            self.cache.set(str(file_path), result)
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing JSP file {file_path}: {e}")
            return {}
    
    def _extract_ui_business_rules(self, content: str, file_path: Path) -> List[BusinessRule]:
        """Extract business rules from JSP UI elements."""
        rules = []
        
        # Extract rules from JSP comments
        comment_pattern = r'<%--\s*(.*?)\s*--%>'
        comments = re.findall(comment_pattern, content, re.DOTALL)
        
        for i, comment in enumerate(comments):
            if any(indicator in comment.lower() for indicator in 
                   ['business rule', 'requirement', 'must', 'should', 'validation']):
                
                rule = BusinessRule(
                    id=f"jsp_comment_{file_path.name}_{i}",
                    name=f"UI Business Rule from JSP Comment",
                    description=comment.strip(),
                    type="ui",
                    source_file=str(file_path),
                    source_location=f"comment_{i}",
                    business_context="User interface business requirement"
                )
                rules.append(rule)
        
        # Extract rules from conditional displays
        if_pattern = r'<c:if\s+test="([^"]+)"[^>]*>(.*?)</c:if>'
        conditionals = re.findall(if_pattern, content, re.DOTALL)
        
        for i, (condition, body) in enumerate(conditionals):
            rule = BusinessRule(
                id=f"jsp_conditional_{file_path.name}_{i}",
                name=f"Conditional Display Rule",
                description=f"UI element displayed when: {condition}",
                type="ui",
                source_file=str(file_path),
                source_location=f"c:if test='{condition}'",
                business_context=self._analyze_condition_business_context(condition)
            )
            rules.append(rule)
        
        return rules
    
    def _extract_conditional_logic(self, content: str) -> List[Dict[str, Any]]:
        """Extract conditional logic patterns from JSP."""
        conditionals = []
        
        # JSTL conditional tags
        patterns = [
            (r'<c:if\s+test="([^"]+)"[^>]*>', 'if'),
            (r'<c:when\s+test="([^"]+)"[^>]*>', 'when'),
            (r'<c:choose[^>]*>', 'choose'),
            (r'<c:otherwise[^>]*>', 'otherwise')
        ]
        
        for pattern, tag_type in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                conditional = {
                    'type': tag_type,
                    'condition': match.group(1) if len(match.groups()) > 0 else '',
                    'start_pos': match.start(),
                    'business_context': self._analyze_condition_business_context(
                        match.group(1) if len(match.groups()) > 0 else ''
                    )
                }
                conditionals.append(conditional)
        
        return conditionals
    
    def _extract_form_bindings(self, content: str) -> List[Dict[str, Any]]:
        """Extract form bindings and validation patterns."""
        bindings = []
        
        # Struts form tags
        form_patterns = [
            r'<html:form\s+([^>]+)>',
            r'<html:text\s+([^>]+)/>',
            r'<html:password\s+([^>]+)/>',
            r'<html:select\s+([^>]+)>',
            r'<html:submit\s+([^>]+)/>'
        ]
        
        for pattern in form_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                attributes = self._parse_tag_attributes(match.group(1))
                binding = {
                    'tag_type': pattern.split('<')[1].split('\\s')[0],
                    'attributes': attributes,
                    'business_purpose': self._infer_form_element_purpose(attributes)
                }
                bindings.append(binding)
        
        return bindings
    
    def _extract_navigation_elements(self, content: str) -> List[Dict[str, Any]]:
        """Extract navigation and link elements."""
        navigation = []
        
        # Struts link tags
        link_patterns = [
            r'<html:link\s+([^>]+)>',
            r'<html:rewrite\s+([^>]+)/>',
            r'<html:forward\s+([^>]+)/>'
        ]
        
        for pattern in link_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                attributes = self._parse_tag_attributes(match.group(1))
                nav_element = {
                    'type': pattern.split('<')[1].split('\\s')[0],
                    'attributes': attributes,
                    'business_purpose': self._infer_navigation_purpose(attributes)
                }
                navigation.append(nav_element)
        
        return navigation
    
    def _parse_tag_attributes(self, attr_string: str) -> Dict[str, str]:
        """Parse HTML/JSP tag attributes."""
        attributes = {}
        attr_pattern = r'(\w+)="([^"]*)"'
        matches = re.findall(attr_pattern, attr_string)
        
        for name, value in matches:
            attributes[name] = value
        
        return attributes
    
    def _analyze_condition_business_context(self, condition: str) -> str:
        """Analyze business context from conditional expressions."""
        condition_lower = condition.lower()
        
        if 'user' in condition_lower or 'login' in condition_lower:
            return "User authentication and authorization"
        elif 'permission' in condition_lower or 'role' in condition_lower:
            return "Role-based access control"
        elif 'status' in condition_lower or 'state' in condition_lower:
            return "Business state validation"
        elif 'error' in condition_lower or 'message' in condition_lower:
            return "Error handling and user feedback"
        elif 'empty' in condition_lower or 'null' in condition_lower:
            return "Data validation and display logic"
        else:
            return "Business logic conditional display"
    
    def _infer_form_element_purpose(self, attributes: Dict[str, str]) -> str:
        """Infer business purpose from form element attributes."""
        property_name = attributes.get('property', '').lower()
        
        if 'password' in property_name or 'pwd' in property_name:
            return "User authentication"
        elif 'email' in property_name or 'mail' in property_name:
            return "Communication contact"
        elif 'phone' in property_name or 'tel' in property_name:
            return "Communication contact"
        elif 'amount' in property_name or 'price' in property_name:
            return "Financial data entry"
        elif 'date' in property_name or 'time' in property_name:
            return "Temporal data entry"
        elif 'search' in property_name or 'filter' in property_name:
            return "Data search and filtering"
        else:
            return "Data input and validation"
    
    def _infer_navigation_purpose(self, attributes: Dict[str, str]) -> str:
        """Infer business purpose from navigation attributes."""
        action = attributes.get('action', '').lower()
        forward = attributes.get('forward', '').lower()
        
        if 'login' in action or 'login' in forward:
            return "User authentication navigation"
        elif 'search' in action or 'search' in forward:
            return "Data search navigation"
        elif 'create' in action or 'add' in action:
            return "Data creation navigation"
        elif 'edit' in action or 'update' in action:
            return "Data modification navigation"
        elif 'delete' in action or 'remove' in action:
            return "Data deletion navigation"
        else:
            return "General navigation"


class JavaActionAnalyzer(BaseParser):
    """Analyzer for Java Action classes to extract business logic."""
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Java Action class file."""
        return (file_path.suffix == '.java' and 
                ('action' in file_path.name.lower() or 
                 self._contains_action_patterns(file_path)))
    
    def _contains_action_patterns(self, file_path: Path) -> bool:
        """Check if file contains Struts Action patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Read first 1KB
                return ('extends Action' in content or 
                        'implements Action' in content or
                        '@Action' in content)
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> Dict[str, Any]:
        """Parse Java Action class and extract business logic."""
        if self._should_skip_file(file_path):
            return {}
        
        cached_result = self.cache.get(str(file_path))
        if cached_result:
            return cached_result
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            result = {
                'class_info': {},
                'methods': [],
                'business_rules': [],
                'dependencies': [],
                'file_path': str(file_path)
            }
            
            # Parse Java code
            try:
                tree = javalang.parse.parse(content)
                result['class_info'] = self._extract_class_info(tree, file_path)
                result['methods'] = self._extract_methods(tree, file_path)
                result['dependencies'] = self._extract_dependencies(tree)
                result['business_rules'] = self._extract_business_logic_rules(tree, content, file_path)
            except Exception as e:
                self.logger.warning(f"Failed to parse Java file {file_path}: {e}")
                # Fallback to regex-based parsing
                result = self._fallback_parse(content, file_path)
            
            self.cache.set(str(file_path), result)
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing Java file {file_path}: {e}")
            return {}
    
    def _extract_class_info(self, tree: javalang.tree.CompilationUnit, file_path: Path) -> Dict[str, Any]:
        """Extract class-level information."""
        class_info = {}
        
        for type_decl in tree.types:
            if isinstance(type_decl, javalang.tree.ClassDeclaration):
                class_info = {
                    'name': type_decl.name,
                    'package': tree.package.name if tree.package else '',
                    'extends': type_decl.extends.name if type_decl.extends else None,
                    'implements': [impl.name for impl in type_decl.implements or []],
                    'modifiers': type_decl.modifiers or [],
                    'is_action_class': self._is_action_class(type_decl)
                }
                break
        
        return class_info
    
    def _extract_methods(self, tree: javalang.tree.CompilationUnit, file_path: Path) -> List[Dict[str, Any]]:
        """Extract method information and business logic."""
        methods = []
        
        for type_decl in tree.types:
            if isinstance(type_decl, javalang.tree.ClassDeclaration):
                for method in type_decl.methods or []:
                    method_info = {
                        'name': method.name,
                        'modifiers': method.modifiers or [],
                        'return_type': str(method.return_type) if method.return_type else 'void',
                        'parameters': [str(param.type) + ' ' + param.name for param in method.parameters or []],
                        'is_execute_method': method.name in ['execute', 'perform'],
                        'business_logic_indicators': self._analyze_method_business_logic(method)
                    }
                    methods.append(method_info)
        
        return methods
    
    def _extract_dependencies(self, tree: javalang.tree.CompilationUnit) -> List[str]:
        """Extract class dependencies."""
        dependencies = []
        
        # Extract imports
        for imp in tree.imports or []:
            dependencies.append(imp.path)
        
        return dependencies
    
    def _extract_business_logic_rules(self, tree: javalang.tree.CompilationUnit, 
                                    content: str, file_path: Path) -> List[BusinessRule]:
        """Extract business rules from Action class code."""
        rules = []
        
        # Extract rules from comments
        comment_rules = self._extract_rules_from_comments(content, file_path)
        rules.extend(comment_rules)
        
        # Extract rules from method patterns
        for type_decl in tree.types:
            if isinstance(type_decl, javalang.tree.ClassDeclaration):
                for method in type_decl.methods or []:
                    method_rules = self._extract_method_business_rules(method, type_decl.name, file_path)
                    rules.extend(method_rules)
        
        return rules
    
    def _is_action_class(self, class_decl: javalang.tree.ClassDeclaration) -> bool:
        """Check if class is a Struts Action class."""
        if class_decl.extends and 'Action' in class_decl.extends.name:
            return True
        
        for impl in class_decl.implements or []:
            if 'Action' in impl.name:
                return True
        
        return False
    
    def _analyze_method_business_logic(self, method: javalang.tree.MethodDeclaration) -> List[str]:
        """Analyze method for business logic indicators."""
        indicators = []
        
        if method.name in ['execute', 'perform']:
            indicators.append('main_action_method')
        
        if method.name.lower().startswith('validate'):
            indicators.append('validation_logic')
        
        if any(param_type in str(method.return_type or '') for param_type in ['ActionForward', 'Forward']):
            indicators.append('navigation_logic')
        
        # Analyze method body for business patterns (simplified)
        if hasattr(method, 'body') and method.body:
            body_str = str(method.body)
            if 'if' in body_str or 'switch' in body_str:
                indicators.append('conditional_business_logic')
            if 'for' in body_str or 'while' in body_str:
                indicators.append('iterative_processing')
        
        return indicators
    
    def _extract_rules_from_comments(self, content: str, file_path: Path) -> List[BusinessRule]:
        """Extract business rules from code comments."""
        rules = []
        
        # Find multi-line comments that might contain business rules
        comment_pattern = r'/\*\*(.*?)\*/'
        comments = re.findall(comment_pattern, content, re.DOTALL)
        
        for i, comment in enumerate(comments):
            comment_lines = [line.strip().lstrip('*').strip() for line in comment.split('\n')]
            comment_text = ' '.join(line for line in comment_lines if line)
            
            # Look for business rule indicators
            if any(indicator in comment_text.lower() for indicator in 
                   ['business rule', 'requirement', 'must', 'should', 'validation']):
                
                rule = BusinessRule(
                    id=f"comment_rule_{file_path.name}_{i}",
                    name=f"Business Rule from Comment",
                    description=comment_text,
                    type="business_logic",
                    source_file=str(file_path),
                    source_location=f"comment_{i}",
                    business_context="Documented business requirement"
                )
                rules.append(rule)
        
        return rules
    
    def _extract_method_business_rules(self, method: javalang.tree.MethodDeclaration, 
                                     class_name: str, file_path: Path) -> List[BusinessRule]:
        """Extract business rules from method implementation."""
        rules = []
        
        if method.name in ['execute', 'perform']:
            rule = BusinessRule(
                id=f"action_execute_{class_name}_{method.name}",
                name=f"Action Execution: {class_name}.{method.name}",
                description=f"Main business logic execution in {class_name}",
                type="workflow",
                source_file=str(file_path),
                source_location=f"{class_name}.{method.name}()",
                business_context="Primary action processing logic"
            )
            rules.append(rule)
        
        return rules
    
    def _fallback_parse(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Fallback parsing using regex when Java parser fails."""
        result = {
            'class_info': {'name': file_path.stem},
            'methods': [],
            'business_rules': [],
            'dependencies': [],
            'file_path': str(file_path)
        }
        
        # Extract method names with regex
        method_pattern = r'public\s+\w+\s+(\w+)\s*\([^)]*\)\s*{'
        methods = re.findall(method_pattern, content)
        
        for method_name in methods:
            result['methods'].append({
                'name': method_name,
                'modifiers': ['public'],
                'is_execute_method': method_name in ['execute', 'perform']
            })
        
        return result


class BusinessRuleExtractor:
    """Main class for extracting and organizing business rules."""
    
    def __init__(self, config: ConfigurationManager):
        self.config = config
        self.cache = CacheManager()
        self.parsers = self._initialize_parsers()
        self.business_rules = []
        self.action_mappings = []
        self.validation_rules = []
        self.dependencies = []
    
    def _initialize_parsers(self) -> List[BaseParser]:
        """Initialize all parser instances."""
        return [
            StrutsConfigParser(self.config, self.cache),
            ValidationParser(self.config, self.cache),
            JavaActionAnalyzer(self.config, self.cache),
            JSPAnalyzer(self.config, self.cache)
        ]
    
    def analyze_directory(self, directory: Path) -> Dict[str, Any]:
        """Analyze entire directory structure for business rules."""
        logger.info(f"Starting analysis of directory: {directory}")
        
        # Find all relevant files
        files_to_analyze = self._find_relevant_files(directory)
        logger.info(f"Found {len(files_to_analyze)} files to analyze")
        
        # Process files in parallel if configured
        if self.config.get('analysis.parallel_workers', 1) > 1:
            self._process_files_parallel(files_to_analyze)
        else:
            self._process_files_sequential(files_to_analyze)
        
        # Build dependency graph
        dependency_graph = self._build_dependency_graph()
        
        # Generate migration assessment
        migration_assessment = self._generate_migration_assessment()
        
        return {
            'business_rules': [asdict(rule) for rule in self.business_rules],
            'action_mappings': [asdict(mapping) for mapping in self.action_mappings],
            'validation_rules': [asdict(rule) for rule in self.validation_rules],
            'dependencies': dependency_graph,
            'migration_assessment': [asdict(assessment) for assessment in migration_assessment],
            'summary': self._generate_summary()
        }
    
    def _find_relevant_files(self, directory: Path) -> List[Path]:
        """Find all files relevant for analysis."""
        relevant_files = []
        
        # File patterns to look for
        patterns = [
            '**/*.xml',      # Configuration files
            '**/*.java',     # Action classes
            '**/*.jsp',      # JSP files
            '**/*.properties'  # Message resources
        ]
        
        for pattern in patterns:
            files = list(directory.glob(pattern))
            relevant_files.extend(files)
        
        # Filter out irrelevant files
        filtered_files = []
        for file_path in relevant_files:
            if any(parser.can_parse(file_path) for parser in self.parsers):
                filtered_files.append(file_path)
        
        return filtered_files
    
    def _process_files_sequential(self, files: List[Path]):
        """Process files sequentially."""
        for file_path in tqdm(files, desc="Analyzing files"):
            self._process_single_file(file_path)
    
    def _process_files_parallel(self, files: List[Path]):
        """Process files in parallel."""
        max_workers = self.config.get('analysis.parallel_workers', 4)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._process_single_file, file_path) 
                      for file_path in files]
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Analyzing files"):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error processing file: {e}")
    
    def _process_single_file(self, file_path: Path):
        """Process a single file with appropriate parser."""
        for parser in self.parsers:
            if parser.can_parse(file_path):
                try:
                    result = parser.parse(file_path)
                    self._integrate_parser_results(result)
                    break
                except Exception as e:
                    logger.error(f"Error parsing {file_path} with {parser.__class__.__name__}: {e}")
    
    def _integrate_parser_results(self, result: Dict[str, Any]):
        """Integrate results from a parser into the main collections."""
        if 'business_rules' in result:
            for rule_data in result['business_rules']:
                if isinstance(rule_data, dict):
                    rule = BusinessRule(**rule_data)
                else:
                    rule = rule_data
                self.business_rules.append(rule)
        
        if 'action_mappings' in result:
            for mapping_data in result['action_mappings']:
                if isinstance(mapping_data, dict):
                    mapping = ActionMapping(**mapping_data)
                else:
                    mapping = mapping_data
                self.action_mappings.append(mapping)
        
        if 'validation_rules' in result:
            for rule_data in result['validation_rules']:
                if isinstance(rule_data, dict):
                    rule = ValidationRule(**rule_data)
                else:
                    rule = rule_data
                self.validation_rules.append(rule)
    
    def _build_dependency_graph(self) -> Dict[str, Any]:
        """Build comprehensive dependency graph."""
        graph = nx.DiGraph()
        
        # Add action mappings as nodes
        for action in self.action_mappings:
            graph.add_node(action.path, type='action', data=asdict(action))
            
            # Add edges for forwards
            for forward_name, forward_path in action.forwards.items():
                graph.add_edge(action.path, forward_path, type='forward', name=forward_name)
        
        # Analyze strongly connected components
        components = list(nx.strongly_connected_components(graph))
        
        return {
            'nodes': list(graph.nodes(data=True)),
            'edges': list(graph.edges(data=True)),
            'strongly_connected_components': [list(comp) for comp in components],
            'cycles': [comp for comp in components if len(comp) > 1]
        }
    
    def _generate_migration_assessment(self) -> List[MigrationAssessment]:
        """Generate migration complexity assessment."""
        assessments = []
        
        # Assess action mappings
        for action in self.action_mappings:
            complexity = self._calculate_action_complexity(action)
            risk_level = self._assess_migration_risk(complexity, action)
            
            assessment = MigrationAssessment(
                component_name=action.path,
                component_type='action',
                complexity_score=complexity,
                risk_level=risk_level,
                migration_effort=self._estimate_migration_effort(complexity),
                recommendations=self._generate_migration_recommendations(action, complexity)
            )
            assessments.append(assessment)
        
        return assessments
    
    def _calculate_action_complexity(self, action: ActionMapping) -> int:
        """Calculate complexity score for an action mapping."""
        score = 1  # Base complexity
        
        # Add complexity for forwards
        score += len(action.forwards) * 2
        
        # Add complexity for exceptions
        score += len(action.exceptions) * 3
        
        # Add complexity for validation rules
        score += len(action.validation_rules) * 2
        
        # Add complexity for form bean
        if action.form_bean:
            score += 3
        
        return score
    
    def _assess_migration_risk(self, complexity: int, action: ActionMapping) -> str:
        """Assess migration risk based on complexity and patterns."""
        if complexity > 15:
            return "critical"
        elif complexity > 10:
            return "high"
        elif complexity > 5:
            return "medium"
        else:
            return "low"
    
    def _estimate_migration_effort(self, complexity: int) -> str:
        """Estimate migration effort based on complexity."""
        if complexity > 15:
            return "2-3 days"
        elif complexity > 10:
            return "1-2 days"
        elif complexity > 5:
            return "4-8 hours"
        else:
            return "1-4 hours"
    
    def _generate_migration_recommendations(self, action: ActionMapping, complexity: int) -> List[str]:
        """Generate specific migration recommendations."""
        recommendations = []
        
        if len(action.forwards) > 3:
            recommendations.append("Consider consolidating multiple forwards into a single controller method")
        
        if action.form_bean:
            recommendations.append("Map form bean to GraphQL input type or Angular reactive form")
        
        if len(action.validation_rules) > 0:
            recommendations.append("Implement validation rules using GraphQL schema validation or Angular validators")
        
        if complexity > 10:
            recommendations.append("Break down complex action into multiple GraphQL resolvers")
        
        return recommendations
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate analysis summary."""
        return {
            'total_business_rules': len(self.business_rules),
            'total_actions': len(self.action_mappings),
            'total_validation_rules': len(self.validation_rules),
            'rule_types': Counter(rule.type for rule in self.business_rules),
            'complexity_distribution': self._get_complexity_distribution(),
            'migration_risk_summary': self._get_migration_risk_summary(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_complexity_distribution(self) -> Dict[str, int]:
        """Get distribution of complexity scores."""
        complexities = [self._calculate_action_complexity(action) for action in self.action_mappings]
        return {
            'low (1-5)': sum(1 for c in complexities if c <= 5),
            'medium (6-10)': sum(1 for c in complexities if 6 <= c <= 10),
            'high (11-15)': sum(1 for c in complexities if 11 <= c <= 15),
            'critical (16+)': sum(1 for c in complexities if c > 15)
        }
    
    def _get_migration_risk_summary(self) -> Dict[str, int]:
        """Get summary of migration risks."""
        risks = []
        for action in self.action_mappings:
            complexity = self._calculate_action_complexity(action)
            risk = self._assess_migration_risk(complexity, action)
            risks.append(risk)
        
        return Counter(risks)


class DocumentationGenerator:
    """Generates stakeholder-friendly documentation from analysis results."""
    
    def __init__(self, config: ConfigurationManager):
        self.config = config
    
    def generate(self, analysis_results: Dict[str, Any], output_dir: Path):
        """Generate comprehensive documentation."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate main business rules documentation
        self._generate_business_rules_doc(analysis_results, output_dir)
        
        # Generate action flow documentation
        self._generate_action_flow_doc(analysis_results, output_dir)
        
        # Generate migration assessment
        self._generate_migration_assessment_doc(analysis_results, output_dir)
        
        # Generate dependency graphs
        if self.config.get('output.include_diagrams', True):
            self._generate_dependency_diagrams(analysis_results, output_dir)
        
        # Generate executive summary
        self._generate_executive_summary(analysis_results, output_dir)
    
    def _generate_business_rules_doc(self, results: Dict[str, Any], output_dir: Path):
        """Generate business rules documentation."""
        doc_path = output_dir / "business_rules.md"
        
        with open(doc_path, 'w') as f:
            f.write("# Business Rules Analysis\n\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary
            summary = results.get('summary', {})
            f.write("## Summary\n\n")
            f.write(f"- **Total Business Rules Identified**: {summary.get('total_business_rules', 0)}\n")
            f.write(f"- **Total Actions**: {summary.get('total_actions', 0)}\n")
            f.write(f"- **Total Validation Rules**: {summary.get('total_validation_rules', 0)}\n\n")
            
            # Rule types breakdown
            rule_types = summary.get('rule_types', {})
            if rule_types:
                f.write("### Rule Types Distribution\n\n")
                for rule_type, count in rule_types.items():
                    f.write(f"- **{rule_type.title()}**: {count} rules\n")
                f.write("\n")
            
            # Detailed rules by category
            rules = results.get('business_rules', [])
            rules_by_type = defaultdict(list)
            for rule in rules:
                rules_by_type[rule.get('type', 'unknown')].append(rule)
            
            for rule_type, type_rules in rules_by_type.items():
                f.write(f"## {rule_type.title()} Rules\n\n")
                
                for rule in type_rules:
                    f.write(f"### {rule.get('name', 'Unknown Rule')}\n\n")
                    f.write(f"**Description**: {rule.get('description', 'No description available')}\n\n")
                    f.write(f"**Source**: {rule.get('source_file', 'Unknown')} - {rule.get('source_location', 'Unknown location')}\n\n")
                    
                    if rule.get('business_context'):
                        f.write(f"**Business Context**: {rule.get('business_context')}\n\n")
                    
                    if rule.get('dependencies'):
                        f.write(f"**Dependencies**: {', '.join(rule.get('dependencies', []))}\n\n")
                    
                    f.write(f"**Migration Risk**: {rule.get('migration_risk', 'medium').upper()}\n\n")
                    f.write("---\n\n")
    
    def _generate_action_flow_doc(self, results: Dict[str, Any], output_dir: Path):
        """Generate action flow documentation."""
        doc_path = output_dir / "action_flows.md"
        
        with open(doc_path, 'w') as f:
            f.write("# Action Flow Analysis\n\n")
            f.write("This document describes the user journey flows and action mappings in the Struts application.\n\n")
            
            actions = results.get('action_mappings', [])
            
            # Group actions by business purpose
            actions_by_purpose = defaultdict(list)
            for action in actions:
                purpose = action.get('business_purpose', 'General Business Process')
                actions_by_purpose[purpose].append(action)
            
            for purpose, purpose_actions in actions_by_purpose.items():
                f.write(f"## {purpose}\n\n")
                
                for action in purpose_actions:
                    f.write(f"### Action: {action.get('path', 'Unknown Path')}\n\n")
                    f.write(f"**Action Class**: `{action.get('action_class', 'Unknown')}`\n\n")
                    
                    if action.get('form_bean'):
                        f.write(f"**Form Bean**: `{action.get('form_bean')}`\n\n")
                    
                    # Document forwards (user navigation paths)
                    forwards = action.get('forwards', {})
                    if forwards:
                        f.write("**Navigation Paths**:\n\n")
                        for forward_name, forward_path in forwards.items():
                            f.write(f"- `{forward_name}` → `{forward_path}`\n")
                        f.write("\n")
                    
                    # Document exceptions
                    exceptions = action.get('exceptions', {})
                    if exceptions:
                        f.write("**Error Handling**:\n\n")
                        for exception_key, exception_path in exceptions.items():
                            f.write(f"- `{exception_key}` → `{exception_path}`\n")
                        f.write("\n")
                    
                    f.write("---\n\n")
    
    def _generate_migration_assessment_doc(self, results: Dict[str, Any], output_dir: Path):
        """Generate migration assessment documentation."""
        doc_path = output_dir / "migration_assessment.md"
        
        with open(doc_path, 'w') as f:
            f.write("# Migration Assessment Report\n\n")
            f.write("This report provides migration complexity analysis and recommendations for transitioning from Struts to GraphQL/Angular.\n\n")
            
            # Overall risk summary
            summary = results.get('summary', {})
            risk_summary = summary.get('migration_risk_summary', {})
            complexity_dist = summary.get('complexity_distribution', {})
            
            f.write("## Executive Summary\n\n")
            f.write("### Risk Level Distribution\n\n")
            for risk_level, count in risk_summary.items():
                f.write(f"- **{risk_level.upper()}**: {count} components\n")
            f.write("\n")
            
            f.write("### Complexity Distribution\n\n")
            for complexity_range, count in complexity_dist.items():
                f.write(f"- **{complexity_range}**: {count} components\n")
            f.write("\n")
            
            # Detailed assessments
            assessments = results.get('migration_assessment', [])
            
            # Group by risk level
            assessments_by_risk = defaultdict(list)
            for assessment in assessments:
                risk = assessment.get('risk_level', 'medium')
                assessments_by_risk[risk].append(assessment)
            
            # Process in order of risk priority
            risk_order = ['critical', 'high', 'medium', 'low']
            for risk_level in risk_order:
                if risk_level in assessments_by_risk:
                    f.write(f"## {risk_level.upper()} Risk Components\n\n")
                    
                    for assessment in assessments_by_risk[risk_level]:
                        f.write(f"### {assessment.get('component_name', 'Unknown Component')}\n\n")
                        f.write(f"**Type**: {assessment.get('component_type', 'unknown')}\n\n")
                        f.write(f"**Complexity Score**: {assessment.get('complexity_score', 0)}\n\n")
                        f.write(f"**Estimated Effort**: {assessment.get('migration_effort', 'Unknown')}\n\n")
                        
                        recommendations = assessment.get('recommendations', [])
                        if recommendations:
                            f.write("**Recommendations**:\n\n")
                            for rec in recommendations:
                                f.write(f"- {rec}\n")
                            f.write("\n")
                        
                        blockers = assessment.get('blockers', [])
                        if blockers:
                            f.write("**Potential Blockers**:\n\n")
                            for blocker in blockers:
                                f.write(f"- {blocker}\n")
                            f.write("\n")
                        
                        f.write("---\n\n")
    
    def _generate_dependency_diagrams(self, results: Dict[str, Any], output_dir: Path):
        """Generate dependency diagrams using graphviz."""
        try:
            import graphviz
            
            dependencies = results.get('dependencies', {})
            nodes = dependencies.get('nodes', [])
            edges = dependencies.get('edges', [])
            
            # Create main dependency graph
            dot = graphviz.Digraph(comment='Struts Application Dependencies')
            dot.attr(rankdir='TB', size='12,8')
            
            # Add nodes
            for node_id, node_data in nodes:
                node_type = node_data.get('type', 'unknown')
                label = node_id.split('/')[-1] if '/' in node_id else node_id
                
                if node_type == 'action':
                    dot.node(node_id, label, shape='box', style='filled', fillcolor='lightblue')
                else:
                    dot.node(node_id, label, shape='ellipse')
            
            # Add edges
            for source, target, edge_data in edges:
                edge_type = edge_data.get('type', 'unknown')
                label = edge_data.get('name', '')
                
                if edge_type == 'forward':
                    dot.edge(source, target, label=label, color='blue')
                else:
                    dot.edge(source, target, label=label)
            
            # Render the graph
            output_file = output_dir / 'dependency_graph'
            dot.render(str(output_file), format='png', cleanup=True)
            
            logger.info(f"Dependency graph generated: {output_file}.png")
            
        except ImportError:
            logger.warning("Graphviz not available, skipping diagram generation")
        except Exception as e:
            logger.error(f"Error generating dependency diagrams: {e}")
    
    def _generate_executive_summary(self, results: Dict[str, Any], output_dir: Path):
        """Generate executive summary for stakeholders."""
        doc_path = output_dir / "executive_summary.md"
        
        with open(doc_path, 'w') as f:
            f.write("# Executive Summary: Struts Legacy Analysis\n\n")
            f.write(f"**Analysis Date**: {datetime.now().strftime('%Y-%m-%d')}\n\n")
            
            summary = results.get('summary', {})
            
            f.write("## Key Findings\n\n")
            f.write(f"Our analysis of the Struts legacy application identified **{summary.get('total_business_rules', 0)} business rules** ")
            f.write(f"across **{summary.get('total_actions', 0)} action mappings**. ")
            f.write(f"The application contains **{summary.get('total_validation_rules', 0)} validation rules** ")
            f.write("that ensure data integrity and business process compliance.\n\n")
            
            # Risk assessment
            risk_summary = summary.get('migration_risk_summary', {})
            total_components = sum(risk_summary.values())
            
            f.write("## Migration Risk Assessment\n\n")
            if risk_summary:
                critical_count = risk_summary.get('critical', 0)
                high_count = risk_summary.get('high', 0)
                
                if critical_count > 0:
                    f.write(f"⚠️ **{critical_count} CRITICAL** components require immediate attention and specialized expertise.\n\n")
                
                if high_count > 0:
                    f.write(f"🔶 **{high_count} HIGH RISK** components will require significant refactoring effort.\n\n")
                
                medium_count = risk_summary.get('medium', 0)
                low_count = risk_summary.get('low', 0)
                
                f.write(f"📊 **Risk Distribution**:\n")
                f.write(f"- Critical: {critical_count} ({critical_count/total_components*100:.1f}%)\n")
                f.write(f"- High: {high_count} ({high_count/total_components*100:.1f}%)\n")
                f.write(f"- Medium: {medium_count} ({medium_count/total_components*100:.1f}%)\n")
                f.write(f"- Low: {low_count} ({low_count/total_components*100:.1f}%)\n\n")
            
            # Business rule insights
            rule_types = summary.get('rule_types', {})
            f.write("## Business Logic Complexity\n\n")
            f.write("The application's business logic is distributed across several categories:\n\n")
            
            for rule_type, count in sorted(rule_types.items(), key=lambda x: x[1], reverse=True):
                percentage = count / summary.get('total_business_rules', 1) * 100
                f.write(f"- **{rule_type.title()}**: {count} rules ({percentage:.1f}%)\n")
            
            f.write("\n## Recommendations\n\n")
            f.write("1. **Prioritize Critical Components**: Address critical risk components first to establish a solid migration foundation.\n\n")
            f.write("2. **Incremental Migration**: Implement a phased approach, starting with low-risk components to build team expertise.\n\n")
            f.write("3. **Business Rule Documentation**: Use this analysis to create comprehensive business requirement documentation for the new system.\n\n")
            f.write("4. **GraphQL Schema Design**: Leverage the identified data validation rules to design robust GraphQL schemas.\n\n")
            f.write("5. **Angular Component Mapping**: Use action flow analysis to design corresponding Angular components and routing.\n\n")
            
            f.write("## Next Steps\n\n")
            f.write("1. Review detailed migration assessment for component-specific recommendations\n")
            f.write("2. Analyze business rule documentation with domain experts\n")
            f.write("3. Create detailed migration project plan based on risk assessments\n")
            f.write("4. Establish testing strategy to validate business rule preservation\n")


def main():
    """Main entry point for the enhanced business rule analyzer."""
    parser = argparse.ArgumentParser(
        description='Enhanced Struts Legacy Business Rules Analyzer',
        epilog='This analyzer provides comprehensive business rule extraction and search capabilities for Struts to GraphQL/Angular migration.'
    )
    
    # Required arguments
    parser.add_argument('directory', help='Directory containing Struts application')
    
    # Configuration options
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output', default='./analysis_output', help='Output directory for results')
    parser.add_argument('--format', choices=['json', 'yaml', 'markdown', 'all'], default='all', 
                       help='Output format (default: all formats)')
    
    # Performance options
    parser.add_argument('--parallel', type=int, help='Number of parallel workers')
    parser.add_argument('--cache', action='store_true', help='Enable caching for improved performance')
    
    # Analysis options
    parser.add_argument('--deep-analysis', action='store_true', default=True,
                       help='Enable deep business rule analysis (default: enabled)')
    parser.add_argument('--search-index', action='store_true', default=True,
                       help='Build search index for business rules (default: enabled)')
    parser.add_argument('--interactive-docs', action='store_true', default=True,
                       help='Generate interactive HTML documentation (default: enabled)')
    
    # Output options
    parser.add_argument('--stakeholder-reports', action='store_true', default=True,
                       help='Generate stakeholder-specific reports (default: enabled)')
    parser.add_argument('--migration-guide', action='store_true', default=True,
                       help='Generate migration planning guide (default: enabled)')
    parser.add_argument('--csv-export', action='store_true', default=True,
                       help='Export business rules to CSV format (default: enabled)')
    
    # Debugging options
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--test-mode', action='store_true', help='Run in test mode with sample data')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    try:
        # Initialize configuration
        config = ConfigurationManager(args.config)
        
        # Override config with command line arguments
        if args.parallel:
            config.config['analysis']['parallel_workers'] = args.parallel
        if args.cache:
            config.config['analysis']['cache_enabled'] = True
        if args.deep_analysis:
            config.config['analysis']['deep_analysis'] = True
        
        # Handle test mode
        if args.test_mode:
            print("Running in test mode...")
            from test_comprehensive_analyzer import run_comprehensive_tests
            success = run_comprehensive_tests()
            sys.exit(0 if success else 1)
        
        # Initialize the enhanced business rule engine
        from business_rule_engine import BusinessRuleEngine
        from generators.enhanced_documentation_generator import EnhancedDocumentationGenerator
        
        engine = BusinessRuleEngine(config)
        
        # Validate directory
        directory = Path(args.directory)
        if not directory.exists():
            logger.error(f"Directory does not exist: {directory}")
            sys.exit(1)
        
        print(f"\n🔍 Starting comprehensive business rule analysis of: {directory}")
        print("=" * 80)
        
        # Run comprehensive analysis
        discovery_result = engine.analyze_application(directory)
        
        # Create output directory
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n📊 Analysis Results Summary:")
        print("-" * 40)
        print(f"Total Business Rules: {discovery_result.total_rules:,}")
        print(f"Business Domains: {len(discovery_result.business_domains)}")
        print(f"High-Impact Rules: {len(discovery_result.high_impact_rules)}")
        print(f"Migration-Critical Rules: {len(discovery_result.migration_critical_rules)}")
        print(f"Potential Duplicates: {len(discovery_result.duplicate_rules)}")
        
        # Export analysis results
        print(f"\n📝 Generating exports...")
        if args.format == 'all':
            formats = ['json', 'yaml', 'markdown']
        else:
            formats = [args.format]
        
        for fmt in formats:
            engine.export_analysis_results(output_dir / f"business_rules_analysis", format=fmt)
            print(f"  ✓ {fmt.upper()} export saved")
        
        # Generate enhanced documentation
        if args.interactive_docs or args.stakeholder_reports or args.migration_guide:
            print(f"\n📚 Generating comprehensive documentation...")
            doc_generator = EnhancedDocumentationGenerator(config)
            
            # Configure documentation generation
            doc_generator.doc_config.include_stakeholder_views = args.stakeholder_reports
            doc_generator.doc_config.include_migration_guide = args.migration_guide
            doc_generator.doc_config.generate_interactive_html = args.interactive_docs
            doc_generator.doc_config.generate_csv_export = args.csv_export
            
            doc_generator.generate_comprehensive_documentation(
                discovery_result,
                engine.all_business_rules,
                engine.search_index,
                output_dir
            )
            print("  ✓ Executive summary generated")
            print("  ✓ Business rule catalog generated")
            print("  ✓ Technical migration guide generated")
            if args.interactive_docs:
                print("  ✓ Interactive HTML documentation generated")
            if args.stakeholder_reports:
                print("  ✓ Stakeholder-specific reports generated")
            if args.csv_export:
                print("  ✓ CSV exports generated")
        
        # Display key findings
        print(f"\n🎯 Key Findings:")
        print("-" * 40)
        
        # Rule type distribution
        for rule_type, count in sorted(discovery_result.rules_by_type.items(), key=lambda x: x[1], reverse=True)[:5]:
            percentage = (count / discovery_result.total_rules) * 100
            print(f"  • {rule_type.replace('_', ' ').title()}: {count:,} rules ({percentage:.1f}%)")
        
        # Complexity distribution
        print(f"\n📈 Complexity Distribution:")
        for complexity, count in discovery_result.rules_by_complexity.items():
            percentage = (count / discovery_result.total_rules) * 100
            print(f"  • {complexity.title()}: {count:,} rules ({percentage:.1f}%)")
        
        # Business domains
        if discovery_result.business_domains:
            print(f"\n🏢 Business Domains Identified:")
            for domain in sorted(discovery_result.business_domains)[:10]:
                print(f"  • {domain}")
            if len(discovery_result.business_domains) > 10:
                print(f"  ... and {len(discovery_result.business_domains) - 10} more")
        
        # Migration recommendations
        print(f"\n🚀 Migration Recommendations:")
        print("-" * 40)
        critical_rules = len(discovery_result.migration_critical_rules)
        total_rules = discovery_result.total_rules
        
        if critical_rules / total_rules > 0.2:
            risk_level = "HIGH"
            timeline = "28-32 weeks"
        elif critical_rules / total_rules > 0.1:
            risk_level = "MEDIUM"
            timeline = "20-24 weeks"
        else:
            risk_level = "LOW"
            timeline = "16-20 weeks"
        
        print(f"  • Migration Risk Level: {risk_level}")
        print(f"  • Estimated Timeline: {timeline}")
        print(f"  • Recommended Approach: Phased migration by business domain")
        print(f"  • Priority: Focus on {len(discovery_result.high_impact_rules)} high-impact rules first")
        
        # Output location
        print(f"\n📁 Analysis Output Location:")
        print(f"  {output_dir.absolute()}")
        
        # Search capabilities reminder
        if args.search_index:
            print(f"\n🔎 Search Capabilities:")
            print("  • Full-text search across all business rules")
            print("  • Filter by type, complexity, migration risk")
            print("  • Similarity detection for duplicate rules")
            print("  • Interactive HTML interface for exploration")
        
        print(f"\n✅ Analysis completed successfully!")
        print("📖 Review the generated documentation for detailed findings and migration guidance.")
        
        # Clean up
        engine.close()
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Analysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()