import sys
sys.path.append('..')

"""
Struts Configuration Analyzer
==============================

This module provides analysis capabilities for Struts configuration files,
particularly struts-config.xml and related configuration files. It extracts
action mappings, form beans, global forwards, and other configuration elements
while inferring business context and rules.

Features:
- Complete struts-config.xml parsing with error handling
- Action mapping extraction with business purpose inference
- Form bean analysis and validation rule discovery
- Global forwards and exception mapping analysis
- Business rule extraction from configuration patterns
- Migration complexity assessment for each component

Author: Claude Code Assistant
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
import hashlib
import re

import sys
sys.path.append('..')
from analyzers.base_analyzer import BaseAnalyzer, AnalysisContext
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource, 
    BusinessRuleLocation, BusinessRuleEvidence
)
from utils.logging_utils import get_logger


logger = get_logger(__name__)


@dataclass
class ActionMapping:
    """Represents a Struts action mapping with business context."""
    path: str
    name: str
    action_class: str
    form_bean: Optional[str] = None
    forwards: Dict[str, str] = field(default_factory=dict)
    exceptions: Dict[str, str] = field(default_factory=dict)
    validation_rules: List[str] = field(default_factory=list)
    business_purpose: str = ""
    user_journey_step: str = ""
    config_file: str = ""
    line_number: int = 0
    complexity_score: int = 1
    migration_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'path': self.path,
            'name': self.name,
            'action_class': self.action_class,
            'form_bean': self.form_bean,
            'forwards': self.forwards,
            'exceptions': self.exceptions,
            'validation_rules': self.validation_rules,
            'business_purpose': self.business_purpose,
            'user_journey_step': self.user_journey_step,
            'config_file': self.config_file,
            'line_number': self.line_number,
            'complexity_score': self.complexity_score,
            'migration_recommendations': self.migration_recommendations
        }


@dataclass
class FormBean:
    """Represents a Struts form bean with validation context."""
    name: str
    type: str
    file_path: str = ""
    fields: List[str] = field(default_factory=list)
    validation_rules: List[str] = field(default_factory=list)
    business_purpose: str = ""
    data_binding_patterns: List[str] = field(default_factory=list)
    migration_target: str = ""  # GraphQL input type or Angular form
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'type': self.type,
            'file_path': self.file_path,
            'fields': self.fields,
            'validation_rules': self.validation_rules,
            'business_purpose': self.business_purpose,
            'data_binding_patterns': self.data_binding_patterns,
            'migration_target': self.migration_target
        }


@dataclass
class GlobalForward:
    """Represents a global forward definition."""
    name: str
    path: str
    redirect: bool = False
    business_context: str = ""
    usage_frequency: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'path': self.path,
            'redirect': self.redirect,
            'business_context': self.business_context,
            'usage_frequency': self.usage_frequency
        }


class StrutsConfigAnalyzer(BaseAnalyzer):
    """
    Analyzer for Struts configuration files.
    
    Extracts and analyzes action mappings, form beans, global forwards,
    and other configuration elements from struts-config.xml files.
    """
    
    def _initialize_analyzer(self) -> None:
        """Initialize Struts config analyzer settings."""
        self._supported_extensions = {'.xml'}
        self._required_patterns = ['struts-config', 'struts.xml']
        
        # Business purpose patterns for action inference
        self._business_patterns = {
            'authentication': ['login', 'logout', 'auth', 'signin', 'signout'],
            'user_management': ['user', 'profile', 'account', 'registration', 'signup'],
            'data_search': ['search', 'find', 'query', 'lookup', 'browse'],
            'data_create': ['create', 'add', 'new', 'insert', 'save'],
            'data_read': ['view', 'show', 'display', 'get', 'read', 'details'],
            'data_update': ['edit', 'update', 'modify', 'change'],
            'data_delete': ['delete', 'remove', 'drop'],
            'reporting': ['report', 'export', 'print', 'generate'],
            'administration': ['admin', 'config', 'settings', 'manage'],
            'workflow': ['approve', 'submit', 'process', 'review', 'workflow'],
            'integration': ['sync', 'import', 'export', 'api', 'service']
        }
    
    def can_analyze(self, file_path: Path) -> bool:
        """
        Check if this is a Struts configuration file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if this is a Struts config file
        """
        if file_path.suffix.lower() != '.xml':
            return False
        
        filename = file_path.name.lower()
        
        # Check for known Struts config file names
        struts_config_files = self.config.get('struts.config_files', 
                                            ['struts-config.xml', 'struts.xml'])
        
        if any(config_name in filename for config_name in struts_config_files):
            return True
        
        # Check file content for Struts DOCTYPE or root element
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Read first 1KB
                return ('struts-config' in content.lower() or 
                        'action-mappings' in content.lower() or
                        'form-beans' in content.lower())
        except Exception:
            return False
    
    def _analyze_file(self, file_path: Path, context: AnalysisContext) -> Dict[str, Any]:
        """
        Analyze a single Struts configuration file.
        
        Args:
            file_path: Path to config file
            context: Analysis context
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            result = {
                'action_mappings': [],
                'form_beans': [],
                'global_forwards': [],
                'business_rules': [],
                'file_path': str(file_path),
                'xml_structure': self._analyze_xml_structure(root)
            }
            
            # Extract action mappings
            action_mappings = self._extract_action_mappings(root, file_path)
            result['action_mappings'] = [mapping.to_dict() for mapping in action_mappings]
            
            # Extract form beans
            form_beans = self._extract_form_beans(root, file_path)
            result['form_beans'] = [form.to_dict() for form in form_beans]
            
            # Extract global forwards
            global_forwards = self._extract_global_forwards(root)
            result['global_forwards'] = [forward.to_dict() for forward in global_forwards]
            
            # Extract business rules from configuration patterns
            business_rules = self._extract_business_rules(
                root, file_path, action_mappings, form_beans
            )
            result['business_rules'] = [rule.to_dict() for rule in business_rules]
            
            # Calculate overall complexity
            result['complexity_metrics'] = self._calculate_complexity_metrics(
                action_mappings, form_beans, global_forwards
            )
            
            # Generate migration recommendations
            result['migration_recommendations'] = self._generate_migration_recommendations(
                action_mappings, form_beans
            )
            
            return result
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error in {file_path}: {e}")
            return {
                'error': f"XML parsing failed: {e}",
                'file_path': str(file_path),
                'action_mappings': [],
                'form_beans': [],
                'global_forwards': [],
                'business_rules': []
            }
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            return {
                'error': f"Analysis failed: {e}",
                'file_path': str(file_path),
                'action_mappings': [],
                'form_beans': [],
                'global_forwards': [],
                'business_rules': []
            }
    
    def _analyze_xml_structure(self, root: ET.Element) -> Dict[str, Any]:
        """Analyze the XML structure for insights."""
        structure = {
            'root_element': root.tag,
            'namespace': root.get('xmlns', ''),
            'element_counts': {},
            'has_dtd': False,
            'struts_version_indicators': []
        }
        
        # Count different element types
        for elem in root.iter():
            tag = elem.tag
            structure['element_counts'][tag] = structure['element_counts'].get(tag, 0) + 1
        
        # Check for version indicators
        if 'action-mappings' in structure['element_counts']:
            structure['struts_version_indicators'].append('Struts 1.x style')
        if 'package' in structure['element_counts']:
            structure['struts_version_indicators'].append('Struts 2.x style')
        
        return structure
    
    def _extract_action_mappings(self, root: ET.Element, file_path: Path) -> List[ActionMapping]:
        """Extract action mappings from configuration."""
        actions = []
        
        # Handle both Struts 1.x and 2.x style configurations
        action_elements = (
            root.findall('.//action') +  # Struts 1.x
            root.findall('.//action-mapping')  # Alternative format
        )
        
        for action_elem in action_elements:
            try:
                action_mapping = ActionMapping(
                    path=action_elem.get('path', ''),
                    name=action_elem.get('name', ''),
                    action_class=action_elem.get('type', action_elem.get('class', '')),
                    form_bean=action_elem.get('name'),
                    config_file=str(file_path),
                    line_number=getattr(action_elem, 'sourceline', 0)
                )
                
                # Extract forwards
                for forward in action_elem.findall('forward'):
                    name = forward.get('name', '')
                    path = forward.get('path', '')
                    if name and path:
                        action_mapping.forwards[name] = path
                
                # Extract exceptions
                for exception in action_elem.findall('exception'):
                    key = exception.get('key', exception.get('type', ''))
                    path = exception.get('path', '')
                    if key and path:
                        action_mapping.exceptions[key] = path
                
                # Infer business purpose and context
                action_mapping.business_purpose = self._infer_business_purpose(action_mapping)
                action_mapping.user_journey_step = self._infer_user_journey_step(action_mapping)
                
                # Calculate complexity
                action_mapping.complexity_score = self._calculate_action_complexity(action_mapping)
                
                # Generate migration recommendations
                action_mapping.migration_recommendations = self._generate_action_migration_recommendations(action_mapping)
                
                actions.append(action_mapping)
                
            except Exception as e:
                logger.warning(f"Error parsing action mapping: {e}")
        
        return actions
    
    def _extract_form_beans(self, root: ET.Element, file_path: Path) -> List[FormBean]:
        """Extract form bean definitions."""
        forms = []
        
        form_elements = root.findall('.//form-bean')
        
        for form_elem in form_elements:
            try:
                form_bean = FormBean(
                    name=form_elem.get('name', ''),
                    type=form_elem.get('type', ''),
                    file_path=str(file_path)
                )
                
                # Extract form properties if available
                for prop in form_elem.findall('form-property'):
                    prop_name = prop.get('name', '')
                    if prop_name:
                        form_bean.fields.append(prop_name)
                
                # Infer business purpose
                form_bean.business_purpose = self._infer_form_purpose(form_bean)
                
                # Identify data binding patterns
                form_bean.data_binding_patterns = self._identify_data_binding_patterns(form_bean)
                
                # Suggest migration target
                form_bean.migration_target = self._suggest_migration_target(form_bean)
                
                forms.append(form_bean)
                
            except Exception as e:
                logger.warning(f"Error parsing form bean: {e}")
        
        return forms
    
    def _extract_global_forwards(self, root: ET.Element) -> List[GlobalForward]:
        """Extract global forward mappings."""
        forwards = []
        
        forward_elements = root.findall('.//global-forwards/forward')
        
        for forward_elem in forward_elements:
            try:
                forward = GlobalForward(
                    name=forward_elem.get('name', ''),
                    path=forward_elem.get('path', ''),
                    redirect=forward_elem.get('redirect', 'false').lower() == 'true'
                )
                
                # Infer business context
                forward.business_context = self._infer_forward_business_context(forward)
                
                forwards.append(forward)
                
            except Exception as e:
                logger.warning(f"Error parsing global forward: {e}")
        
        return forwards
    
    def _extract_business_rules(self, root: ET.Element, file_path: Path,
                              action_mappings: List[ActionMapping],
                              form_beans: List[FormBean]) -> List[BusinessRule]:
        """Extract business rules from configuration patterns."""
        business_rules = []
        
        # Rule 1: Action paths indicate business processes
        for action in action_mappings:
            if action.path:
                rule = BusinessRule(
                    id=f"action_path_{hashlib.md5(action.path.encode()).hexdigest()[:8]}",
                    name=f"Business Process: {action.path}",
                    description=f"Business process accessible via action path {action.path}",
                    rule_type=BusinessRuleType.WORKFLOW,
                    source=BusinessRuleSource.STRUTS_CONFIG,
                    location=BusinessRuleLocation(
                        file_path=str(file_path),
                        line_number=action.line_number,
                        element_xpath=f"//action[@path='{action.path}']"
                    ),
                    evidence=BusinessRuleEvidence(
                        code_snippet=f"<action path=\"{action.path}\" type=\"{action.action_class}\"/>",
                        context=f"Action mapping in {file_path.name}",
                        confidence_score=0.8
                    ),
                    business_context=action.business_purpose,
                    business_rationale=f"User interaction flow defined by action path {action.path}"
                )
                
                # Add dependencies
                if action.form_bean:
                    rule.add_dependency(f"form_bean_{action.form_bean}")
                
                for forward_name in action.forwards.keys():
                    rule.add_dependency(f"forward_{forward_name}")
                
                business_rules.append(rule)
        
        # Rule 2: Form validation requirements
        for form in form_beans:
            if form.name:
                rule = BusinessRule(
                    id=f"form_validation_{hashlib.md5(form.name.encode()).hexdigest()[:8]}",
                    name=f"Form Validation: {form.name}",
                    description=f"Data validation requirements for form {form.name}",
                    rule_type=BusinessRuleType.VALIDATION,
                    source=BusinessRuleSource.STRUTS_CONFIG,
                    location=BusinessRuleLocation(
                        file_path=str(file_path),
                        element_xpath=f"//form-bean[@name='{form.name}']"
                    ),
                    evidence=BusinessRuleEvidence(
                        code_snippet=f"<form-bean name=\"{form.name}\" type=\"{form.type}\"/>",
                        context=f"Form bean definition in {file_path.name}",
                        confidence_score=0.9
                    ),
                    business_context=form.business_purpose,
                    business_rationale=f"Data integrity requirements for {form.business_purpose}"
                )
                
                business_rules.append(rule)
        
        # Rule 3: Exception handling patterns
        exception_mappings = {}
        for action in action_mappings:
            for exception_key, exception_path in action.exceptions.items():
                if exception_key not in exception_mappings:
                    exception_mappings[exception_key] = []
                exception_mappings[exception_key].append((action, exception_path))
        
        for exception_key, mappings in exception_mappings.items():
            rule = BusinessRule(
                id=f"exception_handling_{hashlib.md5(exception_key.encode()).hexdigest()[:8]}",
                name=f"Exception Handling: {exception_key}",
                description=f"Error handling pattern for {exception_key}",
                rule_type=BusinessRuleType.SECURITY,
                source=BusinessRuleSource.STRUTS_CONFIG,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    element_xpath=f"//exception[@key='{exception_key}']"
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"Exception handling for {exception_key}",
                    context=f"Used in {len(mappings)} action(s)",
                    confidence_score=0.7
                ),
                business_context="Error handling and user experience",
                business_rationale=f"Ensures proper error handling for {exception_key} scenarios"
            )
            
            business_rules.append(rule)
        
        return business_rules
    
    def _infer_business_purpose(self, action: ActionMapping) -> str:
        """Infer business purpose from action mapping details."""
        path_lower = action.path.lower()
        class_lower = action.action_class.lower()
        
        # Check against business patterns
        for purpose, patterns in self._business_patterns.items():
            if any(pattern in path_lower or pattern in class_lower for pattern in patterns):
                return purpose.replace('_', ' ').title()
        
        # Default inference based on common patterns
        if any(keyword in path_lower for keyword in ['save', 'create', 'add']):
            return "Data Creation"
        elif any(keyword in path_lower for keyword in ['edit', 'update', 'modify']):
            return "Data Modification"
        elif any(keyword in path_lower for keyword in ['delete', 'remove']):
            return "Data Deletion"
        elif any(keyword in path_lower for keyword in ['view', 'show', 'display']):
            return "Data Display"
        else:
            return "Business Process"
    
    def _infer_user_journey_step(self, action: ActionMapping) -> str:
        """Infer where this action fits in the user journey."""
        path_lower = action.path.lower()
        
        if 'login' in path_lower or 'auth' in path_lower:
            return "Authentication Entry Point"
        elif 'search' in path_lower or 'list' in path_lower:
            return "Information Discovery"
        elif 'create' in path_lower or 'new' in path_lower:
            return "Content Creation"
        elif 'edit' in path_lower or 'update' in path_lower:
            return "Content Modification"
        elif 'confirm' in path_lower or 'submit' in path_lower:
            return "Action Confirmation"
        elif 'success' in path_lower or 'complete' in path_lower:
            return "Process Completion"
        elif 'error' in path_lower or 'fail' in path_lower:
            return "Error Handling"
        else:
            return "Process Step"
    
    def _infer_form_purpose(self, form: FormBean) -> str:
        """Infer business purpose from form bean details."""
        name_lower = form.name.lower()
        type_lower = form.type.lower()
        
        purpose_patterns = {
            'User Authentication': ['login', 'auth', 'signin'],
            'User Registration': ['signup', 'register', 'registration'],
            'Search and Filter': ['search', 'filter', 'query'],
            'User Profile Management': ['profile', 'user', 'account'],
            'Product Management': ['product', 'item', 'catalog'],
            'Order Processing': ['order', 'purchase', 'checkout'],
            'Content Management': ['content', 'article', 'post'],
            'Administrative': ['admin', 'config', 'settings']
        }
        
        for purpose, patterns in purpose_patterns.items():
            if any(pattern in name_lower or pattern in type_lower for pattern in patterns):
                return purpose
        
        return "Data Entry Form"
    
    def _identify_data_binding_patterns(self, form: FormBean) -> List[str]:
        """Identify data binding patterns for the form."""
        patterns = []
        
        # Check form type for common patterns
        if 'dynaactionform' in form.type.lower():
            patterns.append("Dynamic Form Bean")
        elif 'actionform' in form.type.lower():
            patterns.append("Traditional Action Form")
        elif 'validatorform' in form.type.lower():
            patterns.append("Validator Form Bean")
        
        # Check field patterns
        if form.fields:
            if any('id' in field.lower() for field in form.fields):
                patterns.append("Entity Identifier Binding")
            if any('email' in field.lower() for field in form.fields):
                patterns.append("Email Validation Pattern")
            if any('date' in field.lower() for field in form.fields):
                patterns.append("Date/Time Binding")
        
        return patterns
    
    def _suggest_migration_target(self, form: FormBean) -> str:
        """Suggest migration target for the form."""
        name_lower = form.name.lower()
        
        if 'search' in name_lower or 'filter' in name_lower:
            return "GraphQL Query Variables / Angular Reactive Form"
        elif 'create' in name_lower or 'add' in name_lower:
            return "GraphQL CreateInput Type / Angular Form"
        elif 'edit' in name_lower or 'update' in name_lower:
            return "GraphQL UpdateInput Type / Angular Form"
        else:
            return "GraphQL Input Type / Angular Reactive Form"
    
    def _infer_forward_business_context(self, forward: GlobalForward) -> str:
        """Infer business context for global forward."""
        name_lower = forward.name.lower()
        path_lower = forward.path.lower()
        
        if 'error' in name_lower or 'error' in path_lower:
            return "Error handling and user feedback"
        elif 'login' in name_lower or 'login' in path_lower:
            return "Authentication flow"
        elif 'home' in name_lower or 'index' in path_lower:
            return "Application entry point"
        elif 'success' in name_lower:
            return "Success confirmation"
        else:
            return "Navigation flow"
    
    def _calculate_action_complexity(self, action: ActionMapping) -> int:
        """Calculate complexity score for an action."""
        score = 1  # Base complexity
        
        # Add complexity for forwards
        score += len(action.forwards) * 2
        
        # Add complexity for exceptions
        score += len(action.exceptions) * 3
        
        # Add complexity for form bean
        if action.form_bean:
            score += 3
        
        # Add complexity for business logic indicators
        if action.action_class and 'base' not in action.action_class.lower():
            score += 2
        
        return score
    
    def _generate_action_migration_recommendations(self, action: ActionMapping) -> List[str]:
        """Generate migration recommendations for an action."""
        recommendations = []
        
        # Basic recommendation
        recommendations.append(f"Map {action.path} to GraphQL resolver or REST endpoint")
        
        # Form handling
        if action.form_bean:
            recommendations.append(f"Convert form bean {action.form_bean} to GraphQL input type")
        
        # Forwards handling
        if len(action.forwards) > 3:
            recommendations.append("Consider consolidating multiple forwards into single endpoint with status codes")
        
        # Exception handling
        if action.exceptions:
            recommendations.append("Implement GraphQL error handling or HTTP status codes for exceptions")
        
        # Business logic
        if action.business_purpose != "Business Process":
            recommendations.append(f"Preserve {action.business_purpose} logic in new architecture")
        
        return recommendations
    
    def _calculate_complexity_metrics(self, action_mappings: List[ActionMapping],
                                    form_beans: List[FormBean],
                                    global_forwards: List[GlobalForward]) -> Dict[str, Any]:
        """Calculate overall complexity metrics."""
        return {
            'total_actions': len(action_mappings),
            'total_forms': len(form_beans),
            'total_forwards': len(global_forwards),
            'avg_action_complexity': sum(a.complexity_score for a in action_mappings) / len(action_mappings) if action_mappings else 0,
            'max_action_complexity': max((a.complexity_score for a in action_mappings), default=0),
            'complex_actions_count': sum(1 for a in action_mappings if a.complexity_score > 10),
            'total_exception_mappings': sum(len(a.exceptions) for a in action_mappings),
            'total_forward_mappings': sum(len(a.forwards) for a in action_mappings)
        }
    
    def _generate_migration_recommendations(self, action_mappings: List[ActionMapping],
                                          form_beans: List[FormBean]) -> List[str]:
        """Generate overall migration recommendations."""
        recommendations = []
        
        total_actions = len(action_mappings)
        total_forms = len(form_beans)
        complex_actions = sum(1 for a in action_mappings if a.complexity_score > 10)
        
        # General recommendations
        recommendations.append(f"Migrate {total_actions} action mappings to GraphQL resolvers or REST endpoints")
        
        if total_forms > 0:
            recommendations.append(f"Convert {total_forms} form beans to GraphQL input types and Angular reactive forms")
        
        if complex_actions > 0:
            recommendations.append(f"Pay special attention to {complex_actions} complex actions requiring detailed analysis")
        
        # Specific patterns
        auth_actions = [a for a in action_mappings if 'auth' in a.business_purpose.lower()]
        if auth_actions:
            recommendations.append("Implement modern authentication (JWT, OAuth2) for authentication actions")
        
        crud_actions = [a for a in action_mappings if any(op in a.business_purpose.lower() 
                       for op in ['create', 'read', 'update', 'delete'])]
        if crud_actions:
            recommendations.append(f"Standardize {len(crud_actions)} CRUD operations using GraphQL mutations/queries")
        
        return recommendations
    
    def _post_process_results(self, results: List[Dict[str, Any]], 
                            context: AnalysisContext) -> Dict[str, Any]:
        """
        Post-process and aggregate results from all configuration files.
        
        Args:
            results: List of individual file analysis results
            context: Analysis context
            
        Returns:
            Aggregated and processed results
        """
        if not results:
            return {
                'action_mappings': [],
                'form_beans': [],
                'global_forwards': [],
                'business_rules': [],
                'summary': {
                    'total_config_files': 0,
                    'total_actions': 0,
                    'total_forms': 0,
                    'total_forwards': 0,
                    'total_business_rules': 0
                }
            }
        
        # Aggregate all results
        all_action_mappings = []
        all_form_beans = []
        all_global_forwards = []
        all_business_rules = []
        all_migration_recommendations = []
        
        for result in results:
            if 'error' not in result:
                all_action_mappings.extend(result.get('action_mappings', []))
                all_form_beans.extend(result.get('form_beans', []))
                all_global_forwards.extend(result.get('global_forwards', []))
                all_business_rules.extend(result.get('business_rules', []))
                all_migration_recommendations.extend(result.get('migration_recommendations', []))
        
        # Calculate cross-file relationships
        relationships = self._analyze_cross_file_relationships(
            all_action_mappings, all_form_beans, all_global_forwards
        )
        
        # Generate comprehensive migration plan
        migration_plan = self._generate_comprehensive_migration_plan(
            all_action_mappings, all_form_beans, relationships
        )
        
        return {
            'action_mappings': all_action_mappings,
            'form_beans': all_form_beans,
            'global_forwards': all_global_forwards,
            'business_rules': all_business_rules,
            'relationships': relationships,
            'migration_plan': migration_plan,
            'migration_recommendations': list(set(all_migration_recommendations)),
            'summary': {
                'total_config_files': len(results),
                'total_actions': len(all_action_mappings),
                'total_forms': len(all_form_beans),
                'total_forwards': len(all_global_forwards),
                'total_business_rules': len(all_business_rules),
                'average_action_complexity': sum(a.get('complexity_score', 0) for a in all_action_mappings) / len(all_action_mappings) if all_action_mappings else 0,
                'high_complexity_actions': sum(1 for a in all_action_mappings if a.get('complexity_score', 0) > 10)
            }
        }
    
    def _analyze_cross_file_relationships(self, action_mappings: List[Dict[str, Any]],
                                        form_beans: List[Dict[str, Any]],
                                        global_forwards: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze relationships between different configuration elements."""
        relationships = {
            'action_form_mappings': [],
            'forward_usage': {},
            'form_usage': {},
            'orphaned_forms': [],
            'orphaned_forwards': []
        }
        
        # Track form usage
        used_forms = set()
        for action in action_mappings:
            if action.get('form_bean'):
                form_name = action['form_bean']
                used_forms.add(form_name)
                relationships['action_form_mappings'].append({
                    'action_path': action['path'],
                    'form_name': form_name
                })
                
                if form_name not in relationships['form_usage']:
                    relationships['form_usage'][form_name] = []
                relationships['form_usage'][form_name].append(action['path'])
        
        # Track forward usage
        used_forwards = set()
        for action in action_mappings:
            for forward_name in action.get('forwards', {}).keys():
                used_forwards.add(forward_name)
                if forward_name not in relationships['forward_usage']:
                    relationships['forward_usage'][forward_name] = []
                relationships['forward_usage'][forward_name].append(action['path'])
        
        # Find orphaned elements
        all_forms = {form['name'] for form in form_beans}
        all_forwards = {forward['name'] for forward in global_forwards}
        
        relationships['orphaned_forms'] = list(all_forms - used_forms)
        relationships['orphaned_forwards'] = list(all_forwards - used_forwards)
        
        return relationships
    
    def _generate_comprehensive_migration_plan(self, action_mappings: List[Dict[str, Any]],
                                             form_beans: List[Dict[str, Any]],
                                             relationships: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive migration plan."""
        plan = {
            'phases': [],
            'estimated_effort_hours': 0,
            'risk_assessment': 'medium',
            'prerequisites': [],
            'success_criteria': []
        }
        
        # Phase 1: Foundation
        phase1 = {
            'name': 'Foundation Setup',
            'description': 'Set up new architecture foundation',
            'tasks': [
                'Set up GraphQL server with Apollo/Express',
                'Configure Angular project with routing',
                'Implement authentication system',
                'Set up database connections'
            ],
            'estimated_hours': 40,
            'dependencies': []
        }
        
        # Phase 2: Core Entities
        phase2 = {
            'name': 'Core Entity Migration',
            'description': 'Migrate form beans to GraphQL types and Angular forms',
            'tasks': [
                f'Convert {len(form_beans)} form beans to GraphQL input types',
                'Create corresponding Angular reactive forms',
                'Implement form validation logic',
                'Set up data binding patterns'
            ],
            'estimated_hours': len(form_beans) * 4,
            'dependencies': ['Foundation Setup']
        }
        
        # Phase 3: Business Logic
        simple_actions = [a for a in action_mappings if a.get('complexity_score', 0) <= 5]
        complex_actions = [a for a in action_mappings if a.get('complexity_score', 0) > 5]
        
        phase3 = {
            'name': 'Business Logic Migration',
            'description': 'Migrate action mappings to GraphQL resolvers',
            'tasks': [
                f'Migrate {len(simple_actions)} simple actions',
                f'Migrate {len(complex_actions)} complex actions',
                'Implement error handling',
                'Add business rule validation'
            ],
            'estimated_hours': len(simple_actions) * 3 + len(complex_actions) * 8,
            'dependencies': ['Core Entity Migration']
        }
        
        # Phase 4: Integration and Testing
        phase4 = {
            'name': 'Integration and Testing',
            'description': 'Integration testing and optimization',
            'tasks': [
                'End-to-end testing',
                'Performance optimization',
                'Security validation',
                'User acceptance testing'
            ],
            'estimated_hours': 60,
            'dependencies': ['Business Logic Migration']
        }
        
        plan['phases'] = [phase1, phase2, phase3, phase4]
        plan['estimated_effort_hours'] = sum(phase['estimated_hours'] for phase in plan['phases'])
        
        # Risk assessment
        high_complexity_count = len(complex_actions)
        if high_complexity_count > 10:
            plan['risk_assessment'] = 'high'
        elif high_complexity_count > 5:
            plan['risk_assessment'] = 'medium'
        else:
            plan['risk_assessment'] = 'low'
        
        # Prerequisites
        plan['prerequisites'] = [
            'GraphQL and Angular development expertise',
            'Understanding of existing business processes',
            'Database migration strategy',
            'Testing environment setup'
        ]
        
        # Success criteria
        plan['success_criteria'] = [
            'All business functionality preserved',
            'Performance equal or better than legacy system',
            'All validation rules implemented',
            'User experience improved',
            'Code maintainability increased'
        ]
        
        return plan