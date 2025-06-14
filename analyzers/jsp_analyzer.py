import sys
sys.path.append('..')

"""
JSP Analyzer
============

This module provides analysis capabilities for JSP (JavaServer Pages) files in Struts applications.
It extracts UI business rules, conditional logic, form bindings, and navigation patterns while
identifying modernization opportunities for Angular/React migration.

Features:
- JSP tag library analysis (Struts, JSTL, custom tags)
- UI business rule extraction from conditional logic
- Form binding and validation pattern analysis
- Navigation flow and user journey mapping
- Accessibility and usability assessment
- Modern UI framework migration recommendations

Author: Claude Code Assistant
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
import hashlib

from analyzers.base_analyzer import BaseAnalyzer, AnalysisContext
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource, 
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)
from utils.logging_utils import get_logger
from utils.performance_utils import performance_timer


logger = get_logger(__name__)


@dataclass
class JSPElement:
    """Represents a JSP element with its properties."""
    tag_type: str
    tag_name: str
    attributes: Dict[str, str] = field(default_factory=dict)
    content: str = ""
    line_number: int = 0
    business_purpose: str = ""
    accessibility_issues: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'tag_type': self.tag_type,
            'tag_name': self.tag_name,
            'attributes': self.attributes,
            'content': self.content,
            'line_number': self.line_number,
            'business_purpose': self.business_purpose,
            'accessibility_issues': self.accessibility_issues
        }


@dataclass
class FormAnalysis:
    """Analysis of form elements and validation patterns."""
    form_name: str
    action: str
    method: str = "POST"
    form_elements: List[JSPElement] = field(default_factory=list)
    validation_patterns: List[str] = field(default_factory=list)
    business_workflow: str = ""
    data_binding_analysis: Dict[str, Any] = field(default_factory=dict)
    angular_equivalent: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'form_name': self.form_name,
            'action': self.action,
            'method': self.method,
            'form_elements': [elem.to_dict() for elem in self.form_elements],
            'validation_patterns': self.validation_patterns,
            'business_workflow': self.business_workflow,
            'data_binding_analysis': self.data_binding_analysis,
            'angular_equivalent': self.angular_equivalent
        }


@dataclass
class ConditionalLogic:
    """Analysis of conditional logic in JSP."""
    condition_type: str  # c:if, c:when, c:choose, scriptlet
    condition_expression: str
    content_summary: str
    business_rule_implication: str
    line_number: int = 0
    complexity_score: int = 1
    migration_recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'condition_type': self.condition_type,
            'condition_expression': self.condition_expression,
            'content_summary': self.content_summary,
            'business_rule_implication': self.business_rule_implication,
            'line_number': self.line_number,
            'complexity_score': self.complexity_score,
            'migration_recommendation': self.migration_recommendation
        }


@dataclass
class NavigationElement:
    """Analysis of navigation elements."""
    element_type: str  # link, forward, redirect, menu
    target: str
    label: str = ""
    conditions: List[str] = field(default_factory=list)
    user_role_restrictions: List[str] = field(default_factory=list)
    business_context: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'element_type': self.element_type,
            'target': self.target,
            'label': self.label,
            'conditions': self.conditions,
            'user_role_restrictions': self.user_role_restrictions,
            'business_context': self.business_context
        }


@dataclass
class JSPAnalysisResult:
    """Comprehensive JSP analysis results."""
    file_path: str
    jsp_type: str  # page, fragment, error_page, include
    forms: List[FormAnalysis] = field(default_factory=list)
    conditional_logic: List[ConditionalLogic] = field(default_factory=list)
    navigation_elements: List[NavigationElement] = field(default_factory=list)
    business_rules: List[BusinessRule] = field(default_factory=list)
    ui_patterns: List[str] = field(default_factory=list)
    accessibility_assessment: Dict[str, Any] = field(default_factory=dict)
    modernization_assessment: Dict[str, Any] = field(default_factory=dict)
    security_concerns: List[str] = field(default_factory=list)
    performance_concerns: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'file_path': self.file_path,
            'jsp_type': self.jsp_type,
            'forms': [form.to_dict() for form in self.forms],
            'conditional_logic': [logic.to_dict() for logic in self.conditional_logic],
            'navigation_elements': [nav.to_dict() for nav in self.navigation_elements],
            'business_rules': [rule.to_dict() for rule in self.business_rules],
            'ui_patterns': self.ui_patterns,
            'accessibility_assessment': self.accessibility_assessment,
            'modernization_assessment': self.modernization_assessment,
            'security_concerns': self.security_concerns,
            'performance_concerns': self.performance_concerns
        }


class StrutsTagLibraryAnalyzer:
    """Specialized analyzer for Struts tag libraries."""
    
    def __init__(self):
        """Initialize Struts tag library patterns."""
        self.struts_tags = {
            'html:form': {'purpose': 'Form container', 'angular_equivalent': 'Angular Reactive Form'},
            'html:text': {'purpose': 'Text input', 'angular_equivalent': 'input[type="text"] with formControlName'},
            'html:password': {'purpose': 'Password input', 'angular_equivalent': 'input[type="password"] with formControlName'},
            'html:select': {'purpose': 'Dropdown selection', 'angular_equivalent': 'select with formControlName'},
            'html:option': {'purpose': 'Select option', 'angular_equivalent': 'option element'},
            'html:checkbox': {'purpose': 'Checkbox input', 'angular_equivalent': 'input[type="checkbox"] with formControlName'},
            'html:radio': {'purpose': 'Radio button', 'angular_equivalent': 'input[type="radio"] with formControlName'},
            'html:submit': {'purpose': 'Form submission', 'angular_equivalent': 'button[type="submit"]'},
            'html:link': {'purpose': 'Navigation link', 'angular_equivalent': 'Angular Router Link'},
            'html:rewrite': {'purpose': 'URL rewriting', 'angular_equivalent': 'Angular Router with parameters'},
            'logic:if': {'purpose': 'Conditional display', 'angular_equivalent': '*ngIf directive'},
            'logic:equal': {'purpose': 'Equality condition', 'angular_equivalent': '*ngIf with comparison'},
            'logic:notEqual': {'purpose': 'Inequality condition', 'angular_equivalent': '*ngIf with negation'},
            'logic:iterate': {'purpose': 'Loop iteration', 'angular_equivalent': '*ngFor directive'},
            'bean:write': {'purpose': 'Property display', 'angular_equivalent': 'Interpolation {{ }}'},
            'bean:message': {'purpose': 'Internationalization', 'angular_equivalent': 'Angular i18n pipe'}
        }
        
        self.jstl_tags = {
            'c:if': {'purpose': 'Conditional rendering', 'angular_equivalent': '*ngIf directive'},
            'c:when': {'purpose': 'Switch case condition', 'angular_equivalent': '*ngIf with conditions'},
            'c:choose': {'purpose': 'Switch statement', 'angular_equivalent': '*ngSwitch directive'},
            'c:otherwise': {'purpose': 'Default case', 'angular_equivalent': '*ngSwitchDefault'},
            'c:forEach': {'purpose': 'List iteration', 'angular_equivalent': '*ngFor directive'},
            'c:set': {'purpose': 'Variable assignment', 'angular_equivalent': 'Component property'},
            'c:out': {'purpose': 'Output expression', 'angular_equivalent': 'Interpolation {{ }}'},
            'fmt:message': {'purpose': 'Message formatting', 'angular_equivalent': 'Angular i18n'},
            'fmt:formatDate': {'purpose': 'Date formatting', 'angular_equivalent': 'DatePipe'},
            'fmt:formatNumber': {'purpose': 'Number formatting', 'angular_equivalent': 'NumberPipe'}
        }
    
    def analyze_tag(self, tag_name: str, attributes: Dict[str, str]) -> Dict[str, Any]:
        """Analyze a specific Struts or JSTL tag."""
        analysis = {
            'tag_name': tag_name,
            'is_struts_tag': tag_name in self.struts_tags,
            'is_jstl_tag': tag_name in self.jstl_tags,
            'purpose': '',
            'angular_equivalent': '',
            'business_impact': 'low',
            'migration_complexity': 'simple'
        }
        
        if tag_name in self.struts_tags:
            tag_info = self.struts_tags[tag_name]
            analysis['purpose'] = tag_info['purpose']
            analysis['angular_equivalent'] = tag_info['angular_equivalent']
            analysis['business_impact'] = 'medium'
        elif tag_name in self.jstl_tags:
            tag_info = self.jstl_tags[tag_name]
            analysis['purpose'] = tag_info['purpose']
            analysis['angular_equivalent'] = tag_info['angular_equivalent']
            analysis['business_impact'] = 'medium'
        
        # Assess complexity based on attributes
        if 'property' in attributes or 'name' in attributes:
            analysis['migration_complexity'] = 'moderate'
        
        if 'test' in attributes or 'value' in attributes:
            analysis['migration_complexity'] = 'moderate'
        
        return analysis


class JSPParser(HTMLParser):
    """Custom HTML parser for JSP content."""
    
    def __init__(self):
        super().__init__()
        self.elements = []
        self.current_line = 1
        self.in_script = False
        self.in_style = False
        
    def handle_starttag(self, tag, attrs):
        """Handle start tags."""
        attributes = dict(attrs)
        element = JSPElement(
            tag_type='start_tag',
            tag_name=tag,
            attributes=attributes,
            line_number=self.current_line
        )
        self.elements.append(element)
        
        if tag.lower() == 'script':
            self.in_script = True
        elif tag.lower() == 'style':
            self.in_style = True
    
    def handle_endtag(self, tag):
        """Handle end tags."""
        if tag.lower() == 'script':
            self.in_script = False
        elif tag.lower() == 'style':
            self.in_style = False
    
    def handle_data(self, data):
        """Handle text data."""
        if data.strip() and not self.in_script and not self.in_style:
            self.current_line += data.count('\n')
    
    def error(self, message):
        """Handle parsing errors."""
        logger.warning(f"JSP parsing error: {message}")


class JSPAnalyzer(BaseAnalyzer):
    """
    Analyzer for JSP files in Struts applications.
    
    Provides comprehensive analysis of JSP files including UI business rules,
    form patterns, navigation flows, and modernization recommendations.
    """
    
    def _initialize_analyzer(self) -> None:
        """Initialize JSP analyzer settings."""
        self._supported_extensions = {'.jsp', '.jspx', '.jspf'}
        self._required_patterns = []
        
        # Initialize tag library analyzer
        self.tag_analyzer = StrutsTagLibraryAnalyzer()
        
        # Business logic patterns in JSP
        self._business_patterns = {
            'authentication': ['login', 'logout', 'signin', 'user', 'auth'],
            'authorization': ['role', 'permission', 'access', 'allowed'],
            'validation': ['error', 'valid', 'required', 'check'],
            'workflow': ['step', 'wizard', 'process', 'next', 'previous'],
            'data_display': ['list', 'table', 'grid', 'display', 'show'],
            'data_entry': ['form', 'input', 'create', 'edit', 'update'],
            'navigation': ['menu', 'link', 'breadcrumb', 'tab'],
            'reporting': ['report', 'export', 'print', 'download']
        }
        
        # UI patterns
        self._ui_patterns = {
            'master_detail': ['master', 'detail', 'list', 'item'],
            'wizard': ['wizard', 'step', 'next', 'previous'],
            'dashboard': ['dashboard', 'summary', 'overview'],
            'crud_interface': ['create', 'read', 'update', 'delete', 'edit'],
            'search_results': ['search', 'results', 'filter', 'sort'],
            'data_table': ['table', 'grid', 'pagination', 'sort'],
            'form_validation': ['validate', 'error', 'message', 'required']
        }
        
        # Accessibility patterns
        self._accessibility_patterns = {
            'missing_alt': r'<img(?![^>]*alt=)',
            'missing_label': r'<input(?![^>]*(?:aria-label|id=))',
            'missing_title': r'<a(?![^>]*title=)',
            'missing_heading_structure': r'<h[1-6]',
            'inline_styles': r'style=',
            'javascript_links': r'href="javascript:'
        }
    
    def can_analyze(self, file_path: Path) -> bool:
        """
        Check if this is a JSP file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if this is a JSP file
        """
        return file_path.suffix.lower() in self._supported_extensions
    
    @performance_timer("jsp_analysis")
    def _analyze_file(self, file_path: Path, context: AnalysisContext) -> Dict[str, Any]:
        """
        Analyze a single JSP file.
        
        Args:
            file_path: Path to JSP file
            context: Analysis context
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Create analysis result
            analysis = JSPAnalysisResult(
                file_path=str(file_path),
                jsp_type=self._determine_jsp_type(content, file_path)
            )
            
            # Parse JSP content
            self._parse_jsp_content(content, analysis)
            
            # Extract forms
            analysis.forms = self._extract_forms(content, file_path)
            
            # Extract conditional logic
            analysis.conditional_logic = self._extract_conditional_logic(content)
            
            # Extract navigation elements
            analysis.navigation_elements = self._extract_navigation_elements(content)
            
            # Extract business rules
            analysis.business_rules = self._extract_business_rules(content, file_path, analysis)
            
            # Identify UI patterns
            analysis.ui_patterns = self._identify_ui_patterns(content, analysis)
            
            # Assess accessibility
            analysis.accessibility_assessment = self._assess_accessibility(content)
            
            # Generate modernization assessment
            analysis.modernization_assessment = self._generate_modernization_assessment(analysis)
            
            # Identify security concerns
            analysis.security_concerns = self._identify_security_concerns(content)
            
            # Identify performance concerns
            analysis.performance_concerns = self._identify_performance_concerns(content)
            
            return {
                'jsp_analysis': analysis.to_dict(),
                'file_size_kb': len(content) / 1024,
                'line_count': len(content.split('\n'))
            }
            
        except Exception as e:
            logger.error(f"Error analyzing JSP file {file_path}: {e}")
            return {
                'error': f"Analysis failed: {e}",
                'file_path': str(file_path),
                'jsp_analysis': None
            }
    
    def _determine_jsp_type(self, content: str, file_path: Path) -> str:
        """Determine the type of JSP file."""
        filename = file_path.name.lower()
        
        if 'error' in filename or '<%@ page isErrorPage="true"' in content:
            return 'error_page'
        elif filename.endswith('.jspf') or 'include' in filename:
            return 'fragment'
        elif '<%@ include' in content or '<jsp:include' in content:
            return 'include'
        elif '<%@ page' in content:
            return 'page'
        else:
            return 'page'
    
    def _parse_jsp_content(self, content: str, analysis: JSPAnalysisResult) -> None:
        """Parse JSP content using custom parser."""
        try:
            parser = JSPParser()
            # Remove JSP scriptlets and directives for HTML parsing
            clean_content = self._clean_content_for_parsing(content)
            parser.feed(clean_content)
        except Exception as e:
            logger.warning(f"JSP parsing failed: {e}")
    
    def _clean_content_for_parsing(self, content: str) -> str:
        """Clean JSP content for HTML parsing."""
        # Remove JSP comments
        content = re.sub(r'<%--.*?--%>', '', content, flags=re.DOTALL)
        
        # Remove JSP scriptlets
        content = re.sub(r'<%.*?%>', '', content, flags=re.DOTALL)
        
        # Remove JSP directives
        content = re.sub(r'<%@.*?%>', '', content, flags=re.DOTALL)
        
        return content
    
    def _extract_forms(self, content: str, file_path: Path) -> List[FormAnalysis]:
        """Extract and analyze form elements."""
        forms = []
        
        # Find Struts forms
        struts_form_pattern = r'<html:form\s+([^>]+)>(.*?)</html:form>'
        struts_matches = re.finditer(struts_form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for match in struts_matches:
            form = self._analyze_struts_form(match, file_path)
            if form:
                forms.append(form)
        
        # Find regular HTML forms
        html_form_pattern = r'<form\s+([^>]+)>(.*?)</form>'
        html_matches = re.finditer(html_form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for match in html_matches:
            form = self._analyze_html_form(match, file_path)
            if form:
                forms.append(form)
        
        return forms
    
    def _analyze_struts_form(self, match: re.Match, file_path: Path) -> Optional[FormAnalysis]:
        """Analyze a Struts form element."""
        attributes_str = match.group(1)
        form_content = match.group(2)
        
        # Parse attributes
        attributes = self._parse_tag_attributes(attributes_str)
        
        form = FormAnalysis(
            form_name=attributes.get('name', ''),
            action=attributes.get('action', ''),
            method=attributes.get('method', 'POST').upper()
        )
        
        # Extract form elements
        form.form_elements = self._extract_form_elements(form_content)
        
        # Analyze validation patterns
        form.validation_patterns = self._extract_validation_patterns(form_content)
        
        # Determine business workflow
        form.business_workflow = self._determine_form_workflow(form, attributes)
        
        # Analyze data binding
        form.data_binding_analysis = self._analyze_data_binding(form_content, attributes)
        
        # Generate Angular equivalent
        form.angular_equivalent = self._generate_angular_form_equivalent(form)
        
        return form
    
    def _analyze_html_form(self, match: re.Match, file_path: Path) -> Optional[FormAnalysis]:
        """Analyze a regular HTML form element."""
        attributes_str = match.group(1)
        form_content = match.group(2)
        
        attributes = self._parse_tag_attributes(attributes_str)
        
        form = FormAnalysis(
            form_name=attributes.get('name', attributes.get('id', '')),
            action=attributes.get('action', ''),
            method=attributes.get('method', 'GET').upper()
        )
        
        form.form_elements = self._extract_form_elements(form_content)
        form.business_workflow = self._determine_form_workflow(form, attributes)
        form.angular_equivalent = self._generate_angular_form_equivalent(form)
        
        return form
    
    def _parse_tag_attributes(self, attr_string: str) -> Dict[str, str]:
        """Parse tag attributes from string."""
        attributes = {}
        attr_pattern = r'(\w+)=(["\'])(.*?)\2'
        matches = re.findall(attr_pattern, attr_string)
        
        for name, quote, value in matches:
            attributes[name] = value
        
        return attributes
    
    def _extract_form_elements(self, form_content: str) -> List[JSPElement]:
        """Extract form elements from form content."""
        elements = []
        
        # Form input patterns
        input_patterns = [
            (r'<html:text\s+([^>]+)/?>', 'struts_text'),
            (r'<html:password\s+([^>]+)/?>', 'struts_password'),
            (r'<html:select\s+([^>]+)>', 'struts_select'),
            (r'<html:checkbox\s+([^>]+)/?>', 'struts_checkbox'),
            (r'<html:radio\s+([^>]+)/?>', 'struts_radio'),
            (r'<html:submit\s+([^>]+)/?>', 'struts_submit'),
            (r'<input\s+([^>]+)/?>', 'html_input'),
            (r'<select\s+([^>]+)>', 'html_select'),
            (r'<textarea\s+([^>]+)>', 'html_textarea')
        ]
        
        for pattern, element_type in input_patterns:
            matches = re.finditer(pattern, form_content, re.IGNORECASE)
            for match in matches:
                attributes = self._parse_tag_attributes(match.group(1))
                
                element = JSPElement(
                    tag_type=element_type,
                    tag_name=element_type.split('_')[1],
                    attributes=attributes
                )
                
                # Determine business purpose
                element.business_purpose = self._determine_element_business_purpose(element)
                
                # Check accessibility
                element.accessibility_issues = self._check_element_accessibility(element)
                
                elements.append(element)
        
        return elements
    
    def _extract_validation_patterns(self, form_content: str) -> List[str]:
        """Extract validation patterns from form content."""
        patterns = []
        
        # Client-side validation patterns
        if 'required' in form_content.lower():
            patterns.append('required_field_validation')
        
        if re.search(r'onsubmit\s*=', form_content, re.IGNORECASE):
            patterns.append('javascript_form_validation')
        
        if 'validate' in form_content.lower():
            patterns.append('custom_validation_function')
        
        # Struts validation patterns
        if '<html:errors' in form_content:
            patterns.append('struts_error_display')
        
        if 'property="' in form_content:
            patterns.append('property_based_validation')
        
        return patterns
    
    def _determine_form_workflow(self, form: FormAnalysis, attributes: Dict[str, str]) -> str:
        """Determine the business workflow of the form."""
        action = form.action.lower()
        form_name = form.form_name.lower()
        
        workflow_patterns = {
            'user_authentication': ['login', 'signin', 'auth'],
            'user_registration': ['register', 'signup', 'create_account'],
            'search_and_filter': ['search', 'filter', 'query'],
            'data_entry': ['create', 'add', 'new'],
            'data_update': ['edit', 'update', 'modify'],
            'order_processing': ['order', 'checkout', 'purchase'],
            'contact_form': ['contact', 'message', 'inquiry'],
            'configuration': ['config', 'settings', 'preferences']
        }
        
        for workflow, keywords in workflow_patterns.items():
            if any(keyword in action or keyword in form_name for keyword in keywords):
                return workflow.replace('_', ' ').title()
        
        return 'General Data Processing'
    
    def _analyze_data_binding(self, form_content: str, attributes: Dict[str, str]) -> Dict[str, Any]:
        """Analyze data binding patterns in the form."""
        analysis = {
            'binding_type': 'unknown',
            'property_mappings': [],
            'bean_references': [],
            'complexity_score': 1
        }
        
        # Check for Struts property binding
        property_matches = re.findall(r'property="([^"]+)"', form_content)
        if property_matches:
            analysis['binding_type'] = 'struts_property_binding'
            analysis['property_mappings'] = property_matches
            analysis['complexity_score'] = len(property_matches)
        
        # Check for bean references
        bean_matches = re.findall(r'name="([^"]+)"', form_content)
        if bean_matches:
            analysis['bean_references'] = bean_matches
        
        # Check for nested properties
        nested_properties = [prop for prop in property_matches if '.' in prop]
        if nested_properties:
            analysis['complexity_score'] += len(nested_properties)
        
        return analysis
    
    def _generate_angular_form_equivalent(self, form: FormAnalysis) -> str:
        """Generate Angular equivalent for the form."""
        if form.business_workflow == 'User Authentication':
            return 'Angular Reactive Form with FormBuilder and Validators'
        elif 'search' in form.business_workflow.lower():
            return 'Angular Search Form with debounceTime and distinctUntilChanged'
        elif any(pattern in form.validation_patterns for pattern in ['required_field_validation', 'custom_validation_function']):
            return 'Angular Reactive Form with custom validators'
        else:
            return 'Angular Reactive Form with FormControl binding'
    
    def _extract_conditional_logic(self, content: str) -> List[ConditionalLogic]:
        """Extract conditional logic from JSP content."""
        conditional_elements = []
        
        # JSTL conditional patterns
        jstl_patterns = [
            (r'<c:if\s+test="([^"]+)"[^>]*>(.*?)</c:if>', 'c:if'),
            (r'<c:when\s+test="([^"]+)"[^>]*>(.*?)</c:when>', 'c:when'),
            (r'<logic:if\s+([^>]+)>(.*?)</logic:if>', 'logic:if'),
            (r'<logic:equal\s+([^>]+)>(.*?)</logic:equal>', 'logic:equal'),
            (r'<logic:notEqual\s+([^>]+)>(.*?)</logic:notEqual>', 'logic:notEqual')
        ]
        
        for pattern, condition_type in jstl_patterns:
            matches = re.finditer(pattern, content, re.DOTALL | re.IGNORECASE)
            for match in matches:
                condition_expr = match.group(1)
                content_block = match.group(2)
                
                logic = ConditionalLogic(
                    condition_type=condition_type,
                    condition_expression=condition_expr,
                    content_summary=self._summarize_content_block(content_block),
                    business_rule_implication=self._analyze_condition_business_implication(condition_expr),
                    complexity_score=self._calculate_condition_complexity(condition_expr),
                    migration_recommendation=self._generate_condition_migration_recommendation(condition_type, condition_expr)
                )
                conditional_elements.append(logic)
        
        # JSP scriptlet conditionals
        scriptlet_pattern = r'<%\s*if\s*\([^)]+\)\s*{[^}]*}?\s*%>'
        scriptlet_matches = re.finditer(scriptlet_pattern, content, re.DOTALL)
        
        for match in scriptlet_matches:
            logic = ConditionalLogic(
                condition_type='scriptlet',
                condition_expression=match.group(0),
                content_summary='JSP scriptlet conditional logic',
                business_rule_implication='Server-side conditional rendering',
                complexity_score=3,
                migration_recommendation='Convert to Angular *ngIf with component logic'
            )
            conditional_elements.append(logic)
        
        return conditional_elements
    
    def _summarize_content_block(self, content: str) -> str:
        """Summarize the content of a conditional block."""
        content = content.strip()
        if len(content) > 100:
            return content[:100] + "..."
        return content
    
    def _analyze_condition_business_implication(self, condition: str) -> str:
        """Analyze the business implication of a condition."""
        condition_lower = condition.lower()
        
        if any(term in condition_lower for term in ['user', 'login', 'auth']):
            return 'User authentication and authorization control'
        elif any(term in condition_lower for term in ['role', 'permission']):
            return 'Role-based access control'
        elif any(term in condition_lower for term in ['error', 'valid']):
            return 'Error handling and validation feedback'
        elif any(term in condition_lower for term in ['empty', 'null']):
            return 'Data presence validation'
        elif any(term in condition_lower for term in ['status', 'state']):
            return 'Business state-dependent display'
        else:
            return 'Conditional business logic implementation'
    
    def _calculate_condition_complexity(self, condition: str) -> int:
        """Calculate complexity score for a condition."""
        complexity = 1
        
        # Logical operators increase complexity
        complexity += condition.count('&&')
        complexity += condition.count('||')
        complexity += condition.count('!')
        
        # Nested conditions
        complexity += condition.count('(')
        
        # Method calls
        complexity += len(re.findall(r'\w+\([^)]*\)', condition))
        
        return complexity
    
    def _generate_condition_migration_recommendation(self, condition_type: str, condition_expr: str) -> str:
        """Generate migration recommendation for conditional logic."""
        if condition_type == 'c:if':
            return f"Convert to Angular *ngIf directive: *ngIf=\"{self._convert_condition_to_angular(condition_expr)}\""
        elif condition_type in ['c:when', 'c:choose']:
            return "Convert to Angular *ngSwitch directive or multiple *ngIf conditions"
        elif condition_type.startswith('logic:'):
            return f"Convert Struts logic tag to Angular *ngIf with component method"
        else:
            return "Refactor scriptlet logic to Angular component methods"
    
    def _convert_condition_to_angular(self, condition: str) -> str:
        """Convert JSP condition to Angular equivalent."""
        # Basic conversion examples
        condition = condition.replace('${', '').replace('}', '')
        condition = condition.replace('empty ', '!')
        condition = condition.replace(' eq ', ' === ')
        condition = condition.replace(' ne ', ' !== ')
        return condition
    
    def _extract_navigation_elements(self, content: str) -> List[NavigationElement]:
        """Extract navigation elements from JSP content."""
        navigation_elements = []
        
        # Navigation patterns
        nav_patterns = [
            (r'<html:link\s+([^>]+)>(.*?)</html:link>', 'struts_link'),
            (r'<a\s+href="([^"]+)"[^>]*>(.*?)</a>', 'html_link'),
            (r'<html:forward\s+([^>]+)/>', 'struts_forward'),
            (r'<html:rewrite\s+([^>]+)/>', 'struts_rewrite')
        ]
        
        for pattern, nav_type in nav_patterns:
            matches = re.finditer(pattern, content, re.DOTALL | re.IGNORECASE)
            for match in matches:
                if nav_type == 'html_link':
                    target = match.group(1)
                    label = match.group(2).strip()
                    conditions = []
                else:
                    attributes = self._parse_tag_attributes(match.group(1))
                    target = attributes.get('action', attributes.get('page', attributes.get('href', '')))
                    label = match.group(2).strip() if len(match.groups()) > 1 else ''
                    conditions = self._extract_navigation_conditions(match.group(0))
                
                nav_element = NavigationElement(
                    element_type=nav_type,
                    target=target,
                    label=label,
                    conditions=conditions,
                    business_context=self._determine_navigation_business_context(target, label)
                )
                navigation_elements.append(nav_element)
        
        return navigation_elements
    
    def _extract_navigation_conditions(self, nav_content: str) -> List[str]:
        """Extract conditions that affect navigation visibility."""
        conditions = []
        
        # Check for surrounding conditional logic
        # This is a simplified approach - in practice, you'd need more sophisticated parsing
        if 'c:if' in nav_content or 'logic:' in nav_content:
            conditions.append('conditional_navigation')
        
        if 'role' in nav_content.lower():
            conditions.append('role_based_navigation')
        
        return conditions
    
    def _determine_navigation_business_context(self, target: str, label: str) -> str:
        """Determine business context of navigation element."""
        target_lower = target.lower()
        label_lower = label.lower()
        
        nav_contexts = {
            'user_management': ['user', 'profile', 'account'],
            'content_management': ['create', 'edit', 'manage', 'admin'],
            'reporting': ['report', 'export', 'print'],
            'search_and_browse': ['search', 'browse', 'list', 'view'],
            'transaction_processing': ['order', 'purchase', 'checkout', 'payment'],
            'system_administration': ['admin', 'config', 'settings', 'system']
        }
        
        for context, keywords in nav_contexts.items():
            if any(keyword in target_lower or keyword in label_lower for keyword in keywords):
                return context.replace('_', ' ').title()
        
        return 'General Navigation'
    
    def _determine_element_business_purpose(self, element: JSPElement) -> str:
        """Determine business purpose of form element."""
        element_name = element.attributes.get('property', element.attributes.get('name', '')).lower()
        
        purpose_patterns = {
            'authentication': ['username', 'password', 'login', 'email'],
            'personal_information': ['firstname', 'lastname', 'name', 'address', 'phone'],
            'financial': ['amount', 'price', 'cost', 'payment', 'card'],
            'temporal': ['date', 'time', 'birth', 'expiry'],
            'search_criteria': ['search', 'query', 'filter', 'criteria'],
            'configuration': ['config', 'setting', 'preference', 'option']
        }
        
        for purpose, patterns in purpose_patterns.items():
            if any(pattern in element_name for pattern in patterns):
                return purpose.replace('_', ' ').title()
        
        return 'Data Input'
    
    def _check_element_accessibility(self, element: JSPElement) -> List[str]:
        """Check accessibility issues for form element."""
        issues = []
        
        # Check for missing labels
        if element.tag_name in ['text', 'password', 'email', 'number'] and 'aria-label' not in element.attributes:
            issues.append('missing_label')
        
        # Check for missing required indicators
        if 'required' in element.attributes and 'aria-required' not in element.attributes:
            issues.append('missing_aria_required')
        
        # Check for proper input types
        if element.tag_name == 'text' and 'email' in element.attributes.get('property', '').lower():
            issues.append('should_use_email_input_type')
        
        return issues
    
    def _extract_business_rules(self, content: str, file_path: Path, 
                              analysis: JSPAnalysisResult) -> List[BusinessRule]:
        """Extract business rules from JSP analysis."""
        rules = []
        
        # Rules from conditional logic
        for logic in analysis.conditional_logic:
            rule = BusinessRule(
                id="auto",
                name=f"UI Conditional Logic: {logic.condition_type}",
                description=f"Conditional display logic: {logic.condition_expression}",
                rule_type=BusinessRuleType.UI,
                source=BusinessRuleSource.JSP_FILE,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    line_number=logic.line_number
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=logic.condition_expression,
                    context=f"JSP conditional logic in {file_path.name}"
                ),
                business_context=logic.business_rule_implication
            )
            
            if logic.complexity_score > 3:
                rule.complexity = BusinessRuleComplexity.COMPLEX
            elif logic.complexity_score > 1:
                rule.complexity = BusinessRuleComplexity.MODERATE
            else:
                rule.complexity = BusinessRuleComplexity.SIMPLE
            
            rules.append(rule)
        
        # Rules from form validation patterns
        for form in analysis.forms:
            if form.validation_patterns:
                rule = BusinessRule(
                    id="auto",
                    name=f"Form Validation Rules: {form.form_name}",
                    description=f"Client-side validation patterns for {form.form_name}",
                    rule_type=BusinessRuleType.VALIDATION,
                    source=BusinessRuleSource.JSP_FILE,
                    location=BusinessRuleLocation(file_path=str(file_path)),
                    evidence=BusinessRuleEvidence(
                        code_snippet=f"Form: {form.form_name}, Patterns: {form.validation_patterns}",
                        context=f"Form validation in {file_path.name}"
                    ),
                    business_context=form.business_workflow
                )
                rules.append(rule)
        
        # Rules from navigation patterns
        role_based_nav = [nav for nav in analysis.navigation_elements 
                         if 'role_based_navigation' in nav.conditions]
        if role_based_nav:
            rule = BusinessRule(
                id="auto",
                name="Role-Based Navigation Control",
                description="Navigation elements with role-based access control",
                rule_type=BusinessRuleType.SECURITY,
                source=BusinessRuleSource.JSP_FILE,
                location=BusinessRuleLocation(file_path=str(file_path)),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"{len(role_based_nav)} navigation elements with role restrictions",
                    context=f"Role-based navigation in {file_path.name}"
                ),
                business_context="User access control and authorization"
            )
            rules.append(rule)
        
        return rules
    
    def _identify_ui_patterns(self, content: str, analysis: JSPAnalysisResult) -> List[str]:
        """Identify UI patterns in the JSP file."""
        patterns = []
        
        # Check for specific UI patterns
        for pattern_name, keywords in self._ui_patterns.items():
            if any(keyword in content.lower() for keyword in keywords):
                patterns.append(pattern_name)
        
        # Pattern inference from analysis
        if len(analysis.forms) > 1:
            patterns.append('multi_step_form')
        
        if any('search' in form.business_workflow.lower() for form in analysis.forms):
            patterns.append('search_interface')
        
        if len(analysis.conditional_logic) > 3:
            patterns.append('complex_conditional_ui')
        
        if any('iterate' in logic.condition_type for logic in analysis.conditional_logic):
            patterns.append('data_listing')
        
        return patterns
    
    def _assess_accessibility(self, content: str) -> Dict[str, Any]:
        """Assess accessibility of the JSP file."""
        assessment = {
            'accessibility_score': 100,  # Start with perfect score
            'issues_found': [],
            'recommendations': [],
            'wcag_compliance_level': 'unknown'
        }
        
        # Check for common accessibility issues
        for issue_name, pattern in self._accessibility_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                assessment['issues_found'].append({
                    'issue': issue_name,
                    'count': len(matches),
                    'severity': self._get_accessibility_severity(issue_name)
                })
                assessment['accessibility_score'] -= len(matches) * self._get_accessibility_penalty(issue_name)
        
        # Generate recommendations
        if assessment['issues_found']:
            assessment['recommendations'] = self._generate_accessibility_recommendations(assessment['issues_found'])
        
        # Determine WCAG compliance level
        if assessment['accessibility_score'] >= 90:
            assessment['wcag_compliance_level'] = 'AA'
        elif assessment['accessibility_score'] >= 70:
            assessment['wcag_compliance_level'] = 'A'
        else:
            assessment['wcag_compliance_level'] = 'Non-compliant'
        
        assessment['accessibility_score'] = max(0, assessment['accessibility_score'])
        
        return assessment
    
    def _get_accessibility_severity(self, issue_name: str) -> str:
        """Get severity level for accessibility issue."""
        severity_map = {
            'missing_alt': 'high',
            'missing_label': 'high',
            'missing_title': 'medium',
            'missing_heading_structure': 'medium',
            'inline_styles': 'low',
            'javascript_links': 'medium'
        }
        return severity_map.get(issue_name, 'low')
    
    def _get_accessibility_penalty(self, issue_name: str) -> int:
        """Get penalty points for accessibility issue."""
        penalty_map = {
            'missing_alt': 10,
            'missing_label': 10,
            'missing_title': 5,
            'missing_heading_structure': 3,
            'inline_styles': 2,
            'javascript_links': 5
        }
        return penalty_map.get(issue_name, 1)
    
    def _generate_accessibility_recommendations(self, issues: List[Dict[str, Any]]) -> List[str]:
        """Generate accessibility improvement recommendations."""
        recommendations = []
        
        for issue in issues:
            issue_name = issue['issue']
            if issue_name == 'missing_alt':
                recommendations.append('Add alt attributes to all images for screen reader compatibility')
            elif issue_name == 'missing_label':
                recommendations.append('Add proper labels or aria-label attributes to form inputs')
            elif issue_name == 'missing_title':
                recommendations.append('Add title attributes to links for better context')
            elif issue_name == 'missing_heading_structure':
                recommendations.append('Ensure proper heading hierarchy (h1, h2, h3, etc.)')
            elif issue_name == 'inline_styles':
                recommendations.append('Move inline styles to external CSS files')
            elif issue_name == 'javascript_links':
                recommendations.append('Replace javascript: links with proper button elements')
        
        return recommendations
    
    def _generate_modernization_assessment(self, analysis: JSPAnalysisResult) -> Dict[str, Any]:
        """Generate modernization assessment for the JSP file."""
        assessment = {
            'modernization_complexity': 'medium',
            'estimated_effort_hours': 0,
            'angular_equivalent': '',
            'migration_strategy': '',
            'blocking_issues': [],
            'recommendations': []
        }
        
        # Calculate complexity
        complexity_score = 0
        complexity_score += len(analysis.forms) * 3
        complexity_score += len(analysis.conditional_logic) * 2
        complexity_score += len(analysis.navigation_elements)
        complexity_score += len(analysis.security_concerns) * 4
        
        if complexity_score > 20:
            assessment['modernization_complexity'] = 'critical'
        elif complexity_score > 15:
            assessment['modernization_complexity'] = 'high'
        elif complexity_score > 8:
            assessment['modernization_complexity'] = 'medium'
        else:
            assessment['modernization_complexity'] = 'low'
        
        # Estimate effort
        base_hours = 4  # Base migration effort
        base_hours += len(analysis.forms) * 4  # Per form
        base_hours += len(analysis.conditional_logic) * 2  # Per conditional
        base_hours += len(analysis.navigation_elements) * 1  # Per navigation element
        
        assessment['estimated_effort_hours'] = base_hours
        
        # Determine Angular equivalent
        if 'master_detail' in analysis.ui_patterns:
            assessment['angular_equivalent'] = 'Angular Master-Detail Component with Routing'
        elif 'crud_interface' in analysis.ui_patterns:
            assessment['angular_equivalent'] = 'Angular CRUD Component with Reactive Forms'
        elif 'search_interface' in analysis.ui_patterns:
            assessment['angular_equivalent'] = 'Angular Search Component with RxJS Operators'
        elif analysis.forms:
            assessment['angular_equivalent'] = 'Angular Component with Reactive Forms'
        else:
            assessment['angular_equivalent'] = 'Angular Display Component'
        
        # Migration strategy
        if analysis.jsp_type == 'fragment':
            assessment['migration_strategy'] = 'Convert to Angular Shared Component'
        elif analysis.jsp_type == 'error_page':
            assessment['migration_strategy'] = 'Convert to Angular Error Handling Component'
        else:
            assessment['migration_strategy'] = 'Convert to Angular Routed Component'
        
        # Identify blocking issues
        if analysis.security_concerns:
            assessment['blocking_issues'].extend(analysis.security_concerns)
        
        if analysis.performance_concerns:
            assessment['blocking_issues'].extend(analysis.performance_concerns)
        
        # Generate recommendations
        recommendations = []
        
        if analysis.forms:
            recommendations.append('Implement Angular Reactive Forms for all form handling')
        
        if analysis.conditional_logic:
            recommendations.append('Convert conditional logic to Angular directives (*ngIf, *ngFor)')
        
        if analysis.navigation_elements:
            recommendations.append('Implement Angular Router for navigation')
        
        if analysis.accessibility_assessment['issues_found']:
            recommendations.append('Address accessibility issues before migration')
        
        assessment['recommendations'] = recommendations
        
        return assessment
    
    def _identify_security_concerns(self, content: str) -> List[str]:
        """Identify security concerns in JSP content."""
        concerns = []
        
        # XSS vulnerabilities
        if re.search(r'<%=.*%>', content):
            concerns.append('Potential XSS through JSP expression without escaping')
        
        if '<c:out' not in content and '${' in content:
            concerns.append('Potential XSS through EL expression without c:out')
        
        # CSRF vulnerabilities
        if 'method="post"' in content.lower() and 'csrf' not in content.lower():
            concerns.append('Missing CSRF protection on POST forms')
        
        # Information disclosure
        if re.search(r'<%.*printStackTrace.*%>', content):
            concerns.append('Stack trace disclosure in JSP')
        
        # Insecure includes
        if re.search(r'<%@\s*include.*file="\$\{', content):
            concerns.append('Dynamic file inclusion vulnerability')
        
        return concerns
    
    def _identify_performance_concerns(self, content: str) -> List[str]:
        """Identify performance concerns in JSP content."""
        concerns = []
        
        # Excessive database calls
        if content.count('<%') > 10:
            concerns.append('Excessive server-side processing in JSP')
        
        # Large page size
        if len(content) > 50000:  # 50KB
            concerns.append('Large JSP file size affecting load time')
        
        # Inline JavaScript
        if '<script>' in content.lower() and content.lower().count('<script>') > 3:
            concerns.append('Excessive inline JavaScript affecting performance')
        
        # Missing optimization
        if 'cache' not in content.lower():
            concerns.append('No caching headers or mechanisms detected')
        
        return concerns
    
    def _post_process_results(self, results: List[Dict[str, Any]], 
                            context: AnalysisContext) -> Dict[str, Any]:
        """
        Post-process and aggregate results from all JSP files.
        
        Args:
            results: List of individual file analysis results
            context: Analysis context
            
        Returns:
            Aggregated and processed results
        """
        if not results:
            return {
                'jsp_analyses': [],
                'summary': {
                    'total_jsp_files': 0,
                    'total_forms': 0,
                    'total_conditional_logic': 0,
                    'total_navigation_elements': 0,
                    'total_business_rules': 0
                }
            }
        
        # Filter successful analyses
        successful_results = [r for r in results if 'error' not in r and r.get('jsp_analysis')]
        jsp_analyses = [r['jsp_analysis'] for r in successful_results]
        
        # Calculate aggregated metrics
        total_forms = sum(len(analysis.get('forms', [])) for analysis in jsp_analyses)
        total_conditional_logic = sum(len(analysis.get('conditional_logic', [])) for analysis in jsp_analyses)
        total_navigation_elements = sum(len(analysis.get('navigation_elements', [])) for analysis in jsp_analyses)
        total_business_rules = sum(len(analysis.get('business_rules', [])) for analysis in jsp_analyses)
        
        # Analyze UI architecture
        ui_architecture = self._analyze_ui_architecture(jsp_analyses)
        
        # Generate comprehensive modernization plan
        modernization_plan = self._generate_comprehensive_modernization_plan(jsp_analyses)
        
        # Identify common patterns and anti-patterns
        pattern_analysis = self._analyze_ui_patterns_across_files(jsp_analyses)
        
        return {
            'jsp_analyses': jsp_analyses,
            'ui_architecture': ui_architecture,
            'modernization_plan': modernization_plan,
            'pattern_analysis': pattern_analysis,
            'summary': {
                'total_jsp_files': len(jsp_analyses),
                'total_forms': total_forms,
                'total_conditional_logic': total_conditional_logic,
                'total_navigation_elements': total_navigation_elements,
                'total_business_rules': total_business_rules,
                'average_complexity': sum(
                    self._calculate_file_complexity(analysis) for analysis in jsp_analyses
                ) / len(jsp_analyses) if jsp_analyses else 0,
                'accessibility_compliance_rate': sum(
                    1 for analysis in jsp_analyses 
                    if analysis.get('accessibility_assessment', {}).get('wcag_compliance_level') in ['A', 'AA']
                ) / len(jsp_analyses) * 100 if jsp_analyses else 0
            }
        }
    
    def _calculate_file_complexity(self, analysis: Dict[str, Any]) -> int:
        """Calculate complexity score for a JSP file."""
        complexity = 0
        complexity += len(analysis.get('forms', []))
        complexity += len(analysis.get('conditional_logic', [])) * 2
        complexity += len(analysis.get('navigation_elements', []))
        complexity += len(analysis.get('security_concerns', [])) * 3
        return complexity
    
    def _analyze_ui_architecture(self, jsp_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze overall UI architecture patterns."""
        architecture = {
            'dominant_patterns': [],
            'component_hierarchy': {},
            'navigation_flow': {},
            'form_complexity_distribution': {},
            'reusability_assessment': {}
        }
        
        # Analyze dominant UI patterns
        all_patterns = []
        for analysis in jsp_analyses:
            all_patterns.extend(analysis.get('ui_patterns', []))
        
        pattern_counts = {}
        for pattern in all_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        architecture['dominant_patterns'] = sorted(
            pattern_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]
        
        # Analyze navigation flow
        all_nav_targets = []
        for analysis in jsp_analyses:
            nav_elements = analysis.get('navigation_elements', [])
            for nav in nav_elements:
                all_nav_targets.append(nav.get('target', ''))
        
        # Find most referenced pages
        target_counts = {}
        for target in all_nav_targets:
            if target:
                target_counts[target] = target_counts.get(target, 0) + 1
        
        architecture['navigation_flow'] = {
            'hub_pages': sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            'total_navigation_links': len(all_nav_targets),
            'unique_targets': len(set(all_nav_targets))
        }
        
        return architecture
    
    def _generate_comprehensive_modernization_plan(self, jsp_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive modernization plan for all JSP files."""
        plan = {
            'strategy': 'Component-Based Migration',
            'phases': [],
            'total_estimated_hours': 0,
            'risk_assessment': 'medium',
            'technology_stack': {
                'frontend': 'Angular with TypeScript',
                'styling': 'Angular Material or Bootstrap',
                'state_management': 'NgRx (if complex state)',
                'forms': 'Angular Reactive Forms',
                'routing': 'Angular Router'
            },
            'success_criteria': []
        }
        
        # Calculate total effort
        total_hours = sum(
            analysis.get('modernization_assessment', {}).get('estimated_effort_hours', 0)
            for analysis in jsp_analyses
        )
        plan['total_estimated_hours'] = total_hours
        
        # Define migration phases
        plan['phases'] = [
            {
                'name': 'UI Architecture Setup',
                'description': 'Set up Angular project structure and shared components',
                'estimated_hours': 40,
                'deliverables': [
                    'Angular project scaffolding',
                    'Shared component library',
                    'Routing configuration',
                    'Style guide implementation'
                ]
            },
            {
                'name': 'Core Components Migration',
                'description': 'Migrate main application components',
                'estimated_hours': total_hours * 0.4,
                'deliverables': [
                    'Main layout components',
                    'Navigation components',
                    'Core business forms',
                    'Data display components'
                ]
            },
            {
                'name': 'Advanced Features',
                'description': 'Implement complex UI patterns and interactions',
                'estimated_hours': total_hours * 0.4,
                'deliverables': [
                    'Complex conditional logic',
                    'Multi-step forms',
                    'Data tables and grids',
                    'Advanced navigation patterns'
                ]
            },
            {
                'name': 'Quality Assurance',
                'description': 'Testing, accessibility, and performance optimization',
                'estimated_hours': total_hours * 0.2,
                'deliverables': [
                    'Unit and integration tests',
                    'Accessibility compliance',
                    'Performance optimization',
                    'Cross-browser testing'
                ]
            }
        ]
        
        # Success criteria
        plan['success_criteria'] = [
            'All JSP functionality preserved in Angular components',
            'WCAG 2.1 AA accessibility compliance',
            'Performance metrics meet or exceed current application',
            'Responsive design for all screen sizes',
            'Comprehensive test coverage (>80%)'
        ]
        
        return plan
    
    def _analyze_ui_patterns_across_files(self, jsp_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze UI patterns across all JSP files."""
        pattern_analysis = {
            'common_patterns': {},
            'anti_patterns': [],
            'reusability_opportunities': [],
            'consistency_issues': []
        }
        
        # Analyze common patterns
        all_ui_patterns = []
        for analysis in jsp_analyses:
            all_ui_patterns.extend(analysis.get('ui_patterns', []))
        
        pattern_counts = {}
        for pattern in all_ui_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        pattern_analysis['common_patterns'] = pattern_counts
        
        # Identify anti-patterns
        anti_patterns = []
        
        # Files with excessive complexity
        complex_files = [
            analysis for analysis in jsp_analyses
            if self._calculate_file_complexity(analysis) > 15
        ]
        if complex_files:
            anti_patterns.append(f"Complex JSP files: {len(complex_files)} files with high complexity")
        
        # Files with security concerns
        security_issues = sum(
            len(analysis.get('security_concerns', [])) for analysis in jsp_analyses
        )
        if security_issues > 0:
            anti_patterns.append(f"Security vulnerabilities: {security_issues} issues across files")
        
        # Files with poor accessibility
        accessibility_issues = sum(
            len(analysis.get('accessibility_assessment', {}).get('issues_found', []))
            for analysis in jsp_analyses
        )
        if accessibility_issues > 0:
            anti_patterns.append(f"Accessibility issues: {accessibility_issues} violations")
        
        pattern_analysis['anti_patterns'] = anti_patterns
        
        # Identify reusability opportunities
        # Forms with similar patterns
        form_patterns = {}
        for analysis in jsp_analyses:
            for form in analysis.get('forms', []):
                workflow = form.get('business_workflow', 'unknown')
                if workflow not in form_patterns:
                    form_patterns[workflow] = 0
                form_patterns[workflow] += 1
        
        reusable_forms = [
            workflow for workflow, count in form_patterns.items()
            if count > 1
        ]
        
        if reusable_forms:
            pattern_analysis['reusability_opportunities'].append(
                f"Reusable form patterns: {', '.join(reusable_forms)}"
            )
        
        return pattern_analysis