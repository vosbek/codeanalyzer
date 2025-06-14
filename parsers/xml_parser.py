"""
XML Configuration Parser
========================

This parser handles various XML configuration files used in Struts applications,
including struts-config.xml, validation.xml, web.xml, and other XML-based
configuration files.

Features:
- Struts configuration parsing with action mappings and form beans
- Validation rule extraction from validation.xml
- Web.xml deployment descriptor analysis
- Custom XML schema support
- Business rule inference from XML structure and comments

Author: Claude Code Assistant
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import re
from datetime import datetime

from parsers.base_parser import BaseParser, ParseResult
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource,
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)


class XMLConfigurationParser(BaseParser):
    """Parser for XML configuration files in Struts applications."""
    
    def __init__(self):
        """Initialize XML parser."""
        super().__init__()
        self.supported_extensions = {'.xml'}
        self.supported_patterns = [
            'struts-config', 'struts', 'validation', 'validator-rules',
            'web', 'faces-config', 'spring', 'applicationContext'
        ]
        
        # XML namespace mappings
        self.namespaces = {
            'struts': 'http://struts.apache.org/dtds/struts-config_1_3.dtd',
            'validation': 'http://jakarta.apache.org/commons/dtds/validator_1_3_0.dtd'
        }
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the XML file."""
        if not self.supports_extension(file_path.suffix):
            return False
        
        if self.supports_filename_pattern(file_path.name):
            return True
        
        # Check if it's a valid XML file with Struts-related content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Read first 1KB
                return any(indicator in content.lower() for indicator in [
                    'struts', 'action', 'form-bean', 'validation', 'web-app'
                ])
        except Exception:
            return False
    
    def get_priority(self) -> int:
        """XML parser has high priority for XML files."""
        return 80
    
    def parse_file(self, file_path: Path) -> ParseResult:
        """Parse XML configuration file."""
        start_time = datetime.now()
        result = ParseResult(
            file_path=str(file_path),
            parser_name=self.parser_name,
            success=True,
            parse_time_ms=0
        )
        
        try:
            # Parse XML content
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Determine XML file type and parse accordingly
            xml_type = self._determine_xml_type(root, file_path)
            result.add_extracted_data('xml_type', xml_type)
            
            if xml_type == 'struts-config':
                self._parse_struts_config(root, file_path, result)
            elif xml_type == 'validation':
                self._parse_validation_config(root, file_path, result)
            elif xml_type == 'web-xml':
                self._parse_web_xml(root, file_path, result)
            elif xml_type == 'spring':
                self._parse_spring_config(root, file_path, result)
            else:
                self._parse_generic_xml(root, file_path, result)
            
            # Calculate parsing time
            end_time = datetime.now()
            result.parse_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
        except ET.ParseError as e:
            result.add_error(f"XML parsing error: {e}")
        except Exception as e:
            result.add_error(f"Unexpected error parsing XML: {e}")
        
        return result
    
    def _determine_xml_type(self, root: ET.Element, file_path: Path) -> str:
        """Determine the type of XML configuration file."""
        root_tag = root.tag.lower()
        filename = file_path.name.lower()
        
        if 'struts-config' in filename or root_tag == 'struts-config':
            return 'struts-config'
        elif 'validation' in filename or root_tag in ['form-validation', 'validator-rules']:
            return 'validation'
        elif 'web.xml' in filename or root_tag == 'web-app':
            return 'web-xml'
        elif 'spring' in filename or 'applicationcontext' in filename or root_tag == 'beans':
            return 'spring'
        else:
            return 'generic'
    
    def _parse_struts_config(self, root: ET.Element, file_path: Path, result: ParseResult):
        """Parse struts-config.xml file."""
        # Extract action mappings
        actions = self._extract_action_mappings(root, file_path)
        result.add_extracted_data('action_mappings', actions)
        
        # Extract form beans
        form_beans = self._extract_form_beans(root, file_path)
        result.add_extracted_data('form_beans', form_beans)
        
        # Extract global forwards
        global_forwards = self._extract_global_forwards(root)
        result.add_extracted_data('global_forwards', global_forwards)
        
        # Generate business rules from configuration
        self._generate_struts_business_rules(actions, form_beans, file_path, result)
    
    def _extract_action_mappings(self, root: ET.Element, file_path: Path) -> List[Dict[str, Any]]:
        """Extract action mappings from struts-config.xml."""
        actions = []
        
        for action in root.findall('.//action'):
            action_data = {
                'path': action.get('path', ''),
                'type': action.get('type', ''),
                'name': action.get('name', ''),
                'scope': action.get('scope', 'request'),
                'validate': action.get('validate', 'false').lower() == 'true',
                'input': action.get('input', ''),
                'forwards': {},
                'exceptions': {},
                'line_number': getattr(action, 'sourceline', 0)
            }
            
            # Extract forwards
            for forward in action.findall('forward'):
                forward_name = forward.get('name', '')
                forward_path = forward.get('path', '')
                if forward_name and forward_path:
                    action_data['forwards'][forward_name] = forward_path
            
            # Extract exceptions
            for exception in action.findall('exception'):
                exception_key = exception.get('key', '')
                exception_path = exception.get('path', '')
                exception_type = exception.get('type', '')
                if exception_key:
                    action_data['exceptions'][exception_key] = {
                        'path': exception_path,
                        'type': exception_type
                    }
            
            actions.append(action_data)
        
        return actions
    
    def _extract_form_beans(self, root: ET.Element, file_path: Path) -> List[Dict[str, Any]]:
        """Extract form bean definitions."""
        form_beans = []
        
        for form_bean in root.findall('.//form-bean'):
            bean_data = {
                'name': form_bean.get('name', ''),
                'type': form_bean.get('type', ''),
                'dynamic': form_bean.get('dynamic', 'false').lower() == 'true',
                'line_number': getattr(form_bean, 'sourceline', 0)
            }
            
            # Extract form properties for dynamic beans
            properties = []
            for prop in form_bean.findall('form-property'):
                prop_data = {
                    'name': prop.get('name', ''),
                    'type': prop.get('type', ''),
                    'initial': prop.get('initial', ''),
                    'size': prop.get('size', '')
                }
                properties.append(prop_data)
            
            bean_data['properties'] = properties
            form_beans.append(bean_data)
        
        return form_beans
    
    def _extract_global_forwards(self, root: ET.Element) -> Dict[str, str]:
        """Extract global forward definitions."""
        forwards = {}
        
        for forward in root.findall('.//global-forwards/forward'):
            name = forward.get('name', '')
            path = forward.get('path', '')
            if name and path:
                forwards[name] = path
        
        return forwards
    
    def _generate_struts_business_rules(self, actions: List[Dict], form_beans: List[Dict],
                                      file_path: Path, result: ParseResult):
        """Generate business rules from Struts configuration."""
        
        # Business rules for actions
        for action in actions:
            if action['path']:
                rule_id = self._generate_rule_id('action', action['path'])
                
                # Infer business purpose from action path
                business_purpose = self._infer_action_business_purpose(action['path'])
                
                # Create action business rule
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"Action Mapping: {action['path']}",
                    description=f"Business process accessible via {action['path']}",
                    rule_type=BusinessRuleType.WORKFLOW,
                    source=BusinessRuleSource.STRUTS_CONFIG,
                    file_path=file_path,
                    business_context=business_purpose,
                    code_snippet=f"<action path=\"{action['path']}\" type=\"{action['type']}\"/>",
                    location=BusinessRuleLocation(
                        file_path=str(file_path),
                        line_number=action.get('line_number'),
                        element_xpath=f"//action[@path='{action['path']}']"
                    ),
                    complexity=self._calculate_action_complexity(action)
                )
                
                # Add tags based on action characteristics
                rule.add_tag('struts_action')
                if action['validate']:
                    rule.add_tag('validation')
                if action['forwards']:
                    rule.add_tag('navigation')
                if action['exceptions']:
                    rule.add_tag('error_handling')
                
                result.add_business_rule(rule)
        
        # Business rules for form beans
        for form_bean in form_beans:
            if form_bean['name']:
                rule_id = self._generate_rule_id('form_bean', form_bean['name'])
                
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"Form Bean: {form_bean['name']}",
                    description=f"Data structure for {form_bean['name']} form processing",
                    rule_type=BusinessRuleType.DATA,
                    source=BusinessRuleSource.STRUTS_CONFIG,
                    file_path=file_path,
                    business_context=self._infer_form_business_purpose(form_bean['name']),
                    code_snippet=f"<form-bean name=\"{form_bean['name']}\" type=\"{form_bean['type']}\"/>",
                    location=BusinessRuleLocation(
                        file_path=str(file_path),
                        line_number=form_bean.get('line_number'),
                        element_xpath=f"//form-bean[@name='{form_bean['name']}']"
                    )
                )
                
                rule.add_tag('form_bean')
                rule.add_tag('data_structure')
                if form_bean['dynamic']:
                    rule.add_tag('dynamic_form')
                
                result.add_business_rule(rule)
    
    def _parse_validation_config(self, root: ET.Element, file_path: Path, result: ParseResult):
        """Parse validation.xml configuration."""
        validation_rules = []
        
        for form in root.findall('.//form'):
            form_name = form.get('name', '')
            
            for field in form.findall('.//field'):
                field_name = field.get('property', '')
                depends = field.get('depends', '')
                
                if depends:
                    validators = [v.strip() for v in depends.split(',')]
                    
                    for validator in validators:
                        rule_data = {
                            'form': form_name,
                            'field': field_name,
                            'validator': validator,
                            'parameters': {},
                            'message_key': ''
                        }
                        
                        # Extract validation parameters
                        for var in field.findall('var'):
                            var_name = var.find('var-name')
                            var_value = var.find('var-value')
                            if var_name is not None and var_value is not None:
                                rule_data['parameters'][var_name.text] = var_value.text
                        
                        # Extract message key
                        msg = field.find('msg')
                        if msg is not None:
                            rule_data['message_key'] = msg.get('key', '')
                        
                        validation_rules.append(rule_data)
                        
                        # Create business rule for validation
                        rule_id = self._generate_rule_id('validation', form_name, field_name, validator)
                        
                        rule = self._create_business_rule(
                            rule_id=rule_id,
                            name=f"Validation: {form_name}.{field_name}",
                            description=f"Field {field_name} must satisfy {validator} validation",
                            rule_type=BusinessRuleType.VALIDATION,
                            source=BusinessRuleSource.VALIDATION_XML,
                            file_path=file_path,
                            business_context=self._infer_validation_business_context(field_name, validator),
                            code_snippet=f'<field property="{field_name}" depends="{validator}"/>',
                            complexity=BusinessRuleComplexity.SIMPLE
                        )
                        
                        rule.add_tag('validation')
                        rule.add_tag(validator)
                        rule.add_tag(f'form_{form_name}')
                        
                        result.add_business_rule(rule)
        
        result.add_extracted_data('validation_rules', validation_rules)
    
    def _parse_web_xml(self, root: ET.Element, file_path: Path, result: ParseResult):
        """Parse web.xml deployment descriptor."""
        web_config = {
            'servlets': [],
            'filters': [],
            'listeners': [],
            'context_params': {},
            'security_constraints': []
        }
        
        # Extract servlets
        for servlet in root.findall('.//servlet'):
            servlet_name = servlet.find('servlet-name')
            servlet_class = servlet.find('servlet-class')
            
            if servlet_name is not None and servlet_class is not None:
                servlet_data = {
                    'name': servlet_name.text,
                    'class': servlet_class.text,
                    'init_params': {}
                }
                
                # Extract init parameters
                for param in servlet.findall('init-param'):
                    param_name = param.find('param-name')
                    param_value = param.find('param-value')
                    if param_name is not None and param_value is not None:
                        servlet_data['init_params'][param_name.text] = param_value.text
                
                web_config['servlets'].append(servlet_data)
        
        # Extract filters
        for filter_elem in root.findall('.//filter'):
            filter_name = filter_elem.find('filter-name')
            filter_class = filter_elem.find('filter-class')
            
            if filter_name is not None and filter_class is not None:
                filter_data = {
                    'name': filter_name.text,
                    'class': filter_class.text,
                    'init_params': {}
                }
                
                # Extract init parameters
                for param in filter_elem.findall('init-param'):
                    param_name = param.find('param-name')
                    param_value = param.find('param-value')
                    if param_name is not None and param_value is not None:
                        filter_data['init_params'][param_name.text] = param_value.text
                
                web_config['filters'].append(filter_data)
        
        # Extract security constraints
        for constraint in root.findall('.//security-constraint'):
            auth_constraint = constraint.find('auth-constraint')
            if auth_constraint is not None:
                roles = []
                for role in auth_constraint.findall('role-name'):
                    if role.text:
                        roles.append(role.text)
                
                web_resource = constraint.find('web-resource-collection')
                if web_resource is not None:
                    url_patterns = []
                    for pattern in web_resource.findall('url-pattern'):
                        if pattern.text:
                            url_patterns.append(pattern.text)
                    
                    if url_patterns and roles:
                        web_config['security_constraints'].append({
                            'url_patterns': url_patterns,
                            'roles': roles
                        })
        
        result.add_extracted_data('web_config', web_config)
        
        # Generate business rules for security constraints
        for constraint in web_config['security_constraints']:
            for url_pattern in constraint['url_patterns']:
                rule_id = self._generate_rule_id('security', url_pattern)
                
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"Security Constraint: {url_pattern}",
                    description=f"Access to {url_pattern} requires roles: {', '.join(constraint['roles'])}",
                    rule_type=BusinessRuleType.SECURITY,
                    source=BusinessRuleSource.STRUTS_CONFIG,
                    file_path=file_path,
                    business_context="Role-based access control",
                    code_snippet=f"Security constraint for {url_pattern}"
                )
                
                rule.add_tag('security')
                rule.add_tag('access_control')
                for role in constraint['roles']:
                    rule.add_tag(f'role_{role}')
                
                result.add_business_rule(rule)
    
    def _parse_spring_config(self, root: ET.Element, file_path: Path, result: ParseResult):
        """Parse Spring configuration XML."""
        spring_config = {
            'beans': [],
            'imports': [],
            'aspects': []
        }
        
        # Extract bean definitions
        for bean in root.findall('.//bean'):
            bean_id = bean.get('id', bean.get('name', ''))
            bean_class = bean.get('class', '')
            
            if bean_id or bean_class:
                bean_data = {
                    'id': bean_id,
                    'class': bean_class,
                    'scope': bean.get('scope', 'singleton'),
                    'properties': []
                }
                
                # Extract properties
                for prop in bean.findall('property'):
                    prop_name = prop.get('name', '')
                    prop_value = prop.get('value', '')
                    prop_ref = prop.get('ref', '')
                    
                    if prop_name:
                        bean_data['properties'].append({
                            'name': prop_name,
                            'value': prop_value,
                            'ref': prop_ref
                        })
                
                spring_config['beans'].append(bean_data)
        
        result.add_extracted_data('spring_config', spring_config)
    
    def _parse_generic_xml(self, root: ET.Element, file_path: Path, result: ParseResult):
        """Parse generic XML file for business rules in comments."""
        # Extract business context from XML comments
        business_contexts = self._extract_business_context_from_comments(
            ET.tostring(root, encoding='unicode')
        )
        
        if business_contexts:
            for i, context in enumerate(business_contexts):
                rule_id = self._generate_rule_id('xml_comment', str(i))
                
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"XML Configuration Rule {i+1}",
                    description=context,
                    rule_type=BusinessRuleType.CONFIGURATION,
                    source=BusinessRuleSource.STRUTS_CONFIG,
                    file_path=file_path,
                    business_context="Configuration-based business rule",
                    code_snippet=context[:200] + "..." if len(context) > 200 else context
                )
                
                rule.add_tag('xml_config')
                rule.add_tag('configuration')
                
                result.add_business_rule(rule)
    
    def _infer_action_business_purpose(self, action_path: str) -> str:
        """Infer business purpose from action path."""
        path_lower = action_path.lower().strip('/')
        
        if any(word in path_lower for word in ['login', 'auth', 'signin']):
            return "User Authentication and Session Management"
        elif any(word in path_lower for word in ['logout', 'signout']):
            return "User Session Termination"
        elif any(word in path_lower for word in ['search', 'find', 'lookup']):
            return "Data Search and Retrieval"
        elif any(word in path_lower for word in ['create', 'add', 'new']):
            return "Data Creation and Entry"
        elif any(word in path_lower for word in ['edit', 'update', 'modify']):
            return "Data Modification and Updates"
        elif any(word in path_lower for word in ['delete', 'remove', 'cancel']):
            return "Data Deletion and Cleanup"
        elif any(word in path_lower for word in ['report', 'export', 'download']):
            return "Reporting and Data Export"
        elif any(word in path_lower for word in ['admin', 'manage', 'config']):
            return "Administrative Operations"
        elif any(word in path_lower for word in ['order', 'purchase', 'buy']):
            return "Order Processing and Commerce"
        elif any(word in path_lower for word in ['user', 'profile', 'account']):
            return "User Account Management"
        else:
            return f"Business Process: {action_path}"
    
    def _infer_form_business_purpose(self, form_name: str) -> str:
        """Infer business purpose from form bean name."""
        name_lower = form_name.lower()
        
        if any(word in name_lower for word in ['login', 'auth', 'signin']):
            return "User Authentication Form"
        elif any(word in name_lower for word in ['search', 'filter', 'criteria']):
            return "Search and Filter Form"
        elif any(word in name_lower for word in ['user', 'person', 'customer']):
            return "User Information Management"
        elif any(word in name_lower for word in ['product', 'item', 'catalog']):
            return "Product Management Form"
        elif any(word in name_lower for word in ['order', 'purchase', 'transaction']):
            return "Order Processing Form"
        elif any(word in name_lower for word in ['contact', 'address', 'phone']):
            return "Contact Information Form"
        else:
            return f"Data Entry Form: {form_name}"
    
    def _infer_validation_business_context(self, field_name: str, validator: str) -> str:
        """Infer business context from validation rule."""
        field_lower = field_name.lower()
        
        if validator == 'required':
            return f"Field {field_name} is mandatory for business process completion"
        elif validator == 'email':
            return f"Field {field_name} must be valid email for communication"
        elif validator in ['minlength', 'maxlength', 'mask']:
            return f"Field {field_name} format constraints ensure data quality"
        elif validator in ['range', 'min', 'max']:
            return f"Field {field_name} value constraints ensure business compliance"
        elif validator == 'date':
            return f"Field {field_name} temporal validation for business logic"
        else:
            return f"Field {field_name} validation ensures data integrity"
    
    def _calculate_action_complexity(self, action: Dict[str, Any]) -> BusinessRuleComplexity:
        """Calculate complexity of an action mapping."""
        complexity_score = 1  # Base complexity
        
        if action.get('validate'):
            complexity_score += 1
        
        complexity_score += len(action.get('forwards', {}))
        complexity_score += len(action.get('exceptions', {})) * 2
        
        if complexity_score <= 2:
            return BusinessRuleComplexity.SIMPLE
        elif complexity_score <= 5:
            return BusinessRuleComplexity.MODERATE
        elif complexity_score <= 10:
            return BusinessRuleComplexity.COMPLEX
        else:
            return BusinessRuleComplexity.CRITICAL