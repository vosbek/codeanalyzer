import sys
sys.path.append('..')

"""
Validation Analyzer
===================

This module provides analysis capabilities for Struts validation configuration files,
particularly validation.xml and validator-rules.xml. It extracts validation rules,
business constraints, and data integrity requirements while providing modernization
recommendations for Bean Validation and GraphQL schema validation.

Features:
- Complete validation.xml and validator-rules.xml parsing
- Validation rule extraction with business context
- Data integrity constraint analysis
- Custom validator identification and analysis
- Bean Validation (JSR-303/349) migration recommendations
- GraphQL schema validation mapping

Author: Claude Code Assistant
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
import hashlib
import re

from analyzers.base_analyzer import BaseAnalyzer, AnalysisContext
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource, 
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)
from utils.logging_utils import get_logger
from utils.performance_utils import performance_timer


logger = get_logger(__name__)


@dataclass
class ValidationRule:
    """Represents a validation rule with comprehensive context."""
    rule_id: str
    field_name: str
    property_path: str
    validator_type: str
    form_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    message_key: str = ""
    message_text: str = ""
    business_reason: str = ""
    data_type: str = "string"
    is_required: bool = False
    custom_validator: bool = False
    depends_on: List[str] = field(default_factory=list)
    validation_order: int = 0
    bean_validation_equivalent: str = ""
    graphql_constraint: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'rule_id': self.rule_id,
            'field_name': self.field_name,
            'property_path': self.property_path,
            'validator_type': self.validator_type,
            'form_name': self.form_name,
            'parameters': self.parameters,
            'message_key': self.message_key,
            'message_text': self.message_text,
            'business_reason': self.business_reason,
            'data_type': self.data_type,
            'is_required': self.is_required,
            'custom_validator': self.custom_validator,
            'depends_on': self.depends_on,
            'validation_order': self.validation_order,
            'bean_validation_equivalent': self.bean_validation_equivalent,
            'graphql_constraint': self.graphql_constraint
        }


@dataclass
class ValidatorDefinition:
    """Represents a validator definition from validator-rules.xml."""
    name: str
    classname: str
    method: str = ""
    method_params: str = ""
    javascript: str = ""
    javascript_function: str = ""
    depends: List[str] = field(default_factory=list)
    message: str = ""
    is_custom: bool = True
    complexity_score: int = 1
    migration_strategy: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'classname': self.classname,
            'method': self.method,
            'method_params': self.method_params,
            'javascript': self.javascript,
            'javascript_function': self.javascript_function,
            'depends': self.depends,
            'message': self.message,
            'is_custom': self.is_custom,
            'complexity_score': self.complexity_score,
            'migration_strategy': self.migration_strategy
        }


@dataclass
class FormValidationSet:
    """Represents all validation rules for a specific form."""
    form_name: str
    rules: List[ValidationRule] = field(default_factory=list)
    global_rules: List[ValidationRule] = field(default_factory=list)
    field_dependencies: Dict[str, List[str]] = field(default_factory=dict)
    validation_order: List[str] = field(default_factory=list)
    business_context: str = ""
    complexity_score: int = 0
    angular_form_strategy: str = ""
    bean_validation_class: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'form_name': self.form_name,
            'rules': [rule.to_dict() for rule in self.rules],
            'global_rules': [rule.to_dict() for rule in self.global_rules],
            'field_dependencies': self.field_dependencies,
            'validation_order': self.validation_order,
            'business_context': self.business_context,
            'complexity_score': self.complexity_score,
            'angular_form_strategy': self.angular_form_strategy,
            'bean_validation_class': self.bean_validation_class
        }


@dataclass
class ValidationAnalysisResult:
    """Comprehensive validation analysis results."""
    file_path: str
    file_type: str  # validation_xml, validator_rules_xml
    validator_definitions: List[ValidatorDefinition] = field(default_factory=list)
    form_validation_sets: List[FormValidationSet] = field(default_factory=list)
    global_validation_rules: List[ValidationRule] = field(default_factory=list)
    business_rules: List[BusinessRule] = field(default_factory=list)
    data_integrity_constraints: List[str] = field(default_factory=list)
    custom_validators: List[ValidatorDefinition] = field(default_factory=list)
    migration_assessment: Dict[str, Any] = field(default_factory=dict)
    modernization_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'file_path': self.file_path,
            'file_type': self.file_type,
            'validator_definitions': [val.to_dict() for val in self.validator_definitions],
            'form_validation_sets': [form_set.to_dict() for form_set in self.form_validation_sets],
            'global_validation_rules': [rule.to_dict() for rule in self.global_validation_rules],
            'business_rules': [rule.to_dict() for rule in self.business_rules],
            'data_integrity_constraints': self.data_integrity_constraints,
            'custom_validators': [val.to_dict() for val in self.custom_validators],
            'migration_assessment': self.migration_assessment,
            'modernization_recommendations': self.modernization_recommendations
        }


class ValidationAnalyzer(BaseAnalyzer):
    """
    Analyzer for Struts validation configuration files.
    
    Provides comprehensive analysis of validation.xml and validator-rules.xml files,
    extracting validation rules, business constraints, and migration recommendations.
    """
    
    def _initialize_analyzer(self) -> None:
        """Initialize validation analyzer settings."""
        self._supported_extensions = {'.xml'}
        self._required_patterns = ['validation', 'validator']
        
        # Standard Struts validators
        self._standard_validators = {
            'required': {
                'description': 'Checks if field is present and not empty',
                'bean_validation': '@NotNull, @NotEmpty, or @NotBlank',
                'graphql': 'Non-null type (!)',
                'complexity': 1
            },
            'requiredif': {
                'description': 'Conditional required validation',
                'bean_validation': 'Custom validator with conditional logic',
                'graphql': 'Custom scalar with validation',
                'complexity': 3
            },
            'minlength': {
                'description': 'Minimum string length validation',
                'bean_validation': '@Size(min=X)',
                'graphql': '@Length(min: X) directive',
                'complexity': 1
            },
            'maxlength': {
                'description': 'Maximum string length validation',
                'bean_validation': '@Size(max=X)',
                'graphql': '@Length(max: X) directive',
                'complexity': 1
            },
            'mask': {
                'description': 'Regular expression pattern validation',
                'bean_validation': '@Pattern(regexp="...")',
                'graphql': '@Pattern directive',
                'complexity': 2
            },
            'range': {
                'description': 'Numeric range validation',
                'bean_validation': '@Min(X) @Max(Y)',
                'graphql': '@Range directive',
                'complexity': 2
            },
            'min': {
                'description': 'Minimum numeric value',
                'bean_validation': '@Min(X)',
                'graphql': '@Min directive',
                'complexity': 1
            },
            'max': {
                'description': 'Maximum numeric value',
                'bean_validation': '@Max(X)',
                'graphql': '@Max directive',
                'complexity': 1
            },
            'date': {
                'description': 'Date format validation',
                'bean_validation': '@Past, @Future, or custom date validator',
                'graphql': 'Date scalar with validation',
                'complexity': 2
            },
            'email': {
                'description': 'Email format validation',
                'bean_validation': '@Email',
                'graphql': 'Email scalar type',
                'complexity': 1
            },
            'creditCard': {
                'description': 'Credit card number validation',
                'bean_validation': 'Custom credit card validator',
                'graphql': 'Custom scalar with validation',
                'complexity': 3
            },
            'url': {
                'description': 'URL format validation',
                'bean_validation': '@URL',
                'graphql': 'URL scalar type',
                'complexity': 1
            },
            'integer': {
                'description': 'Integer format validation',
                'bean_validation': '@Digits(integer=X, fraction=0)',
                'graphql': 'Int type with validation',
                'complexity': 1
            },
            'long': {
                'description': 'Long integer validation',
                'bean_validation': '@Digits(integer=X, fraction=0)',
                'graphql': 'Long scalar with validation',
                'complexity': 1
            },
            'short': {
                'description': 'Short integer validation',
                'bean_validation': '@Digits(integer=X, fraction=0)',
                'graphql': 'Short scalar with validation',
                'complexity': 1
            },
            'byte': {
                'description': 'Byte value validation',
                'bean_validation': '@Min(0) @Max(255)',
                'graphql': 'Byte scalar with validation',
                'complexity': 1
            },
            'float': {
                'description': 'Float number validation',
                'bean_validation': '@Digits(integer=X, fraction=Y)',
                'graphql': 'Float type with validation',
                'complexity': 1
            },
            'double': {
                'description': 'Double precision validation',
                'bean_validation': '@Digits(integer=X, fraction=Y)',
                'graphql': 'Float type with validation',
                'complexity': 1
            }
        }
        
        # Business context patterns
        self._business_context_patterns = {
            'financial': ['amount', 'price', 'cost', 'payment', 'salary', 'balance'],
            'personal_data': ['name', 'firstname', 'lastname', 'address', 'phone', 'ssn'],
            'temporal': ['date', 'time', 'birth', 'expiry', 'created', 'modified'],
            'authentication': ['username', 'password', 'email', 'login'],
            'identification': ['id', 'number', 'code', 'reference', 'key'],
            'measurement': ['length', 'width', 'height', 'weight', 'size', 'quantity'],
            'textual': ['description', 'comment', 'note', 'message', 'content']
        }
    
    def can_analyze(self, file_path: Path) -> bool:
        """
        Check if this is a Struts validation configuration file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if this is a validation config file
        """
        if file_path.suffix.lower() != '.xml':
            return False
        
        filename = file_path.name.lower()
        
        # Check for known validation file names
        validation_files = self.config.get('struts.validation_files', 
                                         ['validation.xml', 'validator-rules.xml'])
        
        if any(val_file in filename for val_file in validation_files):
            return True
        
        # Check file content for validation-specific elements
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Read first 1KB
                return ('form-validation' in content.lower() or 
                        'validator-rules' in content.lower() or
                        'form-validation' in content.lower())
        except Exception:
            return False
    
    @performance_timer("validation_analysis")
    def _analyze_file(self, file_path: Path, context: AnalysisContext) -> Dict[str, Any]:
        """
        Analyze a single validation configuration file.
        
        Args:
            file_path: Path to validation file
            context: Analysis context
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Determine file type
            file_type = self._determine_file_type(root, file_path)
            
            # Create analysis result
            analysis = ValidationAnalysisResult(
                file_path=str(file_path),
                file_type=file_type
            )
            
            if file_type == 'validator_rules_xml':
                # Parse validator definitions
                analysis.validator_definitions = self._extract_validator_definitions(root)
                analysis.custom_validators = [v for v in analysis.validator_definitions if v.is_custom]
            elif file_type == 'validation_xml':
                # Parse form validation rules
                analysis.form_validation_sets = self._extract_form_validation_sets(root, file_path)
                analysis.global_validation_rules = self._extract_global_validation_rules(root)
            
            # Extract business rules
            analysis.business_rules = self._extract_business_rules(analysis, file_path)
            
            # Identify data integrity constraints
            analysis.data_integrity_constraints = self._identify_data_integrity_constraints(analysis)
            
            # Generate migration assessment
            analysis.migration_assessment = self._generate_migration_assessment(analysis)
            
            # Generate modernization recommendations
            analysis.modernization_recommendations = self._generate_modernization_recommendations(analysis)
            
            return {
                'validation_analysis': analysis.to_dict(),
                'file_size_kb': file_path.stat().st_size / 1024
            }
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error in {file_path}: {e}")
            return {
                'error': f"XML parsing failed: {e}",
                'file_path': str(file_path),
                'validation_analysis': None
            }
        except Exception as e:
            logger.error(f"Error analyzing validation file {file_path}: {e}")
            return {
                'error': f"Analysis failed: {e}",
                'file_path': str(file_path),
                'validation_analysis': None
            }
    
    def _determine_file_type(self, root: ET.Element, file_path: Path) -> str:
        """Determine the type of validation file."""
        root_tag = root.tag.lower()
        filename = file_path.name.lower()
        
        if 'validator-rules' in root_tag or 'validator-rules' in filename:
            return 'validator_rules_xml'
        elif 'form-validation' in root_tag or 'validation.xml' in filename:
            return 'validation_xml'
        else:
            return 'unknown_validation_file'
    
    def _extract_validator_definitions(self, root: ET.Element) -> List[ValidatorDefinition]:
        """Extract validator definitions from validator-rules.xml."""
        validators = []
        
        for validator_elem in root.findall('.//validator'):
            try:
                validator = ValidatorDefinition(
                    name=validator_elem.get('name', ''),
                    classname=validator_elem.get('classname', ''),
                    method=validator_elem.get('method', ''),
                    method_params=validator_elem.get('methodParams', ''),
                    javascript=validator_elem.get('javascript', ''),
                    message=validator_elem.get('msg', '')
                )
                
                # Extract JavaScript function if present
                js_elem = validator_elem.find('javascript')
                if js_elem is not None and js_elem.text:
                    validator.javascript_function = js_elem.text.strip()
                
                # Determine if this is a custom validator
                validator.is_custom = validator.name not in self._standard_validators
                
                # Calculate complexity score
                validator.complexity_score = self._calculate_validator_complexity(validator)
                
                # Generate migration strategy
                validator.migration_strategy = self._generate_validator_migration_strategy(validator)
                
                validators.append(validator)
                
            except Exception as e:
                logger.warning(f"Error parsing validator definition: {e}")
        
        return validators
    
    def _calculate_validator_complexity(self, validator: ValidatorDefinition) -> int:
        """Calculate complexity score for a validator."""
        complexity = 1  # Base complexity
        
        # Custom validators are more complex
        if validator.is_custom:
            complexity += 2
        
        # JavaScript validation adds complexity
        if validator.javascript or validator.javascript_function:
            complexity += 1
        
        # Method parameters add complexity
        if validator.method_params:
            complexity += len(validator.method_params.split(','))
        
        return complexity
    
    def _generate_validator_migration_strategy(self, validator: ValidatorDefinition) -> str:
        """Generate migration strategy for a validator."""
        if not validator.is_custom and validator.name in self._standard_validators:
            standard_info = self._standard_validators[validator.name]
            return f"Use {standard_info['bean_validation']} for Bean Validation"
        else:
            return "Create custom Bean Validation constraint annotation"
    
    def _extract_form_validation_sets(self, root: ET.Element, file_path: Path) -> List[FormValidationSet]:
        """Extract validation rules organized by form."""
        form_sets = []
        
        for form_elem in root.findall('.//form'):
            try:
                form_name = form_elem.get('name', '')
                if not form_name:
                    continue
                
                form_set = FormValidationSet(form_name=form_name)
                
                # Extract field validation rules
                for field_elem in form_elem.findall('.//field'):
                    field_rules = self._extract_field_validation_rules(field_elem, form_name, file_path)
                    form_set.rules.extend(field_rules)
                
                # Analyze field dependencies
                form_set.field_dependencies = self._analyze_field_dependencies(form_set.rules)
                
                # Determine validation order
                form_set.validation_order = self._determine_validation_order(form_set.rules)
                
                # Determine business context
                form_set.business_context = self._determine_form_business_context(form_set)
                
                # Calculate complexity
                form_set.complexity_score = self._calculate_form_complexity(form_set)
                
                # Generate migration strategies
                form_set.angular_form_strategy = self._generate_angular_form_strategy(form_set)
                form_set.bean_validation_class = self._generate_bean_validation_class_name(form_set)
                
                form_sets.append(form_set)
                
            except Exception as e:
                logger.warning(f"Error parsing form validation set: {e}")
        
        return form_sets
    
    def _extract_field_validation_rules(self, field_elem: ET.Element, 
                                      form_name: str, file_path: Path) -> List[ValidationRule]:
        """Extract validation rules for a specific field."""
        rules = []
        field_name = field_elem.get('property', '')
        
        # Extract depends attribute (comma-separated list of validators)
        depends = field_elem.get('depends', '')
        if depends:
            validators = [v.strip() for v in depends.split(',')]
            for validator_type in validators:
                rule = ValidationRule(
                    rule_id=f"{form_name}_{field_name}_{validator_type}",
                    field_name=field_name,
                    property_path=field_name,
                    validator_type=validator_type,
                    form_name=form_name,
                    is_required=(validator_type == 'required')
                )
                
                # Extract parameters for this validator
                rule.parameters = self._extract_validator_parameters(field_elem, validator_type)
                
                # Extract message
                rule.message_key, rule.message_text = self._extract_validation_message(field_elem, validator_type)
                
                # Determine business reason
                rule.business_reason = self._determine_business_reason(rule)
                
                # Determine data type
                rule.data_type = self._infer_data_type(field_name, validator_type)
                
                # Check if custom validator
                rule.custom_validator = validator_type not in self._standard_validators
                
                # Generate Bean Validation equivalent
                rule.bean_validation_equivalent = self._generate_bean_validation_equivalent(rule)
                
                # Generate GraphQL constraint
                rule.graphql_constraint = self._generate_graphql_constraint(rule)
                
                rules.append(rule)
        
        # Extract individual validator elements
        for validator_elem in field_elem.findall('*'):
            if validator_elem.tag in ['msg', 'arg', 'var']:
                continue  # Skip message and parameter elements
                
            validator_type = validator_elem.tag
            rule = ValidationRule(
                rule_id=f"{form_name}_{field_name}_{validator_type}",
                field_name=field_name,
                property_path=field_name,
                validator_type=validator_type,
                form_name=form_name,
                is_required=(validator_type == 'required')
            )
            
            # Extract parameters from child elements
            rule.parameters = self._extract_element_parameters(validator_elem)
            
            # Extract message
            rule.message_key, rule.message_text = self._extract_element_message(validator_elem)
            
            # Fill in other properties
            rule.business_reason = self._determine_business_reason(rule)
            rule.data_type = self._infer_data_type(field_name, validator_type)
            rule.custom_validator = validator_type not in self._standard_validators
            rule.bean_validation_equivalent = self._generate_bean_validation_equivalent(rule)
            rule.graphql_constraint = self._generate_graphql_constraint(rule)
            
            rules.append(rule)
        
        return rules
    
    def _extract_validator_parameters(self, field_elem: ET.Element, validator_type: str) -> Dict[str, Any]:
        """Extract parameters for a specific validator from var elements."""
        parameters = {}
        
        for var_elem in field_elem.findall('var'):
            var_name_elem = var_elem.find('var-name')
            var_value_elem = var_elem.find('var-value')
            
            if var_name_elem is not None and var_value_elem is not None:
                var_name = var_name_elem.text
                var_value = var_value_elem.text
                
                # Check if this parameter belongs to the current validator
                if var_name and var_value and (not var_name.startswith(validator_type) or var_name == validator_type):
                    parameters[var_name] = var_value
        
        return parameters
    
    def _extract_element_parameters(self, validator_elem: ET.Element) -> Dict[str, Any]:
        """Extract parameters from validator element children."""
        parameters = {}
        
        for var_elem in validator_elem.findall('var'):
            var_name_elem = var_elem.find('var-name')
            var_value_elem = var_elem.find('var-value')
            
            if var_name_elem is not None and var_value_elem is not None:
                var_name = var_name_elem.text
                var_value = var_value_elem.text
                if var_name and var_value:
                    parameters[var_name] = var_value
        
        return parameters
    
    def _extract_validation_message(self, field_elem: ET.Element, validator_type: str) -> Tuple[str, str]:
        """Extract validation message for a specific validator."""
        # Look for msg elements with specific key
        for msg_elem in field_elem.findall('msg'):
            key = msg_elem.get('key', '')
            if validator_type in key or not key:
                return key, msg_elem.text or ""
        
        return "", ""
    
    def _extract_element_message(self, validator_elem: ET.Element) -> Tuple[str, str]:
        """Extract message from validator element."""
        msg_elem = validator_elem.find('msg')
        if msg_elem is not None:
            return msg_elem.get('key', ''), msg_elem.text or ""
        return "", ""
    
    def _determine_business_reason(self, rule: ValidationRule) -> str:
        """Determine the business reason for a validation rule."""
        field_name_lower = rule.field_name.lower()
        validator_type = rule.validator_type
        
        # Context-based reasons
        for context, patterns in self._business_context_patterns.items():
            if any(pattern in field_name_lower for pattern in patterns):
                if validator_type == 'required':
                    return f"Field {rule.field_name} is mandatory for {context} data integrity"
                elif validator_type in ['minlength', 'maxlength']:
                    return f"Length constraints ensure {context} data quality and system compatibility"
                elif validator_type == 'mask':
                    return f"Format validation ensures {context} data consistency"
                elif validator_type in ['email', 'url']:
                    return f"Format validation for {context} communication purposes"
        
        # General reasons by validator type
        validator_reasons = {
            'required': f"Field {rule.field_name} is mandatory for business process completion",
            'email': f"Email format validation for communication purposes",
            'minlength': f"Minimum length ensures data quality",
            'maxlength': f"Maximum length prevents data overflow and ensures compatibility",
            'range': f"Value range validation ensures business rule compliance",
            'min': f"Minimum value validation prevents invalid business data",
            'max': f"Maximum value validation prevents data overflow",
            'date': f"Date format validation for temporal business logic",
            'mask': f"Format validation ensures data consistency",
            'creditCard': f"Credit card validation for secure payment processing",
            'url': f"URL format validation for web resource references"
        }
        
        return validator_reasons.get(validator_type, f"Validation ensures data integrity for {rule.field_name}")
    
    def _infer_data_type(self, field_name: str, validator_type: str) -> str:
        """Infer the data type based on field name and validator."""
        field_name_lower = field_name.lower()
        
        # Type inference from validator
        type_mapping = {
            'integer': 'integer',
            'long': 'long',
            'short': 'short',
            'byte': 'byte',
            'float': 'float',
            'double': 'double',
            'date': 'date',
            'email': 'email',
            'url': 'url',
            'creditCard': 'string'
        }
        
        if validator_type in type_mapping:
            return type_mapping[validator_type]
        
        # Type inference from field name
        if any(keyword in field_name_lower for keyword in ['date', 'time', 'birth', 'expiry']):
            return 'date'
        elif any(keyword in field_name_lower for keyword in ['email', 'mail']):
            return 'email'
        elif any(keyword in field_name_lower for keyword in ['url', 'link', 'website']):
            return 'url'
        elif any(keyword in field_name_lower for keyword in ['amount', 'price', 'cost', 'salary']):
            return 'decimal'
        elif any(keyword in field_name_lower for keyword in ['id', 'number', 'count', 'quantity']):
            return 'integer'
        elif any(keyword in field_name_lower for keyword in ['phone', 'tel', 'zip', 'postal']):
            return 'string'
        else:
            return 'string'
    
    def _generate_bean_validation_equivalent(self, rule: ValidationRule) -> str:
        """Generate Bean Validation equivalent for the rule."""
        if rule.validator_type in self._standard_validators:
            standard_info = self._standard_validators[rule.validator_type]
            
            # Customize based on parameters
            bean_validation = standard_info['bean_validation']
            
            if rule.parameters:
                if rule.validator_type in ['minlength', 'maxlength'] and 'min' in rule.parameters:
                    bean_validation = f"@Size(min={rule.parameters.get('min', 0)}, max={rule.parameters.get('max', 255)})"
                elif rule.validator_type == 'range':
                    bean_validation = f"@Min({rule.parameters.get('min', 0)}) @Max({rule.parameters.get('max', 100)})"
                elif rule.validator_type == 'mask' and 'mask' in rule.parameters:
                    bean_validation = f"@Pattern(regexp=\"{rule.parameters['mask']}\")"
            
            return bean_validation
        else:
            return f"@CustomValidation(validator = {rule.validator_type.capitalize()}Validator.class)"
    
    def _generate_graphql_constraint(self, rule: ValidationRule) -> str:
        """Generate GraphQL constraint equivalent for the rule."""
        if rule.validator_type in self._standard_validators:
            standard_info = self._standard_validators[rule.validator_type]
            
            # Customize based on parameters
            graphql_constraint = standard_info['graphql']
            
            if rule.parameters:
                if rule.validator_type in ['minlength', 'maxlength']:
                    min_val = rule.parameters.get('min', 0)
                    max_val = rule.parameters.get('max', 255)
                    graphql_constraint = f"@constraint(minLength: {min_val}, maxLength: {max_val})"
                elif rule.validator_type == 'range':
                    min_val = rule.parameters.get('min', 0)
                    max_val = rule.parameters.get('max', 100)
                    graphql_constraint = f"@constraint(min: {min_val}, max: {max_val})"
                elif rule.validator_type == 'mask' and 'mask' in rule.parameters:
                    graphql_constraint = f"@constraint(pattern: \"{rule.parameters['mask']}\")"
            
            return graphql_constraint
        else:
            return f"@customConstraint(name: \"{rule.validator_type}\")"
    
    def _extract_global_validation_rules(self, root: ET.Element) -> List[ValidationRule]:
        """Extract global validation rules that apply to multiple forms."""
        global_rules = []
        
        # Look for global elements
        for global_elem in root.findall('.//global'):
            for validator_elem in global_elem.findall('*'):
                rule = ValidationRule(
                    rule_id=f"global_{validator_elem.tag}",
                    field_name="*",
                    property_path="*",
                    validator_type=validator_elem.tag,
                    form_name="*"
                )
                
                rule.parameters = self._extract_element_parameters(validator_elem)
                rule.message_key, rule.message_text = self._extract_element_message(validator_elem)
                rule.business_reason = f"Global {validator_elem.tag} validation applies to all forms"
                rule.bean_validation_equivalent = self._generate_bean_validation_equivalent(rule)
                rule.graphql_constraint = self._generate_graphql_constraint(rule)
                
                global_rules.append(rule)
        
        return global_rules
    
    def _analyze_field_dependencies(self, rules: List[ValidationRule]) -> Dict[str, List[str]]:
        """Analyze dependencies between form fields based on validation rules."""
        dependencies = {}
        
        for rule in rules:
            if rule.validator_type == 'requiredif':
                # Parse requiredif dependencies
                field_param = rule.parameters.get('field', '')
                if field_param:
                    if rule.field_name not in dependencies:
                        dependencies[rule.field_name] = []
                    dependencies[rule.field_name].append(field_param)
        
        return dependencies
    
    def _determine_validation_order(self, rules: List[ValidationRule]) -> List[str]:
        """Determine the optimal validation order for form fields."""
        # Simple ordering: required fields first, then others
        required_fields = [rule.field_name for rule in rules if rule.is_required]
        other_fields = [rule.field_name for rule in rules if not rule.is_required]
        
        return list(dict.fromkeys(required_fields + other_fields))  # Remove duplicates while preserving order
    
    def _determine_form_business_context(self, form_set: FormValidationSet) -> str:
        """Determine the business context of a form based on its validation rules."""
        field_names = [rule.field_name.lower() for rule in form_set.rules]
        
        # Analyze field patterns
        context_scores = {}
        for context, patterns in self._business_context_patterns.items():
            score = sum(1 for field in field_names if any(pattern in field for pattern in patterns))
            if score > 0:
                context_scores[context] = score
        
        if context_scores:
            dominant_context = max(context_scores, key=context_scores.get)
            return dominant_context.replace('_', ' ').title()
        
        return "General Data Validation"
    
    def _calculate_form_complexity(self, form_set: FormValidationSet) -> int:
        """Calculate complexity score for a form validation set."""
        complexity = 0
        
        # Base complexity from number of rules
        complexity += len(form_set.rules)
        
        # Add complexity for custom validators
        custom_rules = [rule for rule in form_set.rules if rule.custom_validator]
        complexity += len(custom_rules) * 2
        
        # Add complexity for dependencies
        complexity += len(form_set.field_dependencies) * 3
        
        # Add complexity for complex validators
        complex_validators = ['requiredif', 'mask', 'creditCard']
        complex_rules = [rule for rule in form_set.rules if rule.validator_type in complex_validators]
        complexity += len(complex_rules) * 2
        
        return complexity
    
    def _generate_angular_form_strategy(self, form_set: FormValidationSet) -> str:
        """Generate Angular form implementation strategy."""
        if form_set.complexity_score > 15:
            return "Angular Reactive Form with custom validators and complex validation patterns"
        elif form_set.field_dependencies:
            return "Angular Reactive Form with cross-field validators"
        elif any(rule.validator_type == 'requiredif' for rule in form_set.rules):
            return "Angular Reactive Form with conditional validators"
        else:
            return "Angular Reactive Form with standard validators"
    
    def _generate_bean_validation_class_name(self, form_set: FormValidationSet) -> str:
        """Generate Bean Validation class name for the form."""
        form_name = form_set.form_name
        if form_name.lower().endswith('form'):
            class_name = form_name[:-4]  # Remove 'form' suffix
        else:
            class_name = form_name
        
        return f"{class_name.capitalize()}ValidationDto"
    
    def _extract_business_rules(self, analysis: ValidationAnalysisResult, 
                              file_path: Path) -> List[BusinessRule]:
        """Extract business rules from validation analysis."""
        business_rules = []
        
        # Rules from form validation sets
        for form_set in analysis.form_validation_sets:
            # Create a rule for the form's validation requirements
            rule = BusinessRule(
                id="auto",
                name=f"Form Validation Requirements: {form_set.form_name}",
                description=f"Comprehensive validation rules for {form_set.form_name} form",
                rule_type=BusinessRuleType.VALIDATION,
                source=BusinessRuleSource.VALIDATION_XML,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    element_xpath=f"//form[@name='{form_set.form_name}']"
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"Form: {form_set.form_name} with {len(form_set.rules)} validation rules",
                    context=f"Validation configuration in {file_path.name}"
                ),
                business_context=form_set.business_context,
                business_rationale=f"Data integrity and business rule enforcement for {form_set.business_context}"
            )
            
            # Set complexity based on form complexity
            if form_set.complexity_score > 15:
                rule.complexity = BusinessRuleComplexity.CRITICAL
            elif form_set.complexity_score > 10:
                rule.complexity = BusinessRuleComplexity.COMPLEX
            elif form_set.complexity_score > 5:
                rule.complexity = BusinessRuleComplexity.MODERATE
            else:
                rule.complexity = BusinessRuleComplexity.SIMPLE
            
            business_rules.append(rule)
            
            # Create individual rules for complex validations
            complex_rules = [r for r in form_set.rules if r.validator_type in ['requiredif', 'mask', 'creditCard']]
            for validation_rule in complex_rules:
                business_rule = BusinessRule(
                    id="auto",
                    name=f"Complex Validation: {validation_rule.field_name}",
                    description=validation_rule.business_reason,
                    rule_type=BusinessRuleType.VALIDATION,
                    source=BusinessRuleSource.VALIDATION_XML,
                    location=BusinessRuleLocation(
                        file_path=str(file_path),
                        element_xpath=f"//field[@property='{validation_rule.field_name}']"
                    ),
                    evidence=BusinessRuleEvidence(
                        code_snippet=f"{validation_rule.validator_type} validation on {validation_rule.field_name}",
                        context=f"Field validation in {form_set.form_name}"
                    ),
                    business_context=validation_rule.business_reason,
                    complexity=BusinessRuleComplexity.COMPLEX if validation_rule.validator_type == 'requiredif' else BusinessRuleComplexity.MODERATE
                )
                business_rules.append(business_rule)
        
        # Rules from custom validators
        for custom_validator in analysis.custom_validators:
            rule = BusinessRule(
                id="auto",
                name=f"Custom Validator: {custom_validator.name}",
                description=f"Custom validation logic implemented in {custom_validator.classname}",
                rule_type=BusinessRuleType.VALIDATION,
                source=BusinessRuleSource.VALIDATION_XML,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    element_xpath=f"//validator[@name='{custom_validator.name}']"
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"Custom validator: {custom_validator.name}",
                    context=f"Custom validation logic in {custom_validator.classname}"
                ),
                business_context="Custom business rule validation",
                complexity=BusinessRuleComplexity.COMPLEX
            )
            business_rules.append(rule)
        
        return business_rules
    
    def _identify_data_integrity_constraints(self, analysis: ValidationAnalysisResult) -> List[str]:
        """Identify data integrity constraints from validation rules."""
        constraints = []
        
        # Collect all validation rules
        all_rules = []
        for form_set in analysis.form_validation_sets:
            all_rules.extend(form_set.rules)
        all_rules.extend(analysis.global_validation_rules)
        
        # Analyze constraint patterns
        constraint_patterns = {
            'referential_integrity': ['requiredif', 'depends'],
            'data_format_constraints': ['mask', 'email', 'url', 'date'],
            'business_range_constraints': ['range', 'min', 'max'],
            'length_constraints': ['minlength', 'maxlength'],
            'mandatory_data_constraints': ['required'],
            'type_safety_constraints': ['integer', 'long', 'float', 'double']
        }
        
        for constraint_type, validator_types in constraint_patterns.items():
            matching_rules = [rule for rule in all_rules if rule.validator_type in validator_types]
            if matching_rules:
                constraints.append(f"{constraint_type}: {len(matching_rules)} rules")
        
        # Identify cross-field constraints
        dependent_fields = []
        for form_set in analysis.form_validation_sets:
            if form_set.field_dependencies:
                dependent_fields.extend(form_set.field_dependencies.keys())
        
        if dependent_fields:
            constraints.append(f"cross_field_dependencies: {len(dependent_fields)} fields with dependencies")
        
        return constraints
    
    def _generate_migration_assessment(self, analysis: ValidationAnalysisResult) -> Dict[str, Any]:
        """Generate comprehensive migration assessment."""
        assessment = {
            'complexity_level': 'medium',
            'estimated_effort_hours': 0,
            'migration_approach': '',
            'bean_validation_strategy': '',
            'graphql_validation_strategy': '',
            'challenges': [],
            'benefits': [],
            'risk_factors': []
        }
        
        # Calculate complexity
        total_rules = sum(len(form_set.rules) for form_set in analysis.form_validation_sets)
        custom_validators = len(analysis.custom_validators)
        complex_forms = sum(1 for form_set in analysis.form_validation_sets if form_set.complexity_score > 10)
        
        complexity_score = total_rules + (custom_validators * 3) + (complex_forms * 2)
        
        if complexity_score > 50:
            assessment['complexity_level'] = 'critical'
        elif complexity_score > 30:
            assessment['complexity_level'] = 'high'
        elif complexity_score > 15:
            assessment['complexity_level'] = 'medium'
        else:
            assessment['complexity_level'] = 'low'
        
        # Estimate effort
        base_hours = 8  # Base setup
        base_hours += len(analysis.form_validation_sets) * 4  # Per form
        base_hours += total_rules * 0.5  # Per rule
        base_hours += custom_validators * 8  # Per custom validator
        
        assessment['estimated_effort_hours'] = base_hours
        
        # Migration approach
        if custom_validators > 0:
            assessment['migration_approach'] = 'Hybrid approach with custom Bean Validation constraints'
        else:
            assessment['migration_approach'] = 'Standard Bean Validation migration'
        
        # Bean Validation strategy
        assessment['bean_validation_strategy'] = 'Create DTO classes with Bean Validation annotations'
        
        # GraphQL validation strategy
        assessment['graphql_validation_strategy'] = 'Implement GraphQL custom scalars and directives for validation'
        
        # Identify challenges
        challenges = []
        if custom_validators > 0:
            challenges.append(f"Migration of {custom_validators} custom validators")
        
        if any(form_set.field_dependencies for form_set in analysis.form_validation_sets):
            challenges.append("Cross-field validation dependencies")
        
        complex_validations = sum(
            1 for form_set in analysis.form_validation_sets
            for rule in form_set.rules
            if rule.validator_type in ['requiredif', 'mask']
        )
        if complex_validations > 0:
            challenges.append(f"{complex_validations} complex validation rules")
        
        assessment['challenges'] = challenges
        
        # Benefits
        assessment['benefits'] = [
            'Type-safe validation with Bean Validation',
            'Consistent validation across layers',
            'Better IDE support and tooling',
            'Integration with Spring Boot ecosystem',
            'GraphQL schema-first validation'
        ]
        
        # Risk factors
        risk_factors = []
        if assessment['complexity_level'] in ['high', 'critical']:
            risk_factors.append('High complexity may lead to migration errors')
        
        if custom_validators > 3:
            risk_factors.append('Many custom validators require careful analysis')
        
        assessment['risk_factors'] = risk_factors
        
        return assessment
    
    def _generate_modernization_recommendations(self, analysis: ValidationAnalysisResult) -> List[str]:
        """Generate modernization recommendations."""
        recommendations = []
        
        # General recommendations
        recommendations.append("Migrate to Bean Validation (JSR-349) for consistent validation")
        recommendations.append("Implement GraphQL custom scalars for type-safe validation")
        
        # Form-specific recommendations
        for form_set in analysis.form_validation_sets:
            if form_set.complexity_score > 10:
                recommendations.append(f"Break down complex validation in {form_set.form_name} into smaller, focused validators")
            
            if form_set.field_dependencies:
                recommendations.append(f"Implement cross-field validators for {form_set.form_name}")
        
        # Custom validator recommendations
        if analysis.custom_validators:
            recommendations.append("Create custom Bean Validation constraint annotations for business-specific validators")
            recommendations.append("Implement server-side validation with client-side counterparts")
        
        # Technology-specific recommendations
        recommendations.append("Use Angular Reactive Forms with custom validators for client-side validation")
        recommendations.append("Implement validation error handling with internationalization support")
        recommendations.append("Consider validation groups for different scenarios (create, update, etc.)")
        
        return recommendations
    
    def _post_process_results(self, results: List[Dict[str, Any]], 
                            context: AnalysisContext) -> Dict[str, Any]:
        """
        Post-process and aggregate results from all validation files.
        
        Args:
            results: List of individual file analysis results
            context: Analysis context
            
        Returns:
            Aggregated and processed results
        """
        if not results:
            return {
                'validation_analyses': [],
                'summary': {
                    'total_validation_files': 0,
                    'total_forms': 0,
                    'total_validation_rules': 0,
                    'total_custom_validators': 0
                }
            }
        
        # Filter successful analyses
        successful_results = [r for r in results if 'error' not in r and r.get('validation_analysis')]
        validation_analyses = [r['validation_analysis'] for r in successful_results]
        
        # Aggregate metrics
        total_forms = sum(len(analysis.get('form_validation_sets', [])) for analysis in validation_analyses)
        total_rules = sum(
            sum(len(form_set.get('rules', [])) for form_set in analysis.get('form_validation_sets', []))
            for analysis in validation_analyses
        )
        total_custom_validators = sum(len(analysis.get('custom_validators', [])) for analysis in validation_analyses)
        
        # Analyze validation patterns
        validation_patterns = self._analyze_validation_patterns(validation_analyses)
        
        # Generate comprehensive migration plan
        migration_plan = self._generate_comprehensive_validation_migration_plan(validation_analyses)
        
        # Identify data quality requirements
        data_quality_requirements = self._identify_data_quality_requirements(validation_analyses)
        
        return {
            'validation_analyses': validation_analyses,
            'validation_patterns': validation_patterns,
            'migration_plan': migration_plan,
            'data_quality_requirements': data_quality_requirements,
            'summary': {
                'total_validation_files': len(validation_analyses),
                'total_forms': total_forms,
                'total_validation_rules': total_rules,
                'total_custom_validators': total_custom_validators,
                'total_business_rules': sum(len(analysis.get('business_rules', [])) for analysis in validation_analyses),
                'average_form_complexity': sum(
                    form_set.get('complexity_score', 0)
                    for analysis in validation_analyses
                    for form_set in analysis.get('form_validation_sets', [])
                ) / total_forms if total_forms > 0 else 0
            }
        }
    
    def _analyze_validation_patterns(self, validation_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns across all validation configurations."""
        patterns = {
            'common_validators': {},
            'business_domains': {},
            'complexity_distribution': {},
            'custom_validator_usage': {}
        }
        
        # Analyze common validators
        all_validators = []
        for analysis in validation_analyses:
            for form_set in analysis.get('form_validation_sets', []):
                for rule in form_set.get('rules', []):
                    all_validators.append(rule.get('validator_type', ''))
        
        validator_counts = {}
        for validator in all_validators:
            validator_counts[validator] = validator_counts.get(validator, 0) + 1
        
        patterns['common_validators'] = dict(
            sorted(validator_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        
        # Analyze business domains
        all_contexts = []
        for analysis in validation_analyses:
            for form_set in analysis.get('form_validation_sets', []):
                context = form_set.get('business_context', '')
                if context:
                    all_contexts.append(context)
        
        context_counts = {}
        for context in all_contexts:
            context_counts[context] = context_counts.get(context, 0) + 1
        
        patterns['business_domains'] = context_counts
        
        return patterns
    
    def _generate_comprehensive_validation_migration_plan(self, validation_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive validation migration plan."""
        plan = {
            'strategy': 'Layered Validation Architecture',
            'phases': [],
            'total_estimated_hours': 0,
            'technologies': {
                'backend_validation': 'Bean Validation (JSR-349)',
                'frontend_validation': 'Angular Reactive Forms',
                'api_validation': 'GraphQL Custom Scalars and Directives',
                'database_constraints': 'JPA/Hibernate Constraints'
            },
            'deliverables': []
        }
        
        # Calculate total effort
        total_hours = sum(
            analysis.get('migration_assessment', {}).get('estimated_effort_hours', 0)
            for analysis in validation_analyses
        )
        plan['total_estimated_hours'] = total_hours
        
        # Define phases
        plan['phases'] = [
            {
                'name': 'Validation Infrastructure Setup',
                'description': 'Set up Bean Validation and validation architecture',
                'estimated_hours': 20,
                'tasks': [
                    'Configure Bean Validation in Spring Boot',
                    'Set up validation error handling',
                    'Create validation utility classes',
                    'Configure internationalization for error messages'
                ]
            },
            {
                'name': 'Standard Validator Migration',
                'description': 'Migrate standard Struts validators to Bean Validation',
                'estimated_hours': total_hours * 0.4,
                'tasks': [
                    'Create DTO classes with Bean Validation annotations',
                    'Migrate standard validators (required, length, range, etc.)',
                    'Implement Angular form validators',
                    'Test validation consistency'
                ]
            },
            {
                'name': 'Custom Validator Migration',
                'description': 'Migrate custom validators and complex business rules',
                'estimated_hours': total_hours * 0.4,
                'tasks': [
                    'Analyze custom validator business logic',
                    'Create custom Bean Validation constraints',
                    'Implement corresponding Angular validators',
                    'Create GraphQL custom scalars'
                ]
            },
            {
                'name': 'Integration and Testing',
                'description': 'Integration testing and validation consistency verification',
                'estimated_hours': total_hours * 0.2,
                'tasks': [
                    'Cross-layer validation testing',
                    'Performance validation',
                    'Error message consistency verification',
                    'User experience testing'
                ]
            }
        ]
        
        return plan
    
    def _identify_data_quality_requirements(self, validation_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identify data quality requirements from validation rules."""
        requirements = {
            'data_completeness': [],
            'data_accuracy': [],
            'data_consistency': [],
            'data_validity': [],
            'business_rule_compliance': []
        }
        
        for analysis in validation_analyses:
            for form_set in analysis.get('form_validation_sets', []):
                for rule in form_set.get('rules', []):
                    validator_type = rule.get('validator_type', '')
                    field_name = rule.get('field_name', '')
                    business_reason = rule.get('business_reason', '')
                    
                    # Categorize requirements
                    if validator_type == 'required':
                        requirements['data_completeness'].append({
                            'field': field_name,
                            'form': form_set.get('form_name', ''),
                            'reason': business_reason
                        })
                    elif validator_type in ['email', 'url', 'date', 'creditCard']:
                        requirements['data_accuracy'].append({
                            'field': field_name,
                            'format': validator_type,
                            'reason': business_reason
                        })
                    elif validator_type in ['mask', 'range', 'min', 'max']:
                        requirements['data_validity'].append({
                            'field': field_name,
                            'constraint': validator_type,
                            'parameters': rule.get('parameters', {}),
                            'reason': business_reason
                        })
                    elif validator_type in ['requiredif']:
                        requirements['business_rule_compliance'].append({
                            'field': field_name,
                            'rule_type': validator_type,
                            'dependencies': rule.get('depends_on', []),
                            'reason': business_reason
                        })
        
        return requirements