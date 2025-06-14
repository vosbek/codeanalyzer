"""
Java Source Parser
==================

This parser handles Java source files, particularly Action classes and other
business logic components in Struts applications.

Features:
- AST-based Java parsing for accurate code analysis
- Business logic extraction from method implementations
- Comment analysis for business requirements
- Complexity metrics and dependency analysis
- Migration recommendations for GraphQL/Angular

Author: Claude Code Assistant
"""

import re
import ast
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime

try:
    import javalang
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False

from parsers.base_parser import BaseParser, ParseResult
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource,
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)


class JavaSourceParser(BaseParser):
    """Parser for Java source files in Struts applications."""
    
    def __init__(self):
        """Initialize Java parser."""
        super().__init__()
        self.supported_extensions = {'.java'}
        self.supported_patterns = ['action', 'form', 'bean', 'service', 'util']
        
        # Business logic indicators in Java code
        self.business_indicators = [
            'business rule', 'requirement', 'validation', 'constraint',
            'policy', 'process', 'workflow', 'calculate', 'validate',
            'authorize', 'authenticate', 'approve', 'reject'
        ]
        
        # Struts-specific patterns
        self.struts_patterns = {
            'action_class': ['extends Action', 'implements Action'],
            'form_class': ['extends ActionForm', 'extends ValidatorForm'],
            'interceptor': ['implements Interceptor', 'extends AbstractInterceptor']
        }
    
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the Java file."""
        if not self.supports_extension(file_path.suffix):
            return False
        
        # Check for Struts-related content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2000)  # Read first 2KB
                return any(pattern in content for patterns in self.struts_patterns.values() 
                          for pattern in patterns)
        except Exception:
            return False
    
    def get_priority(self) -> int:
        """Java parser has high priority for Java files."""
        return 85
    
    def parse_file(self, file_path: Path) -> ParseResult:
        """Parse Java source file."""
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
            
            if JAVALANG_AVAILABLE:
                self._parse_with_javalang(content, file_path, result)
            else:
                self._parse_with_regex(content, file_path, result)
            
            # Calculate parsing time
            end_time = datetime.now()
            result.parse_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
        except Exception as e:
            result.add_error(f"Error parsing Java file: {e}")
        
        return result
    
    def _parse_with_javalang(self, content: str, file_path: Path, result: ParseResult):
        """Parse Java using javalang AST parser."""
        try:
            tree = javalang.parse.parse(content)
            
            # Extract class information
            class_info = self._extract_class_info(tree, content, file_path)
            result.add_extracted_data('class_info', class_info)
            
            # Extract methods
            methods = self._extract_methods(tree, content, file_path)
            result.add_extracted_data('methods', methods)
            
            # Extract business rules from various sources
            self._extract_business_rules_from_ast(tree, content, file_path, result)
            
        except javalang.parser.JavaSyntaxError as e:
            result.add_warning(f"Java syntax error, falling back to regex parsing: {e}")
            self._parse_with_regex(content, file_path, result)
        except Exception as e:
            result.add_error(f"AST parsing failed: {e}")
            self._parse_with_regex(content, file_path, result)
    
    def _parse_with_regex(self, content: str, file_path: Path, result: ParseResult):
        """Fallback parsing using regular expressions."""
        # Extract class information
        class_info = self._extract_class_info_regex(content, file_path)
        result.add_extracted_data('class_info', class_info)
        
        # Extract methods
        methods = self._extract_methods_regex(content, file_path)
        result.add_extracted_data('methods', methods)
        
        # Extract business rules
        self._extract_business_rules_from_regex(content, file_path, result)
    
    def _extract_class_info(self, tree: javalang.tree.CompilationUnit, 
                           content: str, file_path: Path) -> Dict[str, Any]:
        """Extract class information from AST."""
        class_info = {
            'package': tree.package.name if tree.package else '',
            'imports': [imp.path for imp in tree.imports or []],
            'classes': []
        }
        
        for type_decl in tree.types or []:
            if isinstance(type_decl, javalang.tree.ClassDeclaration):
                class_data = {
                    'name': type_decl.name,
                    'modifiers': type_decl.modifiers or [],
                    'extends': type_decl.extends.name if type_decl.extends else None,
                    'implements': [impl.name for impl in type_decl.implements or []],
                    'is_action': self._is_struts_action(type_decl),
                    'is_form': self._is_struts_form(type_decl),
                    'is_interceptor': self._is_struts_interceptor(type_decl),
                    'fields': [],
                    'methods': []
                }
                
                # Extract fields
                for field in type_decl.fields or []:
                    for declarator in field.declarators:
                        class_data['fields'].append({
                            'name': declarator.name,
                            'type': str(field.type),
                            'modifiers': field.modifiers or []
                        })
                
                # Method names (detailed extraction done separately)
                for method in type_decl.methods or []:
                    class_data['methods'].append(method.name)
                
                class_info['classes'].append(class_data)
        
        return class_info
    
    def _extract_methods(self, tree: javalang.tree.CompilationUnit,
                        content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Extract method information from AST."""
        methods = []
        
        for type_decl in tree.types or []:
            if isinstance(type_decl, javalang.tree.ClassDeclaration):
                class_name = type_decl.name
                
                for method in type_decl.methods or []:
                    method_data = {
                        'class_name': class_name,
                        'name': method.name,
                        'modifiers': method.modifiers or [],
                        'return_type': str(method.return_type) if method.return_type else 'void',
                        'parameters': [],
                        'throws': [exc.name for exc in method.throws or []],
                        'is_execute_method': method.name in ['execute', 'perform'],
                        'is_validation_method': method.name.lower().startswith('validate'),
                        'complexity_indicators': [],
                        'business_logic_patterns': []
                    }
                    
                    # Extract parameters
                    for param in method.parameters or []:
                        method_data['parameters'].append({
                            'name': param.name,
                            'type': str(param.type)
                        })
                    
                    # Analyze method body for business logic
                    if method.body:
                        body_analysis = self._analyze_method_body(method.body, content)
                        method_data.update(body_analysis)
                    
                    methods.append(method_data)
        
        return methods
    
    def _extract_business_rules_from_ast(self, tree: javalang.tree.CompilationUnit,
                                       content: str, file_path: Path, result: ParseResult):
        """Extract business rules from AST analysis."""
        
        # Extract rules from comments
        comment_rules = self._extract_rules_from_comments(content, file_path)
        for rule in comment_rules:
            result.add_business_rule(rule)
        
        # Extract rules from class structure
        for type_decl in tree.types or []:
            if isinstance(type_decl, javalang.tree.ClassDeclaration):
                class_rules = self._extract_class_business_rules(type_decl, file_path)
                for rule in class_rules:
                    result.add_business_rule(rule)
                
                # Extract rules from methods
                for method in type_decl.methods or []:
                    method_rules = self._extract_method_business_rules(
                        method, type_decl.name, file_path, content
                    )
                    for rule in method_rules:
                        result.add_business_rule(rule)
    
    def _extract_class_info_regex(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Extract class information using regex."""
        class_info = {
            'package': '',
            'imports': [],
            'classes': []
        }
        
        # Extract package
        package_match = re.search(r'package\s+([\w.]+);', content)
        if package_match:
            class_info['package'] = package_match.group(1)
        
        # Extract imports
        import_matches = re.findall(r'import\s+([\w.*]+);', content)
        class_info['imports'] = import_matches
        
        # Extract class declarations
        class_pattern = r'public\s+class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?'
        class_matches = re.finditer(class_pattern, content)
        
        for match in class_matches:
            class_name = match.group(1)
            extends = match.group(2)
            implements = match.group(3).split(',') if match.group(3) else []
            implements = [impl.strip() for impl in implements]
            
            class_data = {
                'name': class_name,
                'extends': extends,
                'implements': implements,
                'is_action': extends and 'Action' in extends,
                'is_form': extends and 'Form' in extends,
                'is_interceptor': any('Interceptor' in impl for impl in implements)
            }
            
            class_info['classes'].append(class_data)
        
        return class_info
    
    def _extract_methods_regex(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Extract method information using regex."""
        methods = []
        
        # Method pattern
        method_pattern = r'(public|private|protected)\s+(?:static\s+)?(\w+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+([^{]+))?\s*{'
        method_matches = re.finditer(method_pattern, content)
        
        for match in method_matches:
            visibility = match.group(1)
            return_type = match.group(2)
            method_name = match.group(3)
            params = match.group(4)
            throws = match.group(5)
            
            method_data = {
                'name': method_name,
                'modifiers': [visibility],
                'return_type': return_type,
                'parameters': self._parse_parameters_regex(params),
                'throws': throws.split(',') if throws else [],
                'is_execute_method': method_name in ['execute', 'perform'],
                'is_validation_method': method_name.lower().startswith('validate')
            }
            
            methods.append(method_data)
        
        return methods
    
    def _parse_parameters_regex(self, params_str: str) -> List[Dict[str, str]]:
        """Parse method parameters from string."""
        if not params_str.strip():
            return []
        
        parameters = []
        param_parts = params_str.split(',')
        
        for part in param_parts:
            part = part.strip()
            if part:
                # Simple parsing: type name
                tokens = part.split()
                if len(tokens) >= 2:
                    param_type = ' '.join(tokens[:-1])
                    param_name = tokens[-1]
                    parameters.append({
                        'name': param_name,
                        'type': param_type
                    })
        
        return parameters
    
    def _extract_business_rules_from_regex(self, content: str, file_path: Path, result: ParseResult):
        """Extract business rules using regex patterns."""
        
        # Extract rules from comments
        comment_rules = self._extract_rules_from_comments(content, file_path)
        for rule in comment_rules:
            result.add_business_rule(rule)
        
        # Extract rules from method patterns
        self._extract_validation_method_rules(content, file_path, result)
        self._extract_execute_method_rules(content, file_path, result)
    
    def _extract_rules_from_comments(self, content: str, file_path: Path) -> List[BusinessRule]:
        """Extract business rules from Java comments."""
        rules = []
        
        # Javadoc comments
        javadoc_pattern = r'/\*\*(.*?)\*/'
        javadoc_matches = re.findall(javadoc_pattern, content, re.DOTALL)
        
        for i, comment in enumerate(javadoc_matches):
            # Clean up comment
            lines = comment.split('\n')
            clean_lines = []
            for line in lines:
                clean_line = line.strip().lstrip('*').strip()
                if clean_line:
                    clean_lines.append(clean_line)
            
            comment_text = ' '.join(clean_lines)
            
            # Check for business rule indicators
            if any(indicator in comment_text.lower() for indicator in self.business_indicators):
                rule_id = self._generate_rule_id('comment', str(i))
                
                rule = self._create_business_rule(
                    rule_id=rule_id,
                    name=f"Business Rule from Comment {i+1}",
                    description=comment_text,
                    rule_type=BusinessRuleType.BUSINESS_LOGIC,
                    source=BusinessRuleSource.COMMENT,
                    file_path=file_path,
                    business_context="Documented business requirement",
                    code_snippet=comment_text[:200] + "..." if len(comment_text) > 200 else comment_text,
                    confidence_score=0.9
                )
                
                rule.add_tag('comment')
                rule.add_tag('documentation')
                
                rules.append(rule)
        
        return rules
    
    def _extract_class_business_rules(self, class_decl: javalang.tree.ClassDeclaration,
                                    file_path: Path) -> List[BusinessRule]:
        """Extract business rules from class structure."""
        rules = []
        
        if self._is_struts_action(class_decl):
            rule_id = self._generate_rule_id('action_class', class_decl.name)
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Action Class: {class_decl.name}",
                description=f"Struts Action class implementing business workflow",
                rule_type=BusinessRuleType.WORKFLOW,
                source=BusinessRuleSource.ACTION_CLASS,
                file_path=file_path,
                business_context=self._infer_action_business_context(class_decl.name),
                code_snippet=f"public class {class_decl.name} extends {class_decl.extends.name if class_decl.extends else 'Action'}",
                complexity=BusinessRuleComplexity.MODERATE
            )
            
            rule.add_tag('action_class')
            rule.add_tag('struts')
            rule.add_tag('workflow')
            
            rules.append(rule)
        
        elif self._is_struts_form(class_decl):
            rule_id = self._generate_rule_id('form_class', class_decl.name)
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Form Bean: {class_decl.name}",
                description=f"Struts Form Bean for data binding and validation",
                rule_type=BusinessRuleType.DATA,
                source=BusinessRuleSource.FORM_BEAN,
                file_path=file_path,
                business_context=self._infer_form_business_context(class_decl.name),
                code_snippet=f"public class {class_decl.name} extends {class_decl.extends.name if class_decl.extends else 'ActionForm'}",
                complexity=BusinessRuleComplexity.SIMPLE
            )
            
            rule.add_tag('form_bean')
            rule.add_tag('data_binding')
            rule.add_tag('validation')
            
            rules.append(rule)
        
        return rules
    
    def _extract_method_business_rules(self, method: javalang.tree.MethodDeclaration,
                                     class_name: str, file_path: Path, content: str) -> List[BusinessRule]:
        """Extract business rules from method implementation."""
        rules = []
        
        if method.name in ['execute', 'perform']:
            rule_id = self._generate_rule_id('execute_method', class_name, method.name)
            
            # Analyze method complexity
            complexity = self._analyze_method_complexity(method, content)
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Action Execution: {class_name}.{method.name}",
                description=f"Main business logic execution in {class_name}",
                rule_type=BusinessRuleType.WORKFLOW,
                source=BusinessRuleSource.METHOD_BODY,
                file_path=file_path,
                business_context="Primary action processing logic",
                code_snippet=f"public ActionForward {method.name}(...)",
                complexity=complexity,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    class_name=class_name,
                    method_name=method.name
                )
            )
            
            rule.add_tag('execute_method')
            rule.add_tag('action_logic')
            rule.add_tag('business_process')
            
            rules.append(rule)
        
        elif method.name.lower().startswith('validate'):
            rule_id = self._generate_rule_id('validation_method', class_name, method.name)
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Validation Logic: {class_name}.{method.name}",
                description=f"Business validation logic in {method.name}",
                rule_type=BusinessRuleType.VALIDATION,
                source=BusinessRuleSource.METHOD_BODY,
                file_path=file_path,
                business_context="Data validation and business constraint enforcement",
                code_snippet=f"public ActionErrors {method.name}(...)",
                complexity=BusinessRuleComplexity.MODERATE,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    class_name=class_name,
                    method_name=method.name
                )
            )
            
            rule.add_tag('validation')
            rule.add_tag('business_constraints')
            rule.add_tag('data_integrity')
            
            rules.append(rule)
        
        return rules
    
    def _extract_validation_method_rules(self, content: str, file_path: Path, result: ParseResult):
        """Extract business rules from validation methods using regex."""
        validation_pattern = r'public\s+ActionErrors\s+validate\w*\s*\([^)]*\)\s*{'
        matches = re.finditer(validation_pattern, content)
        
        for i, match in enumerate(matches):
            rule_id = self._generate_rule_id('validation_regex', str(i))
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Validation Method {i+1}",
                description="Business validation logic implementation",
                rule_type=BusinessRuleType.VALIDATION,
                source=BusinessRuleSource.METHOD_BODY,
                file_path=file_path,
                business_context="Data validation and constraint enforcement",
                code_snippet=match.group(0)
            )
            
            rule.add_tag('validation')
            rule.add_tag('method')
            
            result.add_business_rule(rule)
    
    def _extract_execute_method_rules(self, content: str, file_path: Path, result: ParseResult):
        """Extract business rules from execute methods using regex."""
        execute_pattern = r'public\s+ActionForward\s+(execute|perform)\s*\([^)]*\)\s*{'
        matches = re.finditer(execute_pattern, content)
        
        for i, match in enumerate(matches):
            method_name = match.group(1)
            rule_id = self._generate_rule_id('execute_regex', method_name, str(i))
            
            rule = self._create_business_rule(
                rule_id=rule_id,
                name=f"Action Execution: {method_name}",
                description="Primary business logic execution method",
                rule_type=BusinessRuleType.WORKFLOW,
                source=BusinessRuleSource.METHOD_BODY,
                file_path=file_path,
                business_context="Main action processing workflow",
                code_snippet=match.group(0)
            )
            
            rule.add_tag('execute_method')
            rule.add_tag('workflow')
            rule.add_tag('action_logic')
            
            result.add_business_rule(rule)
    
    def _is_struts_action(self, class_decl: javalang.tree.ClassDeclaration) -> bool:
        """Check if class is a Struts Action."""
        if class_decl.extends and 'Action' in class_decl.extends.name:
            return True
        
        for impl in class_decl.implements or []:
            if 'Action' in impl.name:
                return True
        
        return False
    
    def _is_struts_form(self, class_decl: javalang.tree.ClassDeclaration) -> bool:
        """Check if class is a Struts Form."""
        if class_decl.extends:
            extends_name = class_decl.extends.name
            return any(form_type in extends_name for form_type in ['ActionForm', 'ValidatorForm', 'DynaActionForm'])
        
        return False
    
    def _is_struts_interceptor(self, class_decl: javalang.tree.ClassDeclaration) -> bool:
        """Check if class is a Struts Interceptor."""
        for impl in class_decl.implements or []:
            if 'Interceptor' in impl.name:
                return True
        
        if class_decl.extends and 'Interceptor' in class_decl.extends.name:
            return True
        
        return False
    
    def _analyze_method_body(self, method_body, content: str) -> Dict[str, Any]:
        """Analyze method body for business logic indicators."""
        analysis = {
            'complexity_indicators': [],
            'business_logic_patterns': []
        }
        
        # Convert AST to string for analysis (simplified)
        body_str = str(method_body) if method_body else ""
        
        # Complexity indicators
        if 'if' in body_str:
            analysis['complexity_indicators'].append('conditional_logic')
        if 'for' in body_str or 'while' in body_str:
            analysis['complexity_indicators'].append('loops')
        if 'try' in body_str:
            analysis['complexity_indicators'].append('exception_handling')
        
        # Business logic patterns
        if any(pattern in body_str.lower() for pattern in ['validate', 'check', 'verify']):
            analysis['business_logic_patterns'].append('validation')
        if any(pattern in body_str.lower() for pattern in ['calculate', 'compute', 'total']):
            analysis['business_logic_patterns'].append('calculation')
        if any(pattern in body_str.lower() for pattern in ['save', 'update', 'delete', 'create']):
            analysis['business_logic_patterns'].append('data_operation')
        
        return analysis
    
    def _analyze_method_complexity(self, method: javalang.tree.MethodDeclaration, 
                                 content: str) -> BusinessRuleComplexity:
        """Analyze method complexity."""
        complexity_score = 1  # Base complexity
        
        if method.parameters:
            complexity_score += len(method.parameters)
        
        if method.throws:
            complexity_score += len(method.throws) * 2
        
        # Analyze method body (simplified)
        if method.body:
            body_str = str(method.body)
            
            # Count control flow statements
            complexity_score += body_str.count('if')
            complexity_score += body_str.count('for')
            complexity_score += body_str.count('while')
            complexity_score += body_str.count('switch')
            complexity_score += body_str.count('try')
        
        if complexity_score <= 3:
            return BusinessRuleComplexity.SIMPLE
        elif complexity_score <= 7:
            return BusinessRuleComplexity.MODERATE
        elif complexity_score <= 15:
            return BusinessRuleComplexity.COMPLEX
        else:
            return BusinessRuleComplexity.CRITICAL
    
    def _infer_action_business_context(self, class_name: str) -> str:
        """Infer business context from Action class name."""
        name_lower = class_name.lower()
        
        if any(word in name_lower for word in ['login', 'auth', 'signin']):
            return "User Authentication and Security"
        elif any(word in name_lower for word in ['search', 'find', 'lookup']):
            return "Data Search and Retrieval"
        elif any(word in name_lower for word in ['create', 'add', 'new']):
            return "Data Creation and Management"
        elif any(word in name_lower for word in ['edit', 'update', 'modify']):
            return "Data Modification and Updates"
        elif any(word in name_lower for word in ['delete', 'remove']):
            return "Data Deletion and Cleanup"
        elif any(word in name_lower for word in ['report', 'export']):
            return "Reporting and Analytics"
        elif any(word in name_lower for word in ['order', 'purchase', 'payment']):
            return "Order Processing and Commerce"
        else:
            return f"Business Process Implementation: {class_name}"
    
    def _infer_form_business_context(self, class_name: str) -> str:
        """Infer business context from Form class name."""
        name_lower = class_name.lower()
        
        if any(word in name_lower for word in ['login', 'auth']):
            return "Authentication Form Data"
        elif any(word in name_lower for word in ['search', 'filter']):
            return "Search and Filter Criteria"
        elif any(word in name_lower for word in ['user', 'customer', 'person']):
            return "User Information Management"
        elif any(word in name_lower for word in ['order', 'purchase']):
            return "Order Processing Data"
        elif any(word in name_lower for word in ['product', 'item']):
            return "Product Management Data"
        else:
            return f"Data Structure: {class_name}"