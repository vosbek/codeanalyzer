import sys
sys.path.append('..')

"""
Interceptor Analyzer
====================

This module analyzes Struts interceptors and interceptor chains to extract
business logic, security rules, and cross-cutting concerns that are often
critical for application functionality but easy to miss during migration.

Features:
- Interceptor configuration analysis from struts.xml
- Custom interceptor class analysis
- Interceptor chain mapping and dependency analysis
- Cross-cutting concern identification (security, logging, validation)
- Business rule extraction from interceptor logic
- Migration recommendations for Spring Boot/GraphQL middleware

Author: Claude Code Assistant
"""

import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
import hashlib

try:
    import javalang
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False

from analyzers.base_analyzer import BaseAnalyzer, AnalysisContext
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource, 
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)
from utils.logging_utils import get_logger


logger = get_logger(__name__)


@dataclass
class InterceptorDefinition:
    """Represents an interceptor definition."""
    name: str
    class_name: str
    file_path: str
    is_custom: bool = True
    parameters: Dict[str, str] = field(default_factory=dict)
    description: str = ""
    business_purpose: str = ""
    cross_cutting_concerns: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    affects: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'class_name': self.class_name,
            'file_path': self.file_path,
            'is_custom': self.is_custom,
            'parameters': self.parameters,
            'description': self.description,
            'business_purpose': self.business_purpose,
            'cross_cutting_concerns': self.cross_cutting_concerns,
            'depends_on': self.depends_on,
            'affects': self.affects
        }


@dataclass
class InterceptorStack:
    """Represents an interceptor stack configuration."""
    name: str
    interceptors: List[str] = field(default_factory=list)
    file_path: str = ""
    business_purpose: str = ""
    execution_order: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'interceptors': self.interceptors,
            'file_path': self.file_path,
            'business_purpose': self.business_purpose,
            'execution_order': self.execution_order
        }


@dataclass
class InterceptorChain:
    """Represents a complete interceptor chain for actions."""
    action_pattern: str
    chain: List[str] = field(default_factory=list)
    stack_refs: List[str] = field(default_factory=list)
    business_impact: str = ""
    security_implications: List[str] = field(default_factory=list)
    performance_impact: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'action_pattern': self.action_pattern,
            'chain': self.chain,
            'stack_refs': self.stack_refs,
            'business_impact': self.business_impact,
            'security_implications': self.security_implications,
            'performance_impact': self.performance_impact
        }


class InterceptorAnalyzer(BaseAnalyzer):
    """
    Analyzer for Struts interceptors and interceptor configurations.
    """
    
    def _initialize_analyzer(self) -> None:
        """Initialize interceptor analyzer settings."""
        self._supported_extensions = {'.xml', '.java'}
        self._required_patterns = []
        
        # Built-in Struts interceptors
        self._builtin_interceptors = {
            'alias', 'autowiring', 'chain', 'checkbox', 'cookie', 'conversionError',
            'createSession', 'debugging', 'exception', 'fileUpload', 'i18n',
            'logger', 'modelDriven', 'params', 'prepare', 'scopedModelDriven',
            'servletConfig', 'staticParams', 'timer', 'token', 'tokenSession',
            'validation', 'workflow', 'store', 'clearSession', 'roles'
        }
        
        # Cross-cutting concern patterns
        self._concern_patterns = {
            'security': ['auth', 'security', 'permission', 'role', 'token', 'session'],
            'validation': ['validation', 'validate', 'check', 'verify'],
            'transaction': ['transaction', 'tx', 'commit', 'rollback'],
            'logging': ['log', 'audit', 'trace', 'monitor'],
            'caching': ['cache', 'cached', 'store', 'retrieve'],
            'internationalization': ['i18n', 'locale', 'message', 'text'],
            'performance': ['timer', 'profiling', 'benchmark', 'metric']
        }
    
    def can_analyze(self, file_path: Path) -> bool:
        """Check if this file contains interceptor configurations or classes."""
        if file_path.suffix.lower() == '.xml':
            # Check if it's a struts configuration file
            filename = file_path.name.lower()
            return any(name in filename for name in ['struts', 'interceptor'])
        elif file_path.suffix.lower() == '.java':
            # Check if it's an interceptor class
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2000)  # Read first 2KB
                    return ('Interceptor' in content and 
                            ('implements' in content or 'extends' in content))
            except Exception:
                return False
        return False
    
    def _analyze_file(self, file_path: Path, context: AnalysisContext) -> Dict[str, Any]:
        """Analyze a file for interceptor configurations or implementations."""
        if file_path.suffix.lower() == '.xml':
            return self._analyze_xml_config(file_path)
        elif file_path.suffix.lower() == '.java':
            return self._analyze_interceptor_class(file_path)
        else:
            return {}
    
    def _analyze_xml_config(self, file_path: Path) -> Dict[str, Any]:
        """Analyze XML configuration file for interceptor definitions."""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            interceptor_definitions = []
            interceptor_stacks = []
            action_interceptors = []
            business_rules = []
            
            # Find interceptor definitions
            for interceptor in root.findall('.//interceptor'):
                definition = self._parse_interceptor_definition(interceptor, file_path)
                interceptor_definitions.append(definition)
                
                # Extract business rules from interceptor configuration
                rules = self._extract_interceptor_business_rules(definition, file_path)
                business_rules.extend(rules)
            
            # Find interceptor stacks
            for stack in root.findall('.//interceptor-stack'):
                stack_def = self._parse_interceptor_stack(stack, file_path)
                interceptor_stacks.append(stack_def)
            
            # Find action-level interceptor references
            for action in root.findall('.//action'):
                action_interceptors.extend(
                    self._parse_action_interceptors(action, file_path)
                )
            
            return {
                'file_path': str(file_path),
                'interceptor_definitions': [i.to_dict() for i in interceptor_definitions],
                'interceptor_stacks': [s.to_dict() for s in interceptor_stacks],
                'action_interceptors': [a.to_dict() for a in action_interceptors],
                'business_rules': [r.to_dict() for r in business_rules]
            }
            
        except Exception as e:
            logger.error(f"Error analyzing XML interceptor config {file_path}: {e}")
            return {}
    
    def _analyze_interceptor_class(self, file_path: Path) -> Dict[str, Any]:
        """Analyze Java interceptor class implementation."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if JAVALANG_AVAILABLE:
                return self._analyze_java_interceptor_ast(content, file_path)
            else:
                return self._analyze_java_interceptor_regex(content, file_path)
                
        except Exception as e:
            logger.error(f"Error analyzing Java interceptor class {file_path}: {e}")
            return {}
    
    def _parse_interceptor_definition(self, interceptor_elem: ET.Element, 
                                    file_path: Path) -> InterceptorDefinition:
        """Parse interceptor definition from XML element."""
        name = interceptor_elem.get('name', '')
        class_name = interceptor_elem.get('class', '')
        
        definition = InterceptorDefinition(
            name=name,
            class_name=class_name,
            file_path=str(file_path),
            is_custom=(name not in self._builtin_interceptors)
        )
        
        # Parse parameters
        for param in interceptor_elem.findall('param'):
            param_name = param.get('name', '')
            param_value = param.text or ''
            definition.parameters[param_name] = param_value
        
        # Infer business purpose and concerns
        definition.business_purpose = self._infer_interceptor_purpose(definition)
        definition.cross_cutting_concerns = self._identify_cross_cutting_concerns(definition)
        
        return definition
    
    def _parse_interceptor_stack(self, stack_elem: ET.Element, 
                               file_path: Path) -> InterceptorStack:
        """Parse interceptor stack definition from XML element."""
        name = stack_elem.get('name', '')
        
        stack = InterceptorStack(
            name=name,
            file_path=str(file_path)
        )
        
        # Parse interceptor references
        for interceptor_ref in stack_elem.findall('.//interceptor-ref'):
            interceptor_name = interceptor_ref.get('name', '')
            if interceptor_name:
                stack.interceptors.append(interceptor_name)
                stack.execution_order.append(interceptor_name)
        
        # Infer business purpose
        stack.business_purpose = self._infer_stack_purpose(stack)
        
        return stack
    
    def _parse_action_interceptors(self, action_elem: ET.Element, 
                                 file_path: Path) -> List[InterceptorChain]:
        """Parse interceptor chains for specific actions."""
        chains = []
        action_path = action_elem.get('path', '')
        
        interceptor_refs = []
        stack_refs = []
        
        # Find direct interceptor references
        for interceptor_ref in action_elem.findall('.//interceptor-ref'):
            ref_name = interceptor_ref.get('name', '')
            if ref_name:
                if ref_name.endswith('Stack'):
                    stack_refs.append(ref_name)
                else:
                    interceptor_refs.append(ref_name)
        
        if interceptor_refs or stack_refs:
            chain = InterceptorChain(
                action_pattern=action_path,
                chain=interceptor_refs,
                stack_refs=stack_refs
            )
            
            # Analyze business impact
            chain.business_impact = self._analyze_chain_business_impact(chain)
            chain.security_implications = self._analyze_security_implications(chain)
            chain.performance_impact = self._analyze_performance_impact(chain)
            
            chains.append(chain)
        
        return chains
    
    def _infer_interceptor_purpose(self, definition: InterceptorDefinition) -> str:
        """Infer the business purpose of an interceptor."""
        name_lower = definition.name.lower()
        class_lower = definition.class_name.lower()
        
        if any(word in name_lower or word in class_lower 
               for word in ['auth', 'security', 'permission', 'role']):
            return "Security and Access Control"
        elif any(word in name_lower or word in class_lower 
                for word in ['validation', 'validate']):
            return "Data Validation and Business Rules"
        elif any(word in name_lower or word in class_lower 
                for word in ['log', 'audit', 'trace']):
            return "Auditing and Compliance"
        elif any(word in name_lower or word in class_lower 
                for word in ['cache', 'performance']):
            return "Performance Optimization"
        elif any(word in name_lower or word in class_lower 
                for word in ['transaction', 'tx']):
            return "Transaction Management"
        elif any(word in name_lower or word in class_lower 
                for word in ['i18n', 'locale']):
            return "Internationalization"
        else:
            return "Cross-cutting Business Concern"
    
    def _identify_cross_cutting_concerns(self, definition: InterceptorDefinition) -> List[str]:
        """Identify cross-cutting concerns addressed by the interceptor."""
        concerns = []
        name_lower = definition.name.lower()
        class_lower = definition.class_name.lower()
        
        for concern, keywords in self._concern_patterns.items():
            if any(keyword in name_lower or keyword in class_lower 
                   for keyword in keywords):
                concerns.append(concern)
        
        # Check parameters for additional clues
        for param_name, param_value in definition.parameters.items():
            param_lower = f"{param_name} {param_value}".lower()
            for concern, keywords in self._concern_patterns.items():
                if any(keyword in param_lower for keyword in keywords):
                    if concern not in concerns:
                        concerns.append(concern)
        
        return concerns
    
    def _infer_stack_purpose(self, stack: InterceptorStack) -> str:
        """Infer the business purpose of an interceptor stack."""
        name_lower = stack.name.lower()
        
        if 'default' in name_lower:
            return "Standard application processing pipeline"
        elif 'secure' in name_lower or 'auth' in name_lower:
            return "Secured action processing with authentication"
        elif 'json' in name_lower or 'ajax' in name_lower:
            return "AJAX/JSON request processing"
        elif 'upload' in name_lower or 'file' in name_lower:
            return "File upload processing pipeline"
        elif 'validation' in name_lower:
            return "Data validation and business rule enforcement"
        else:
            return f"Specialized processing pipeline: {stack.name}"
    
    def _analyze_chain_business_impact(self, chain: InterceptorChain) -> str:
        """Analyze the business impact of an interceptor chain."""
        impacts = []
        
        for interceptor_name in chain.chain + chain.stack_refs:
            name_lower = interceptor_name.lower()
            
            if any(word in name_lower for word in ['auth', 'security', 'permission']):
                impacts.append("Security enforcement")
            if any(word in name_lower for word in ['validation', 'validate']):
                impacts.append("Business rule validation")
            if any(word in name_lower for word in ['transaction', 'tx']):
                impacts.append("Data consistency")
            if any(word in name_lower for word in ['audit', 'log']):
                impacts.append("Compliance tracking")
        
        return "; ".join(impacts) if impacts else "Standard request processing"
    
    def _analyze_security_implications(self, chain: InterceptorChain) -> List[str]:
        """Analyze security implications of an interceptor chain."""
        implications = []
        
        for interceptor_name in chain.chain + chain.stack_refs:
            name_lower = interceptor_name.lower()
            
            if 'token' in name_lower:
                implications.append("CSRF protection via token validation")
            if 'auth' in name_lower or 'login' in name_lower:
                implications.append("Authentication requirement")
            if 'role' in name_lower or 'permission' in name_lower:
                implications.append("Authorization and access control")
            if 'session' in name_lower:
                implications.append("Session management and validation")
            if 'ssl' in name_lower or 'secure' in name_lower:
                implications.append("Secure communication requirement")
        
        return implications
    
    def _analyze_performance_impact(self, chain: InterceptorChain) -> str:
        """Analyze performance impact of an interceptor chain."""
        total_interceptors = len(chain.chain) + len(chain.stack_refs)
        
        heavy_interceptors = []
        for interceptor_name in chain.chain + chain.stack_refs:
            name_lower = interceptor_name.lower()
            if any(word in name_lower for word in ['file', 'upload', 'validation', 'transaction']):
                heavy_interceptors.append(interceptor_name)
        
        if len(heavy_interceptors) > 2:
            return "high"
        elif len(heavy_interceptors) > 0 or total_interceptors > 5:
            return "medium"
        else:
            return "low"
    
    def _extract_interceptor_business_rules(self, definition: InterceptorDefinition, 
                                          file_path: Path) -> List[BusinessRule]:
        """Extract business rules from interceptor configuration."""
        business_rules = []
        
        # Create business rule for custom interceptors with business logic
        if definition.is_custom and definition.cross_cutting_concerns:
            rule_id = f"interceptor_{hashlib.md5(f'{file_path}_{definition.name}'.encode()).hexdigest()[:12]}"
            
            description = f"Interceptor {definition.name} implements {definition.business_purpose}"
            if definition.parameters:
                param_desc = ", ".join([f"{k}={v}" for k, v in definition.parameters.items()])
                description += f" with parameters: {param_desc}"
            
            business_rule = BusinessRule(
                id=rule_id,
                name=f"Interceptor Business Logic: {definition.name}",
                description=description,
                rule_type=self._determine_rule_type(definition),
                source=BusinessRuleSource.INTERCEPTOR,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    class_name=definition.class_name
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"Interceptor: {definition.name} -> {definition.class_name}",
                    context=definition.business_purpose,
                    confidence_score=0.8
                ),
                business_context=definition.business_purpose,
                complexity=BusinessRuleComplexity.MODERATE if len(definition.parameters) > 2 else BusinessRuleComplexity.SIMPLE
            )
            
            # Add tags based on cross-cutting concerns
            for concern in definition.cross_cutting_concerns:
                business_rule.add_tag(concern)
            business_rule.add_tag("interceptor")
            business_rule.add_tag("cross_cutting")
            
            business_rules.append(business_rule)
        
        return business_rules
    
    def _determine_rule_type(self, definition: InterceptorDefinition) -> BusinessRuleType:
        """Determine the business rule type based on interceptor concerns."""
        concerns = definition.cross_cutting_concerns
        
        if 'security' in concerns:
            return BusinessRuleType.SECURITY
        elif 'validation' in concerns:
            return BusinessRuleType.VALIDATION
        elif 'transaction' in concerns:
            return BusinessRuleType.DATA
        else:
            return BusinessRuleType.BUSINESS_LOGIC
    
    def _analyze_java_interceptor_ast(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Analyze Java interceptor class using AST parsing."""
        try:
            tree = javalang.parse.parse(content)
            
            class_info = None
            methods = []
            business_rules = []
            
            for type_decl in tree.types:
                if isinstance(type_decl, javalang.tree.ClassDeclaration):
                    class_info = {
                        'name': type_decl.name,
                        'package': tree.package.name if tree.package else '',
                        'extends': type_decl.extends.name if type_decl.extends else None,
                        'implements': [impl.name for impl in type_decl.implements or []],
                        'is_interceptor': self._is_interceptor_class(type_decl)
                    }
                    
                    # Analyze methods
                    for method in type_decl.methods or []:
                        method_analysis = self._analyze_interceptor_method(method, type_decl.name, file_path)
                        methods.append(method_analysis)
                        
                        # Extract business rules from significant methods
                        if method.name in ['intercept', 'execute', 'preProcess', 'postProcess']:
                            rule = self._create_method_business_rule(method, type_decl.name, file_path)
                            if rule:
                                business_rules.append(rule)
            
            return {
                'file_path': str(file_path),
                'class_info': class_info,
                'methods': methods,
                'business_rules': [r.to_dict() for r in business_rules]
            }
            
        except Exception as e:
            logger.error(f"Error parsing Java interceptor with AST {file_path}: {e}")
            return self._analyze_java_interceptor_regex(content, file_path)
    
    def _analyze_java_interceptor_regex(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Fallback analysis using regex patterns."""
        # Extract class name
        class_match = re.search(r'public\s+class\s+(\w+)', content)
        class_name = class_match.group(1) if class_match else file_path.stem
        
        # Find interceptor interface implementations
        implements_interceptor = bool(re.search(r'implements\s+.*Interceptor', content))
        extends_interceptor = bool(re.search(r'extends\s+.*Interceptor', content))
        
        # Extract method signatures
        method_pattern = r'public\s+\w+\s+(\w+)\s*\([^)]*\)\s*{'
        methods = re.findall(method_pattern, content)
        
        business_rules = []
        
        # Create business rule for interceptor classes
        if implements_interceptor or extends_interceptor:
            rule_id = f"interceptor_class_{hashlib.md5(str(file_path).encode()).hexdigest()[:12]}"
            
            business_rule = BusinessRule(
                id=rule_id,
                name=f"Custom Interceptor: {class_name}",
                description=f"Custom interceptor implementation in {class_name}",
                rule_type=BusinessRuleType.BUSINESS_LOGIC,
                source=BusinessRuleSource.ACTION_CLASS,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    class_name=class_name
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"Custom interceptor class: {class_name}",
                    context="Custom cross-cutting concern implementation",
                    confidence_score=0.7
                ),
                business_context="Cross-cutting business concern implementation",
                complexity=BusinessRuleComplexity.MODERATE
            )
            
            business_rule.add_tag("interceptor")
            business_rule.add_tag("custom")
            business_rule.add_tag("cross_cutting")
            
            business_rules.append(business_rule)
        
        return {
            'file_path': str(file_path),
            'class_info': {
                'name': class_name,
                'is_interceptor': implements_interceptor or extends_interceptor
            },
            'methods': [{'name': method} for method in methods],
            'business_rules': [r.to_dict() for r in business_rules]
        }
    
    def _is_interceptor_class(self, class_decl: javalang.tree.ClassDeclaration) -> bool:
        """Check if class is an interceptor implementation."""
        # Check interfaces
        for interface in class_decl.implements or []:
            if 'Interceptor' in interface.name:
                return True
        
        # Check superclass
        if class_decl.extends and 'Interceptor' in class_decl.extends.name:
            return True
        
        return False
    
    def _analyze_interceptor_method(self, method: javalang.tree.MethodDeclaration,
                                  class_name: str, file_path: Path) -> Dict[str, Any]:
        """Analyze a single interceptor method."""
        return {
            'name': method.name,
            'modifiers': method.modifiers or [],
            'return_type': str(method.return_type) if method.return_type else 'void',
            'parameters': [str(param.type) + ' ' + param.name for param in method.parameters or []],
            'is_intercept_method': method.name == 'intercept',
            'is_lifecycle_method': method.name in ['preProcess', 'postProcess', 'init', 'destroy']
        }
    
    def _create_method_business_rule(self, method: javalang.tree.MethodDeclaration,
                                   class_name: str, file_path: Path) -> Optional[BusinessRule]:
        """Create business rule from significant interceptor method."""
        if method.name not in ['intercept', 'execute', 'preProcess', 'postProcess']:
            return None
        
        rule_id = f"interceptor_method_{hashlib.md5(f'{file_path}_{class_name}_{method.name}'.encode()).hexdigest()[:12]}"
        
        return BusinessRule(
            id=rule_id,
            name=f"Interceptor Method: {class_name}.{method.name}",
            description=f"Business logic in interceptor method {method.name} of {class_name}",
            rule_type=BusinessRuleType.BUSINESS_LOGIC,
            source=BusinessRuleSource.ACTION_CLASS,
            location=BusinessRuleLocation(
                file_path=str(file_path),
                class_name=class_name,
                method_name=method.name
            ),
            evidence=BusinessRuleEvidence(
                code_snippet=f"Method: {method.name}({', '.join(str(p.type) + ' ' + p.name for p in method.parameters or [])})",
                context=f"Interceptor business logic implementation",
                confidence_score=0.8
            ),
            business_context="Cross-cutting business concern implementation",
            complexity=BusinessRuleComplexity.MODERATE
        )
    
    def _post_process_results(self, results: List[Dict[str, Any]], 
                            context: AnalysisContext) -> Dict[str, Any]:
        """Post-process interceptor analysis results."""
        all_definitions = []
        all_stacks = []
        all_chains = []
        all_business_rules = []
        class_analyses = []
        
        for result in results:
            if result:
                all_definitions.extend(result.get('interceptor_definitions', []))
                all_stacks.extend(result.get('interceptor_stacks', []))
                all_chains.extend(result.get('action_interceptors', []))
                all_business_rules.extend(result.get('business_rules', []))
                
                if 'class_info' in result:
                    class_analyses.append(result)
        
        # Analyze interceptor usage patterns
        usage_analysis = self._analyze_interceptor_usage(all_definitions, all_stacks, all_chains)
        
        return {
            'interceptor_definitions': all_definitions,
            'interceptor_stacks': all_stacks,
            'action_interceptor_chains': all_chains,
            'business_rules': all_business_rules,
            'class_analyses': class_analyses,
            'usage_analysis': usage_analysis,
            'summary': {
                'total_interceptors': len(all_definitions),
                'custom_interceptors': len([d for d in all_definitions if d.get('is_custom')]),
                'total_stacks': len(all_stacks),
                'total_chains': len(all_chains),
                'total_business_rules': len(all_business_rules),
                'cross_cutting_concerns': self._summarize_concerns(all_definitions)
            }
        }
    
    def _analyze_interceptor_usage(self, definitions: List[Dict], stacks: List[Dict], 
                                 chains: List[Dict]) -> Dict[str, Any]:
        """Analyze interceptor usage patterns across the application."""
        # Count interceptor usage
        interceptor_usage = {}
        for chain in chains:
            for interceptor in chain.get('chain', []) + chain.get('stack_refs', []):
                interceptor_usage[interceptor] = interceptor_usage.get(interceptor, 0) + 1
        
        # Identify most critical interceptors
        critical_interceptors = sorted(
            interceptor_usage.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return {
            'interceptor_usage_counts': interceptor_usage,
            'most_critical_interceptors': critical_interceptors,
            'unused_interceptors': [
                d['name'] for d in definitions 
                if d['name'] not in interceptor_usage
            ]
        }
    
    def _summarize_concerns(self, definitions: List[Dict]) -> Dict[str, int]:
        """Summarize cross-cutting concerns across all interceptors."""
        concern_counts = {}
        for definition in definitions:
            for concern in definition.get('cross_cutting_concerns', []):
                concern_counts[concern] = concern_counts.get(concern, 0) + 1
        return concern_counts