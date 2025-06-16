import sys
sys.path.append('..')

"""
Java Action Analyzer
====================

This module provides analysis capabilities for Java Action classes in Struts applications.
It extracts business logic, method signatures, dependencies, and complexity metrics while
identifying migration patterns and modernization opportunities.

Features:
- Complete Java Action class parsing with AST analysis
- Business logic extraction from method implementations
- Dependency analysis and coupling metrics
- Complexity calculation and technical debt identification
- Migration recommendations for Spring Boot/GraphQL
- Performance bottleneck identification

Author: Claude Code Assistant
"""

import ast
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
    import logging
    logging.getLogger(__name__).warning("javalang not available, using fallback parsing")

import sys
sys.path.append('..')
from analyzers.base_analyzer import BaseAnalyzer, AnalysisContext
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource, 
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)
from models.class_info import ClassInfo, ClassType, MethodSignature, ClassMetrics
from models.dependency_info import DependencyInfo, DependencyType, DependencyStrength
from utils.logging_utils import get_logger
from utils.performance_utils import performance_timer


logger = get_logger(__name__)


@dataclass
class MethodAnalysis:
    """Analysis results for a single method."""
    name: str
    signature: str
    return_type: str
    parameters: List[str] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    lines_of_code: int = 0
    cyclomatic_complexity: int = 1
    cognitive_complexity: int = 1
    business_logic_indicators: List[str] = field(default_factory=list)
    database_operations: List[str] = field(default_factory=list)
    external_calls: List[str] = field(default_factory=list)
    validation_logic: List[str] = field(default_factory=list)
    error_handling: List[str] = field(default_factory=list)
    performance_concerns: List[str] = field(default_factory=list)
    migration_complexity: str = "medium"
    migration_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'signature': self.signature,
            'return_type': self.return_type,
            'parameters': self.parameters,
            'modifiers': self.modifiers,
            'annotations': self.annotations,
            'lines_of_code': self.lines_of_code,
            'cyclomatic_complexity': self.cyclomatic_complexity,
            'cognitive_complexity': self.cognitive_complexity,
            'business_logic_indicators': self.business_logic_indicators,
            'database_operations': self.database_operations,
            'external_calls': self.external_calls,
            'validation_logic': self.validation_logic,
            'error_handling': self.error_handling,
            'performance_concerns': self.performance_concerns,
            'migration_complexity': self.migration_complexity,
            'migration_recommendations': self.migration_recommendations
        }


@dataclass
class ClassAnalysis:
    """Comprehensive analysis results for a Java class."""
    class_info: ClassInfo
    methods: List[MethodAnalysis] = field(default_factory=list)
    dependencies: List[DependencyInfo] = field(default_factory=list)
    business_rules: List[BusinessRule] = field(default_factory=list)
    architecture_patterns: List[str] = field(default_factory=list)
    design_patterns: List[str] = field(default_factory=list)
    code_smells: List[str] = field(default_factory=list)
    security_concerns: List[str] = field(default_factory=list)
    performance_issues: List[str] = field(default_factory=list)
    migration_assessment: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'class_info': self.class_info.to_dict(),
            'methods': [method.to_dict() for method in self.methods],
            'dependencies': [dep.to_dict() for dep in self.dependencies],
            'business_rules': [rule.to_dict() for rule in self.business_rules],
            'architecture_patterns': self.architecture_patterns,
            'design_patterns': self.design_patterns,
            'code_smells': self.code_smells,
            'security_concerns': self.security_concerns,
            'performance_issues': self.performance_issues,
            'migration_assessment': self.migration_assessment
        }


class JavaActionAnalyzer(BaseAnalyzer):
    """
    Analyzer for Java Action classes in Struts applications.
    
    Provides comprehensive analysis of Java Action classes including
    business logic extraction, complexity metrics, and migration recommendations.
    """
    
    def _initialize_analyzer(self) -> None:
        """Initialize Java Action analyzer settings."""
        self._supported_extensions = {'.java'}
        self._required_patterns = ['action']
        
        # Struts-specific patterns
        self._struts_imports = {
            'org.apache.struts.action.Action',
            'org.apache.struts.action.ActionForm',
            'org.apache.struts.action.ActionForward',
            'org.apache.struts.action.ActionMapping',
            'org.apache.struts.action.ActionServlet',
            'org.apache.struts2.Action'
        }
        
        # Business logic indicators
        self._business_logic_patterns = {
            'validation': ['validate', 'check', 'verify', 'isValid', 'hasError'],
            'calculation': ['calculate', 'compute', 'sum', 'total', 'amount'],
            'transformation': ['convert', 'transform', 'format', 'parse'],
            'workflow': ['process', 'handle', 'execute', 'perform', 'run'],
            'decision': ['decide', 'determine', 'choose', 'select'],
            'integration': ['send', 'receive', 'call', 'invoke', 'request']
        }
        
        # Database operation patterns
        self._database_patterns = {
            'jdbc': ['Connection', 'Statement', 'ResultSet', 'PreparedStatement'],
            'hibernate': ['Session', 'Transaction', 'Query', 'Criteria'],
            'dao': ['DAO', 'Repository', 'persist', 'merge', 'delete', 'find'],
            'sql': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP']
        }
        
        # Performance concern patterns
        self._performance_patterns = {
            'loops': ['for', 'while', 'do'],
            'collections': ['List', 'Set', 'Map', 'ArrayList', 'HashMap'],
            'io': ['File', 'InputStream', 'OutputStream', 'Reader', 'Writer'],
            'network': ['Socket', 'URL', 'HTTP', 'REST', 'SOAP'],
            'sync': ['synchronized', 'wait', 'notify', 'Lock', 'Semaphore']
        }
    
    def can_analyze(self, file_path: Path) -> bool:
        """
        Check if this is a Java Action class file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if this is a Java Action class
        """
        if file_path.suffix.lower() != '.java':
            return False
        
        # Quick check based on filename
        filename_lower = file_path.name.lower()
        if 'action' in filename_lower:
            return True
        
        # Check file content for Struts Action patterns
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2000)  # Read first 2KB
                
                # Check for Struts imports
                if any(struts_import in content for struts_import in self._struts_imports):
                    return True
                
                # Check for Action class patterns
                if re.search(r'extends\s+.*Action', content) or re.search(r'implements\s+.*Action', content):
                    return True
                
                # Check for @Action annotation (Struts 2)
                if '@Action' in content:
                    return True
                    
        except Exception:
            pass
        
        return False
    
    @performance_timer("java_action_analysis")
    def _analyze_file(self, file_path: Path, context: AnalysisContext) -> Dict[str, Any]:
        """
        Analyze a single Java Action class file.
        
        Args:
            file_path: Path to Java file
            context: Analysis context
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Try javalang parsing first, fall back to regex if needed
            if JAVALANG_AVAILABLE:
                analysis = self._analyze_with_javalang(content, file_path)
            else:
                analysis = self._analyze_with_regex(content, file_path)
            
            if analysis:
                # Enhance analysis with additional insights
                self._enhance_analysis(analysis, content, file_path)
                
                return {
                    'class_analysis': analysis.to_dict(),
                    'file_path': str(file_path),
                    'analysis_method': 'javalang' if JAVALANG_AVAILABLE else 'regex',
                    'file_size_kb': len(content) / 1024
                }
            else:
                return {
                    'error': 'Failed to parse Java file',
                    'file_path': str(file_path),
                    'class_analysis': None
                }
                
        except Exception as e:
            logger.error(f"Error analyzing Java file {file_path}: {e}")
            return {
                'error': f"Analysis failed: {e}",
                'file_path': str(file_path),
                'class_analysis': None
            }
    
    def _analyze_with_javalang(self, content: str, file_path: Path) -> Optional[ClassAnalysis]:
        """Analyze Java file using javalang AST parser."""
        try:
            tree = javalang.parse.parse(content)
            
            # Extract main class
            main_class = None
            for type_decl in tree.types:
                if isinstance(type_decl, javalang.tree.ClassDeclaration):
                    main_class = type_decl
                    break
            
            if not main_class:
                return None
            
            # Create ClassInfo
            class_info = self._extract_class_info(main_class, tree, file_path)
            
            # Create ClassAnalysis
            analysis = ClassAnalysis(class_info=class_info)
            
            # Analyze methods
            if main_class.methods:
                for method in main_class.methods:
                    method_analysis = self._analyze_method(method, content)
                    analysis.methods.append(method_analysis)
            
            # Extract dependencies
            analysis.dependencies = self._extract_dependencies(tree, file_path)
            
            # Extract business rules
            analysis.business_rules = self._extract_business_rules_from_ast(
                main_class, tree, file_path, content
            )
            
            # Identify patterns and issues
            analysis.architecture_patterns = self._identify_architecture_patterns(main_class, content)
            analysis.design_patterns = self._identify_design_patterns(main_class, content)
            analysis.code_smells = self._identify_code_smells(main_class, analysis.methods)
            analysis.security_concerns = self._identify_security_concerns(content)
            analysis.performance_issues = self._identify_performance_issues(content, analysis.methods)
            
            # Generate migration assessment
            analysis.migration_assessment = self._generate_migration_assessment(analysis)
            
            return analysis
            
        except Exception as e:
            logger.warning(f"javalang parsing failed for {file_path}: {e}")
            return self._analyze_with_regex(content, file_path)
    
    def _analyze_with_regex(self, content: str, file_path: Path) -> Optional[ClassAnalysis]:
        """Fallback analysis using regex parsing."""
        try:
            # Extract class information
            class_match = re.search(r'(?:public\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([^{]+))?', content)
            if not class_match:
                return None
            
            class_name = class_match.group(1)
            superclass = class_match.group(2)
            interfaces = class_match.group(3).split(',') if class_match.group(3) else []
            
            # Extract package
            package_match = re.search(r'package\s+([\w.]+);', content)
            package_name = package_match.group(1) if package_match else ""
            
            # Create basic ClassInfo
            class_info = ClassInfo(
                name=class_name,
                package=package_name,
                file_path=str(file_path),
                superclass=superclass,
                interfaces=[iface.strip() for iface in interfaces],
                class_type=self._determine_class_type(class_name, superclass, content)
            )
            
            # Create ClassAnalysis
            analysis = ClassAnalysis(class_info=class_info)
            
            # Extract methods using regex
            method_pattern = r'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[^{]+)?\s*{'
            method_matches = re.finditer(method_pattern, content)
            
            for match in method_matches:
                method_analysis = self._analyze_method_regex(match, content)
                analysis.methods.append(method_analysis)
            
            # Basic dependency extraction
            analysis.dependencies = self._extract_dependencies_regex(content, file_path)
            
            # Extract business rules
            analysis.business_rules = self._extract_business_rules_regex(content, file_path)
            
            # Basic pattern identification
            analysis.architecture_patterns = self._identify_architecture_patterns_regex(content)
            analysis.code_smells = self._identify_code_smells_regex(content)
            analysis.security_concerns = self._identify_security_concerns(content)
            analysis.performance_issues = self._identify_performance_issues_regex(content)
            
            # Generate migration assessment
            analysis.migration_assessment = self._generate_migration_assessment(analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Regex parsing failed for {file_path}: {e}")
            return None
    
    def _extract_class_info(self, class_decl: 'javalang.tree.ClassDeclaration', 
                           tree: 'javalang.tree.CompilationUnit', 
                           file_path: Path) -> ClassInfo:
        """Extract comprehensive class information from AST."""
        # Basic class info
        class_info = ClassInfo(
            name=class_decl.name,
            package=tree.package.name if tree.package else '',
            file_path=str(file_path),
            superclass=class_decl.extends.name if class_decl.extends else None,
            interfaces=[impl.name for impl in class_decl.implements or []],
            modifiers=class_decl.modifiers or [],
            class_type=self._determine_class_type_from_ast(class_decl)
        )
        
        # Extract imports as dependencies
        if tree.imports:
            for imp in tree.imports:
                class_info.add_dependency(imp.path)
        
        # Extract methods
        if class_decl.methods:
            for method in class_decl.methods:
                method_sig = MethodSignature(
                    name=method.name,
                    return_type=str(method.return_type) if method.return_type else 'void',
                    parameters=[f"{param.type} {param.name}" for param in method.parameters or []],
                    modifiers=method.modifiers or [],
                    is_abstract='abstract' in (method.modifiers or []),
                    is_static='static' in (method.modifiers or []),
                    is_final='final' in (method.modifiers or [])
                )
                class_info.add_method(method_sig)
        
        # Extract fields
        if class_decl.fields:
            for field_decl in class_decl.fields:
                for declarator in field_decl.declarators:
                    class_info.fields.append(f"{field_decl.type} {declarator.name}")
        
        # Calculate metrics
        class_info.metrics = self._calculate_class_metrics(class_decl, class_info)
        
        # Determine Struts role
        class_info.struts_role = self._determine_struts_role(class_info)
        
        return class_info
    
    def _determine_class_type_from_ast(self, class_decl: 'javalang.tree.ClassDeclaration') -> ClassType:
        """Determine class type from AST analysis."""
        class_name = class_decl.name.lower()
        
        # Check superclass
        if class_decl.extends:
            superclass = class_decl.extends.name.lower()
            if 'action' in superclass:
                return ClassType.ACTION
            elif 'form' in superclass:
                return ClassType.FORM_BEAN
            elif 'interceptor' in superclass:
                return ClassType.INTERCEPTOR
        
        # Check interfaces
        for interface in class_decl.implements or []:
            interface_name = interface.name.lower()
            if 'action' in interface_name:
                return ClassType.ACTION
            elif 'interceptor' in interface_name:
                return ClassType.INTERCEPTOR
        
        # Check class name
        if 'action' in class_name:
            return ClassType.ACTION
        elif 'form' in class_name:
            return ClassType.FORM_BEAN
        elif 'interceptor' in class_name:
            return ClassType.INTERCEPTOR
        elif 'service' in class_name:
            return ClassType.SERVICE
        elif 'dao' in class_name or 'repository' in class_name:
            return ClassType.DAO
        
        return ClassType.UNKNOWN
    
    def _determine_class_type(self, class_name: str, superclass: Optional[str], content: str) -> ClassType:
        """Determine class type from basic information."""
        name_lower = class_name.lower()
        super_lower = superclass.lower() if superclass else ""
        
        if 'action' in name_lower or 'action' in super_lower:
            return ClassType.ACTION
        elif 'form' in name_lower or 'form' in super_lower:
            return ClassType.FORM_BEAN
        elif 'interceptor' in name_lower or 'interceptor' in super_lower:
            return ClassType.INTERCEPTOR
        elif 'service' in name_lower:
            return ClassType.SERVICE
        elif 'dao' in name_lower or 'repository' in name_lower:
            return ClassType.DAO
        
        return ClassType.UNKNOWN
    
    def _calculate_class_metrics(self, class_decl: 'javalang.tree.ClassDeclaration', 
                                class_info: ClassInfo) -> ClassMetrics:
        """Calculate comprehensive class metrics."""
        metrics = ClassMetrics()
        
        # Basic counts
        metrics.number_of_methods = len(class_info.methods)
        metrics.number_of_fields = len(class_info.fields)
        
        # Calculate inheritance depth
        depth = 0
        current_class = class_decl
        while current_class and current_class.extends:
            depth += 1
            if depth > 10:  # Prevent infinite loops
                break
            # In a real implementation, we'd need to resolve the superclass
            break
        metrics.inheritance_depth = depth
        
        # Coupling (number of dependencies)
        metrics.coupling_factor = len(class_info.dependencies)
        
        # Default values for metrics that require deeper analysis
        metrics.lines_of_code = 0  # Would need source line counting
        metrics.cyclomatic_complexity = 1  # Would need method analysis
        metrics.cognitive_complexity = 1  # Would need detailed AST analysis
        metrics.cohesion_score = 0.8  # Default assumption
        
        return metrics
    
    def _determine_struts_role(self, class_info: ClassInfo) -> str:
        """Determine the specific Struts role of the class."""
        if class_info.class_type == ClassType.ACTION:
            # Check for specific action patterns
            if any('execute' in method.name for method in class_info.methods):
                return "Struts 1.x Action"
            elif any('@Action' in str(method.annotations) for method in class_info.methods):
                return "Struts 2.x Action"
            else:
                return "Action Class"
        elif class_info.class_type == ClassType.FORM_BEAN:
            if 'DynaActionForm' in class_info.superclass:
                return "Dynamic Form Bean"
            elif 'ValidatorForm' in class_info.superclass:
                return "Validator Form Bean"
            else:
                return "Action Form Bean"
        elif class_info.class_type == ClassType.INTERCEPTOR:
            return "Struts Interceptor"
        
        return "Unknown Struts Component"
    
    def _analyze_method(self, method: 'javalang.tree.MethodDeclaration', content: str) -> MethodAnalysis:
        """Analyze a single method from AST."""
        analysis = MethodAnalysis(
            name=method.name,
            return_type=str(method.return_type) if method.return_type else 'void',
            parameters=[f"{param.type} {param.name}" for param in method.parameters or []],
            modifiers=method.modifiers or [],
            signature=self._build_method_signature(method)
        )
        
        # Extract method body for analysis
        method_body = self._extract_method_body(method.name, content)
        if method_body:
            analysis.lines_of_code = len(method_body.split('\n'))
            analysis.cyclomatic_complexity = self._calculate_cyclomatic_complexity(method_body)
            analysis.cognitive_complexity = self._calculate_cognitive_complexity(method_body)
            
            # Analyze business logic patterns
            analysis.business_logic_indicators = self._identify_business_logic_in_method(method_body)
            analysis.database_operations = self._identify_database_operations(method_body)
            analysis.external_calls = self._identify_external_calls(method_body)
            analysis.validation_logic = self._identify_validation_logic(method_body)
            analysis.error_handling = self._identify_error_handling(method_body)
            analysis.performance_concerns = self._identify_method_performance_concerns(method_body)
            
            # Determine migration complexity
            analysis.migration_complexity = self._assess_method_migration_complexity(analysis)
            analysis.migration_recommendations = self._generate_method_migration_recommendations(analysis)
        
        return analysis
    
    def _analyze_method_regex(self, match: re.Match, content: str) -> MethodAnalysis:
        """Analyze method using regex match."""
        return_type = match.group(1)
        method_name = match.group(2)
        parameters_str = match.group(3)
        
        parameters = []
        if parameters_str.strip():
            param_parts = parameters_str.split(',')
            parameters = [param.strip() for param in param_parts]
        
        analysis = MethodAnalysis(
            name=method_name,
            return_type=return_type,
            parameters=parameters,
            signature=f"{return_type} {method_name}({parameters_str})"
        )
        
        # Extract and analyze method body
        method_body = self._extract_method_body(method_name, content)
        if method_body:
            analysis.lines_of_code = len(method_body.split('\n'))
            analysis.cyclomatic_complexity = self._calculate_cyclomatic_complexity(method_body)
            
            # Basic pattern identification
            analysis.business_logic_indicators = self._identify_business_logic_in_method(method_body)
            analysis.database_operations = self._identify_database_operations(method_body)
            analysis.validation_logic = self._identify_validation_logic(method_body)
            analysis.error_handling = self._identify_error_handling(method_body)
        
        return analysis
    
    def _build_method_signature(self, method: 'javalang.tree.MethodDeclaration') -> str:
        """Build method signature string."""
        modifiers = ' '.join(method.modifiers or [])
        return_type = str(method.return_type) if method.return_type else 'void'
        name = method.name
        params = ', '.join(f"{param.type} {param.name}" for param in method.parameters or [])
        
        parts = [part for part in [modifiers, return_type, f"{name}({params})"] if part]
        return ' '.join(parts)
    
    def _extract_method_body(self, method_name: str, content: str) -> Optional[str]:
        """Extract method body from source content."""
        # Find method start
        method_pattern = rf'\b{re.escape(method_name)}\s*\([^{{]*\{{'
        match = re.search(method_pattern, content)
        
        if not match:
            return None
        
        start_pos = match.end() - 1  # Position of opening brace
        brace_count = 1
        pos = start_pos + 1
        
        # Find matching closing brace
        while pos < len(content) and brace_count > 0:
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
            pos += 1
        
        if brace_count == 0:
            return content[start_pos + 1:pos - 1].strip()
        
        return None
    
    def _calculate_cyclomatic_complexity(self, method_body: str) -> int:
        """Calculate cyclomatic complexity of method."""
        complexity = 1  # Base complexity
        
        # Count decision points
        decision_keywords = ['if', 'while', 'for', 'case', 'catch', '&&', '||', '?']
        
        for keyword in decision_keywords:
            if keyword in ['&&', '||', '?']:
                complexity += method_body.count(keyword)
            else:
                # Use word boundaries for keywords
                pattern = rf'\b{re.escape(keyword)}\b'
                complexity += len(re.findall(pattern, method_body))
        
        return complexity
    
    def _calculate_cognitive_complexity(self, method_body: str) -> int:
        """Calculate cognitive complexity (simplified version)."""
        complexity = 0
        nesting_level = 0
        
        lines = method_body.split('\n')
        for line in lines:
            line = line.strip()
            
            # Count nesting increases
            if any(keyword in line for keyword in ['if', 'while', 'for', 'try']):
                nesting_level += 1
                complexity += nesting_level
            
            # Count logical operators
            complexity += line.count('&&') + line.count('||')
            
            # Decrease nesting for closing braces
            if '}' in line:
                nesting_level = max(0, nesting_level - line.count('}'))
        
        return complexity
    
    def _identify_business_logic_in_method(self, method_body: str) -> List[str]:
        """Identify business logic patterns in method."""
        indicators = []
        
        for category, patterns in self._business_logic_patterns.items():
            for pattern in patterns:
                if pattern in method_body.lower():
                    indicators.append(f"{category}: {pattern}")
        
        # Check for custom business logic patterns
        if re.search(r'\bif\s*\([^)]*\s*(==|!=|<|>|<=|>=)', method_body):
            indicators.append("conditional_logic: business_rules")
        
        if re.search(r'\bswitch\s*\(', method_body):
            indicators.append("decision_logic: state_machine")
        
        return indicators
    
    def _identify_database_operations(self, method_body: str) -> List[str]:
        """Identify database operations in method."""
        operations = []
        
        for category, patterns in self._database_patterns.items():
            for pattern in patterns:
                if pattern in method_body:
                    operations.append(f"{category}: {pattern}")
        
        # Check for SQL statements
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
        for keyword in sql_keywords:
            if keyword in method_body.upper():
                operations.append(f"sql: {keyword}")
        
        return operations
    
    def _identify_external_calls(self, method_body: str) -> List[str]:
        """Identify external system calls."""
        calls = []
        
        # HTTP calls
        if re.search(r'\b(HttpClient|URLConnection|REST|HTTP)', method_body):
            calls.append("http_call")
        
        # Web service calls
        if re.search(r'\b(SOAP|WebService|Service)', method_body):
            calls.append("web_service")
        
        # File I/O
        if re.search(r'\b(File|InputStream|OutputStream)', method_body):
            calls.append("file_io")
        
        return calls
    
    def _identify_validation_logic(self, method_body: str) -> List[str]:
        """Identify validation logic patterns."""
        validations = []
        
        validation_patterns = [
            r'\bisEmpty\(',
            r'\bisNull\(',
            r'\.length\(\)\s*[<>=]',
            r'\.size\(\)\s*[<>=]',
            r'\bvalidate\w*\(',
            r'\bcheck\w*\(',
            r'\bverify\w*\('
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, method_body):
                validations.append(f"validation_pattern: {pattern}")
        
        return validations
    
    def _identify_error_handling(self, method_body: str) -> List[str]:
        """Identify error handling patterns."""
        error_handling = []
        
        if 'try' in method_body and 'catch' in method_body:
            error_handling.append("try_catch_block")
        
        if 'throws' in method_body:
            error_handling.append("throws_declaration")
        
        if re.search(r'\bthrow\s+new', method_body):
            error_handling.append("exception_throwing")
        
        if 'finally' in method_body:
            error_handling.append("finally_block")
        
        return error_handling
    
    def _identify_method_performance_concerns(self, method_body: str) -> List[str]:
        """Identify performance concerns in method."""
        concerns = []
        
        # Nested loops
        if method_body.count('for') > 1 or method_body.count('while') > 1:
            concerns.append("nested_loops")
        
        # String concatenation in loops
        if re.search(r'for.*\+.*String', method_body, re.DOTALL):
            concerns.append("string_concatenation_in_loop")
        
        # Database calls in loops
        if re.search(r'for.*(?:execute|query|select)', method_body, re.DOTALL | re.IGNORECASE):
            concerns.append("database_calls_in_loop")
        
        # Large collection operations
        if re.search(r'\b(ArrayList|HashMap|HashSet)\s*\(.*\d{3,}', method_body):
            concerns.append("large_collection_initialization")
        
        return concerns
    
    def _assess_method_migration_complexity(self, analysis: MethodAnalysis) -> str:
        """Assess migration complexity for a method."""
        complexity_score = 0
        
        # Base complexity from cyclomatic complexity
        complexity_score += analysis.cyclomatic_complexity
        
        # Add complexity for business logic
        complexity_score += len(analysis.business_logic_indicators) * 2
        
        # Add complexity for database operations
        complexity_score += len(analysis.database_operations) * 3
        
        # Add complexity for external calls
        complexity_score += len(analysis.external_calls) * 4
        
        # Add complexity for validation logic
        complexity_score += len(analysis.validation_logic)
        
        # Add complexity for performance concerns
        complexity_score += len(analysis.performance_concerns) * 2
        
        if complexity_score >= 20:
            return "critical"
        elif complexity_score >= 15:
            return "high"
        elif complexity_score >= 8:
            return "medium"
        else:
            return "low"
    
    def _generate_method_migration_recommendations(self, analysis: MethodAnalysis) -> List[str]:
        """Generate migration recommendations for a method."""
        recommendations = []
        
        # Basic recommendation
        if analysis.name in ['execute', 'perform']:
            recommendations.append("Convert to GraphQL resolver or REST controller method")
        
        # Business logic recommendations
        if analysis.business_logic_indicators:
            recommendations.append("Extract business logic into service layer")
        
        # Database recommendations
        if analysis.database_operations:
            recommendations.append("Replace direct database access with repository pattern")
        
        # Validation recommendations
        if analysis.validation_logic:
            recommendations.append("Convert validation logic to Bean Validation or GraphQL schema validation")
        
        # Performance recommendations
        if analysis.performance_concerns:
            recommendations.append("Address performance concerns before migration")
        
        # Complexity recommendations
        if analysis.migration_complexity in ["high", "critical"]:
            recommendations.append("Consider breaking down complex method into smaller functions")
        
        return recommendations
    
    def _extract_dependencies(self, tree: 'javalang.tree.CompilationUnit', 
                            file_path: Path) -> List[DependencyInfo]:
        """Extract dependencies from AST."""
        dependencies = []
        
        if tree.imports:
            for imp in tree.imports:
                dep = DependencyInfo(
                    id="auto",
                    source_component=file_path.stem,
                    target_component=imp.path,
                    dependency_type=DependencyType.IMPORT,
                    source_location=str(file_path)
                )
                
                if any(struts in imp.path for struts in self._struts_imports):
                    dep.tags.add("struts_specific")
                
                # Assess dependency strength
                if any(struts in imp.path for struts in self._struts_imports):
                    dep.strength = DependencyStrength.CRITICAL
                    dep.migration_complexity = "high"
                elif 'java.lang' in imp.path or 'java.util' in imp.path:
                    dep.strength = DependencyStrength.WEAK
                else:
                    dep.strength = DependencyStrength.MODERATE
                
                dependencies.append(dep)
        
        return dependencies
    
    def _extract_dependencies_regex(self, content: str, file_path: Path) -> List[DependencyInfo]:
        """Extract dependencies using regex parsing."""
        dependencies = []
        
        # Find import statements
        import_pattern = r'import\s+([\w.]+);'
        import_matches = re.findall(import_pattern, content)
        
        for import_path in import_matches:
            dep = DependencyInfo(
                id="auto",
                source_component=file_path.stem,
                target_component=import_path,
                dependency_type=DependencyType.IMPORT,
                source_location=str(file_path)
            )
            
            if any(struts in import_path for struts in self._struts_imports):
                dep.tags.add("struts_specific")
            
            if any(struts in import_path for struts in self._struts_imports):
                dep.strength = DependencyStrength.CRITICAL
                dep.migration_complexity = "high"
            else:
                dep.strength = DependencyStrength.MODERATE
            
            dependencies.append(dep)
        
        return dependencies
    
    def _extract_business_rules_from_ast(self, class_decl: 'javalang.tree.ClassDeclaration',
                                       tree: 'javalang.tree.CompilationUnit',
                                       file_path: Path, content: str) -> List[BusinessRule]:
        """Extract business rules from AST analysis."""
        rules = []
        
        # Rule from class purpose
        if self._is_action_class(class_decl):
            rule = BusinessRule(
                id="auto",
                name=f"Action Class Business Logic: {class_decl.name}",
                description=f"Business logic implemented in Action class {class_decl.name}",
                rule_type=BusinessRuleType.BUSINESS_LOGIC,
                source=BusinessRuleSource.ACTION_CLASS,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    class_name=class_decl.name
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"class {class_decl.name}",
                    context="Struts Action class implementation"
                )
            )
            rules.append(rule)
        
        # Rules from method analysis
        if class_decl.methods:
            for method in class_decl.methods:
                method_rules = self._extract_method_business_rules(method, class_decl.name, file_path, content)
                rules.extend(method_rules)
        
        return rules
    
    def _extract_business_rules_regex(self, content: str, file_path: Path) -> List[BusinessRule]:
        """Extract business rules using regex analysis."""
        rules = []
        
        # Extract from comments
        comment_pattern = r'/\*\*(.*?)\*/'
        comments = re.findall(comment_pattern, content, re.DOTALL)
        
        for i, comment in enumerate(comments):
            if any(indicator in comment.lower() for indicator in 
                   ['business rule', 'requirement', 'must', 'should', 'validation']):
                
                rule = BusinessRule(
                    id=f"comment_rule_{file_path.stem}_{i}",
                    name="Business Rule from Comment",
                    description=comment.strip(),
                    rule_type=BusinessRuleType.BUSINESS_LOGIC,
                    source=BusinessRuleSource.COMMENT,
                    location=BusinessRuleLocation(file_path=str(file_path)),
                    evidence=BusinessRuleEvidence(
                        code_snippet=comment.strip(),
                        context="Javadoc comment"
                    )
                )
                rules.append(rule)
        
        return rules
    
    def _extract_method_business_rules(self, method: 'javalang.tree.MethodDeclaration',
                                     class_name: str, file_path: Path, content: str) -> List[BusinessRule]:
        """Extract business rules from method implementation."""
        rules = []
        
        # Main action method rule
        if method.name in ['execute', 'perform']:
            rule = BusinessRule(
                id=f"action_execute_{class_name}_{method.name}",
                name=f"Action Execution: {class_name}.{method.name}",
                description=f"Main business logic execution in {class_name}",
                rule_type=BusinessRuleType.WORKFLOW,
                source=BusinessRuleSource.METHOD_BODY,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    class_name=class_name,
                    method_name=method.name
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"public ActionForward {method.name}(...)",
                    context="Main action method implementation"
                ),
                complexity=BusinessRuleComplexity.COMPLEX
            )
            rules.append(rule)
        
        # Validation method rules
        if 'validate' in method.name.lower():
            rule = BusinessRule(
                id=f"validation_{class_name}_{method.name}",
                name=f"Validation Logic: {method.name}",
                description=f"Validation business rules in {method.name}",
                rule_type=BusinessRuleType.VALIDATION,
                source=BusinessRuleSource.METHOD_BODY,
                location=BusinessRuleLocation(
                    file_path=str(file_path),
                    class_name=class_name,
                    method_name=method.name
                ),
                evidence=BusinessRuleEvidence(
                    code_snippet=f"validation method {method.name}",
                    context="Validation logic implementation"
                )
            )
            rules.append(rule)
        
        return rules
    
    def _is_action_class(self, class_decl: 'javalang.tree.ClassDeclaration') -> bool:
        """Check if class is a Struts Action class."""
        if class_decl.extends and 'Action' in class_decl.extends.name:
            return True
        
        for impl in class_decl.implements or []:
            if 'Action' in impl.name:
                return True
        
        return 'action' in class_decl.name.lower()
    
    def _identify_architecture_patterns(self, class_decl: 'javalang.tree.ClassDeclaration', 
                                      content: str) -> List[str]:
        """Identify architecture patterns in the class."""
        patterns = []
        
        # MVC Pattern
        if self._is_action_class(class_decl):
            patterns.append("MVC Controller")
        
        # DAO Pattern
        if any('dao' in method.name.lower() for method in class_decl.methods or []):
            patterns.append("Data Access Object")
        
        # Service Pattern
        if any('service' in method.name.lower() for method in class_decl.methods or []):
            patterns.append("Service Layer")
        
        # Factory Pattern
        if any('create' in method.name.lower() or 'factory' in method.name.lower() 
               for method in class_decl.methods or []):
            patterns.append("Factory Pattern")
        
        return patterns
    
    def _identify_architecture_patterns_regex(self, content: str) -> List[str]:
        """Identify architecture patterns using regex."""
        patterns = []
        
        if re.search(r'\bextends\s+.*Action', content):
            patterns.append("MVC Controller")
        
        if re.search(r'\b(DAO|Repository)', content):
            patterns.append("Data Access Object")
        
        if re.search(r'\bService\b', content):
            patterns.append("Service Layer")
        
        return patterns
    
    def _identify_design_patterns(self, class_decl: 'javalang.tree.ClassDeclaration', 
                                content: str) -> List[str]:
        """Identify design patterns in the class."""
        patterns = []
        
        # Singleton Pattern
        if any('getInstance' in method.name for method in class_decl.methods or []):
            patterns.append("Singleton")
        
        # Observer Pattern
        if any('notify' in method.name.lower() or 'observer' in method.name.lower() 
               for method in class_decl.methods or []):
            patterns.append("Observer")
        
        # Strategy Pattern
        if len([m for m in class_decl.methods or [] if 'execute' in m.name.lower()]) > 1:
            patterns.append("Strategy")
        
        return patterns
    
    def _identify_code_smells(self, class_decl: 'javalang.tree.ClassDeclaration', 
                            methods: List[MethodAnalysis]) -> List[str]:
        """Identify code smells in the class."""
        smells = []
        
        # Large class
        if len(methods) > 20:
            smells.append("Large Class (God Object)")
        
        # Long methods
        long_methods = [m for m in methods if m.lines_of_code > 50]
        if long_methods:
            smells.append(f"Long Methods ({len(long_methods)} methods)")
        
        # High complexity methods
        complex_methods = [m for m in methods if m.cyclomatic_complexity > 10]
        if complex_methods:
            smells.append(f"Complex Methods ({len(complex_methods)} methods)")
        
        # Too many parameters
        param_heavy = [m for m in methods if len(m.parameters) > 5]
        if param_heavy:
            smells.append(f"Parameter Heavy Methods ({len(param_heavy)} methods)")
        
        return smells
    
    def _identify_code_smells_regex(self, content: str) -> List[str]:
        """Identify code smells using regex analysis."""
        smells = []
        
        # Count methods
        method_count = len(re.findall(r'\b(?:public|private|protected)\s+\w+\s+\w+\s*\(', content))
        if method_count > 20:
            smells.append("Large Class (God Object)")
        
        # Long lines
        long_lines = [line for line in content.split('\n') if len(line) > 120]
        if len(long_lines) > 10:
            smells.append("Long Lines")
        
        return smells
    
    def _identify_security_concerns(self, content: str) -> List[str]:
        """Identify security concerns in the code."""
        concerns = []
        
        # SQL Injection
        if re.search(r'Statement.*execute.*\+', content):
            concerns.append("Potential SQL Injection")
        
        # Hardcoded passwords
        if re.search(r'password\s*=\s*["\']', content, re.IGNORECASE):
            concerns.append("Hardcoded Password")
        
        # Unvalidated input
        if re.search(r'request\.getParameter.*without validation', content):
            concerns.append("Unvalidated Input")
        
        # Insecure random
        if 'Random()' in content and 'SecureRandom' not in content:
            concerns.append("Insecure Random Number Generation")
        
        return concerns
    
    def _identify_performance_issues(self, content: str, methods: List[MethodAnalysis]) -> List[str]:
        """Identify performance issues in the class."""
        issues = []
        
        # Methods with performance concerns
        perf_methods = [m for m in methods if m.performance_concerns]
        if perf_methods:
            issues.append(f"Performance Concerns in {len(perf_methods)} methods")
        
        # String concatenation
        if content.count('String') > 5 and '+' in content:
            issues.append("Potential String Concatenation Issues")
        
        # Synchronization
        if 'synchronized' in content:
            issues.append("Synchronization Usage (potential bottleneck)")
        
        return issues
    
    def _identify_performance_issues_regex(self, content: str) -> List[str]:
        """Identify performance issues using regex."""
        issues = []
        
        if re.search(r'for.*for.*for', content, re.DOTALL):
            issues.append("Nested Loops (O(n³) complexity)")
        
        if re.search(r'String.*\+.*for', content, re.DOTALL):
            issues.append("String Concatenation in Loop")
        
        return issues
    
    def _generate_migration_assessment(self, analysis: ClassAnalysis) -> Dict[str, Any]:
        """Generate comprehensive migration assessment."""
        assessment = {
            'overall_complexity': 'medium',
            'estimated_effort_hours': 0,
            'migration_strategy': '',
            'blockers': [],
            'recommendations': [],
            'spring_boot_equivalent': '',
            'graphql_considerations': []
        }
        
        # Calculate overall complexity
        method_complexities = [m.migration_complexity for m in analysis.methods]
        critical_count = method_complexities.count('critical')
        high_count = method_complexities.count('high')
        
        if critical_count > 0:
            assessment['overall_complexity'] = 'critical'
        elif high_count > 2:
            assessment['overall_complexity'] = 'high'
        elif high_count > 0:
            assessment['overall_complexity'] = 'medium'
        else:
            assessment['overall_complexity'] = 'low'
        
        # Estimate effort
        base_hours = 8  # Base migration effort
        base_hours += len(analysis.methods) * 2  # Per method
        base_hours += len(analysis.dependencies) * 1  # Per dependency
        base_hours += len(analysis.code_smells) * 4  # Per code smell
        base_hours += len(analysis.security_concerns) * 6  # Per security concern
        
        assessment['estimated_effort_hours'] = base_hours
        
        # Migration strategy
        if analysis.class_info.class_type == ClassType.ACTION:
            assessment['migration_strategy'] = 'Convert to Spring Boot Controller with GraphQL resolvers'
            assessment['spring_boot_equivalent'] = '@RestController or @Controller with @RequestMapping'
        elif analysis.class_info.class_type == ClassType.FORM_BEAN:
            assessment['migration_strategy'] = 'Convert to GraphQL Input Types and Bean Validation'
            assessment['spring_boot_equivalent'] = 'DTO classes with @Valid annotations'
        
        # Identify blockers
        if analysis.security_concerns:
            assessment['blockers'].extend([f"Security: {concern}" for concern in analysis.security_concerns])
        
        if analysis.performance_issues:
            assessment['blockers'].extend([f"Performance: {issue}" for issue in analysis.performance_issues])
        
        # Generate recommendations
        recommendations = []
        
        if len(analysis.methods) > 10:
            recommendations.append("Break down large class into smaller, focused components")
        
        if analysis.code_smells:
            recommendations.append("Address code smells before migration")
        
        if any('database' in str(m.database_operations) for m in analysis.methods):
            recommendations.append("Implement repository pattern for data access")
        
        if any(m.validation_logic for m in analysis.methods):
            recommendations.append("Convert validation logic to Bean Validation")
        
        assessment['recommendations'] = recommendations
        
        # GraphQL considerations
        graphql_considerations = []
        
        if any('execute' in m.name for m in analysis.methods):
            graphql_considerations.append("Convert execute methods to GraphQL resolvers")
        
        if any(m.validation_logic for m in analysis.methods):
            graphql_considerations.append("Use GraphQL schema validation")
        
        assessment['graphql_considerations'] = graphql_considerations
        
        return assessment
    
    def _enhance_analysis(self, analysis: ClassAnalysis, content: str, file_path: Path) -> None:
        """Enhance analysis with additional insights."""
        # Update class metrics with actual line count
        analysis.class_info.metrics.lines_of_code = len(content.split('\n'))
        
        # Calculate total complexity
        total_complexity = sum(m.cyclomatic_complexity for m in analysis.methods)
        analysis.class_info.metrics.cyclomatic_complexity = total_complexity
        
        # Update business purpose based on analysis
        if analysis.class_info.class_type == ClassType.ACTION:
            business_purposes = []
            for method in analysis.methods:
                for indicator in method.business_logic_indicators:
                    if 'validation' in indicator:
                        business_purposes.append("Data Validation")
                    elif 'calculation' in indicator:
                        business_purposes.append("Business Calculations")
                    elif 'workflow' in indicator:
                        business_purposes.append("Process Workflow")
            
            if business_purposes:
                analysis.class_info.business_purpose = " | ".join(set(business_purposes))
    
    def _post_process_results(self, results: List[Dict[str, Any]], 
                            context: AnalysisContext) -> Dict[str, Any]:
        """
        Post-process and aggregate results from all Java Action files.
        
        Args:
            results: List of individual file analysis results
            context: Analysis context
            
        Returns:
            Aggregated and processed results
        """
        if not results:
            return {
                'class_analyses': [],
                'summary': {
                    'total_classes': 0,
                    'total_methods': 0,
                    'total_business_rules': 0,
                    'total_dependencies': 0
                }
            }
        
        # Filter successful analyses
        successful_results = [r for r in results if 'error' not in r and r.get('class_analysis')]
        class_analyses = [r['class_analysis'] for r in successful_results]
        
        # Calculate aggregated metrics
        total_classes = len(class_analyses)
        total_methods = sum(len(analysis.get('methods', [])) for analysis in class_analyses)
        total_business_rules = sum(len(analysis.get('business_rules', [])) for analysis in class_analyses)
        total_dependencies = sum(len(analysis.get('dependencies', [])) for analysis in class_analyses)
        
        # Analyze patterns across all classes
        cross_class_patterns = self._analyze_cross_class_patterns(class_analyses)
        
        # Generate migration strategy
        migration_strategy = self._generate_overall_migration_strategy(class_analyses)
        
        # Identify architectural concerns
        architectural_concerns = self._identify_architectural_concerns(class_analyses)
        
        return {
            'class_analyses': class_analyses,
            'cross_class_patterns': cross_class_patterns,
            'migration_strategy': migration_strategy,
            'architectural_concerns': architectural_concerns,
            'summary': {
                'total_classes': total_classes,
                'total_methods': total_methods,
                'total_business_rules': total_business_rules,
                'total_dependencies': total_dependencies,
                'average_methods_per_class': total_methods / total_classes if total_classes > 0 else 0,
                'complex_classes': sum(1 for analysis in class_analyses 
                                     if analysis.get('migration_assessment', {}).get('overall_complexity') in ['high', 'critical']),
                'total_estimated_effort_hours': sum(analysis.get('migration_assessment', {}).get('estimated_effort_hours', 0) 
                                                   for analysis in class_analyses)
            }
        }
    
    def _analyze_cross_class_patterns(self, class_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns across multiple classes."""
        patterns = {
            'common_dependencies': {},
            'shared_patterns': [],
            'coupling_analysis': {},
            'inheritance_hierarchies': []
        }
        
        # Analyze common dependencies
        all_dependencies = []
        for analysis in class_analyses:
            dependencies = analysis.get('dependencies', [])
            for dep in dependencies:
                target = dep.get('target_component', '')
                if target not in patterns['common_dependencies']:
                    patterns['common_dependencies'][target] = 0
                patterns['common_dependencies'][target] += 1
        
        # Find most common dependencies
        patterns['common_dependencies'] = dict(
            sorted(patterns['common_dependencies'].items(), 
                  key=lambda x: x[1], reverse=True)[:10]
        )
        
        # Analyze shared architecture patterns
        all_patterns = []
        for analysis in class_analyses:
            all_patterns.extend(analysis.get('architecture_patterns', []))
        
        pattern_counts = {}
        for pattern in all_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        patterns['shared_patterns'] = [
            {'pattern': pattern, 'count': count}
            for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)
        ]
        
        return patterns
    
    def _generate_overall_migration_strategy(self, class_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate overall migration strategy for all Action classes."""
        strategy = {
            'approach': 'Incremental Migration',
            'phases': [],
            'total_estimated_hours': 0,
            'risk_level': 'medium',
            'prerequisites': [],
            'success_metrics': []
        }
        
        # Calculate total effort
        total_hours = sum(
            analysis.get('migration_assessment', {}).get('estimated_effort_hours', 0)
            for analysis in class_analyses
        )
        strategy['total_estimated_hours'] = total_hours
        
        # Determine risk level
        critical_classes = sum(
            1 for analysis in class_analyses
            if analysis.get('migration_assessment', {}).get('overall_complexity') == 'critical'
        )
        
        if critical_classes > len(class_analyses) * 0.3:
            strategy['risk_level'] = 'high'
        elif critical_classes > 0:
            strategy['risk_level'] = 'medium'
        else:
            strategy['risk_level'] = 'low'
        
        # Define migration phases
        strategy['phases'] = [
            {
                'name': 'Foundation Setup',
                'description': 'Set up Spring Boot and GraphQL infrastructure',
                'estimated_hours': 40,
                'tasks': [
                    'Set up Spring Boot project structure',
                    'Configure GraphQL server',
                    'Implement authentication/authorization',
                    'Set up data access layer'
                ]
            },
            {
                'name': 'Simple Actions Migration',
                'description': 'Migrate low-complexity Action classes',
                'estimated_hours': total_hours * 0.3,
                'tasks': [
                    'Convert simple CRUD actions',
                    'Implement basic GraphQL resolvers',
                    'Set up form validation'
                ]
            },
            {
                'name': 'Complex Actions Migration',
                'description': 'Migrate high-complexity Action classes',
                'estimated_hours': total_hours * 0.6,
                'tasks': [
                    'Refactor complex business logic',
                    'Implement advanced GraphQL features',
                    'Address performance concerns'
                ]
            },
            {
                'name': 'Integration and Testing',
                'description': 'Final integration and comprehensive testing',
                'estimated_hours': total_hours * 0.1,
                'tasks': [
                    'End-to-end testing',
                    'Performance optimization',
                    'Security validation'
                ]
            }
        ]
        
        return strategy
    
    def _identify_architectural_concerns(self, class_analyses: List[Dict[str, Any]]) -> List[str]:
        """Identify architectural concerns across all classes."""
        concerns = []
        
        # High coupling
        high_coupling_classes = [
            analysis for analysis in class_analyses
            if len(analysis.get('dependencies', [])) > 10
        ]
        if high_coupling_classes:
            concerns.append(f"High coupling in {len(high_coupling_classes)} classes")
        
        # Code duplication
        method_names = []
        for analysis in class_analyses:
            for method in analysis.get('methods', []):
                method_names.append(method.get('name', ''))
        
        duplicate_methods = set([name for name in method_names if method_names.count(name) > 1])
        if duplicate_methods:
            concerns.append(f"Potential code duplication: {len(duplicate_methods)} repeated method names")
        
        # Security concerns
        security_issues = sum(
            len(analysis.get('security_concerns', []))
            for analysis in class_analyses
        )
        if security_issues > 0:
            concerns.append(f"Security concerns found in {security_issues} locations")
        
        # Performance issues
        performance_issues = sum(
            len(analysis.get('performance_issues', []))
            for analysis in class_analyses
        )
        if performance_issues > 0:
            concerns.append(f"Performance issues found in {performance_issues} locations")
        
        return concerns