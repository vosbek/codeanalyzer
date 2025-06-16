import sys
sys.path.append('..')

"""
Dependency Analyzer
===================

This module provides comprehensive dependency analysis for Struts applications.
It identifies dependencies between components, analyzes coupling patterns,
creates dependency graphs, and provides architectural insights for migration planning.

Features:
- Multi-level dependency analysis (class, package, module)
- Coupling strength assessment and metrics
- Circular dependency detection
- Architectural pattern identification
- Dependency graph visualization data
- Migration impact analysis

Author: Claude Code Assistant
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    nx = None
    HAS_NETWORKX = False

from analyzers.base_analyzer import BaseAnalyzer, AnalysisContext
from models.dependency_info import (
    DependencyInfo, DependencyType, DependencyStrength, DependencyDirection,
    DependencyContext, DependencyMetrics
)
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource, 
    BusinessRuleLocation, BusinessRuleEvidence
)
from utils.logging_utils import get_logger
from utils.performance_utils import performance_timer


logger = get_logger(__name__)


@dataclass
class ComponentInfo:
    """Information about a component in the dependency graph."""
    name: str
    component_type: str  # class, package, module, config
    file_path: str
    package: str = ""
    dependencies_out: Set[str] = field(default_factory=set)
    dependencies_in: Set[str] = field(default_factory=set)
    lines_of_code: int = 0
    complexity_score: int = 0
    business_importance: str = "medium"
    migration_priority: str = "medium"
    
    @property
    def fan_out(self) -> int:
        """Number of outgoing dependencies."""
        return len(self.dependencies_out)
    
    @property
    def fan_in(self) -> int:
        """Number of incoming dependencies."""
        return len(self.dependencies_in)
    
    @property
    def instability(self) -> float:
        """Instability metric (fan_out / (fan_in + fan_out))."""
        total = self.fan_in + self.fan_out
        return self.fan_out / total if total > 0 else 0.0
    
    @property
    def is_stable(self) -> bool:
        """Check if component is stable (low instability)."""
        return self.instability < 0.3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'component_type': self.component_type,
            'file_path': self.file_path,
            'package': self.package,
            'dependencies_out': list(self.dependencies_out),
            'dependencies_in': list(self.dependencies_in),
            'lines_of_code': self.lines_of_code,
            'complexity_score': self.complexity_score,
            'business_importance': self.business_importance,
            'migration_priority': self.migration_priority,
            'fan_out': self.fan_out,
            'fan_in': self.fan_in,
            'instability': self.instability,
            'is_stable': self.is_stable
        }


@dataclass
class DependencyCluster:
    """Represents a cluster of tightly coupled components."""
    cluster_id: str
    components: List[str] = field(default_factory=list)
    internal_dependencies: List[DependencyInfo] = field(default_factory=list)
    external_dependencies: List[DependencyInfo] = field(default_factory=list)
    cluster_type: str = ""  # feature, layer, domain
    cohesion_score: float = 0.0
    coupling_score: float = 0.0
    migration_complexity: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'cluster_id': self.cluster_id,
            'components': self.components,
            'internal_dependencies': [dep.to_dict() for dep in self.internal_dependencies],
            'external_dependencies': [dep.to_dict() for dep in self.external_dependencies],
            'cluster_type': self.cluster_type,
            'cohesion_score': self.cohesion_score,
            'coupling_score': self.coupling_score,
            'migration_complexity': self.migration_complexity
        }


@dataclass
class ArchitecturalInsight:
    """Represents an architectural insight derived from dependency analysis."""
    insight_type: str  # violation, pattern, concern, recommendation
    title: str
    description: str
    affected_components: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical
    architectural_principle: str = ""
    migration_impact: str = ""
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'insight_type': self.insight_type,
            'title': self.title,
            'description': self.description,
            'affected_components': self.affected_components,
            'severity': self.severity,
            'architectural_principle': self.architectural_principle,
            'migration_impact': self.migration_impact,
            'recommendations': self.recommendations
        }


class DependencyAnalyzer(BaseAnalyzer):
    """
    Analyzer for dependency relationships in Struts applications.
    
    Provides comprehensive dependency analysis including coupling metrics,
    architectural insights, and migration recommendations.
    """
    
    def _initialize_analyzer(self) -> None:
        """Initialize dependency analyzer settings."""
        self._supported_extensions = {'.java', '.xml', '.jsp', '.properties'}
        self._required_patterns = []  # Can analyze any file type
        
        # Dependency patterns for different file types
        self._java_import_pattern = re.compile(r'import\s+([\w.]+);')
        self._java_class_usage_pattern = re.compile(r'\b([A-Z][a-zA-Z0-9]*)\s+\w+\s*[=;]')
        self._struts_config_patterns = {
            'action_forward': re.compile(r'<forward\s+[^>]*path="([^"]+)"'),
            'form_bean': re.compile(r'<form-bean\s+[^>]*type="([^"]+)"'),
            'action_class': re.compile(r'<action\s+[^>]*type="([^"]+)"')
        }
        self._jsp_patterns = {
            'jsp_include': re.compile(r'<%@\s*include\s+file="([^"]+)"'),
            'struts_tag': re.compile(r'<(html|logic|bean):[^>]+>'),
            'jsp_forward': re.compile(r'<jsp:forward\s+page="([^"]+)"')
        }
        
        # Struts-specific component types
        self._struts_component_types = {
            'Action': 'action_class',
            'ActionForm': 'form_bean',
            'DynaActionForm': 'dynamic_form',
            'ValidatorForm': 'validator_form',
            'Interceptor': 'interceptor',
            'RequestProcessor': 'request_processor'
        }
        
        # Architectural layer patterns
        self._layer_patterns = {
            'presentation': ['action', 'form', 'jsp', 'struts'],
            'business': ['service', 'manager', 'business', 'logic'],
            'persistence': ['dao', 'repository', 'entity', 'model'],
            'infrastructure': ['util', 'helper', 'config', 'common']
        }
    
    def can_analyze(self, file_path: Path) -> bool:
        """
        Check if this file can be analyzed for dependencies.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file can be analyzed for dependencies
        """
        return file_path.suffix.lower() in self._supported_extensions
    
    @performance_timer("dependency_analysis")
    def _analyze_file(self, file_path: Path, context: AnalysisContext) -> Dict[str, Any]:
        """
        Analyze dependencies in a single file.
        
        Args:
            file_path: Path to file
            context: Analysis context
            
        Returns:
            Dictionary containing file dependency analysis
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Determine component info
            component = self._create_component_info(file_path, content)
            
            # Extract dependencies based on file type
            dependencies = self._extract_dependencies(file_path, content, component)
            
            return {
                'component': component.to_dict(),
                'dependencies': [dep.to_dict() for dep in dependencies],
                'file_path': str(file_path),
                'analysis_metrics': {
                    'total_dependencies': len(dependencies),
                    'unique_targets': len(set(dep.target_component for dep in dependencies)),
                    'struts_dependencies': len([dep for dep in dependencies if dep.is_struts_specific]),
                    'external_dependencies': len([dep for dep in dependencies if self._is_external_dependency(dep)])
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing dependencies in {file_path}: {e}")
            return {
                'error': f"Dependency analysis failed: {e}",
                'file_path': str(file_path),
                'component': None,
                'dependencies': []
            }
    
    def _create_component_info(self, file_path: Path, content: str) -> ComponentInfo:
        """Create component information from file analysis."""
        # Extract component name and type
        if file_path.suffix == '.java':
            component_name = self._extract_java_class_name(content) or file_path.stem
            component_type = self._determine_java_component_type(content, component_name)
            package = self._extract_java_package(content)
        elif file_path.suffix == '.xml':
            component_name = file_path.stem
            component_type = self._determine_xml_component_type(content, file_path)
            package = ""
        elif file_path.suffix in ['.jsp', '.jspx']:
            component_name = file_path.stem
            component_type = 'jsp_page'
            package = self._extract_jsp_package_context(file_path)
        else:
            component_name = file_path.stem
            component_type = 'resource_file'
            package = ""
        
        component = ComponentInfo(
            name=component_name,
            component_type=component_type,
            file_path=str(file_path),
            package=package,
            lines_of_code=len(content.split('\n')),
            complexity_score=self._calculate_component_complexity(content, component_type)
        )
        
        # Determine business importance and migration priority
        component.business_importance = self._assess_business_importance(component, content)
        component.migration_priority = self._assess_migration_priority(component, content)
        
        return component
    
    def _extract_java_class_name(self, content: str) -> Optional[str]:
        """Extract the main class name from Java content."""
        class_match = re.search(r'(?:public\s+)?class\s+(\w+)', content)
        return class_match.group(1) if class_match else None
    
    def _extract_java_package(self, content: str) -> str:
        """Extract package name from Java content."""
        package_match = re.search(r'package\s+([\w.]+);', content)
        return package_match.group(1) if package_match else ""
    
    def _determine_java_component_type(self, content: str, class_name: str) -> str:
        """Determine the type of Java component."""
        class_name_lower = class_name.lower()
        
        # Check for Struts-specific inheritance
        if re.search(r'extends\s+.*Action', content):
            return 'struts_action'
        elif re.search(r'extends\s+.*Form', content):
            return 'struts_form'
        elif re.search(r'implements\s+.*Interceptor', content):
            return 'struts_interceptor'
        
        # Check for common patterns
        if 'action' in class_name_lower:
            return 'action_class'
        elif 'form' in class_name_lower or 'bean' in class_name_lower:
            return 'form_bean'
        elif 'service' in class_name_lower:
            return 'service_class'
        elif 'dao' in class_name_lower or 'repository' in class_name_lower:
            return 'dao_class'
        elif 'util' in class_name_lower or 'helper' in class_name_lower:
            return 'utility_class'
        elif 'exception' in class_name_lower or 'error' in class_name_lower:
            return 'exception_class'
        else:
            return 'java_class'
    
    def _determine_xml_component_type(self, content: str, file_path: Path) -> str:
        """Determine the type of XML component."""
        filename = file_path.name.lower()
        
        if 'struts-config' in filename or 'struts.xml' in filename:
            return 'struts_config'
        elif 'validation' in filename:
            return 'validation_config'
        elif 'web.xml' in filename:
            return 'web_config'
        elif 'applicationContext' in filename or 'spring' in filename:
            return 'spring_config'
        else:
            return 'xml_config'
    
    def _extract_jsp_package_context(self, file_path: Path) -> str:
        """Extract package context from JSP file path."""
        # Use directory structure as package context
        parts = file_path.parts
        if len(parts) > 1:
            return '.'.join(parts[:-1])
        return ""
    
    def _calculate_component_complexity(self, content: str, component_type: str) -> int:
        """Calculate complexity score for a component."""
        complexity = 1
        
        # Base complexity from size
        lines = len(content.split('\n'))
        complexity += lines // 50  # 1 point per 50 lines
        
        # Type-specific complexity
        if component_type.startswith('struts_'):
            complexity += 2  # Struts components are inherently more complex
        
        # Content-based complexity
        if component_type == 'java_class':
            # Count methods, classes, and imports
            method_count = len(re.findall(r'\s+(public|private|protected)\s+\w+\s+\w+\s*\(', content))
            import_count = len(re.findall(r'import\s+[\w.]+;', content))
            complexity += method_count // 5 + import_count // 10
        elif component_type in ['struts_config', 'validation_config']:
            # Count XML elements
            element_count = len(re.findall(r'<\w+[^>]*>', content))
            complexity += element_count // 20
        elif component_type == 'jsp_page':
            # Count JSP tags and scriptlets
            jsp_tag_count = len(re.findall(r'<%[^>]*%>', content))
            struts_tag_count = len(re.findall(r'<(html|logic|bean):[^>]+>', content))
            complexity += jsp_tag_count // 10 + struts_tag_count // 5
        
        return complexity
    
    def _assess_business_importance(self, component: ComponentInfo, content: str) -> str:
        """Assess the business importance of a component."""
        # High importance indicators
        high_importance_indicators = [
            'main', 'core', 'critical', 'business', 'service',
            'transaction', 'payment', 'order', 'customer'
        ]
        
        # Check component name and content
        name_lower = component.name.lower()
        content_lower = content.lower()
        
        high_score = sum(1 for indicator in high_importance_indicators 
                        if indicator in name_lower or indicator in content_lower)
        
        if high_score >= 3:
            return "high"
        elif high_score >= 1:
            return "medium"
        else:
            return "low"
    
    def _assess_migration_priority(self, component: ComponentInfo, content: str) -> str:
        """Assess migration priority of a component."""
        priority_score = 0
        
        # Struts-specific components have higher priority
        if component.component_type.startswith('struts_'):
            priority_score += 3
        
        # Complex components need more attention
        if component.complexity_score > 10:
            priority_score += 2
        
        # Business-critical components
        if component.business_importance == "high":
            priority_score += 2
        
        # Components with many dependencies
        if component.fan_out > 10:
            priority_score += 1
        
        if priority_score >= 5:
            return "critical"
        elif priority_score >= 3:
            return "high"
        elif priority_score >= 1:
            return "medium"
        else:
            return "low"
    
    def _extract_dependencies(self, file_path: Path, content: str, 
                            component: ComponentInfo) -> List[DependencyInfo]:
        """Extract dependencies from file content."""
        dependencies = []
        
        if file_path.suffix == '.java':
            dependencies.extend(self._extract_java_dependencies(content, component))
        elif file_path.suffix == '.xml':
            dependencies.extend(self._extract_xml_dependencies(content, component, file_path))
        elif file_path.suffix in ['.jsp', '.jspx']:
            dependencies.extend(self._extract_jsp_dependencies(content, component))
        elif file_path.suffix == '.properties':
            dependencies.extend(self._extract_properties_dependencies(content, component))
        
        return dependencies
    
    def _extract_java_dependencies(self, content: str, component: ComponentInfo) -> List[DependencyInfo]:
        """Extract dependencies from Java file."""
        dependencies = []
        
        # Import dependencies
        import_matches = self._java_import_pattern.findall(content)
        for import_path in import_matches:
            dep = DependencyInfo(
                id="auto",
                source_component=component.name,
                target_component=import_path,
                dependency_type=DependencyType.IMPORT,
                source_location=component.file_path
            )
            
            # Add Struts-specific information as a tag
            if self._is_struts_import(import_path):
                dep.tags.add("struts_specific")
                dep.custom_attributes["is_struts_specific"] = True
            
            # Assess dependency characteristics
            dep.strength = self._assess_import_dependency_strength(import_path)
            dep.context = self._create_dependency_context(import_path, "Java import")
            dep.is_optional = self._is_optional_dependency(import_path)
            
            dependencies.append(dep)
        
        # Class usage dependencies (simplified)
        class_usage_matches = self._java_class_usage_pattern.findall(content)
        for class_name in class_usage_matches:
            if class_name != component.name:  # Don't include self-references
                dep = DependencyInfo(
                    id="auto",
                    source_component=component.name,
                    target_component=class_name,
                    dependency_type=DependencyType.COMPOSITION,
                    source_location=component.file_path,
                    strength=DependencyStrength.MODERATE
                )
                
                dep.context = self._create_dependency_context(class_name, "Class usage")
                dependencies.append(dep)
        
        # Inheritance dependencies
        extends_match = re.search(r'extends\s+([\w.]+)', content)
        if extends_match:
            superclass = extends_match.group(1)
            dep = DependencyInfo(
                id="auto",
                source_component=component.name,
                target_component=superclass,
                dependency_type=DependencyType.INHERITANCE,
                source_location=component.file_path,
                strength=DependencyStrength.STRONG
            )
            
            if self._is_struts_class(superclass):
                dep.tags.add("struts_specific")
            
            dep.context = self._create_dependency_context(superclass, "Inheritance relationship")
            dependencies.append(dep)
        
        # Interface implementation dependencies
        implements_match = re.search(r'implements\s+([\w.,\s]+)', content)
        if implements_match:
            interfaces = [iface.strip() for iface in implements_match.group(1).split(',')]
            for interface in interfaces:
                dep = DependencyInfo(
                    id="auto",
                    source_component=component.name,
                    target_component=interface,
                    dependency_type=DependencyType.IMPLEMENTATION,
                    source_location=component.file_path,
                    strength=DependencyStrength.STRONG
                )
                
                if self._is_struts_class(interface):
                    dep.tags.add("struts_specific")
                
                dep.context = self._create_dependency_context(interface, "Interface implementation")
                dependencies.append(dep)
        
        return dependencies
    
    def _extract_xml_dependencies(self, content: str, component: ComponentInfo, 
                                 file_path: Path) -> List[DependencyInfo]:
        """Extract dependencies from XML configuration files."""
        dependencies = []
        
        if component.component_type == 'struts_config':
            # Action class dependencies
            for pattern_name, pattern in self._struts_config_patterns.items():
                matches = pattern.findall(content)
                for match in matches:
                    dep_type = self._get_struts_dependency_type(pattern_name)
                    dep = DependencyInfo(
                        id="auto",
                        source_component=component.name,
                        target_component=match,
                        dependency_type=dep_type,
                        source_location=component.file_path,
                        strength=DependencyStrength.STRONG
                    )
                    
                    dep.tags.add("struts_specific")
                    
                    dep.context = self._create_dependency_context(match, f"Struts {pattern_name}")
                    dependencies.append(dep)
        
        # General XML class references
        class_ref_pattern = re.compile(r'class="([^"]+)"')
        class_matches = class_ref_pattern.findall(content)
        for class_name in class_matches:
            dep = DependencyInfo(
                id="auto",
                source_component=component.name,
                target_component=class_name,
                dependency_type=DependencyType.ASSOCIATION,
                source_location=component.file_path,
                strength=DependencyStrength.MODERATE
            )
            
            dep.context = self._create_dependency_context(class_name, "XML class reference")
            dependencies.append(dep)
        
        return dependencies
    
    def _extract_jsp_dependencies(self, content: str, component: ComponentInfo) -> List[DependencyInfo]:
        """Extract dependencies from JSP files."""
        dependencies = []
        
        # JSP include dependencies
        for pattern_name, pattern in self._jsp_patterns.items():
            matches = pattern.findall(content)
            for match in matches:
                dep_type = self._get_jsp_dependency_type(pattern_name)
                dep = DependencyInfo(
                    id="auto",
                    source_component=component.name,
                    target_component=match,
                    dependency_type=dep_type,
                    source_location=component.file_path,
                    strength=DependencyStrength.MODERATE
                )
                
                dep.context = self._create_dependency_context(match, f"JSP {pattern_name}")
                dependencies.append(dep)
        
        # Bean references in JSP
        bean_pattern = re.compile(r'name="([^"]+)"')
        bean_matches = bean_pattern.findall(content)
        for bean_name in bean_matches:
            dep = DependencyInfo(
                id="auto",
                source_component=component.name,
                target_component=bean_name,
                dependency_type=DependencyType.ASSOCIATION,
                source_location=component.file_path,
                strength=DependencyStrength.WEAK
            )
            
            dep.context = self._create_dependency_context(bean_name, "JSP bean reference")
            dependencies.append(dep)
        
        return dependencies
    
    def _extract_properties_dependencies(self, content: str, component: ComponentInfo) -> List[DependencyInfo]:
        """Extract dependencies from properties files."""
        dependencies = []
        
        # Class references in properties
        class_pattern = re.compile(r'([a-zA-Z_][a-zA-Z0-9_.]*[A-Z][a-zA-Z0-9_]*)')
        class_matches = class_pattern.findall(content)
        
        for class_ref in set(class_matches):  # Remove duplicates
            if '.' in class_ref and class_ref[0].isupper():  # Likely a class name
                dep = DependencyInfo(
                    id="auto",
                    source_component=component.name,
                    target_component=class_ref,
                    dependency_type=DependencyType.ASSOCIATION,
                    source_location=component.file_path,
                    strength=DependencyStrength.WEAK
                )
                
                dep.context = self._create_dependency_context(class_ref, "Properties class reference")
                dependencies.append(dep)
        
        return dependencies
    
    def _is_struts_import(self, import_path: str) -> bool:
        """Check if import is Struts-specific."""
        struts_packages = [
            'org.apache.struts',
            'org.apache.struts2',
            'com.opensymphony.xwork'
        ]
        return any(import_path.startswith(pkg) for pkg in struts_packages)
    
    def _is_struts_class(self, class_name: str) -> bool:
        """Check if class is Struts-specific."""
        struts_indicators = ['Action', 'Form', 'Interceptor', 'Struts']
        return any(indicator in class_name for indicator in struts_indicators)
    
    def _assess_import_dependency_strength(self, import_path: str) -> DependencyStrength:
        """Assess the strength of an import dependency."""
        if self._is_struts_import(import_path):
            return DependencyStrength.CRITICAL
        elif any(pkg in import_path for pkg in ['java.lang', 'java.util']):
            return DependencyStrength.WEAK
        elif 'javax' in import_path:
            return DependencyStrength.MODERATE
        else:
            return DependencyStrength.MODERATE
    
    def _create_dependency_context(self, target: str, usage_type: str) -> DependencyContext:
        """Create dependency context information."""
        return DependencyContext(
            usage_context=usage_type,
            business_context=self._infer_business_context(target),
            architectural_layer=self._infer_architectural_layer(target),
            coupling_reason=f"Component uses {target} for {usage_type}"
        )
    
    def _infer_business_context(self, target: str) -> str:
        """Infer business context from target name."""
        target_lower = target.lower()
        
        if any(term in target_lower for term in ['action', 'controller']):
            return "Request handling and business logic execution"
        elif any(term in target_lower for term in ['form', 'bean', 'dto']):
            return "Data transfer and validation"
        elif any(term in target_lower for term in ['service', 'manager']):
            return "Business service layer operations"
        elif any(term in target_lower for term in ['dao', 'repository']):
            return "Data access and persistence"
        elif any(term in target_lower for term in ['util', 'helper']):
            return "Utility and support functions"
        else:
            return "General component dependency"
    
    def _infer_architectural_layer(self, target: str) -> str:
        """Infer architectural layer from target name."""
        target_lower = target.lower()
        
        for layer, patterns in self._layer_patterns.items():
            if any(pattern in target_lower for pattern in patterns):
                return layer
        
        return "unknown"
    
    def _is_optional_dependency(self, import_path: str) -> bool:
        """Check if dependency is optional."""
        # Simple heuristic: logging, testing, and utility dependencies are often optional
        optional_patterns = ['log', 'test', 'mock', 'debug', 'util']
        return any(pattern in import_path.lower() for pattern in optional_patterns)
    
    def _get_struts_dependency_type(self, pattern_name: str) -> DependencyType:
        """Get dependency type for Struts configuration patterns."""
        mapping = {
            'action_forward': DependencyType.ACTION_FORWARD,
            'form_bean': DependencyType.FORM_BINDING,
            'action_class': DependencyType.ASSOCIATION
        }
        return mapping.get(pattern_name, DependencyType.ASSOCIATION)
    
    def _get_jsp_dependency_type(self, pattern_name: str) -> DependencyType:
        """Get dependency type for JSP patterns."""
        mapping = {
            'jsp_include': DependencyType.JSP_INCLUDE,
            'struts_tag': DependencyType.ASSOCIATION,
            'jsp_forward': DependencyType.ACTION_FORWARD
        }
        return mapping.get(pattern_name, DependencyType.ASSOCIATION)
    
    def _is_external_dependency(self, dep: DependencyInfo) -> bool:
        """Check if dependency is external to the application."""
        external_packages = [
            'java.',
            'javax.',
            'org.apache.',
            'org.springframework.',
            'com.sun.',
            'org.hibernate.'
        ]
        return any(dep.target_component.startswith(pkg) for pkg in external_packages)
    
    def _post_process_results(self, results: List[Dict[str, Any]], 
                            context: AnalysisContext) -> Dict[str, Any]:
        """
        Post-process and aggregate dependency analysis results.
        
        Args:
            results: List of individual file analysis results
            context: Analysis context
            
        Returns:
            Comprehensive dependency analysis results
        """
        if not results:
            return {
                'dependency_graph': {},
                'components': [],
                'dependency_metrics': {},
                'architectural_insights': [],
                'summary': {'total_components': 0, 'total_dependencies': 0}
            }
        
        # Filter successful analyses
        successful_results = [r for r in results if 'error' not in r and r.get('component')]
        
        # Build comprehensive dependency graph
        dependency_graph = self._build_dependency_graph(successful_results)
        
        # Analyze coupling and cohesion
        coupling_analysis = self._analyze_coupling_patterns(dependency_graph)
        
        # Detect architectural violations
        architectural_insights = self._detect_architectural_insights(dependency_graph)
        
        # Identify dependency clusters
        dependency_clusters = self._identify_dependency_clusters(dependency_graph)
        
        # Calculate comprehensive metrics
        dependency_metrics = self._calculate_dependency_metrics(dependency_graph)
        
        # Generate migration recommendations
        migration_recommendations = self._generate_migration_recommendations(
            dependency_graph, architectural_insights, dependency_clusters
        )
        
        return {
            'dependency_graph': self._serialize_dependency_graph(dependency_graph),
            'components': [result['component'] for result in successful_results],
            'coupling_analysis': coupling_analysis,
            'architectural_insights': [insight.to_dict() for insight in architectural_insights],
            'dependency_clusters': [cluster.to_dict() for cluster in dependency_clusters],
            'dependency_metrics': dependency_metrics,
            'migration_recommendations': migration_recommendations,
            'summary': {
                'total_components': len(successful_results),
                'total_dependencies': sum(result['analysis_metrics']['total_dependencies'] 
                                        for result in successful_results),
                'struts_components': len([r for r in successful_results 
                                        if r['component']['component_type'].startswith('struts_')]),
                'high_coupling_components': len([r for r in successful_results 
                                               if r['component']['fan_out'] > 10]),
                'circular_dependencies': len(self._find_circular_dependencies(dependency_graph))
            }
        }
    
    def _build_dependency_graph(self, results: List[Dict[str, Any]]) -> Any:
        """Build a NetworkX dependency graph from analysis results."""
        if not HAS_NETWORKX:
            return None
        
        graph = nx.DiGraph()
        
        # Add components as nodes
        for result in results:
            component = result['component']
            graph.add_node(
                component['name'],
                **component
            )
        
        # Add dependencies as edges
        for result in results:
            source_component = result['component']['name']
            for dep_data in result['dependencies']:
                target_component = dep_data['target_component']
                
                # Add edge with dependency information
                graph.add_edge(
                    source_component,
                    target_component,
                    **dep_data
                )
        
        return graph
    
    def _analyze_coupling_patterns(self, graph: Any) -> Dict[str, Any]:
        """Analyze coupling patterns in the dependency graph."""
        coupling_analysis = {
            'afferent_coupling': {},
            'efferent_coupling': {},
            'instability_metrics': {},
            'tightly_coupled_components': [],
            'loosely_coupled_components': [],
            'coupling_hotspots': []
        }
        
        for node in graph.nodes():
            # Calculate afferent coupling (fan-in)
            afferent = len(list(graph.predecessors(node)))
            # Calculate efferent coupling (fan-out)
            efferent = len(list(graph.successors(node)))
            
            coupling_analysis['afferent_coupling'][node] = afferent
            coupling_analysis['efferent_coupling'][node] = efferent
            
            # Calculate instability
            total_coupling = afferent + efferent
            instability = efferent / total_coupling if total_coupling > 0 else 0
            coupling_analysis['instability_metrics'][node] = instability
            
            # Categorize components
            if efferent > 15:  # High efferent coupling
                coupling_analysis['tightly_coupled_components'].append({
                    'component': node,
                    'efferent_coupling': efferent,
                    'reason': 'High outgoing dependencies'
                })
            elif efferent < 3 and afferent < 3:  # Low coupling both ways
                coupling_analysis['loosely_coupled_components'].append({
                    'component': node,
                    'coupling_score': efferent + afferent
                })
            
            # Identify coupling hotspots (high both ways)
            if afferent > 10 and efferent > 10:
                coupling_analysis['coupling_hotspots'].append({
                    'component': node,
                    'afferent_coupling': afferent,
                    'efferent_coupling': efferent,
                    'total_coupling': total_coupling
                })
        
        return coupling_analysis
    
    def _detect_architectural_insights(self, graph: nx.DiGraph) -> List[ArchitecturalInsight]:
        """Detect architectural insights and violations."""
        insights = []
        
        # Detect circular dependencies
        circular_deps = self._find_circular_dependencies(graph)
        if circular_deps:
            insights.append(ArchitecturalInsight(
                insight_type="violation",
                title="Circular Dependencies Detected",
                description=f"Found {len(circular_deps)} circular dependency cycles",
                affected_components=[comp for cycle in circular_deps for comp in cycle],
                severity="high",
                architectural_principle="Acyclic Dependencies Principle",
                migration_impact="High - circular dependencies complicate migration and testing",
                recommendations=[
                    "Break circular dependencies by introducing interfaces",
                    "Consider dependency inversion to resolve cycles",
                    "Refactor tightly coupled components"
                ]
            ))
        
        # Detect violation of layered architecture
        layer_violations = self._detect_layer_violations(graph)
        if layer_violations:
            insights.append(ArchitecturalInsight(
                insight_type="violation",
                title="Layered Architecture Violations",
                description=f"Found {len(layer_violations)} layer boundary violations",
                affected_components=[v['component'] for v in layer_violations],
                severity="medium",
                architectural_principle="Layered Architecture",
                migration_impact="Medium - may require refactoring to establish clear boundaries",
                recommendations=[
                    "Establish clear layer boundaries",
                    "Use dependency injection to manage cross-layer dependencies",
                    "Consider moving business logic to appropriate layers"
                ]
            ))
        
        # Detect components with excessive dependencies
        high_coupling_components = [
            node for node in graph.nodes()
            if len(list(graph.successors(node))) > 20
        ]
        if high_coupling_components:
            insights.append(ArchitecturalInsight(
                insight_type="concern",
                title="High Coupling Components",
                description=f"Found {len(high_coupling_components)} components with excessive dependencies",
                affected_components=high_coupling_components,
                severity="medium",
                architectural_principle="Low Coupling",
                migration_impact="Medium - high coupling increases migration complexity",
                recommendations=[
                    "Break down large components into smaller, focused ones",
                    "Apply Single Responsibility Principle",
                    "Use facade or adapter patterns to reduce coupling"
                ]
            ))
        
        # Detect Struts-specific architecture patterns
        struts_patterns = self._detect_struts_patterns(graph)
        insights.extend(struts_patterns)
        
        return insights
    
    def _find_circular_dependencies(self, graph: Any) -> List[List[str]]:
        """Find circular dependencies in the graph."""
        try:
            cycles = list(nx.simple_cycles(graph))
            return cycles
        except Exception as e:
            logger.warning(f"Error detecting cycles: {e}")
            return []
    
    def _detect_layer_violations(self, graph: nx.DiGraph) -> List[Dict[str, Any]]:
        """Detect violations of layered architecture."""
        violations = []
        
        # Define layer hierarchy (lower layers should not depend on higher layers)
        layer_hierarchy = ['persistence', 'business', 'presentation', 'infrastructure']
        
        for edge in graph.edges(data=True):
            source, target, edge_data = edge
            source_layer = self._get_component_layer(source)
            target_layer = self._get_component_layer(target)
            
            if source_layer and target_layer:
                source_level = layer_hierarchy.index(source_layer) if source_layer in layer_hierarchy else -1
                target_level = layer_hierarchy.index(target_layer) if target_layer in layer_hierarchy else -1
                
                # Violation: lower layer depending on higher layer
                if source_level != -1 and target_level != -1 and source_level < target_level:
                    violations.append({
                        'component': source,
                        'depends_on': target,
                        'source_layer': source_layer,
                        'target_layer': target_layer,
                        'violation_type': 'upward_dependency'
                    })
        
        return violations
    
    def _get_component_layer(self, component_name: str) -> Optional[str]:
        """Determine the architectural layer of a component."""
        component_lower = component_name.lower()
        
        for layer, patterns in self._layer_patterns.items():
            if any(pattern in component_lower for pattern in patterns):
                return layer
        
        return None
    
    def _detect_struts_patterns(self, graph: nx.DiGraph) -> List[ArchitecturalInsight]:
        """Detect Struts-specific architectural patterns."""
        insights = []
        
        # Find Action classes and their dependencies
        action_components = [
            node for node in graph.nodes()
            if graph.nodes[node].get('component_type', '').startswith('struts_action')
        ]
        
        if action_components:
            # Analyze Action class patterns
            complex_actions = []
            for action in action_components:
                successors = list(graph.successors(action))
                if len(successors) > 15:
                    complex_actions.append(action)
            
            if complex_actions:
                insights.append(ArchitecturalInsight(
                    insight_type="pattern",
                    title="Complex Action Classes Detected",
                    description=f"Found {len(complex_actions)} Action classes with high complexity",
                    affected_components=complex_actions,
                    severity="medium",
                    architectural_principle="Single Responsibility Principle",
                    migration_impact="Medium - complex Actions require careful refactoring",
                    recommendations=[
                        "Extract business logic into service classes",
                        "Use Command pattern for complex operations",
                        "Consider breaking large Actions into smaller controllers"
                    ]
                ))
        
        # Find Form beans and their usage patterns
        form_components = [
            node for node in graph.nodes()
            if 'form' in graph.nodes[node].get('component_type', '').lower()
        ]
        
        if form_components:
            insights.append(ArchitecturalInsight(
                insight_type="pattern",
                title="Struts Form Bean Pattern",
                description=f"Found {len(form_components)} Form beans requiring migration",
                affected_components=form_components,
                severity="low",
                architectural_principle="Data Transfer Object Pattern",
                migration_impact="Low - Form beans can be migrated to DTOs with validation",
                recommendations=[
                    "Convert Form beans to DTOs with Bean Validation",
                    "Use GraphQL input types for API endpoints",
                    "Implement Angular reactive forms for client-side"
                ]
            ))
        
        return insights
    
    def _identify_dependency_clusters(self, graph: nx.DiGraph) -> List[DependencyCluster]:
        """Identify clusters of tightly coupled components."""
        clusters = []
        
        try:
            # Use community detection to find clusters
            undirected_graph = graph.to_undirected()
            
            # Simple clustering based on connected components
            connected_components = list(nx.connected_components(undirected_graph))
            
            for i, component_set in enumerate(connected_components):
                if len(component_set) > 1:  # Only consider clusters with multiple components
                    cluster_components = list(component_set)
                    
                    # Extract internal and external dependencies
                    internal_deps = []
                    external_deps = []
                    
                    for comp in cluster_components:
                        for successor in graph.successors(comp):
                            edge_data = graph.get_edge_data(comp, successor)
                            dep_info = DependencyInfo(
                                id=edge_data.get('id', 'unknown'),
                                source_component=comp,
                                target_component=successor,
                                dependency_type=DependencyType(edge_data.get('dependency_type', 'unknown'))
                            )
                            
                            if successor in cluster_components:
                                internal_deps.append(dep_info)
                            else:
                                external_deps.append(dep_info)
                    
                    # Calculate cluster metrics
                    internal_count = len(internal_deps)
                    external_count = len(external_deps)
                    total_deps = internal_count + external_count
                    
                    cohesion_score = internal_count / total_deps if total_deps > 0 else 0
                    coupling_score = external_count / len(cluster_components)
                    
                    # Determine cluster type
                    cluster_type = self._determine_cluster_type(cluster_components, graph)
                    
                    # Assess migration complexity
                    migration_complexity = self._assess_cluster_migration_complexity(
                        cluster_components, internal_deps, external_deps
                    )
                    
                    cluster = DependencyCluster(
                        cluster_id=f"cluster_{i}",
                        components=cluster_components,
                        internal_dependencies=internal_deps,
                        external_dependencies=external_deps,
                        cluster_type=cluster_type,
                        cohesion_score=cohesion_score,
                        coupling_score=coupling_score,
                        migration_complexity=migration_complexity
                    )
                    clusters.append(cluster)
        
        except Exception as e:
            logger.warning(f"Error identifying dependency clusters: {e}")
        
        return clusters
    
    def _determine_cluster_type(self, components: List[str], graph: nx.DiGraph) -> str:
        """Determine the type of dependency cluster."""
        component_types = [
            graph.nodes[comp].get('component_type', '') 
            for comp in components
        ]
        
        # Analyze component type patterns
        if all('struts_' in comp_type for comp_type in component_types):
            return "struts_feature"
        elif any('action' in comp_type for comp_type in component_types):
            return "feature_module"
        elif any('service' in comp_type for comp_type in component_types):
            return "service_layer"
        elif any('dao' in comp_type or 'repository' in comp_type for comp_type in component_types):
            return "data_layer"
        else:
            return "mixed_cluster"
    
    def _assess_cluster_migration_complexity(self, components: List[str], 
                                           internal_deps: List[DependencyInfo],
                                           external_deps: List[DependencyInfo]) -> str:
        """Assess migration complexity for a dependency cluster."""
        complexity_score = 0
        
        # Size complexity
        complexity_score += len(components) * 2
        
        # Internal coupling complexity
        complexity_score += len(internal_deps)
        
        # External coupling complexity
        complexity_score += len(external_deps) * 2
        
        # Struts-specific complexity
        struts_deps = [dep for dep in internal_deps + external_deps if dep.is_struts_specific]
        complexity_score += len(struts_deps) * 3
        
        if complexity_score > 50:
            return "critical"
        elif complexity_score > 30:
            return "high"
        elif complexity_score > 15:
            return "medium"
        else:
            return "low"
    
    def _calculate_dependency_metrics(self, graph: nx.DiGraph) -> Dict[str, Any]:
        """Calculate comprehensive dependency metrics."""
        metrics = {
            'graph_metrics': {},
            'component_metrics': {},
            'dependency_distribution': {},
            'architectural_metrics': {}
        }
        
        # Graph-level metrics
        metrics['graph_metrics'] = {
            'total_components': graph.number_of_nodes(),
            'total_dependencies': graph.number_of_edges(),
            'density': nx.density(graph),
            'average_clustering': nx.average_clustering(graph.to_undirected()),
            'number_of_strongly_connected_components': nx.number_strongly_connected_components(graph)
        }
        
        # Component-level metrics
        in_degrees = dict(graph.in_degree())
        out_degrees = dict(graph.out_degree())
        
        metrics['component_metrics'] = {
            'max_fan_in': max(in_degrees.values()) if in_degrees else 0,
            'max_fan_out': max(out_degrees.values()) if out_degrees else 0,
            'average_fan_in': sum(in_degrees.values()) / len(in_degrees) if in_degrees else 0,
            'average_fan_out': sum(out_degrees.values()) / len(out_degrees) if out_degrees else 0
        }
        
        # Dependency distribution
        edge_types = defaultdict(int)
        for _, _, edge_data in graph.edges(data=True):
            dep_type = edge_data.get('dependency_type', 'unknown')
            edge_types[dep_type] += 1
        
        metrics['dependency_distribution'] = dict(edge_types)
        
        # Architectural metrics
        layers = defaultdict(int)
        for node in graph.nodes():
            layer = self._get_component_layer(node)
            if layer:
                layers[layer] += 1
        
        metrics['architectural_metrics'] = {
            'layer_distribution': dict(layers),
            'cross_layer_dependencies': self._count_cross_layer_dependencies(graph)
        }
        
        return metrics
    
    def _count_cross_layer_dependencies(self, graph: nx.DiGraph) -> int:
        """Count dependencies that cross architectural layers."""
        cross_layer_count = 0
        
        for source, target in graph.edges():
            source_layer = self._get_component_layer(source)
            target_layer = self._get_component_layer(target)
            
            if source_layer and target_layer and source_layer != target_layer:
                cross_layer_count += 1
        
        return cross_layer_count
    
    def _generate_migration_recommendations(self, graph: nx.DiGraph, 
                                          insights: List[ArchitecturalInsight],
                                          clusters: List[DependencyCluster]) -> List[str]:
        """Generate migration recommendations based on dependency analysis."""
        recommendations = []
        
        # General recommendations
        recommendations.append("Analyze dependency graph to understand migration impact")
        recommendations.append("Prioritize migration of loosely coupled components first")
        
        # Circular dependency recommendations
        circular_deps = self._find_circular_dependencies(graph)
        if circular_deps:
            recommendations.append(f"Resolve {len(circular_deps)} circular dependencies before migration")
            recommendations.append("Use dependency inversion and interfaces to break cycles")
        
        # High coupling recommendations
        high_coupling = [node for node in graph.nodes() if len(list(graph.successors(node))) > 15]
        if high_coupling:
            recommendations.append(f"Refactor {len(high_coupling)} highly coupled components")
            recommendations.append("Apply Single Responsibility Principle to reduce coupling")
        
        # Cluster-specific recommendations
        critical_clusters = [c for c in clusters if c.migration_complexity == "critical"]
        if critical_clusters:
            recommendations.append(f"Pay special attention to {len(critical_clusters)} critical dependency clusters")
            recommendations.append("Consider incremental migration approach for complex clusters")
        
        # Struts-specific recommendations
        struts_components = [
            node for node in graph.nodes()
            if graph.nodes[node].get('component_type', '').startswith('struts_')
        ]
        if struts_components:
            recommendations.append(f"Migrate {len(struts_components)} Struts-specific components")
            recommendations.append("Convert Actions to Spring Controllers or GraphQL resolvers")
            recommendations.append("Replace Form beans with DTOs and validation annotations")
        
        # Architecture-specific recommendations
        layer_violations = len([i for i in insights if i.title == "Layered Architecture Violations"])
        if layer_violations > 0:
            recommendations.append("Establish clear architectural boundaries before migration")
            recommendations.append("Consider using hexagonal architecture for better testability")
        
        return recommendations
    
    def _serialize_dependency_graph(self, graph: nx.DiGraph) -> Dict[str, Any]:
        """Serialize dependency graph for output."""
        return {
            'nodes': [
                {
                    'id': node,
                    'properties': graph.nodes[node]
                }
                for node in graph.nodes()
            ],
            'edges': [
                {
                    'source': source,
                    'target': target,
                    'properties': edge_data
                }
                for source, target, edge_data in graph.edges(data=True)
            ],
            'metrics': {
                'node_count': graph.number_of_nodes(),
                'edge_count': graph.number_of_edges(),
                'density': nx.density(graph)
            }
        }