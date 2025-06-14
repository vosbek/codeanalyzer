"""
Framework-Specific Analysis Plugins
====================================

This module contains plugins for analyzing framework-specific components
that may be integrated with Struts applications.

Plugins included:
- Spring Framework integration analysis
- Hibernate ORM business rule extraction
- Apache Tiles layout analysis
- Custom framework detection

Author: Claude Code Assistant
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import xml.etree.ElementTree as ET
import re

from plugins.base_plugin import FrameworkPlugin, PluginResult, PluginMetadata, PluginType
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource,
    BusinessRuleLocation, BusinessRuleEvidence, BusinessRuleComplexity
)


class SpringIntegrationPlugin(FrameworkPlugin):
    """Plugin for analyzing Spring Framework integration with Struts."""
    
    def _get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="SpringIntegrationPlugin",
            version="1.0.0",
            description="Analyzes Spring Framework integration and business logic",
            author="Claude Code Assistant",
            plugin_type=PluginType.FRAMEWORK,
            supported_file_types={'.xml', '.java'},
            configuration_schema={
                'spring_config_patterns': {
                    'type': 'list',
                    'default': ['applicationContext*.xml', 'spring-*.xml', '*-context.xml'],
                    'description': 'Patterns for Spring configuration files'
                },
                'analyze_annotations': {
                    'type': 'boolean',
                    'default': True,
                    'description': 'Analyze Spring annotations for business logic'
                }
            }
        )
    
    def can_handle(self, context: Dict[str, Any]) -> bool:
        """Check if Spring integration is present."""
        project_path = context.get('project_path')
        if not project_path:
            return False
        
        return self.detect_framework(Path(project_path))
    
    def detect_framework(self, project_path: Path) -> bool:
        """Detect Spring Framework usage."""
        # Check for Spring configuration files
        spring_patterns = self.configuration.get('spring_config_patterns', [
            'applicationContext*.xml', 'spring-*.xml', '*-context.xml'
        ])
        
        for pattern in spring_patterns:
            if list(project_path.glob(f"**/{pattern}")):
                return True
        
        # Check for Spring dependencies in common build files
        build_files = ['pom.xml', 'build.gradle', 'ivy.xml']
        for build_file in build_files:
            build_path = project_path / build_file
            if build_path.exists():
                try:
                    content = build_path.read_text(encoding='utf-8', errors='ignore')
                    if any(spring_indicator in content.lower() for spring_indicator in [
                        'spring-core', 'spring-context', 'spring-beans', 'springframework'
                    ]):
                        return True
                except Exception:
                    continue
        
        return False
    
    def execute(self, context: Dict[str, Any]) -> PluginResult:
        """Execute Spring integration analysis."""
        project_path = Path(context['project_path'])
        return self.analyze_framework_usage(project_path, context)
    
    def analyze_framework_usage(self, project_path: Path, 
                              context: Dict[str, Any]) -> PluginResult:
        """Analyze Spring Framework usage and extract business rules."""
        start_time = datetime.now()
        result = PluginResult(
            plugin_name=self.metadata.name,
            success=True,
            execution_time_ms=0
        )
        
        try:
            # Find Spring configuration files
            spring_configs = self._find_spring_configs(project_path)
            result.add_extracted_data('spring_config_files', [str(f) for f in spring_configs])
            
            # Analyze each configuration file
            for config_file in spring_configs:
                self._analyze_spring_config(config_file, result)
            
            # Analyze Spring annotations if enabled
            if self.configuration.get('analyze_annotations', True):
                self._analyze_spring_annotations(project_path, result)
            
            # Calculate execution time
            end_time = datetime.now()
            result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
        except Exception as e:
            result.add_error(f"Spring analysis failed: {e}")
        
        return result
    
    def _find_spring_configs(self, project_path: Path) -> List[Path]:
        """Find Spring configuration files."""
        spring_configs = []
        patterns = self.configuration.get('spring_config_patterns', [
            'applicationContext*.xml', 'spring-*.xml', '*-context.xml'
        ])
        
        for pattern in patterns:
            spring_configs.extend(project_path.glob(f"**/{pattern}"))
        
        return spring_configs
    
    def _analyze_spring_config(self, config_file: Path, result: PluginResult):
        """Analyze a Spring configuration file."""
        try:
            tree = ET.parse(config_file)
            root = tree.getroot()
            
            # Extract bean definitions
            beans = []
            for bean in root.findall('.//{http://www.springframework.org/schema/beans}bean'):
                bean_data = {
                    'id': bean.get('id', ''),
                    'class': bean.get('class', ''),
                    'scope': bean.get('scope', 'singleton'),
                    'properties': []
                }
                
                # Extract properties
                for prop in bean.findall('.//{http://www.springframework.org/schema/beans}property'):
                    prop_data = {
                        'name': prop.get('name', ''),
                        'value': prop.get('value', ''),
                        'ref': prop.get('ref', '')
                    }
                    bean_data['properties'].append(prop_data)
                
                beans.append(bean_data)
                
                # Create business rule for significant beans
                if self._is_business_bean(bean_data):
                    rule_id = f"spring_bean_{bean_data['id'] or bean_data['class']}"
                    
                    rule = self._create_business_rule_from_plugin(
                        rule_id=rule_id,
                        name=f"Spring Bean: {bean_data['id'] or bean_data['class']}",
                        description=f"Spring-managed business component",
                        rule_type=BusinessRuleType.BUSINESS_LOGIC,
                        source=BusinessRuleSource.STRUTS_CONFIG,
                        file_path=str(config_file),
                        business_context=self._infer_bean_business_context(bean_data),
                        code_snippet=f"<bean id=\"{bean_data['id']}\" class=\"{bean_data['class']}\"/>",
                        complexity=BusinessRuleComplexity.MODERATE
                    )
                    
                    rule.add_tag('spring_bean')
                    rule.add_tag('dependency_injection')
                    
                    result.add_business_rule(rule)
            
            result.add_extracted_data(f'spring_beans_{config_file.name}', beans)
            
            # Analyze AOP configurations
            self._analyze_spring_aop(root, config_file, result)
            
        except ET.ParseError as e:
            result.add_warning(f"Could not parse Spring config {config_file}: {e}")
        except Exception as e:
            result.add_error(f"Error analyzing Spring config {config_file}: {e}")
    
    def _analyze_spring_aop(self, root: ET.Element, config_file: Path, result: PluginResult):
        """Analyze Spring AOP configurations."""
        # Look for aspect definitions
        aspects = root.findall('.//{http://www.springframework.org/schema/aop}aspect')
        
        for aspect in aspects:
            aspect_ref = aspect.get('ref', '')
            
            # Find pointcuts and advice
            pointcuts = aspect.findall('.//{http://www.springframework.org/schema/aop}pointcut')
            advice_elements = aspect.findall('.//{http://www.springframework.org/schema/aop}before') + \
                            aspect.findall('.//{http://www.springframework.org/schema/aop}after') + \
                            aspect.findall('.//{http://www.springframework.org/schema/aop}around')
            
            if pointcuts or advice_elements:
                rule_id = f"spring_aspect_{aspect_ref}"
                
                rule = self._create_business_rule_from_plugin(
                    rule_id=rule_id,
                    name=f"Spring AOP Aspect: {aspect_ref}",
                    description=f"Aspect-oriented programming cross-cutting concern",
                    rule_type=BusinessRuleType.BUSINESS_LOGIC,
                    source=BusinessRuleSource.INTERCEPTOR,
                    file_path=str(config_file),
                    business_context="Cross-cutting concern implementation",
                    code_snippet=f"Spring AOP aspect with {len(pointcuts)} pointcuts and {len(advice_elements)} advice",
                    complexity=BusinessRuleComplexity.COMPLEX
                )
                
                rule.add_tag('spring_aop')
                rule.add_tag('cross_cutting')
                rule.add_tag('aspect')
                
                result.add_business_rule(rule)
    
    def _analyze_spring_annotations(self, project_path: Path, result: PluginResult):
        """Analyze Spring annotations in Java files."""
        java_files = list(project_path.glob("**/*.java"))
        
        spring_annotations = [
            '@Service', '@Component', '@Repository', '@Controller',
            '@Transactional', '@Autowired', '@Qualifier', '@Value'
        ]
        
        for java_file in java_files:
            try:
                content = java_file.read_text(encoding='utf-8', errors='ignore')
                
                for annotation in spring_annotations:
                    if annotation in content:
                        # Create business rule for Spring-annotated classes
                        class_match = re.search(r'public\s+class\s+(\w+)', content)
                        if class_match:
                            class_name = class_match.group(1)
                            
                            rule_id = f"spring_annotation_{class_name}_{annotation.replace('@', '')}"
                            
                            rule = self._create_business_rule_from_plugin(
                                rule_id=rule_id,
                                name=f"Spring Component: {class_name}",
                                description=f"Spring-managed component with {annotation} annotation",
                                rule_type=BusinessRuleType.BUSINESS_LOGIC,
                                source=BusinessRuleSource.ANNOTATION,
                                file_path=str(java_file),
                                business_context=self._infer_annotation_business_context(annotation),
                                code_snippet=f"{annotation} class {class_name}",
                                complexity=BusinessRuleComplexity.MODERATE
                            )
                            
                            rule.add_tag('spring_annotation')
                            rule.add_tag(annotation.replace('@', '').lower())
                            
                            result.add_business_rule(rule)
                            
            except Exception as e:
                result.add_warning(f"Could not analyze Spring annotations in {java_file}: {e}")
    
    def _is_business_bean(self, bean_data: Dict[str, Any]) -> bool:
        """Check if a bean represents business logic."""
        class_name = bean_data.get('class', '').lower()
        bean_id = bean_data.get('id', '').lower()
        
        # Skip infrastructure beans
        infrastructure_patterns = [
            'datasource', 'sessionfactory', 'transactionmanager',
            'propertyplaceholder', 'messageresource'
        ]
        
        if any(pattern in class_name or pattern in bean_id for pattern in infrastructure_patterns):
            return False
        
        # Look for business indicators
        business_patterns = [
            'service', 'manager', 'processor', 'validator',
            'business', 'logic', 'workflow', 'handler'
        ]
        
        return any(pattern in class_name or pattern in bean_id for pattern in business_patterns)
    
    def _infer_bean_business_context(self, bean_data: Dict[str, Any]) -> str:
        """Infer business context from Spring bean."""
        class_name = bean_data.get('class', '').lower()
        bean_id = bean_data.get('id', '').lower()
        
        if 'service' in class_name or 'service' in bean_id:
            return "Business Service Layer"
        elif 'manager' in class_name or 'manager' in bean_id:
            return "Business Process Management"
        elif 'validator' in class_name or 'validator' in bean_id:
            return "Business Validation Logic"
        elif 'processor' in class_name or 'processor' in bean_id:
            return "Business Data Processing"
        else:
            return "Spring-managed Business Component"
    
    def _infer_annotation_business_context(self, annotation: str) -> str:
        """Infer business context from Spring annotation."""
        annotation_contexts = {
            '@Service': "Business Service Layer",
            '@Component': "Business Component",
            '@Repository': "Data Access Layer",
            '@Controller': "Web Controller Layer",
            '@Transactional': "Transaction Management",
            '@Autowired': "Dependency Injection",
            '@Qualifier': "Component Qualification",
            '@Value': "Configuration Value Injection"
        }
        
        return annotation_contexts.get(annotation, "Spring Framework Integration")


class HibernateAnalysisPlugin(FrameworkPlugin):
    """Plugin for analyzing Hibernate ORM business rules."""
    
    def _get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="HibernateAnalysisPlugin",
            version="1.0.0",
            description="Analyzes Hibernate ORM mappings and business rules",
            author="Claude Code Assistant",
            plugin_type=PluginType.FRAMEWORK,
            supported_file_types={'.xml', '.hbm.xml', '.java'},
            configuration_schema={
                'hibernate_config_files': {
                    'type': 'list',
                    'default': ['hibernate.cfg.xml', 'hibernate.properties'],
                    'description': 'Hibernate configuration files to analyze'
                },
                'analyze_entities': {
                    'type': 'boolean',
                    'default': True,
                    'description': 'Analyze Hibernate entity mappings'
                }
            }
        )
    
    def can_handle(self, context: Dict[str, Any]) -> bool:
        """Check if Hibernate is present."""
        project_path = context.get('project_path')
        if not project_path:
            return False
        
        return self.detect_framework(Path(project_path))
    
    def detect_framework(self, project_path: Path) -> bool:
        """Detect Hibernate ORM usage."""
        # Check for Hibernate configuration files
        hibernate_files = ['hibernate.cfg.xml', 'hibernate.properties']
        for file_name in hibernate_files:
            if (project_path / file_name).exists() or list(project_path.glob(f"**/{file_name}")):
                return True
        
        # Check for .hbm.xml mapping files
        if list(project_path.glob("**/*.hbm.xml")):
            return True
        
        # Check for Hibernate dependencies
        build_files = ['pom.xml', 'build.gradle']
        for build_file in build_files:
            build_path = project_path / build_file
            if build_path.exists():
                try:
                    content = build_path.read_text(encoding='utf-8', errors='ignore')
                    if any(hibernate_indicator in content.lower() for hibernate_indicator in [
                        'hibernate-core', 'hibernate-annotations', 'org.hibernate'
                    ]):
                        return True
                except Exception:
                    continue
        
        return False
    
    def execute(self, context: Dict[str, Any]) -> PluginResult:
        """Execute Hibernate analysis."""
        project_path = Path(context['project_path'])
        return self.analyze_framework_usage(project_path, context)
    
    def analyze_framework_usage(self, project_path: Path, 
                              context: Dict[str, Any]) -> PluginResult:
        """Analyze Hibernate usage and extract business rules."""
        start_time = datetime.now()
        result = PluginResult(
            plugin_name=self.metadata.name,
            success=True,
            execution_time_ms=0
        )
        
        try:
            # Analyze Hibernate configuration
            self._analyze_hibernate_config(project_path, result)
            
            # Analyze entity mappings
            if self.configuration.get('analyze_entities', True):
                self._analyze_hibernate_mappings(project_path, result)
                self._analyze_hibernate_annotations(project_path, result)
            
            # Calculate execution time
            end_time = datetime.now()
            result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
        except Exception as e:
            result.add_error(f"Hibernate analysis failed: {e}")
        
        return result
    
    def _analyze_hibernate_config(self, project_path: Path, result: PluginResult):
        """Analyze Hibernate configuration files."""
        config_files = ['hibernate.cfg.xml', 'hibernate.properties']
        
        for config_file in config_files:
            config_paths = [project_path / config_file] + list(project_path.glob(f"**/{config_file}"))
            
            for config_path in config_paths:
                if config_path.exists():
                    try:
                        if config_path.suffix == '.xml':
                            self._analyze_hibernate_xml_config(config_path, result)
                        else:
                            self._analyze_hibernate_properties_config(config_path, result)
                    except Exception as e:
                        result.add_warning(f"Could not analyze Hibernate config {config_path}: {e}")
    
    def _analyze_hibernate_xml_config(self, config_path: Path, result: PluginResult):
        """Analyze hibernate.cfg.xml configuration."""
        tree = ET.parse(config_path)
        root = tree.getroot()
        
        # Extract mapping files
        mappings = []
        for mapping in root.findall('.//mapping'):
            resource = mapping.get('resource', '')
            file_attr = mapping.get('file', '')
            class_attr = mapping.get('class', '')
            
            if resource:
                mappings.append({'type': 'resource', 'value': resource})
            elif file_attr:
                mappings.append({'type': 'file', 'value': file_attr})
            elif class_attr:
                mappings.append({'type': 'class', 'value': class_attr})
        
        result.add_extracted_data('hibernate_mappings', mappings)
        
        # Create business rule for Hibernate configuration
        if mappings:
            rule_id = "hibernate_configuration"
            
            rule = self._create_business_rule_from_plugin(
                rule_id=rule_id,
                name="Hibernate ORM Configuration",
                description=f"Hibernate configuration with {len(mappings)} entity mappings",
                rule_type=BusinessRuleType.DATA,
                source=BusinessRuleSource.STRUTS_CONFIG,
                file_path=str(config_path),
                business_context="Object-Relational Mapping Configuration",
                code_snippet=f"Hibernate config with {len(mappings)} mappings",
                complexity=BusinessRuleComplexity.MODERATE
            )
            
            rule.add_tag('hibernate')
            rule.add_tag('orm')
            rule.add_tag('data_mapping')
            
            result.add_business_rule(rule)
    
    def _analyze_hibernate_properties_config(self, config_path: Path, result: PluginResult):
        """Analyze hibernate.properties configuration."""
        content = config_path.read_text(encoding='utf-8', errors='ignore')
        
        # Count meaningful properties (skip comments and empty lines)
        properties = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    properties.append({'key': key.strip(), 'value': value.strip()})
        
        result.add_extracted_data('hibernate_properties', properties)
    
    def _analyze_hibernate_mappings(self, project_path: Path, result: PluginResult):
        """Analyze Hibernate mapping files (.hbm.xml)."""
        mapping_files = list(project_path.glob("**/*.hbm.xml"))
        
        for mapping_file in mapping_files:
            try:
                tree = ET.parse(mapping_file)
                root = tree.getroot()
                
                # Find class mappings
                for class_mapping in root.findall('.//class'):
                    class_name = class_mapping.get('name', '')
                    table_name = class_mapping.get('table', '')
                    
                    if class_name:
                        rule_id = f"hibernate_entity_{class_name}"
                        
                        # Count properties and relationships
                        properties = len(class_mapping.findall('.//property'))
                        relationships = len(class_mapping.findall('.//many-to-one')) + \
                                      len(class_mapping.findall('.//one-to-many')) + \
                                      len(class_mapping.findall('.//many-to-many'))
                        
                        rule = self._create_business_rule_from_plugin(
                            rule_id=rule_id,
                            name=f"Hibernate Entity: {class_name}",
                            description=f"Hibernate entity mapping with {properties} properties and {relationships} relationships",
                            rule_type=BusinessRuleType.DATA,
                            source=BusinessRuleSource.STRUTS_CONFIG,
                            file_path=str(mapping_file),
                            business_context=self._infer_entity_business_context(class_name),
                            code_snippet=f'<class name="{class_name}" table="{table_name}">',
                            complexity=self._calculate_entity_complexity(properties, relationships)
                        )
                        
                        rule.add_tag('hibernate_entity')
                        rule.add_tag('orm_mapping')
                        rule.add_tag('data_model')
                        
                        result.add_business_rule(rule)
                        
            except Exception as e:
                result.add_warning(f"Could not analyze Hibernate mapping {mapping_file}: {e}")
    
    def _analyze_hibernate_annotations(self, project_path: Path, result: PluginResult):
        """Analyze Hibernate annotations in Java files."""
        java_files = list(project_path.glob("**/*.java"))
        
        hibernate_annotations = [
            '@Entity', '@Table', '@Id', '@GeneratedValue',
            '@Column', '@ManyToOne', '@OneToMany', '@ManyToMany'
        ]
        
        for java_file in java_files:
            try:
                content = java_file.read_text(encoding='utf-8', errors='ignore')
                
                # Check if file contains Hibernate annotations
                if any(annotation in content for annotation in hibernate_annotations):
                    class_match = re.search(r'public\s+class\s+(\w+)', content)
                    if class_match:
                        class_name = class_match.group(1)
                        
                        # Count annotation usage
                        annotation_count = sum(1 for annotation in hibernate_annotations if annotation in content)
                        
                        rule_id = f"hibernate_annotated_entity_{class_name}"
                        
                        rule = self._create_business_rule_from_plugin(
                            rule_id=rule_id,
                            name=f"Hibernate Annotated Entity: {class_name}",
                            description=f"JPA/Hibernate annotated entity with {annotation_count} annotations",
                            rule_type=BusinessRuleType.DATA,
                            source=BusinessRuleSource.ANNOTATION,
                            file_path=str(java_file),
                            business_context=self._infer_entity_business_context(class_name),
                            code_snippet=f"@Entity class {class_name}",
                            complexity=self._calculate_annotation_complexity(annotation_count)
                        )
                        
                        rule.add_tag('hibernate_entity')
                        rule.add_tag('jpa_annotations')
                        rule.add_tag('data_model')
                        
                        result.add_business_rule(rule)
                        
            except Exception as e:
                result.add_warning(f"Could not analyze Hibernate annotations in {java_file}: {e}")
    
    def _infer_entity_business_context(self, class_name: str) -> str:
        """Infer business context from entity class name."""
        name_lower = class_name.lower()
        
        if any(word in name_lower for word in ['user', 'customer', 'person', 'account']):
            return "User and Account Management"
        elif any(word in name_lower for word in ['order', 'purchase', 'transaction', 'payment']):
            return "Order and Transaction Processing"
        elif any(word in name_lower for word in ['product', 'item', 'catalog', 'inventory']):
            return "Product and Inventory Management"
        elif any(word in name_lower for word in ['address', 'contact', 'location']):
            return "Contact and Location Information"
        elif any(word in name_lower for word in ['log', 'audit', 'history', 'event']):
            return "Auditing and Logging"
        else:
            return f"Data Entity: {class_name}"
    
    def _calculate_entity_complexity(self, properties: int, relationships: int) -> BusinessRuleComplexity:
        """Calculate entity complexity based on properties and relationships."""
        complexity_score = properties + (relationships * 2)
        
        if complexity_score <= 5:
            return BusinessRuleComplexity.SIMPLE
        elif complexity_score <= 15:
            return BusinessRuleComplexity.MODERATE
        elif complexity_score <= 30:
            return BusinessRuleComplexity.COMPLEX
        else:
            return BusinessRuleComplexity.CRITICAL
    
    def _calculate_annotation_complexity(self, annotation_count: int) -> BusinessRuleComplexity:
        """Calculate complexity based on annotation count."""
        if annotation_count <= 3:
            return BusinessRuleComplexity.SIMPLE
        elif annotation_count <= 7:
            return BusinessRuleComplexity.MODERATE
        elif annotation_count <= 15:
            return BusinessRuleComplexity.COMPLEX
        else:
            return BusinessRuleComplexity.CRITICAL