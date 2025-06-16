"""
Business Rule Analysis Engine
=============================

This is the main engine that orchestrates comprehensive business rule extraction,
analysis, and search capabilities for large Struts applications. It integrates
all analyzers and provides a unified interface for business rule discovery.

Features:
- Comprehensive business rule extraction from all Struts components
- Advanced search and filtering capabilities
- Cross-component relationship analysis
- Business rule categorization and prioritization
- Migration planning and effort estimation
- Stakeholder-friendly reporting

Author: Claude Code Assistant
"""

from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
import json
try:
    import yaml
except ImportError:
    yaml = None
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from tqdm import tqdm
except ImportError:
    # Fallback if tqdm not available
    def tqdm(iterable, desc=None):
        return iterable

from models.business_rule import BusinessRule, BusinessRuleType, BusinessRuleComplexity
from models.search_index import BusinessRuleIndex, SearchQuery, SearchResult
from analyzers.base_analyzer import AnalysisContext, AnalysisResult
from analyzers.struts_config_analyzer import StrutsConfigAnalyzer
from analyzers.validation_analyzer import ValidationAnalyzer
from analyzers.java_action_analyzer import JavaActionAnalyzer
from analyzers.jsp_analyzer import JSPAnalyzer
from analyzers.properties_analyzer import PropertiesAnalyzer
from analyzers.interceptor_analyzer import InterceptorAnalyzer
from analyzers.dependency_analyzer import DependencyAnalyzer
from parsers import BaseParser, ParseResult, XMLConfigurationParser, JavaSourceParser, JSPTemplateParser, PropertiesFileParser
from plugins import PluginManager, BasePlugin
from utils.config_utils import ConfigurationManager
from utils.logging_utils import get_logger
from utils.file_utils import find_files_by_pattern


logger = get_logger(__name__)


@dataclass
class BusinessRuleDiscoveryResult:
    """Results from comprehensive business rule discovery."""
    total_rules: int
    rules_by_type: Dict[str, int] = field(default_factory=dict)
    rules_by_complexity: Dict[str, int] = field(default_factory=dict)
    rules_by_source: Dict[str, int] = field(default_factory=dict)
    high_impact_rules: List[BusinessRule] = field(default_factory=list)
    migration_critical_rules: List[BusinessRule] = field(default_factory=list)
    duplicate_rules: List[Tuple[BusinessRule, BusinessRule, float]] = field(default_factory=list)
    cross_component_relationships: Dict[str, List[str]] = field(default_factory=dict)
    business_domains: Set[str] = field(default_factory=set)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)


class BusinessRuleEngine:
    """
    Main engine for comprehensive business rule analysis of Struts applications.
    """
    
    def __init__(self, config: ConfigurationManager):
        """Initialize the business rule engine."""
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        
        # Initialize search index
        index_path = self.config.get('analysis.index_path')
        self.search_index = BusinessRuleIndex(index_path)
        
        # Initialize parsers
        self.parsers = self._initialize_parsers()
        
        # Initialize plugin manager
        self.plugin_manager = PluginManager(configuration=self.config.get_effective_config())
        self.plugin_manager.discover_plugins()
        self.plugin_manager.initialize_plugins()
        
        # Initialize analyzers
        self.analyzers = self._initialize_analyzers()
        
        # Analysis state
        self.all_business_rules: List[BusinessRule] = []
        self.analysis_results: Dict[str, AnalysisResult] = {}
        self.parser_results: Dict[str, ParseResult] = {}
        self.plugin_results: Dict[str, Any] = {}
        self.discovery_result: Optional[BusinessRuleDiscoveryResult] = None
    
    def _initialize_parsers(self) -> List[BaseParser]:
        """Initialize all file parsers."""
        return [
            XMLConfigurationParser(),
            JavaSourceParser(),
            JSPTemplateParser(),
            PropertiesFileParser()
        ]
    
    def _initialize_analyzers(self) -> List[Any]:
        """Initialize all business rule analyzers."""
        return [
            StrutsConfigAnalyzer(self.config),
            ValidationAnalyzer(self.config),
            JavaActionAnalyzer(self.config),
            JSPAnalyzer(self.config),
            PropertiesAnalyzer(self.config),
            InterceptorAnalyzer(self.config),
            DependencyAnalyzer(self.config)
        ]
    
    def analyze_application(self, application_path: Path) -> BusinessRuleDiscoveryResult:
        """
        Perform comprehensive business rule analysis of a Struts application.
        
        Args:
            application_path: Path to the Struts application root
            
        Returns:
            BusinessRuleDiscoveryResult with comprehensive analysis
        """
        start_time = datetime.now()
        self.logger.info(f"Starting comprehensive business rule analysis of {application_path}")
        
        try:
            # Step 1: Discover all relevant files
            target_files = self._discover_application_files(application_path)
            self.logger.info(f"Discovered {len(target_files)} files for analysis")
            
            # Step 2: Create analysis context
            context = AnalysisContext(
                project_root=application_path,
                target_files=target_files,
                configuration=self.config.get_effective_config()
            )
            
            # Step 3: Run parsers on files
            self._run_all_parsers(target_files)
            
            # Step 4: Run all analyzers
            self._run_all_analyzers(context)
            
            # Step 5: Run plugins for framework detection and migration analysis
            self._run_plugins(application_path, context)
            
            # Step 6: Extract and consolidate business rules
            self._extract_all_business_rules()
            
            # Step 7: Build search index
            self._build_search_index()
            
            # Step 8: Perform advanced analysis
            self.discovery_result = self._perform_advanced_analysis()
            
            # Step 9: Calculate analysis metadata
            execution_time = (datetime.now() - start_time).total_seconds()
            self.discovery_result.analysis_metadata = {
                'execution_time_seconds': execution_time,
                'files_analyzed': len(target_files),
                'parsers_used': [parser.__class__.__name__ for parser in self.parsers],
                'analyzers_used': [analyzer.__class__.__name__ for analyzer in self.analyzers],
                'plugins_used': [plugin.metadata.name for plugin in self.plugin_manager.get_enabled_plugins()],
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            self.logger.info(
                f"Business rule analysis completed: {self.discovery_result.total_rules} rules "
                f"discovered in {execution_time:.2f} seconds"
            )
            
            return self.discovery_result
            
        except Exception as e:
            self.logger.error(f"Business rule analysis failed: {e}", exc_info=True)
            raise
    
    def search_business_rules(self, query: SearchQuery) -> SearchResult:
        """
        Search business rules using the search index.
        
        Args:
            query: Search query with filters and options
            
        Returns:
            SearchResult containing matching business rules
        """
        if not self.search_index:
            raise RuntimeError("Search index not initialized. Run analyze_application first.")
        
        return self.search_index.search(query)
    
    def find_similar_rules(self, rule_id: str, threshold: float = 0.8) -> List[Tuple[BusinessRule, float]]:
        """
        Find business rules similar to the specified rule.
        
        Args:
            rule_id: ID of the rule to find similarities for
            threshold: Similarity threshold (0.0 to 1.0)
            
        Returns:
            List of similar rules with similarity scores
        """
        rule = self.search_index.get_rule_by_id(rule_id)
        if not rule:
            raise ValueError(f"Rule with ID {rule_id} not found")
        
        return self.search_index.find_similar_rules(rule, threshold)
    
    def get_business_domains(self) -> List[str]:
        """Get all identified business domains."""
        if self.discovery_result:
            return list(self.discovery_result.business_domains)
        return []
    
    def get_high_impact_rules(self) -> List[BusinessRule]:
        """Get rules with high business impact."""
        if self.discovery_result:
            return self.discovery_result.high_impact_rules
        return []
    
    def get_migration_critical_rules(self) -> List[BusinessRule]:
        """Get rules critical for migration planning."""
        if self.discovery_result:
            return self.discovery_result.migration_critical_rules
        return []
    
    def export_analysis_results(self, output_path: Path, format: str = "json") -> None:
        """
        Export comprehensive analysis results.
        
        Args:
            output_path: Path to save the results
            format: Export format (json, yaml, or markdown)
        """
        if not self.discovery_result:
            raise RuntimeError("No analysis results to export. Run analyze_application first.")
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == "json":
            self._export_as_json(output_path)
        elif format.lower() == "yaml":
            self._export_as_yaml(output_path)
        elif format.lower() == "markdown":
            self._export_as_markdown(output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _discover_application_files(self, app_path: Path) -> List[Path]:
        """Discover all relevant files in the application."""
        file_patterns = [
            "**/*.xml",      # Configuration files
            "**/*.java",     # Java source files
            "**/*.jsp",      # JSP files
            "**/*.jspx",     # JSPX files
            "**/*.properties" # Properties files
        ]
        
        exclude_patterns = self.config.get('analysis.exclude_patterns', [
            "*/test/*", "*/tests/*", "**/target/**", "**/build/**", "**/.git/**"
        ])
        
        all_files = []
        for pattern in file_patterns:
            files = find_files_by_pattern(app_path, [pattern], exclude_patterns=exclude_patterns)
            all_files.extend(files)
        
        # Remove duplicates and filter by analyzer capability
        unique_files = list(set(all_files))
        analyzable_files = []
        
        for file_path in unique_files:
            if any(analyzer.can_analyze(file_path) for analyzer in self.analyzers):
                analyzable_files.append(file_path)
        
        return analyzable_files
    
    def _run_all_parsers(self, target_files: List[Path]) -> None:
        """Run parsers on all target files."""
        self.logger.info(f"Running parsers on {len(target_files)} files...")
        
        for file_path in tqdm(target_files, desc="Parsing files"):
            # Find appropriate parser
            parser = None
            for p in self.parsers:
                if p.can_parse(file_path):
                    parser = p
                    break
            
            if parser:
                try:
                    result = parser.parse_file(file_path)
                    self.parser_results[str(file_path)] = result
                    
                    if not result.success:
                        self.logger.warning(f"Parser {parser.__class__.__name__} failed on {file_path}")
                        
                except Exception as e:
                    self.logger.error(f"Parser failed on {file_path}: {e}")
    
    def _run_plugins(self, application_path: Path, context: AnalysisContext) -> None:
        """Run plugins for framework detection and migration analysis."""
        self.logger.info("Running framework detection and migration plugins...")
        
        plugin_context = {
            'project_path': str(application_path),
            'business_rules': self.all_business_rules,
            'analysis_results': self.analysis_results,
            'parser_results': self.parser_results
        }
        
        # Run framework plugins
        framework_results = self.plugin_manager.execute_framework_plugins(application_path, plugin_context)
        self.plugin_results['framework'] = framework_results
        
        # Run migration plugins (after we have business rules)
        if self.all_business_rules:
            migration_results = self.plugin_manager.execute_migration_plugins(self.all_business_rules, plugin_context)
            self.plugin_results['migration'] = migration_results
    
    def _run_all_analyzers(self, context: AnalysisContext) -> None:
        """Run all analyzers on the application."""
        if self.config.get('analysis.parallel_enabled', True):
            self._run_analyzers_parallel(context)
        else:
            self._run_analyzers_sequential(context)
    
    def _run_analyzers_sequential(self, context: AnalysisContext) -> None:
        """Run analyzers sequentially."""
        for analyzer in tqdm(self.analyzers, desc="Running analyzers"):
            try:
                result = analyzer.analyze(context)
                self.analysis_results[analyzer.__class__.__name__] = result
                
                if result.has_errors:
                    self.logger.warning(
                        f"{analyzer.__class__.__name__} completed with errors: "
                        f"{len(result.errors)} errors"
                    )
            except Exception as e:
                self.logger.error(f"Analyzer {analyzer.__class__.__name__} failed: {e}")
    
    def _run_analyzers_parallel(self, context: AnalysisContext) -> None:
        """Run analyzers in parallel."""
        max_workers = self.config.get('analysis.parallel_workers', 4)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit analyzer tasks
            future_to_analyzer = {
                executor.submit(analyzer.analyze, context): analyzer
                for analyzer in self.analyzers
            }
            
            # Collect results
            for future in tqdm(
                as_completed(future_to_analyzer),
                total=len(future_to_analyzer),
                desc="Running analyzers"
            ):
                analyzer = future_to_analyzer[future]
                try:
                    result = future.result()
                    self.analysis_results[analyzer.__class__.__name__] = result
                    
                    if result.has_errors:
                        self.logger.warning(
                            f"{analyzer.__class__.__name__} completed with errors: "
                            f"{len(result.errors)} errors"
                        )
                except Exception as e:
                    self.logger.error(f"Analyzer {analyzer.__class__.__name__} failed: {e}")
    
    def _extract_all_business_rules(self) -> None:
        """Extract business rules from all analyzer, parser, and plugin results."""
        self.all_business_rules = []
        
        # Extract from analyzer results
        for analyzer_name, result in self.analysis_results.items():
            if result.success and 'business_rules' in result.data:
                rules_data = result.data['business_rules']
                
                for rule_data in rules_data:
                    try:
                        if isinstance(rule_data, dict):
                            rule = BusinessRule.from_dict(rule_data)
                        else:
                            rule = rule_data
                        
                        # Add analyzer source tag
                        rule.add_tag(f"analyzer_{analyzer_name.lower()}")
                        
                        self.all_business_rules.append(rule)
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to process analyzer business rule: {e}")
        
        # Extract from parser results
        for file_path, result in self.parser_results.items():
            if result.success and result.business_rules:
                for rule in result.business_rules:
                    try:
                        # Add parser source tag
                        rule.add_tag(f"parser_{result.parser_name.lower()}")
                        rule.add_tag("parsed_rule")
                        
                        self.all_business_rules.append(rule)
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to process parser business rule: {e}")
        
        # Extract from plugin results
        for plugin_type, results in self.plugin_results.items():
            if isinstance(results, list):
                for result in results:
                    if hasattr(result, 'business_rules') and result.business_rules:
                        for rule in result.business_rules:
                            try:
                                # Add plugin source tag
                                rule.add_tag(f"plugin_{plugin_type}")
                                rule.add_tag(f"plugin_{result.plugin_name.lower()}")
                                
                                self.all_business_rules.append(rule)
                                
                            except Exception as e:
                                self.logger.warning(f"Failed to process plugin business rule: {e}")
        
        self.logger.info(f"Extracted {len(self.all_business_rules)} business rules total")
    
    def _build_search_index(self) -> None:
        """Build the search index with all business rules."""
        self.logger.info("Building search index...")
        self.search_index.add_rules(self.all_business_rules)
        self.logger.info(f"Search index built with {len(self.all_business_rules)} rules")
    
    def _perform_advanced_analysis(self) -> BusinessRuleDiscoveryResult:
        """Perform advanced analysis on the discovered business rules."""
        self.logger.info("Performing advanced business rule analysis...")
        
        # Basic statistics
        total_rules = len(self.all_business_rules)
        
        rules_by_type = {}
        rules_by_complexity = {}
        rules_by_source = {}
        business_domains = set()
        
        for rule in self.all_business_rules:
            # Count by type
            rule_type = rule.rule_type.value
            rules_by_type[rule_type] = rules_by_type.get(rule_type, 0) + 1
            
            # Count by complexity
            complexity = rule.complexity.name
            rules_by_complexity[complexity] = rules_by_complexity.get(complexity, 0) + 1
            
            # Count by source
            source = rule.source.value
            rules_by_source[source] = rules_by_source.get(source, 0) + 1
            
            # Collect domains
            if rule.business_domain and rule.business_domain != "unknown":
                business_domains.add(rule.business_domain)
        
        # Identify high impact rules
        high_impact_rules = [rule for rule in self.all_business_rules if rule.is_high_impact]
        
        # Identify migration critical rules
        migration_critical_rules = [
            rule for rule in self.all_business_rules 
            if rule.migration_risk in ["high", "critical"]
        ]
        
        # Find duplicate rules
        duplicate_rules = self._find_duplicate_rules()
        
        # Analyze cross-component relationships
        cross_component_relationships = self._analyze_cross_component_relationships()
        
        return BusinessRuleDiscoveryResult(
            total_rules=total_rules,
            rules_by_type=rules_by_type,
            rules_by_complexity=rules_by_complexity,
            rules_by_source=rules_by_source,
            high_impact_rules=high_impact_rules,
            migration_critical_rules=migration_critical_rules,
            duplicate_rules=duplicate_rules,
            cross_component_relationships=cross_component_relationships,
            business_domains=business_domains
        )
    
    def _find_duplicate_rules(self) -> List[Tuple[BusinessRule, BusinessRule, float]]:
        """Find potentially duplicate business rules."""
        duplicates = []
        similarity_threshold = 0.85
        
        self.logger.info("Analyzing business rules for duplicates...")
        
        for i, rule1 in enumerate(self.all_business_rules):
            similar_rules = self.search_index.find_similar_rules(rule1, similarity_threshold)
            
            for rule2, similarity in similar_rules:
                # Avoid duplicate pairs
                rule2_index = next((j for j, r in enumerate(self.all_business_rules) if r.id == rule2.id), -1)
                if rule2_index > i:
                    duplicates.append((rule1, rule2, similarity))
        
        return duplicates
    
    def _analyze_cross_component_relationships(self) -> Dict[str, List[str]]:
        """Analyze relationships between business rules across components."""
        relationships = {}
        
        # Group rules by source file
        rules_by_file = {}
        for rule in self.all_business_rules:
            file_path = rule.location.file_path
            if file_path not in rules_by_file:
                rules_by_file[file_path] = []
            rules_by_file[file_path].append(rule)
        
        # Find relationships based on dependencies and affected components
        for rule in self.all_business_rules:
            rule_relationships = []
            
            # Check dependencies
            for dependency in rule.dependencies:
                related_rules = [r for r in self.all_business_rules if dependency in r.name or dependency in r.id]
                rule_relationships.extend([r.id for r in related_rules])
            
            # Check affected components
            for component in rule.affected_components:
                related_rules = [r for r in self.all_business_rules if component in r.affected_components]
                rule_relationships.extend([r.id for r in related_rules if r.id != rule.id])
            
            if rule_relationships:
                relationships[rule.id] = list(set(rule_relationships))
        
        return relationships
    
    def _export_as_json(self, output_path: Path) -> None:
        """Export results as JSON."""
        export_data = {
            'discovery_summary': {
                'total_rules': self.discovery_result.total_rules,
                'rules_by_type': self.discovery_result.rules_by_type,
                'rules_by_complexity': self.discovery_result.rules_by_complexity,
                'rules_by_source': self.discovery_result.rules_by_source,
                'business_domains': list(self.discovery_result.business_domains),
                'high_impact_count': len(self.discovery_result.high_impact_rules),
                'migration_critical_count': len(self.discovery_result.migration_critical_rules),
                'duplicate_count': len(self.discovery_result.duplicate_rules)
            },
            'business_rules': [rule.to_dict() for rule in self.all_business_rules],
            'high_impact_rules': [rule.to_dict() for rule in self.discovery_result.high_impact_rules],
            'migration_critical_rules': [rule.to_dict() for rule in self.discovery_result.migration_critical_rules],
            'cross_component_relationships': self.discovery_result.cross_component_relationships,
            'analysis_metadata': self.discovery_result.analysis_metadata
        }
        
        with open(output_path.with_suffix('.json'), 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def _export_as_yaml(self, output_path: Path) -> None:
        """Export results as YAML."""
        export_data = {
            'discovery_summary': {
                'total_rules': self.discovery_result.total_rules,
                'rules_by_type': self.discovery_result.rules_by_type,
                'rules_by_complexity': self.discovery_result.rules_by_complexity,
                'rules_by_source': self.discovery_result.rules_by_source,
                'business_domains': list(self.discovery_result.business_domains)
            },
            'analysis_metadata': self.discovery_result.analysis_metadata
        }
        
        with open(output_path.with_suffix('.yaml'), 'w') as f:
            yaml.dump(export_data, f, default_flow_style=False)
    
    def _export_as_markdown(self, output_path: Path) -> None:
        """Export results as Markdown report."""
        lines = [
            "# Comprehensive Business Rules Analysis Report",
            "",
            f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Rules Discovered:** {self.discovery_result.total_rules}",
            "",
            "## Executive Summary",
            "",
            f"This analysis identified **{self.discovery_result.total_rules} business rules** across the Struts application. ",
            f"The rules span **{len(self.discovery_result.business_domains)} business domains** and include ",
            f"**{len(self.discovery_result.high_impact_rules)} high-impact rules** requiring careful migration planning.",
            "",
            "### Key Findings",
            "",
            f"- **High-Impact Rules:** {len(self.discovery_result.high_impact_rules)} rules with significant business impact",
            f"- **Migration-Critical Rules:** {len(self.discovery_result.migration_critical_rules)} rules requiring immediate attention",
            f"- **Potential Duplicates:** {len(self.discovery_result.duplicate_rules)} rule pairs show high similarity",
            f"- **Business Domains:** {', '.join(sorted(self.discovery_result.business_domains))}",
            "",
            "## Rules by Type",
            "",
        ]
        
        for rule_type, count in sorted(self.discovery_result.rules_by_type.items()):
            percentage = (count / self.discovery_result.total_rules) * 100
            lines.append(f"- **{rule_type.title()}:** {count} rules ({percentage:.1f}%)")
        
        lines.extend([
            "",
            "## Rules by Complexity",
            "",
        ])
        
        for complexity, count in sorted(self.discovery_result.rules_by_complexity.items()):
            percentage = (count / self.discovery_result.total_rules) * 100
            lines.append(f"- **{complexity}:** {count} rules ({percentage:.1f}%)")
        
        lines.extend([
            "",
            "## Migration Priority Rules",
            "",
            "### High-Impact Rules",
            "",
        ])
        
        for rule in self.discovery_result.high_impact_rules[:10]:  # Top 10
            lines.extend([
                f"#### {rule.name}",
                f"- **Type:** {rule.rule_type.value}",
                f"- **Source:** {rule.location.file_path}",
                f"- **Description:** {rule.description}",
                ""
            ])
        
        with open(output_path.with_suffix('.md'), 'w') as f:
            f.write('\n'.join(lines))
    
    def close(self) -> None:
        """Clean up resources."""
        if self.search_index:
            self.search_index.close()
        
        if self.plugin_manager:
            self.plugin_manager.cleanup_plugins()