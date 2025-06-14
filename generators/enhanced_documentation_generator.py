"""
Enhanced Documentation Generator
================================

This module generates comprehensive, searchable documentation for business rules
extracted from Struts applications. It creates multiple views and formats to
support different stakeholder needs and migration planning activities.

Features:
- Business rule catalog with full-text search
- Interactive HTML documentation with filtering
- Migration planning guides with effort estimates
- Cross-reference analysis and dependency mapping
- Stakeholder-specific views (business, technical, executive)
- Export to multiple formats (HTML, PDF, JSON, CSV)

Author: Claude Code Assistant
"""

import json
import html
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime
import base64
from collections import defaultdict, Counter

import sys
import os
# Add parent directory to path to access other modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.business_rule import BusinessRule, BusinessRuleType, BusinessRuleComplexity
from models.search_index import BusinessRuleIndex, SearchQuery
from business_rule_engine import BusinessRuleDiscoveryResult
from utils.config_utils import ConfigurationManager
from utils.logging_utils import get_logger


logger = get_logger(__name__)


@dataclass
class DocumentationConfig:
    """Configuration for documentation generation."""
    include_search: bool = True
    include_dependencies: bool = True
    include_migration_guide: bool = True
    include_stakeholder_views: bool = True
    generate_interactive_html: bool = True
    generate_static_markdown: bool = True
    generate_csv_export: bool = True
    include_code_snippets: bool = True
    max_rules_per_page: int = 50


class EnhancedDocumentationGenerator:
    """
    Enhanced documentation generator for comprehensive business rule analysis.
    """
    
    def __init__(self, config: ConfigurationManager):
        """Initialize the documentation generator."""
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.doc_config = DocumentationConfig()
    
    def generate_comprehensive_documentation(self,
                                           discovery_result: BusinessRuleDiscoveryResult,
                                           business_rules: List[BusinessRule],
                                           search_index: BusinessRuleIndex,
                                           output_dir: Path) -> None:
        """
        Generate comprehensive documentation package.
        
        Args:
            discovery_result: Results from business rule discovery
            business_rules: All discovered business rules
            search_index: Search index for rule lookup
            output_dir: Directory to generate documentation
        """
        self.logger.info(f"Generating comprehensive documentation to {output_dir}")
        
        # Create output directory structure
        self._create_output_structure(output_dir)
        
        # Generate main documentation files
        if self.doc_config.generate_static_markdown:
            self._generate_executive_summary(discovery_result, output_dir)
            self._generate_business_rule_catalog(business_rules, output_dir)
            self._generate_migration_guide(discovery_result, business_rules, output_dir)
            self._generate_technical_reference(business_rules, output_dir)
        
        if self.doc_config.generate_interactive_html:
            self._generate_interactive_html_documentation(
                discovery_result, business_rules, search_index, output_dir
            )
        
        if self.doc_config.generate_csv_export:
            self._generate_csv_exports(business_rules, output_dir)
        
        # Generate specialized views
        if self.doc_config.include_stakeholder_views:
            self._generate_stakeholder_views(discovery_result, business_rules, output_dir)
        
        # Generate search and navigation aids
        if self.doc_config.include_search:
            self._generate_search_aids(business_rules, output_dir)
        
        self.logger.info("Documentation generation completed")
    
    def _create_output_structure(self, output_dir: Path) -> None:
        """Create organized output directory structure."""
        directories = [
            output_dir / "executive",
            output_dir / "business",
            output_dir / "technical",
            output_dir / "interactive",
            output_dir / "exports",
            output_dir / "assets" / "css",
            output_dir / "assets" / "js",
            output_dir / "assets" / "images"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _generate_executive_summary(self, discovery_result: BusinessRuleDiscoveryResult, 
                                  output_dir: Path) -> None:
        """Generate executive summary for business stakeholders."""
        doc_path = output_dir / "executive" / "executive_summary.md"
        
        with open(doc_path, 'w') as f:
            f.write(self._create_executive_summary_content(discovery_result))
        
        # Generate HTML version
        html_path = output_dir / "executive" / "executive_summary.html"
        with open(html_path, 'w') as f:
            f.write(self._create_executive_summary_html(discovery_result))
    
    def _create_executive_summary_content(self, discovery_result: BusinessRuleDiscoveryResult) -> str:
        """Create executive summary content."""
        lines = [
            "# Executive Summary: Business Rules Analysis",
            "",
            f"**Analysis Date:** {datetime.now().strftime('%B %d, %Y')}",
            f"**Total Business Rules Identified:** {discovery_result.total_rules:,}",
            "",
            "## Key Findings",
            "",
            f"Our comprehensive analysis of the Struts legacy application has identified **{discovery_result.total_rules:,} distinct business rules** ",
            f"spanning **{len(discovery_result.business_domains)} business domains**. These rules represent the critical business logic ",
            "that must be preserved and modernized during the migration to GraphQL and Angular.",
            "",
            "### Business Impact Assessment",
            "",
            f"- **🔴 High-Impact Rules:** {len(discovery_result.high_impact_rules)} rules requiring specialized attention",
            f"- **⚠️ Migration-Critical:** {len(discovery_result.migration_critical_rules)} rules with migration complexity",
            f"- **🔄 Potential Duplicates:** {len(discovery_result.duplicate_rules)} rule pairs requiring consolidation",
            "",
            "### Business Domain Coverage",
            "",
        ]
        
        # Add business domains
        for domain in sorted(discovery_result.business_domains):
            lines.append(f"- **{domain}**")
        
        lines.extend([
            "",
            "### Rule Distribution by Type",
            "",
        ])
        
        # Add rule type distribution
        total_rules = discovery_result.total_rules
        for rule_type, count in sorted(discovery_result.rules_by_type.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_rules) * 100
            lines.append(f"- **{rule_type.replace('_', ' ').title()}:** {count:,} rules ({percentage:.1f}%)")
        
        lines.extend([
            "",
            "### Complexity Analysis",
            "",
        ])
        
        # Add complexity distribution
        for complexity, count in sorted(discovery_result.rules_by_complexity.items()):
            percentage = (count / total_rules) * 100
            icon = "🟢" if complexity == "SIMPLE" else "🟡" if complexity == "MODERATE" else "🟠" if complexity == "COMPLEX" else "🔴"
            lines.append(f"- {icon} **{complexity.title()}:** {count:,} rules ({percentage:.1f}%)")
        
        lines.extend([
            "",
            "## Strategic Recommendations",
            "",
            "### Immediate Actions Required",
            "",
            "1. **Prioritize High-Impact Rules** - Focus migration planning on the identified high-impact business rules",
            "2. **Address Migration-Critical Items** - Develop specialized strategies for complex business logic",
            "3. **Consolidate Duplicate Rules** - Eliminate redundancy by merging similar business rules",
            "4. **Domain-Driven Planning** - Organize migration efforts by business domain for better coordination",
            "",
            "### Migration Strategy",
            "",
            "Based on the analysis, we recommend a **phased migration approach**:",
            "",
            "**Phase 1: Foundation (Weeks 1-4)**",
            "- Migrate simple validation rules to GraphQL schema validation",
            "- Establish basic Angular component structure",
            "- Set up development and testing infrastructure",
            "",
            "**Phase 2: Core Business Logic (Weeks 5-12)**",
            "- Migrate moderate complexity business rules",
            "- Implement GraphQL resolvers for core business operations",
            "- Develop Angular services for business logic",
            "",
            "**Phase 3: Complex Integrations (Weeks 13-20)**",
            "- Address high-complexity and migration-critical rules",
            "- Implement sophisticated business workflows",
            "- Performance optimization and testing",
            "",
            "**Phase 4: Optimization and Consolidation (Weeks 21-24)**",
            "- Consolidate duplicate rules and optimize performance",
            "- Complete testing and user acceptance",
            "- Final deployment and knowledge transfer",
            "",
            "## Risk Assessment",
            "",
            f"**Overall Migration Risk:** {'HIGH' if len(discovery_result.migration_critical_rules) > total_rules * 0.2 else 'MEDIUM' if len(discovery_result.migration_critical_rules) > total_rules * 0.1 else 'LOW'}",
            "",
            "### Key Risk Factors",
            "",
        ])
        
        # Add risk factors based on analysis
        if len(discovery_result.migration_critical_rules) > 0:
            lines.append(f"- **Complex Business Logic:** {len(discovery_result.migration_critical_rules)} rules require specialized migration strategies")
        
        if len(discovery_result.duplicate_rules) > 0:
            lines.append(f"- **Business Rule Inconsistencies:** {len(discovery_result.duplicate_rules)} potential duplicates may indicate inconsistent business logic")
        
        lines.extend([
            "",
            "## Next Steps",
            "",
            "1. **Review Detailed Analysis** - Examine the comprehensive business rule catalog",
            "2. **Validate Business Rules** - Work with domain experts to verify extracted business logic",
            "3. **Prioritize Migration Items** - Use the migration guide to plan development sprints",
            "4. **Establish Testing Strategy** - Ensure business rule preservation through comprehensive testing",
            "",
            "---",
            "",
            "*This analysis was generated using automated business rule extraction. ",
            "All findings should be validated with domain experts before migration planning.*"
        ])
        
        return "\n".join(lines)
    
    def _create_executive_summary_html(self, discovery_result: BusinessRuleDiscoveryResult) -> str:
        """Create HTML version of executive summary."""
        # Convert markdown to basic HTML structure
        content = self._create_executive_summary_content(discovery_result)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - Business Rules Analysis</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c5282; border-bottom: 3px solid #3182ce; padding-bottom: 10px; }}
        h2 {{ color: #2d3748; margin-top: 30px; }}
        h3 {{ color: #4a5568; }}
        .stats {{ background: #f7fafc; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .risk-high {{ color: #e53e3e; font-weight: bold; }}
        .risk-medium {{ color: #dd6b20; font-weight: bold; }}
        .risk-low {{ color: #38a169; font-weight: bold; }}
        ul {{ padding-left: 20px; }}
        li {{ margin: 5px 0; }}
        .phase {{ background: #edf2f7; padding: 15px; margin: 10px 0; border-radius: 6px; }}
        .recommendation {{ background: #e6fffa; padding: 15px; border-left: 4px solid #38b2ac; margin: 10px 0; }}
    </style>
</head>
<body>
    {self._markdown_to_html(content)}
</body>
</html>
"""
        return html_content
    
    def _generate_business_rule_catalog(self, business_rules: List[BusinessRule], 
                                      output_dir: Path) -> None:
        """Generate comprehensive business rule catalog."""
        doc_path = output_dir / "business" / "business_rule_catalog.md"
        
        # Group rules by type and domain
        rules_by_type = defaultdict(list)
        rules_by_domain = defaultdict(list)
        
        for rule in business_rules:
            rules_by_type[rule.rule_type].append(rule)
            rules_by_domain[rule.business_domain].append(rule)
        
        with open(doc_path, 'w') as f:
            f.write(self._create_catalog_content(rules_by_type, rules_by_domain))
    
    def _create_catalog_content(self, rules_by_type: Dict, rules_by_domain: Dict) -> str:
        """Create business rule catalog content."""
        lines = [
            "# Business Rule Catalog",
            "",
            f"*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            "",
            "This catalog provides a comprehensive overview of all business rules identified in the Struts application. ",
            "Each rule includes its business context, technical details, and migration recommendations.",
            "",
            "## Table of Contents",
            "",
            "- [Rules by Type](#rules-by-type)",
            "- [Rules by Business Domain](#rules-by-business-domain)",
            "- [Search and Filter Guide](#search-and-filter-guide)",
            "",
            "## Rules by Type",
            "",
        ]
        
        # Add rules by type
        for rule_type, rules in sorted(rules_by_type.items(), key=lambda x: len(x[1]), reverse=True):
            type_name = rule_type.value.replace('_', ' ').title()
            lines.extend([
                f"### {type_name} ({len(rules)} rules)",
                "",
            ])
            
            # Sort rules by complexity and impact
            sorted_rules = sorted(rules, key=lambda r: (r.complexity_score, r.impact.total_impact_score), reverse=True)
            
            for rule in sorted_rules[:20]:  # Limit to top 20 per type
                lines.extend([
                    f"#### {rule.name}",
                    "",
                    f"**ID:** `{rule.id}`  ",
                    f"**Complexity:** {rule.complexity.name}  ",
                    f"**Migration Risk:** {rule.migration_risk.upper()}  ",
                    f"**Source:** `{rule.location.file_path}`",
                    "",
                    f"**Description:** {rule.description}",
                    "",
                    f"**Business Context:** {rule.business_context}",
                    "",
                ])
                
                if rule.dependencies:
                    lines.extend([
                        f"**Dependencies:** {', '.join(rule.dependencies)}",
                        ""
                    ])
                
                if rule.modernization_recommendations:
                    lines.extend([
                        "**Migration Recommendations:**",
                        ""
                    ])
                    for rec in rule.modernization_recommendations:
                        lines.append(f"- {rec}")
                    lines.append("")
                
                lines.extend([
                    "---",
                    ""
                ])
            
            if len(rules) > 20:
                lines.extend([
                    f"*... and {len(rules) - 20} more {type_name.lower()} rules*",
                    "",
                ])
        
        lines.extend([
            "",
            "## Rules by Business Domain",
            "",
        ])
        
        # Add rules by domain
        for domain, rules in sorted(rules_by_domain.items(), key=lambda x: len(x[1]), reverse=True):
            if domain == "unknown":
                continue
                
            lines.extend([
                f"### {domain} ({len(rules)} rules)",
                "",
                f"Business rules specific to the {domain} domain:",
                "",
            ])
            
            # Group by type within domain
            domain_rules_by_type = defaultdict(list)
            for rule in rules:
                domain_rules_by_type[rule.rule_type].append(rule)
            
            for rule_type, type_rules in domain_rules_by_type.items():
                type_name = rule_type.value.replace('_', ' ').title()
                lines.append(f"**{type_name}:** {len(type_rules)} rules")
            
            lines.append("")
        
        lines.extend([
            "",
            "## Search and Filter Guide",
            "",
            "### Common Search Patterns",
            "",
            "- **By Business Domain:** Search for domain-specific rules",
            "- **By Migration Risk:** Filter by `high`, `medium`, `low` risk levels",
            "- **By Complexity:** Filter by `SIMPLE`, `MODERATE`, `COMPLEX`, `CRITICAL`",
            "- **By Source:** Find rules from specific files or components",
            "",
            "### Filter Examples",
            "",
            "- **High-Risk Validation Rules:** `type:validation AND risk:high`",
            "- **Security Business Logic:** `type:security OR context:security`",
            "- **Complex Data Rules:** `type:data AND complexity:COMPLEX`",
            "",
            "---",
            "",
            "*For interactive searching and filtering, see the HTML documentation.*"
        ])
        
        return "\n".join(lines)
    
    def _generate_migration_guide(self, discovery_result: BusinessRuleDiscoveryResult,
                                business_rules: List[BusinessRule],
                                output_dir: Path) -> None:
        """Generate detailed migration planning guide."""
        doc_path = output_dir / "technical" / "migration_guide.md"
        
        with open(doc_path, 'w') as f:
            f.write(self._create_migration_guide_content(discovery_result, business_rules))
    
    def _create_migration_guide_content(self, discovery_result: BusinessRuleDiscoveryResult,
                                      business_rules: List[BusinessRule]) -> str:
        """Create migration guide content."""
        lines = [
            "# Business Rules Migration Guide",
            "",
            "This guide provides detailed migration strategies for transitioning business rules from Struts to GraphQL/Angular.",
            "",
            "## Migration Overview",
            "",
            f"**Total Rules to Migrate:** {discovery_result.total_rules:,}",
            f"**High-Priority Rules:** {len(discovery_result.high_impact_rules)}",
            f"**Critical Migration Items:** {len(discovery_result.migration_critical_rules)}",
            "",
            "## Migration Strategy by Rule Type",
            "",
        ]
        
        # Create migration strategies by rule type
        migration_strategies = {
            "validation": {
                "title": "Validation Rules",
                "strategy": "Migrate to GraphQL schema validation and Angular reactive forms",
                "tools": ["GraphQL schema directives", "Angular validators", "Yup/Joi validation"],
                "complexity": "Low to Medium"
            },
            "security": {
                "title": "Security Rules",
                "strategy": "Implement as GraphQL middleware and Angular guards",
                "tools": ["GraphQL middleware", "Angular guards", "JWT authentication"],
                "complexity": "Medium to High"
            },
            "business_logic": {
                "title": "Business Logic Rules",
                "strategy": "Convert to GraphQL resolvers and Angular services",
                "tools": ["GraphQL resolvers", "Angular services", "State management"],
                "complexity": "Medium to High"
            },
            "workflow": {
                "title": "Workflow Rules",
                "strategy": "Implement as orchestrated GraphQL operations",
                "tools": ["GraphQL mutations", "Angular state management", "Workflow engines"],
                "complexity": "High"
            }
        }
        
        for rule_type, count in discovery_result.rules_by_type.items():
            if rule_type in migration_strategies:
                strategy = migration_strategies[rule_type]
                lines.extend([
                    f"### {strategy['title']} ({count} rules)",
                    "",
                    f"**Migration Strategy:** {strategy['strategy']}",
                    "",
                    f"**Recommended Tools:**",
                ])
                
                for tool in strategy['tools']:
                    lines.append(f"- {tool}")
                
                lines.extend([
                    "",
                    f"**Complexity:** {strategy['complexity']}",
                    "",
                ])
        
        lines.extend([
            "",
            "## High-Priority Migration Items",
            "",
            "The following business rules require immediate attention during migration:",
            "",
        ])
        
        # Add high-priority rules
        priority_rules = sorted(
            discovery_result.high_impact_rules,
            key=lambda r: (r.complexity_score, r.impact.total_impact_score),
            reverse=True
        )
        
        for i, rule in enumerate(priority_rules[:10], 1):
            lines.extend([
                f"### {i}. {rule.name}",
                "",
                f"**Priority Level:** {'🔴 CRITICAL' if rule.migration_risk == 'critical' else '🟠 HIGH'}",
                f"**Complexity:** {rule.complexity.name}",
                f"**Source:** `{rule.location.file_path}`",
                "",
                f"**Business Impact:** {rule.business_context}",
                "",
                f"**Migration Approach:**",
            ])
            
            if rule.modernization_recommendations:
                for rec in rule.modernization_recommendations:
                    lines.append(f"- {rec}")
            else:
                lines.extend([
                    f"- Analyze business logic dependencies",
                    f"- Design GraphQL schema for data operations",
                    f"- Implement corresponding Angular components",
                    f"- Create comprehensive test coverage"
                ])
            
            lines.extend([
                "",
                "---",
                ""
            ])
        
        lines.extend([
            "",
            "## Migration Phase Planning",
            "",
            "### Phase 1: Foundation and Simple Rules (Weeks 1-4)",
            "",
            "**Objective:** Establish migration infrastructure and handle simple business rules",
            "",
            "**Scope:**",
        ])
        
        simple_rules = [r for r in business_rules if r.complexity == BusinessRuleComplexity.SIMPLE]
        lines.extend([
            f"- {len(simple_rules)} simple business rules",
            f"- Basic validation rules migration",
            f"- Development environment setup",
            "",
            "**Deliverables:**",
            "- GraphQL schema foundation",
            "- Angular project structure",
            "- Basic CI/CD pipeline",
            "- Simple validation rules implemented",
            "",
            "### Phase 2: Core Business Logic (Weeks 5-12)",
            "",
            "**Objective:** Migrate core business functionality",
            "",
            "**Scope:**",
        ])
        
        moderate_rules = [r for r in business_rules if r.complexity == BusinessRuleComplexity.MODERATE]
        lines.extend([
            f"- {len(moderate_rules)} moderate complexity rules",
            f"- Core business operations",
            f"- Data management workflows",
            "",
            "**Deliverables:**",
            "- Core GraphQL resolvers",
            "- Angular business services",
            "- Database integration layer",
            "- Business logic test coverage",
            "",
            "### Phase 3: Complex Integrations (Weeks 13-20)",
            "",
            "**Objective:** Handle complex business rules and integrations",
            "",
            "**Scope:**",
        ])
        
        complex_rules = [r for r in business_rules if r.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL]]
        lines.extend([
            f"- {len(complex_rules)} complex/critical business rules",
            f"- Advanced workflow implementations",
            f"- External system integrations",
            "",
            "**Deliverables:**",
            "- Advanced GraphQL operations",
            "- Sophisticated Angular workflows",
            "- Integration with external systems",
            "- Performance optimization",
            "",
            "### Phase 4: Optimization and Testing (Weeks 21-24)",
            "",
            "**Objective:** Finalize migration and ensure quality",
            "",
            "**Scope:**",
            "- End-to-end testing",
            "- Performance optimization",
            "- User acceptance testing",
            "- Documentation and training",
            "",
            "## Testing Strategy",
            "",
            "### Business Rule Validation",
            "",
            "Each migrated business rule must be validated against the original Struts implementation:",
            "",
            "1. **Unit Tests:** Verify individual rule logic",
            "2. **Integration Tests:** Ensure rule interactions work correctly",
            "3. **End-to-End Tests:** Validate complete user workflows",
            "4. **Business Validation:** Confirm rules meet business requirements",
            "",
            "### Test Coverage Requirements",
            "",
            "- **Critical Rules:** 100% test coverage with business stakeholder validation",
            "- **High-Impact Rules:** 95% test coverage with automated regression tests",
            "- **Standard Rules:** 90% test coverage with unit and integration tests",
            "",
            "## Risk Mitigation",
            "",
            "### Common Migration Risks",
            "",
            "1. **Business Logic Loss:** Risk of losing subtle business rules during migration",
            "2. **Performance Degradation:** New architecture may impact performance",
            "3. **Integration Complexity:** External system dependencies may complicate migration",
            "4. **Data Consistency:** Ensuring data integrity across the migration",
            "",
            "### Mitigation Strategies",
            "",
            "1. **Parallel Running:** Run old and new systems in parallel during transition",
            "2. **Incremental Migration:** Migrate business domains incrementally",
            "3. **Comprehensive Testing:** Extensive testing at each migration phase",
            "4. **Rollback Planning:** Maintain ability to rollback to previous system",
            "",
            "---",
            "",
            "*This migration guide should be reviewed and validated with business stakeholders and technical teams before implementation.*"
        ])
        
        return "\n".join(lines)
    
    def _generate_interactive_html_documentation(self,
                                               discovery_result: BusinessRuleDiscoveryResult,
                                               business_rules: List[BusinessRule],
                                               search_index: BusinessRuleIndex,
                                               output_dir: Path) -> None:
        """Generate interactive HTML documentation with search capabilities."""
        html_path = output_dir / "interactive" / "index.html"
        
        # Generate main HTML file
        with open(html_path, 'w') as f:
            f.write(self._create_interactive_html(discovery_result, business_rules))
        
        # Generate supporting assets
        self._generate_html_assets(output_dir)
        
        # Generate JSON data for JavaScript
        data_path = output_dir / "interactive" / "business_rules_data.json"
        with open(data_path, 'w') as f:
            json.dump({
                'business_rules': [rule.to_dict() for rule in business_rules],
                'discovery_summary': {
                    'total_rules': discovery_result.total_rules,
                    'rules_by_type': discovery_result.rules_by_type,
                    'rules_by_complexity': discovery_result.rules_by_complexity,
                    'business_domains': list(discovery_result.business_domains)
                }
            }, f, indent=2, default=str)
    
    def _create_interactive_html(self, discovery_result: BusinessRuleDiscoveryResult,
                               business_rules: List[BusinessRule]) -> str:
        """Create interactive HTML documentation."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Business Rules Analysis - Interactive Documentation</title>
    <link rel="stylesheet" href="../assets/css/styles.css">
</head>
<body>
    <header class="header">
        <div class="container">
            <h1>Business Rules Analysis</h1>
            <p>Interactive documentation for Struts to GraphQL/Angular migration</p>
        </div>
    </header>
    
    <nav class="nav">
        <div class="container">
            <ul>
                <li><a href="#dashboard">Dashboard</a></li>
                <li><a href="#rules">Business Rules</a></li>
                <li><a href="#search">Search</a></li>
                <li><a href="#migration">Migration Guide</a></li>
            </ul>
        </div>
    </nav>
    
    <main class="main">
        <div class="container">
            
            <!-- Dashboard Section -->
            <section id="dashboard" class="section">
                <h2>Analysis Dashboard</h2>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>{discovery_result.total_rules:,}</h3>
                        <p>Total Business Rules</p>
                    </div>
                    <div class="stat-card">
                        <h3>{len(discovery_result.business_domains)}</h3>
                        <p>Business Domains</p>
                    </div>
                    <div class="stat-card">
                        <h3>{len(discovery_result.high_impact_rules)}</h3>
                        <p>High-Impact Rules</p>
                    </div>
                    <div class="stat-card">
                        <h3>{len(discovery_result.migration_critical_rules)}</h3>
                        <p>Migration Critical</p>
                    </div>
                </div>
                
                <div class="charts-container">
                    <div class="chart-section">
                        <h3>Rules by Type</h3>
                        <div id="typeChart" class="chart"></div>
                    </div>
                    <div class="chart-section">
                        <h3>Rules by Complexity</h3>
                        <div id="complexityChart" class="chart"></div>
                    </div>
                </div>
            </section>
            
            <!-- Business Rules Section -->
            <section id="rules" class="section">
                <h2>Business Rules Catalog</h2>
                
                <div class="filters">
                    <input type="text" id="searchInput" placeholder="Search business rules...">
                    <select id="typeFilter">
                        <option value="">All Types</option>
                        {"".join(f'<option value="{t}">{t.replace("_", " ").title()}</option>' for t in discovery_result.rules_by_type.keys())}
                    </select>
                    <select id="complexityFilter">
                        <option value="">All Complexities</option>
                        {"".join(f'<option value="{c}">{c.title()}</option>' for c in discovery_result.rules_by_complexity.keys())}
                    </select>
                    <select id="riskFilter">
                        <option value="">All Risk Levels</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
                
                <div id="rulesContainer" class="rules-container">
                    <!-- Rules will be populated by JavaScript -->
                </div>
                
                <div id="pagination" class="pagination">
                    <!-- Pagination will be populated by JavaScript -->
                </div>
            </section>
            
            <!-- Search Section -->
            <section id="search" class="section">
                <h2>Advanced Search</h2>
                <p>Use advanced search capabilities to find specific business rules and patterns.</p>
                
                <div class="search-form">
                    <div class="search-row">
                        <label for="advancedSearch">Search Query:</label>
                        <input type="text" id="advancedSearch" placeholder="Enter search terms...">
                    </div>
                    
                    <div class="search-row">
                        <label for="domainSearch">Business Domain:</label>
                        <select id="domainSearch">
                            <option value="">All Domains</option>
                            {"".join(f'<option value="{d}">{d}</option>' for d in sorted(discovery_result.business_domains))}
                        </select>
                    </div>
                    
                    <button id="searchButton" class="btn-primary">Search</button>
                    <button id="clearSearch" class="btn-secondary">Clear</button>
                </div>
                
                <div id="searchResults" class="search-results">
                    <!-- Search results will be populated by JavaScript -->
                </div>
            </section>
            
            <!-- Migration Guide Section -->
            <section id="migration" class="section">
                <h2>Migration Planning</h2>
                
                <div class="migration-summary">
                    <h3>Migration Overview</h3>
                    <p>Strategic guidance for migrating business rules to GraphQL/Angular architecture.</p>
                    
                    <div class="migration-phases">
                        <div class="phase">
                            <h4>Phase 1: Foundation</h4>
                            <p>Simple rules and infrastructure setup</p>
                            <div class="phase-stats">
                                <span>4 weeks</span>
                                <span>{len([r for r in business_rules if r.complexity == BusinessRuleComplexity.SIMPLE])} rules</span>
                            </div>
                        </div>
                        
                        <div class="phase">
                            <h4>Phase 2: Core Logic</h4>
                            <p>Moderate complexity business operations</p>
                            <div class="phase-stats">
                                <span>8 weeks</span>
                                <span>{len([r for r in business_rules if r.complexity == BusinessRuleComplexity.MODERATE])} rules</span>
                            </div>
                        </div>
                        
                        <div class="phase">
                            <h4>Phase 3: Complex Rules</h4>
                            <p>Advanced workflows and integrations</p>
                            <div class="phase-stats">
                                <span>8 weeks</span>
                                <span>{len([r for r in business_rules if r.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL]])} rules</span>
                            </div>
                        </div>
                        
                        <div class="phase">
                            <h4>Phase 4: Testing</h4>
                            <p>Validation and optimization</p>
                            <div class="phase-stats">
                                <span>4 weeks</span>
                                <span>All rules</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="priority-rules">
                    <h3>High-Priority Migration Items</h3>
                    <div id="priorityRules" class="priority-container">
                        <!-- Priority rules will be populated by JavaScript -->
                    </div>
                </div>
            </section>
            
        </div>
    </main>
    
    <footer class="footer">
        <div class="container">
            <p>&copy; {datetime.now().year} Business Rules Analysis. Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </footer>
    
    <script src="../assets/js/app.js"></script>
</body>
</html>
"""
    
    def _generate_html_assets(self, output_dir: Path) -> None:
        """Generate CSS and JavaScript assets for interactive documentation."""
        # Generate CSS
        css_path = output_dir / "assets" / "css" / "styles.css"
        with open(css_path, 'w') as f:
            f.write(self._create_css_styles())
        
        # Generate JavaScript
        js_path = output_dir / "assets" / "js" / "app.js"
        with open(js_path, 'w') as f:
            f.write(self._create_javascript_app())
    
    def _create_css_styles(self) -> str:
        """Create CSS styles for interactive documentation."""
        return """
/* Business Rules Analysis - Interactive Documentation Styles */

:root {
    --primary-color: #2c5282;
    --secondary-color: #3182ce;
    --accent-color: #38b2ac;
    --success-color: #38a169;
    --warning-color: #dd6b20;
    --error-color: #e53e3e;
    --text-color: #2d3748;
    --text-light: #4a5568;
    --bg-color: #ffffff;
    --bg-light: #f7fafc;
    --border-color: #e2e8f0;
    --shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: var(--bg-light);
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

/* Header */
.header {
    background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
    color: white;
    padding: 2rem 0;
    text-align: center;
}

.header h1 {
    font-size: 2.5rem;
    margin-bottom: 0.5rem;
}

.header p {
    font-size: 1.1rem;
    opacity: 0.9;
}

/* Navigation */
.nav {
    background: var(--bg-color);
    border-bottom: 1px solid var(--border-color);
    position: sticky;
    top: 0;
    z-index: 100;
}

.nav ul {
    display: flex;
    list-style: none;
    padding: 1rem 0;
}

.nav li {
    margin-right: 2rem;
}

.nav a {
    color: var(--text-color);
    text-decoration: none;
    font-weight: 500;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    transition: background-color 0.2s;
}

.nav a:hover {
    background-color: var(--bg-light);
}

/* Main Content */
.main {
    padding: 2rem 0;
}

.section {
    background: var(--bg-color);
    margin-bottom: 2rem;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: var(--shadow);
}

.section h2 {
    color: var(--primary-color);
    margin-bottom: 1rem;
    font-size: 1.8rem;
}

/* Dashboard */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.stat-card {
    background: var(--bg-light);
    padding: 1.5rem;
    border-radius: 8px;
    text-align: center;
    border: 1px solid var(--border-color);
}

.stat-card h3 {
    font-size: 2rem;
    color: var(--secondary-color);
    margin-bottom: 0.5rem;
}

.stat-card p {
    color: var(--text-light);
    font-weight: 500;
}

.charts-container {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
}

.chart-section h3 {
    margin-bottom: 1rem;
    color: var(--text-color);
}

.chart {
    height: 300px;
    background: var(--bg-light);
    border-radius: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-light);
}

/* Filters */
.filters {
    display: flex;
    gap: 1rem;
    margin-bottom: 2rem;
    flex-wrap: wrap;
}

.filters input,
.filters select {
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 1rem;
    min-width: 200px;
}

.filters input:focus,
.filters select:focus {
    outline: none;
    border-color: var(--secondary-color);
    box-shadow: 0 0 0 3px rgba(49, 130, 206, 0.1);
}

/* Rules Container */
.rules-container {
    display: grid;
    gap: 1rem;
}

.rule-card {
    background: var(--bg-light);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1.5rem;
    transition: transform 0.2s, box-shadow 0.2s;
}

.rule-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.rule-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1rem;
}

.rule-title {
    font-size: 1.2rem;
    font-weight: 600;
    color: var(--primary-color);
    margin-bottom: 0.5rem;
}

.rule-badges {
    display: flex;
    gap: 0.5rem;
}

.badge {
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 500;
    text-transform: uppercase;
}

.badge-type { background: #e6fffa; color: #234e52; }
.badge-complexity-simple { background: #f0fff4; color: #22543d; }
.badge-complexity-moderate { background: #fffbf0; color: #744210; }
.badge-complexity-complex { background: #fff5f5; color: #742a2a; }
.badge-risk-low { background: #f0fff4; color: #22543d; }
.badge-risk-medium { background: #fffbf0; color: #744210; }
.badge-risk-high { background: #fff5f5; color: #742a2a; }
.badge-risk-critical { background: #fed7d7; color: #742a2a; }

.rule-description {
    margin-bottom: 1rem;
    color: var(--text-color);
}

.rule-context {
    font-size: 0.9rem;
    color: var(--text-light);
    font-style: italic;
    margin-bottom: 1rem;
}

.rule-source {
    font-size: 0.8rem;
    color: var(--text-light);
    font-family: monospace;
    background: #f1f5f9;
    padding: 0.5rem;
    border-radius: 4px;
}

/* Buttons */
.btn-primary {
    background: var(--secondary-color);
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.2s;
}

.btn-primary:hover {
    background: var(--primary-color);
}

.btn-secondary {
    background: var(--bg-light);
    color: var(--text-color);
    border: 1px solid var(--border-color);
    padding: 0.75rem 1.5rem;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.2s;
}

.btn-secondary:hover {
    background: #e2e8f0;
}

/* Search Form */
.search-form {
    background: var(--bg-light);
    padding: 1.5rem;
    border-radius: 8px;
    margin-bottom: 2rem;
}

.search-row {
    display: flex;
    align-items: center;
    margin-bottom: 1rem;
    gap: 1rem;
}

.search-row label {
    min-width: 120px;
    font-weight: 500;
}

.search-row input,
.search-row select {
    flex: 1;
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
}

/* Migration Phases */
.migration-phases {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}

.phase {
    background: var(--bg-light);
    padding: 1.5rem;
    border-radius: 8px;
    border-left: 4px solid var(--accent-color);
}

.phase h4 {
    color: var(--primary-color);
    margin-bottom: 0.5rem;
}

.phase-stats {
    margin-top: 1rem;
    display: flex;
    justify-content: space-between;
    font-size: 0.9rem;
    color: var(--text-light);
}

/* Pagination */
.pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 0.5rem;
    margin-top: 2rem;
}

.pagination button {
    padding: 0.5rem 1rem;
    border: 1px solid var(--border-color);
    background: var(--bg-color);
    color: var(--text-color);
    border-radius: 4px;
    cursor: pointer;
    transition: background-color 0.2s;
}

.pagination button:hover {
    background: var(--bg-light);
}

.pagination button.active {
    background: var(--secondary-color);
    color: white;
    border-color: var(--secondary-color);
}

.pagination button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

/* Footer */
.footer {
    background: var(--text-color);
    color: white;
    text-align: center;
    padding: 2rem 0;
    margin-top: 2rem;
}

/* Responsive Design */
@media (max-width: 768px) {
    .container {
        padding: 0 15px;
    }
    
    .nav ul {
        flex-wrap: wrap;
    }
    
    .nav li {
        margin-right: 1rem;
        margin-bottom: 0.5rem;
    }
    
    .charts-container {
        grid-template-columns: 1fr;
    }
    
    .filters {
        flex-direction: column;
    }
    
    .filters input,
    .filters select {
        min-width: auto;
        width: 100%;
    }
    
    .search-row {
        flex-direction: column;
        align-items: stretch;
    }
    
    .search-row label {
        min-width: auto;
    }
}
"""
    
    def _create_javascript_app(self) -> str:
        """Create JavaScript application for interactive features."""
        return """
// Business Rules Analysis - Interactive Documentation JavaScript

class BusinessRulesApp {
    constructor() {
        this.businessRules = [];
        this.filteredRules = [];
        this.currentPage = 1;
        this.rulesPerPage = 20;
        this.discoveryData = {};
        
        this.init();
    }
    
    async init() {
        try {
            await this.loadData();
            this.setupEventListeners();
            this.renderDashboard();
            this.renderRules();
            this.setupNavigation();
        } catch (error) {
            console.error('Failed to initialize app:', error);
        }
    }
    
    async loadData() {
        try {
            const response = await fetch('business_rules_data.json');
            const data = await response.json();
            this.businessRules = data.business_rules;
            this.filteredRules = [...this.businessRules];
            this.discoveryData = data.discovery_summary;
        } catch (error) {
            console.error('Failed to load data:', error);
            // Fallback to empty data
            this.businessRules = [];
            this.filteredRules = [];
            this.discoveryData = {};
        }
    }
    
    setupEventListeners() {
        // Search input
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filterRules();
            });
        }
        
        // Filter selects
        const filters = ['typeFilter', 'complexityFilter', 'riskFilter'];
        filters.forEach(filterId => {
            const filter = document.getElementById(filterId);
            if (filter) {
                filter.addEventListener('change', () => {
                    this.filterRules();
                });
            }
        });
        
        // Advanced search
        const searchButton = document.getElementById('searchButton');
        if (searchButton) {
            searchButton.addEventListener('click', () => {
                this.performAdvancedSearch();
            });
        }
        
        const clearSearch = document.getElementById('clearSearch');
        if (clearSearch) {
            clearSearch.addEventListener('click', () => {
                this.clearSearch();
            });
        }
    }
    
    setupNavigation() {
        // Smooth scrolling for navigation links
        document.querySelectorAll('.nav a').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = link.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
    }
    
    renderDashboard() {
        this.renderCharts();
    }
    
    renderCharts() {
        // Simple chart rendering using CSS
        this.renderTypeChart();
        this.renderComplexityChart();
    }
    
    renderTypeChart() {
        const chartContainer = document.getElementById('typeChart');
        if (!chartContainer || !this.discoveryData.rules_by_type) return;
        
        const types = this.discoveryData.rules_by_type;
        const total = Object.values(types).reduce((sum, count) => sum + count, 0);
        
        let html = '<div class="chart-bars">';
        Object.entries(types).forEach(([type, count]) => {
            const percentage = (count / total * 100).toFixed(1);
            const height = Math.max(percentage, 5); // Minimum height for visibility
            html += `
                <div class="chart-bar" style="height: ${height}%; background: var(--secondary-color);">
                    <div class="chart-label">${type.replace('_', ' ')}</div>
                    <div class="chart-value">${count} (${percentage}%)</div>
                </div>
            `;
        });
        html += '</div>';
        
        chartContainer.innerHTML = html;
    }
    
    renderComplexityChart() {
        const chartContainer = document.getElementById('complexityChart');
        if (!chartContainer || !this.discoveryData.rules_by_complexity) return;
        
        const complexities = this.discoveryData.rules_by_complexity;
        const total = Object.values(complexities).reduce((sum, count) => sum + count, 0);
        
        const colors = {
            'SIMPLE': '#38a169',
            'MODERATE': '#dd6b20',
            'COMPLEX': '#e53e3e',
            'CRITICAL': '#742a2a'
        };
        
        let html = '<div class="chart-bars">';
        Object.entries(complexities).forEach(([complexity, count]) => {
            const percentage = (count / total * 100).toFixed(1);
            const height = Math.max(percentage, 5);
            const color = colors[complexity] || 'var(--secondary-color)';
            html += `
                <div class="chart-bar" style="height: ${height}%; background: ${color};">
                    <div class="chart-label">${complexity.toLowerCase()}</div>
                    <div class="chart-value">${count} (${percentage}%)</div>
                </div>
            `;
        });
        html += '</div>';
        
        chartContainer.innerHTML = html;
    }
    
    filterRules() {
        const searchTerm = document.getElementById('searchInput')?.value.toLowerCase() || '';
        const typeFilter = document.getElementById('typeFilter')?.value || '';
        const complexityFilter = document.getElementById('complexityFilter')?.value || '';
        const riskFilter = document.getElementById('riskFilter')?.value || '';
        
        this.filteredRules = this.businessRules.filter(rule => {
            const matchesSearch = !searchTerm || 
                rule.name.toLowerCase().includes(searchTerm) ||
                rule.description.toLowerCase().includes(searchTerm) ||
                rule.business_context.toLowerCase().includes(searchTerm);
            
            const matchesType = !typeFilter || rule.rule_type === typeFilter;
            const matchesComplexity = !complexityFilter || rule.complexity === complexityFilter;
            const matchesRisk = !riskFilter || rule.migration_risk === riskFilter;
            
            return matchesSearch && matchesType && matchesComplexity && matchesRisk;
        });
        
        this.currentPage = 1;
        this.renderRules();
    }
    
    renderRules() {
        const container = document.getElementById('rulesContainer');
        if (!container) return;
        
        const start = (this.currentPage - 1) * this.rulesPerPage;
        const end = start + this.rulesPerPage;
        const pageRules = this.filteredRules.slice(start, end);
        
        if (pageRules.length === 0) {
            container.innerHTML = '<p class="no-rules">No business rules match the current filters.</p>';
            this.renderPagination();
            return;
        }
        
        const html = pageRules.map(rule => this.createRuleCard(rule)).join('');
        container.innerHTML = html;
        
        this.renderPagination();
    }
    
    createRuleCard(rule) {
        const complexityClass = `badge-complexity-${rule.complexity.toLowerCase()}`;
        const riskClass = `badge-risk-${rule.migration_risk}`;
        
        return `
            <div class="rule-card">
                <div class="rule-header">
                    <div>
                        <div class="rule-title">${this.escapeHtml(rule.name)}</div>
                        <div class="rule-badges">
                            <span class="badge badge-type">${rule.rule_type.replace('_', ' ')}</span>
                            <span class="badge ${complexityClass}">${rule.complexity}</span>
                            <span class="badge ${riskClass}">${rule.migration_risk}</span>
                        </div>
                    </div>
                </div>
                <div class="rule-description">
                    ${this.escapeHtml(rule.description)}
                </div>
                ${rule.business_context ? `
                    <div class="rule-context">
                        Business Context: ${this.escapeHtml(rule.business_context)}
                    </div>
                ` : ''}
                <div class="rule-source">
                    Source: ${this.escapeHtml(rule.location.file_path)}
                    ${rule.location.line_number ? `:${rule.location.line_number}` : ''}
                </div>
            </div>
        `;
    }
    
    renderPagination() {
        const container = document.getElementById('pagination');
        if (!container) return;
        
        const totalPages = Math.ceil(this.filteredRules.length / this.rulesPerPage);
        
        if (totalPages <= 1) {
            container.innerHTML = '';
            return;
        }
        
        let html = '';
        
        // Previous button
        html += `
            <button ${this.currentPage === 1 ? 'disabled' : ''} onclick="app.goToPage(${this.currentPage - 1})">
                Previous
            </button>
        `;
        
        // Page numbers
        const startPage = Math.max(1, this.currentPage - 2);
        const endPage = Math.min(totalPages, this.currentPage + 2);
        
        if (startPage > 1) {
            html += `<button onclick="app.goToPage(1)">1</button>`;
            if (startPage > 2) {
                html += '<span>...</span>';
            }
        }
        
        for (let i = startPage; i <= endPage; i++) {
            html += `
                <button class="${i === this.currentPage ? 'active' : ''}" onclick="app.goToPage(${i})">
                    ${i}
                </button>
            `;
        }
        
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                html += '<span>...</span>';
            }
            html += `<button onclick="app.goToPage(${totalPages})">${totalPages}</button>`;
        }
        
        // Next button
        html += `
            <button ${this.currentPage === totalPages ? 'disabled' : ''} onclick="app.goToPage(${this.currentPage + 1})">
                Next
            </button>
        `;
        
        container.innerHTML = html;
    }
    
    goToPage(page) {
        this.currentPage = page;
        this.renderRules();
        
        // Scroll to rules section
        const rulesSection = document.getElementById('rules');
        if (rulesSection) {
            rulesSection.scrollIntoView({ behavior: 'smooth' });
        }
    }
    
    performAdvancedSearch() {
        const searchQuery = document.getElementById('advancedSearch')?.value.toLowerCase() || '';
        const domainFilter = document.getElementById('domainSearch')?.value || '';
        
        this.filteredRules = this.businessRules.filter(rule => {
            const matchesQuery = !searchQuery || 
                rule.name.toLowerCase().includes(searchQuery) ||
                rule.description.toLowerCase().includes(searchQuery) ||
                rule.business_context.toLowerCase().includes(searchQuery) ||
                rule.evidence.code_snippet.toLowerCase().includes(searchQuery);
            
            const matchesDomain = !domainFilter || rule.business_domain === domainFilter;
            
            return matchesQuery && matchesDomain;
        });
        
        this.currentPage = 1;
        this.renderSearchResults();
    }
    
    renderSearchResults() {
        const container = document.getElementById('searchResults');
        if (!container) return;
        
        if (this.filteredRules.length === 0) {
            container.innerHTML = '<p>No business rules match your search criteria.</p>';
            return;
        }
        
        const html = `
            <h3>Search Results (${this.filteredRules.length} rules found)</h3>
            <div class="search-results-list">
                ${this.filteredRules.slice(0, 10).map(rule => this.createRuleCard(rule)).join('')}
            </div>
            ${this.filteredRules.length > 10 ? '<p><em>Showing first 10 results...</em></p>' : ''}
        `;
        
        container.innerHTML = html;
    }
    
    clearSearch() {
        // Clear all search inputs
        const inputs = ['advancedSearch', 'domainSearch'];
        inputs.forEach(id => {
            const input = document.getElementById(id);
            if (input) input.value = '';
        });
        
        // Clear results
        const container = document.getElementById('searchResults');
        if (container) {
            container.innerHTML = '';
        }
        
        // Reset filtered rules
        this.filteredRules = [...this.businessRules];
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new BusinessRulesApp();
});

// Add CSS for charts
const chartStyles = `
<style>
.chart-bars {
    display: flex;
    align-items: end;
    height: 100%;
    gap: 10px;
    padding: 20px;
}

.chart-bar {
    flex: 1;
    min-height: 20px;
    border-radius: 4px 4px 0 0;
    position: relative;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    align-items: center;
    color: white;
    font-size: 0.8rem;
    padding: 5px;
}

.chart-label {
    font-weight: 500;
    margin-bottom: 5px;
}

.chart-value {
    font-size: 0.7rem;
    opacity: 0.9;
}

.no-rules {
    text-align: center;
    color: var(--text-light);
    font-style: italic;
    padding: 2rem;
}

.search-results-list {
    display: grid;
    gap: 1rem;
    margin-top: 1rem;
}
</style>
`;

document.head.insertAdjacentHTML('beforeend', chartStyles);
"""
    
    def _generate_csv_exports(self, business_rules: List[BusinessRule], output_dir: Path) -> None:
        """Generate CSV exports for data analysis."""
        import csv
        
        # Main business rules export
        csv_path = output_dir / "exports" / "business_rules.csv"
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'ID', 'Name', 'Description', 'Type', 'Source', 'Complexity',
                'Migration Risk', 'Business Domain', 'File Path', 'Line Number',
                'Impact Score', 'Dependencies Count', 'Tags'
            ])
            
            # Write data
            for rule in business_rules:
                writer.writerow([
                    rule.id,
                    rule.name,
                    rule.description,
                    rule.rule_type.value,
                    rule.source.value,
                    rule.complexity.name,
                    rule.migration_risk,
                    rule.business_domain,
                    rule.location.file_path,
                    rule.location.line_number or '',
                    rule.impact.total_impact_score,
                    len(rule.dependencies),
                    ', '.join(rule.tags)
                ])
        
        # High-impact rules export
        high_impact_rules = [rule for rule in business_rules if rule.is_high_impact]
        if high_impact_rules:
            high_impact_path = output_dir / "exports" / "high_impact_rules.csv"
            with open(high_impact_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Name', 'Type', 'Complexity', 'Migration Risk', 'Impact Score'])
                
                for rule in high_impact_rules:
                    writer.writerow([
                        rule.id, rule.name, rule.rule_type.value,
                        rule.complexity.name, rule.migration_risk,
                        rule.impact.total_impact_score
                    ])
    
    def _generate_stakeholder_views(self, discovery_result: BusinessRuleDiscoveryResult,
                                  business_rules: List[BusinessRule],
                                  output_dir: Path) -> None:
        """Generate stakeholder-specific views."""
        # Business stakeholder view
        self._generate_business_stakeholder_view(discovery_result, business_rules, output_dir)
        
        # Technical stakeholder view
        self._generate_technical_stakeholder_view(discovery_result, business_rules, output_dir)
    
    def _generate_business_stakeholder_view(self, discovery_result: BusinessRuleDiscoveryResult,
                                          business_rules: List[BusinessRule],
                                          output_dir: Path) -> None:
        """Generate business stakeholder focused view."""
        doc_path = output_dir / "business" / "business_stakeholder_summary.md"
        
        lines = [
            "# Business Stakeholder Summary",
            "",
            "## What We Found",
            "",
            f"Our analysis discovered **{discovery_result.total_rules:,} business rules** in your Struts application. ",
            "These rules represent the critical business logic that powers your operations.",
            "",
            "## Business Impact",
            "",
            f"- **{len(discovery_result.high_impact_rules)} rules** have high business impact",
            f"- **{len(discovery_result.business_domains)} business domains** are covered",
            f"- **{len(discovery_result.migration_critical_rules)} rules** require special attention during migration",
            "",
            "## What This Means for Migration",
            "",
            "### Timeline",
            "Based on the complexity of your business rules, we estimate a **24-week migration timeline** with proper planning and resources.",
            "",
            "### Business Continuity",
            "All identified business rules will be preserved during migration. No business functionality will be lost.",
            "",
            "### Benefits of Migration",
            "- **Improved Performance**: Modern GraphQL/Angular architecture",
            "- **Better Maintainability**: Cleaner, more organized business logic",
            "- **Enhanced User Experience**: Modern, responsive user interface",
            "- **Future-Proof Technology**: Built on current industry standards",
            "",
            "## Next Steps for Business Stakeholders",
            "",
            "1. **Review High-Impact Rules**: Validate that critical business logic is correctly identified",
            "2. **Domain Expert Involvement**: Assign domain experts to verify business rules in their areas",
            "3. **Testing Participation**: Participate in user acceptance testing to ensure business requirements are met",
            "4. **Change Management**: Prepare teams for the new system interface and workflows"
        ]
        
        with open(doc_path, 'w') as f:
            f.write('\n'.join(lines))
    
    def _generate_technical_stakeholder_view(self, discovery_result: BusinessRuleDiscoveryResult,
                                           business_rules: List[BusinessRule],
                                           output_dir: Path) -> None:
        """Generate technical stakeholder focused view."""
        doc_path = output_dir / "technical" / "technical_analysis.md"
        
        # Technical complexity analysis
        complex_rules = [r for r in business_rules if r.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL]]
        
        lines = [
            "# Technical Analysis Report",
            "",
            "## Architecture Overview",
            "",
            f"The Struts application contains **{discovery_result.total_rules:,} business rules** distributed across:",
            "",
            f"- **{discovery_result.rules_by_source.get('struts_config', 0)} configuration-based rules**",
            f"- **{discovery_result.rules_by_source.get('action_class', 0)} Java class-based rules**",
            f"- **{discovery_result.rules_by_source.get('validation_xml', 0)} validation rules**",
            f"- **{discovery_result.rules_by_source.get('jsp_file', 0)} UI-based rules**",
            "",
            "## Technical Complexity Distribution",
            "",
        ]
        
        # Add complexity breakdown
        for complexity, count in discovery_result.rules_by_complexity.items():
            percentage = (count / discovery_result.total_rules) * 100
            lines.append(f"- **{complexity.title()}**: {count:,} rules ({percentage:.1f}%)")
        
        lines.extend([
            "",
            "## High-Complexity Rules Analysis",
            "",
            f"**{len(complex_rules)} rules** require specialized migration attention:",
            "",
        ])
        
        # Add top complex rules
        for rule in sorted(complex_rules, key=lambda r: r.complexity_score, reverse=True)[:10]:
            lines.extend([
                f"### {rule.name}",
                f"- **Complexity Score**: {rule.complexity_score}",
                f"- **Source**: `{rule.location.file_path}`",
                f"- **Dependencies**: {len(rule.dependencies)}",
                ""
            ])
        
        lines.extend([
            "",
            "## Migration Architecture Recommendations",
            "",
            "### GraphQL Schema Design",
            "- Use schema directives for validation rules",
            "- Implement custom scalars for business data types",
            "- Design resolvers to encapsulate business logic",
            "",
            "### Angular Architecture",
            "- Reactive forms for data validation",
            "- Services for business logic implementation",
            "- Guards for security and access control",
            "",
            "### Testing Strategy",
            "- Unit tests for individual business rules",
            "- Integration tests for rule interactions",
            "- End-to-end tests for complete workflows"
        ])
        
        with open(doc_path, 'w') as f:
            f.write('\n'.join(lines))
    
    def _generate_search_aids(self, business_rules: List[BusinessRule], output_dir: Path) -> None:
        """Generate search aids and indexes."""
        # Generate tag index
        tag_index = defaultdict(list)
        for rule in business_rules:
            for tag in rule.tags:
                tag_index[tag].append(rule.id)
        
        tag_index_path = output_dir / "exports" / "tag_index.json"
        with open(tag_index_path, 'w') as f:
            json.dump(dict(tag_index), f, indent=2)
        
        # Generate domain index
        domain_index = defaultdict(list)
        for rule in business_rules:
            domain_index[rule.business_domain].append(rule.id)
        
        domain_index_path = output_dir / "exports" / "domain_index.json"
        with open(domain_index_path, 'w') as f:
            json.dump(dict(domain_index), f, indent=2)
    
    def _markdown_to_html(self, markdown_text: str) -> str:
        """Simple markdown to HTML conversion."""
        lines = markdown_text.split('\n')
        html_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                html_lines.append('<br>')
            elif line.startswith('# '):
                html_lines.append(f'<h1>{html.escape(line[2:])}</h1>')
            elif line.startswith('## '):
                html_lines.append(f'<h2>{html.escape(line[3:])}</h2>')
            elif line.startswith('### '):
                html_lines.append(f'<h3>{html.escape(line[4:])}</h3>')
            elif line.startswith('- '):
                if not html_lines or not html_lines[-1].startswith('<ul>'):
                    html_lines.append('<ul>')
                html_lines.append(f'<li>{html.escape(line[2:])}</li>')
            else:
                if html_lines and html_lines[-1].startswith('<ul>'):
                    html_lines.append('</ul>')
                html_lines.append(f'<p>{html.escape(line)}</p>')
        
        # Close any open lists
        if html_lines and html_lines[-1].startswith('<ul>'):
            html_lines.append('</ul>')
        
        return '\n'.join(html_lines)
    
    def _generate_technical_reference(self, business_rules: List[BusinessRule], output_dir: Path) -> None:
        """Generate comprehensive technical reference."""
        doc_path = output_dir / "technical" / "technical_reference.md"
        
        # Group rules by source for technical analysis
        rules_by_source = defaultdict(list)
        for rule in business_rules:
            rules_by_source[rule.source].append(rule)
        
        lines = [
            "# Technical Reference Guide",
            "",
            "Comprehensive technical documentation for business rules analysis and migration.",
            "",
            "## Rules by Source Component",
            "",
        ]
        
        for source, rules in rules_by_source.items():
            source_name = source.value.replace('_', ' ').title()
            lines.extend([
                f"### {source_name} ({len(rules)} rules)",
                "",
                f"Business rules extracted from {source_name.lower()} components:",
                "",
            ])
            
            # Show complexity distribution for this source
            complexity_counts = Counter(rule.complexity for rule in rules)
            for complexity, count in complexity_counts.items():
                lines.append(f"- **{complexity.name}**: {count} rules")
            
            lines.append("")
        
        # Add migration mapping
        lines.extend([
            "",
            "## Migration Technology Mapping",
            "",
            "| Struts Component | GraphQL/Angular Equivalent | Migration Strategy |",
            "|------------------|---------------------------|-------------------|",
            "| Action Classes | GraphQL Resolvers + Angular Services | Convert business logic to resolvers |",
            "| Validation Rules | GraphQL Schema + Angular Validators | Schema directives + reactive forms |",
            "| JSP Files | Angular Components | Component-based UI architecture |",
            "| Interceptors | GraphQL Middleware + Angular Guards | Cross-cutting concern implementation |",
            "| Form Beans | GraphQL Input Types + Angular Models | Type-safe data structures |",
            "",
            "## Implementation Guidelines",
            "",
            "### GraphQL Schema Design",
            "```graphql",
            "# Example validation directive",
            "directive @validation(",
            "  pattern: String",
            "  required: Boolean = false",
            "  minLength: Int",
            "  maxLength: Int",
            ") on FIELD_DEFINITION | INPUT_FIELD_DEFINITION",
            "",
            "type User {",
            "  email: String @validation(required: true, pattern: \"^[^@]+@[^@]+\\.[^@]+$\")",
            "  age: Int @validation(min: 0, max: 150)",
            "}",
            "```",
            "",
            "### Angular Implementation",
            "```typescript",
            "// Business rule service example",
            "@Injectable()",
            "export class UserValidationService {",
            "  validateUser(user: User): ValidationResult {",
            "    // Implement business rule logic",
            "    return this.applyBusinessRules(user);",
            "  }",
            "}",
            "```",
        ])
        
        with open(doc_path, 'w') as f:
            f.write('\n'.join(lines))
