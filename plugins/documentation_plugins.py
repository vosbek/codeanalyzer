"""
Documentation Generation Plugins
===============================

This module contains plugins for generating custom documentation formats
and specialized reports for business stakeholders and technical teams.

Plugins included:
- Custom documentation generation with multiple formats
- Business stakeholder reports
- Technical migration guides
- API documentation generation

Author: Claude Code Assistant
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

from plugins.base_plugin import DocumentationPlugin, PluginResult, PluginMetadata, PluginType
from models.business_rule import BusinessRule, BusinessRuleType, BusinessRuleComplexity


class CustomDocumentationPlugin(DocumentationPlugin):
    """Plugin for generating custom documentation formats."""
    
    def _get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="CustomDocumentationPlugin",
            version="1.0.0",
            description="Generates custom documentation in multiple formats",
            author="Claude Code Assistant",
            plugin_type=PluginType.DOCUMENTATION,
            supported_file_types=set(),
            configuration_schema={
                'output_formats': {
                    'type': 'list',
                    'default': ['html', 'markdown', 'json'],
                    'description': 'Output formats to generate'
                },
                'include_technical_details': {
                    'type': 'boolean',
                    'default': True,
                    'description': 'Include technical implementation details'
                },
                'stakeholder_focus': {
                    'type': 'string',
                    'default': 'business',
                    'description': 'Primary stakeholder focus (business, technical, mixed)'
                },
                'template_directory': {
                    'type': 'string',
                    'default': '',
                    'description': 'Directory containing custom templates'
                }
            }
        )
    
    def can_handle(self, context: Dict[str, Any]) -> bool:
        """Check if custom documentation generation is applicable."""
        return True
    
    def execute(self, context: Dict[str, Any]) -> PluginResult:
        """Execute custom documentation generation."""
        business_rules = context.get('business_rules', [])
        analysis_results = context.get('analysis_results', {})
        output_path = Path(context.get('output_path', 'output'))
        
        return self.generate_documentation(business_rules, analysis_results, output_path)
    
    def generate_documentation(self,
                             business_rules: List[BusinessRule],
                             analysis_results: Dict[str, Any],
                             output_path: Path) -> PluginResult:
        """Generate custom documentation."""
        start_time = datetime.now()
        result = PluginResult(
            plugin_name=self.metadata.name,
            success=True,
            execution_time_ms=0
        )
        
        try:
            # Ensure output directory exists
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Get configured output formats
            output_formats = self.configuration.get('output_formats', ['html', 'markdown'])
            generated_files = []
            
            # Generate documentation in each requested format
            for format_type in output_formats:
                if format_type == 'html':
                    files = self._generate_html_documentation(business_rules, analysis_results, output_path)
                elif format_type == 'markdown':
                    files = self._generate_markdown_documentation(business_rules, analysis_results, output_path)
                elif format_type == 'json':
                    files = self._generate_json_documentation(business_rules, analysis_results, output_path)
                elif format_type == 'csv':
                    files = self._generate_csv_documentation(business_rules, analysis_results, output_path)
                else:
                    result.add_warning(f"Unsupported output format: {format_type}")
                    continue
                
                generated_files.extend(files)
            
            # Add generated files to result
            result.add_extracted_data('generated_files', generated_files)
            result.add_extracted_data('output_formats', output_formats)
            
            # Generate summary
            summary = self._generate_summary(business_rules, analysis_results)
            result.add_extracted_data('documentation_summary', summary)
            
            # Calculate execution time
            end_time = datetime.now()
            result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            result.add_recommendation(f"Generated {len(generated_files)} documentation files in {len(output_formats)} formats")
            
        except Exception as e:
            result.add_error(f"Custom documentation generation failed: {e}")
        
        return result
    
    def get_output_formats(self) -> List[str]:
        """Get supported output formats."""
        return ['html', 'markdown', 'json', 'csv', 'xml']
    
    def _generate_html_documentation(self, business_rules: List[BusinessRule], 
                                   analysis_results: Dict[str, Any], 
                                   output_path: Path) -> List[str]:
        """Generate HTML documentation."""
        generated_files = []
        
        # Generate main overview page
        overview_file = output_path / 'business_rules_overview.html'
        html_content = self._create_html_overview(business_rules, analysis_results)
        
        with open(overview_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        generated_files.append(str(overview_file))
        
        # Generate detailed rule pages
        if self.configuration.get('include_technical_details', True):
            details_dir = output_path / 'rule_details'
            details_dir.mkdir(exist_ok=True)
            
            for rule in business_rules:
                rule_file = details_dir / f'rule_{rule.id}.html'
                rule_html = self._create_rule_detail_html(rule)
                
                with open(rule_file, 'w', encoding='utf-8') as f:
                    f.write(rule_html)
                generated_files.append(str(rule_file))
        
        # Generate stakeholder summary
        stakeholder_file = output_path / 'stakeholder_summary.html'
        stakeholder_html = self._create_stakeholder_summary_html(business_rules, analysis_results)
        
        with open(stakeholder_file, 'w', encoding='utf-8') as f:
            f.write(stakeholder_html)
        generated_files.append(str(stakeholder_file))
        
        return generated_files
    
    def _generate_markdown_documentation(self, business_rules: List[BusinessRule], 
                                       analysis_results: Dict[str, Any], 
                                       output_path: Path) -> List[str]:
        """Generate Markdown documentation."""
        generated_files = []
        
        # Generate main README
        readme_file = output_path / 'README.md'
        markdown_content = self._create_markdown_overview(business_rules, analysis_results)
        
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        generated_files.append(str(readme_file))
        
        # Generate business rules catalog
        catalog_file = output_path / 'BUSINESS_RULES_CATALOG.md'
        catalog_content = self._create_markdown_catalog(business_rules)
        
        with open(catalog_file, 'w', encoding='utf-8') as f:
            f.write(catalog_content)
        generated_files.append(str(catalog_file))
        
        # Generate migration guide
        migration_file = output_path / 'MIGRATION_GUIDE.md'
        migration_content = self._create_migration_guide_markdown(business_rules, analysis_results)
        
        with open(migration_file, 'w', encoding='utf-8') as f:
            f.write(migration_content)
        generated_files.append(str(migration_file))
        
        return generated_files
    
    def _generate_json_documentation(self, business_rules: List[BusinessRule], 
                                   analysis_results: Dict[str, Any], 
                                   output_path: Path) -> List[str]:
        """Generate JSON documentation."""
        generated_files = []
        
        # Convert business rules to JSON-serializable format
        rules_data = []
        for rule in business_rules:
            rule_data = {
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'rule_type': rule.rule_type.name if rule.rule_type else None,
                'source': rule.source.name if rule.source else None,
                'complexity': rule.complexity.name if rule.complexity else None,
                'business_context': rule.business_context,
                'tags': list(rule.tags) if rule.tags else [],
                'location': {
                    'file_path': rule.location.file_path if rule.location else None,
                    'class_name': rule.location.class_name if rule.location else None,
                    'method_name': rule.location.method_name if rule.location else None,
                    'line_number': rule.location.line_number if rule.location else None
                },
                'evidence': {
                    'code_snippet': rule.evidence.code_snippet if rule.evidence else None,
                    'context': rule.evidence.context if rule.evidence else None,
                    'confidence_score': rule.evidence.confidence_score if rule.evidence else None,
                    'extraction_method': rule.evidence.extraction_method if rule.evidence else None
                } if rule.evidence else None,
                'migration_notes': rule.migration_notes if hasattr(rule, 'migration_notes') else None
            }
            rules_data.append(rule_data)
        
        # Generate main JSON file
        json_file = output_path / 'business_rules.json'
        documentation_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'plugin_name': self.metadata.name,
                'plugin_version': self.metadata.version,
                'total_rules': len(business_rules)
            },
            'summary': self._generate_summary(business_rules, analysis_results),
            'business_rules': rules_data,
            'analysis_results': analysis_results
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(documentation_data, f, indent=2, ensure_ascii=False)
        generated_files.append(str(json_file))
        
        return generated_files
    
    def _generate_csv_documentation(self, business_rules: List[BusinessRule], 
                                  analysis_results: Dict[str, Any], 
                                  output_path: Path) -> List[str]:
        """Generate CSV documentation for spreadsheet analysis."""
        generated_files = []
        
        import csv
        
        # Generate main business rules CSV
        csv_file = output_path / 'business_rules.csv'
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'ID', 'Name', 'Description', 'Type', 'Source', 'Complexity',
                'Business Context', 'File Path', 'Class Name', 'Method Name',
                'Confidence Score', 'Tags'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for rule in business_rules:
                writer.writerow({
                    'ID': rule.id,
                    'Name': rule.name,
                    'Description': rule.description,
                    'Type': rule.rule_type.name if rule.rule_type else '',
                    'Source': rule.source.name if rule.source else '',
                    'Complexity': rule.complexity.name if rule.complexity else '',
                    'Business Context': rule.business_context or '',
                    'File Path': rule.location.file_path if rule.location else '',
                    'Class Name': rule.location.class_name if rule.location else '',
                    'Method Name': rule.location.method_name if rule.location else '',
                    'Confidence Score': rule.evidence.confidence_score if rule.evidence else '',
                    'Tags': ', '.join(rule.tags) if rule.tags else ''
                })
        
        generated_files.append(str(csv_file))
        
        # Generate summary statistics CSV
        stats_file = output_path / 'business_rules_statistics.csv'
        with open(stats_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            
            summary = self._generate_summary(business_rules, analysis_results)
            for key, value in summary.items():
                if isinstance(value, (int, float, str)):
                    writer.writerow([key.replace('_', ' ').title(), value])
                elif isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        writer.writerow([f"{key.replace('_', ' ').title()} - {subkey}", subvalue])
        
        generated_files.append(str(stats_file))
        
        return generated_files
    
    def _create_html_overview(self, business_rules: List[BusinessRule], 
                            analysis_results: Dict[str, Any]) -> str:
        """Create HTML overview page."""
        summary = self._generate_summary(business_rules, analysis_results)
        
        html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Business Rules Analysis Overview</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #e8f4fd; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #2c5282; }}
        .rules-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .rules-table th, .rules-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .rules-table th {{ background-color: #f2f2f2; }}
        .complexity-simple {{ background-color: #c6f6d5; }}
        .complexity-moderate {{ background-color: #faf089; }}
        .complexity-complex {{ background-color: #fed7d7; }}
        .complexity-critical {{ background-color: #fc8181; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Business Rules Analysis Overview</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Business Rules Analyzed: <strong>{len(business_rules)}</strong></p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-number">{summary.get('total_rules', 0)}</div>
            <div>Total Rules</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{summary.get('complexity_breakdown', {}).get('COMPLEX', 0) + summary.get('complexity_breakdown', {}).get('CRITICAL', 0)}</div>
            <div>High Complexity</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{summary.get('type_breakdown', {}).get('WORKFLOW', 0)}</div>
            <div>Workflow Rules</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{summary.get('type_breakdown', {}).get('VALIDATION', 0)}</div>
            <div>Validation Rules</div>
        </div>
    </div>
    
    <h2>Rules by Complexity</h2>
    <table class="rules-table">
        <thead>
            <tr>
                <th>Rule Name</th>
                <th>Type</th>
                <th>Complexity</th>
                <th>Business Context</th>
                <th>Source</th>
            </tr>
        </thead>
        <tbody>
'''
        
        for rule in sorted(business_rules, key=lambda r: r.complexity.value if r.complexity else 0, reverse=True)[:20]:
            complexity_class = f"complexity-{rule.complexity.name.lower()}" if rule.complexity else "complexity-simple"
            html += f'''
            <tr class="{complexity_class}">
                <td><strong>{rule.name}</strong></td>
                <td>{rule.rule_type.name if rule.rule_type else 'N/A'}</td>
                <td>{rule.complexity.name if rule.complexity else 'N/A'}</td>
                <td>{rule.business_context or 'N/A'}</td>
                <td>{rule.source.name if rule.source else 'N/A'}</td>
            </tr>
'''
        
        html += '''
        </tbody>
    </table>
    
    <h2>Migration Recommendations</h2>
    <ul>
        <li>Prioritize migration of CRITICAL complexity rules first</li>
        <li>Focus on WORKFLOW rules for GraphQL mutation design</li>
        <li>Convert VALIDATION rules to client-side validators</li>
        <li>Review DATA rules for GraphQL schema design</li>
    </ul>
    
</body>
</html>
'''
        
        return html
    
    def _create_rule_detail_html(self, rule: BusinessRule) -> str:
        """Create detailed HTML page for a single rule."""
        html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Business Rule: {rule.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .rule-header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }}
        .info-section {{ background: #f9f9f9; padding: 15px; border-radius: 5px; }}
        .code-snippet {{ background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .tags {{ margin: 10px 0; }}
        .tag {{ background: #3182ce; color: white; padding: 3px 8px; border-radius: 3px; margin-right: 5px; font-size: 0.8em; }}
    </style>
</head>
<body>
    <div class="rule-header">
        <h1>{rule.name}</h1>
        <p><strong>ID:</strong> {rule.id}</p>
        <p><strong>Description:</strong> {rule.description}</p>
    </div>
    
    <div class="info-grid">
        <div class="info-section">
            <h3>Rule Information</h3>
            <p><strong>Type:</strong> {rule.rule_type.name if rule.rule_type else 'N/A'}</p>
            <p><strong>Source:</strong> {rule.source.name if rule.source else 'N/A'}</p>
            <p><strong>Complexity:</strong> {rule.complexity.name if rule.complexity else 'N/A'}</p>
            <p><strong>Business Context:</strong> {rule.business_context or 'N/A'}</p>
        </div>
        
        <div class="info-section">
            <h3>Location</h3>
            <p><strong>File:</strong> {rule.location.file_path if rule.location else 'N/A'}</p>
            <p><strong>Class:</strong> {rule.location.class_name if rule.location else 'N/A'}</p>
            <p><strong>Method:</strong> {rule.location.method_name if rule.location else 'N/A'}</p>
            <p><strong>Line:</strong> {rule.location.line_number if rule.location else 'N/A'}</p>
        </div>
    </div>
'''
        
        if rule.evidence and rule.evidence.code_snippet:
            html += f'''
    <h3>Code Evidence</h3>
    <div class="code-snippet">
        <pre>{rule.evidence.code_snippet}</pre>
    </div>
    <p><strong>Confidence Score:</strong> {rule.evidence.confidence_score if rule.evidence else 'N/A'}</p>
'''
        
        if rule.tags:
            html += f'''
    <h3>Tags</h3>
    <div class="tags">
'''
            for tag in rule.tags:
                html += f'<span class="tag">{tag}</span>'
            html += '</div>'
        
        html += '''
    
    <h3>Migration Recommendations</h3>
    <ul>
        <li>Review this rule for GraphQL schema design</li>
        <li>Consider Angular component/service implementation</li>
        <li>Evaluate for business logic extraction</li>
    </ul>
    
</body>
</html>
'''
        
        return html
    
    def _create_stakeholder_summary_html(self, business_rules: List[BusinessRule], 
                                       analysis_results: Dict[str, Any]) -> str:
        """Create stakeholder-focused summary."""
        summary = self._generate_summary(business_rules, analysis_results)
        
        # Focus on business impact
        html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Business Stakeholder Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; color: #333; }}
        .executive-summary {{ background: #e8f4fd; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .key-metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .metric-number {{ font-size: 2.5em; font-weight: bold; color: #2c5282; margin-bottom: 10px; }}
        .priority-high {{ border-left: 5px solid #e53e3e; }}
        .priority-medium {{ border-left: 5px solid #d69e2e; }}
        .priority-low {{ border-left: 5px solid #38a169; }}
    </style>
</head>
<body>
    <div class="executive-summary">
        <h1>Executive Summary: Struts to Modern Architecture Migration</h1>
        <p><strong>Project Overview:</strong> Analysis of {len(business_rules)} business rules extracted from legacy Struts application</p>
        <p><strong>Migration Target:</strong> GraphQL backend with Angular frontend</p>
        <p><strong>Analysis Date:</strong> {datetime.now().strftime('%B %d, %Y')}</p>
    </div>
    
    <div class="key-metrics">
        <div class="metric-card priority-high">
            <div class="metric-number">{summary.get('complexity_breakdown', {}).get('CRITICAL', 0)}</div>
            <h3>Critical Priority Rules</h3>
            <p>Require immediate attention and specialized handling during migration</p>
        </div>
        
        <div class="metric-card priority-medium">
            <div class="metric-number">{summary.get('complexity_breakdown', {}).get('COMPLEX', 0)}</div>
            <h3>Complex Rules</h3>
            <p>Need careful planning and may require architectural decisions</p>
        </div>
        
        <div class="metric-card priority-low">
            <div class="metric-number">{summary.get('complexity_breakdown', {}).get('SIMPLE', 0) + summary.get('complexity_breakdown', {}).get('MODERATE', 0)}</div>
            <h3>Standard Rules</h3>
            <p>Can be migrated using standard patterns and approaches</p>
        </div>
    </div>
    
    <h2>Business Impact Assessment</h2>
    <div class="metric-card">
        <h3>Workflow Operations</h3>
        <p><strong>{summary.get('type_breakdown', {}).get('WORKFLOW', 0)} rules</strong> represent core business processes that will become GraphQL mutations</p>
    </div>
    
    <div class="metric-card">
        <h3>Data Management</h3>
        <p><strong>{summary.get('type_breakdown', {}).get('DATA', 0)} rules</strong> define data structures and relationships for GraphQL schema design</p>
    </div>
    
    <div class="metric-card">
        <h3>Business Validation</h3>
        <p><strong>{summary.get('type_breakdown', {}).get('VALIDATION', 0)} rules</strong> contain business constraints that need frontend and backend validation</p>
    </div>
    
    <h2>Migration Recommendations</h2>
    <ul>
        <li><strong>Phase 1:</strong> Start with simple and moderate complexity rules</li>
        <li><strong>Phase 2:</strong> Address complex business workflows with stakeholder validation</li>
        <li><strong>Phase 3:</strong> Handle critical rules with extensive testing and rollback plans</li>
        <li><strong>Timeline:</strong> Estimated 12-16 weeks for complete migration</li>
        <li><strong>Resources:</strong> Recommend dedicated full-stack team with GraphQL and Angular expertise</li>
    </ul>
    
</body>
</html>
'''
        
        return html
    
    def _create_markdown_overview(self, business_rules: List[BusinessRule], 
                                analysis_results: Dict[str, Any]) -> str:
        """Create Markdown overview document."""
        summary = self._generate_summary(business_rules, analysis_results)
        
        markdown = f'''# Business Rules Analysis Overview

*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

## Summary

This document contains the analysis of **{len(business_rules)} business rules** extracted from a Struts application for migration to GraphQL and Angular.

### Key Metrics

- **Total Rules:** {summary.get('total_rules', 0)}
- **Critical Complexity:** {summary.get('complexity_breakdown', {}).get('CRITICAL', 0)}
- **Complex Rules:** {summary.get('complexity_breakdown', {}).get('COMPLEX', 0)}
- **Workflow Rules:** {summary.get('type_breakdown', {}).get('WORKFLOW', 0)}
- **Validation Rules:** {summary.get('type_breakdown', {}).get('VALIDATION', 0)}
- **Data Rules:** {summary.get('type_breakdown', {}).get('DATA', 0)}

### Complexity Breakdown

'''
        
        for complexity, count in summary.get('complexity_breakdown', {}).items():
            percentage = (count / len(business_rules)) * 100 if business_rules else 0
            markdown += f'- **{complexity}:** {count} rules ({percentage:.1f}%)\n'
        
        markdown += f'''

### Rule Types

'''
        
        for rule_type, count in summary.get('type_breakdown', {}).items():
            percentage = (count / len(business_rules)) * 100 if business_rules else 0
            markdown += f'- **{rule_type}:** {count} rules ({percentage:.1f}%)\n'
        
        markdown += f'''

## Migration Strategy

### Phase 1: Foundation (Weeks 1-4)
- Migrate simple and moderate complexity rules
- Establish GraphQL schema foundation
- Set up Angular project structure

### Phase 2: Core Business Logic (Weeks 5-10)
- Implement complex workflow rules
- Develop GraphQL mutations for business processes
- Create Angular services and components

### Phase 3: Advanced Features (Weeks 11-16)
- Handle critical complexity rules
- Implement advanced validation logic
- Performance optimization and testing

## Files Generated

- `README.md` - This overview document
- `BUSINESS_RULES_CATALOG.md` - Detailed catalog of all business rules
- `MIGRATION_GUIDE.md` - Technical migration guidance
- `business_rules.json` - Machine-readable rule data
- `business_rules.csv` - Spreadsheet-compatible rule export

'''
        
        return markdown
    
    def _create_markdown_catalog(self, business_rules: List[BusinessRule]) -> str:
        """Create detailed business rules catalog."""
        markdown = f'''# Business Rules Catalog

*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

This catalog contains detailed information about all {len(business_rules)} business rules identified in the Struts application.

'''
        
        # Group rules by type
        rules_by_type = {}
        for rule in business_rules:
            rule_type = rule.rule_type.name if rule.rule_type else 'UNKNOWN'
            if rule_type not in rules_by_type:
                rules_by_type[rule_type] = []
            rules_by_type[rule_type].append(rule)
        
        for rule_type, type_rules in rules_by_type.items():
            markdown += f'\n## {rule_type} Rules ({len(type_rules)} rules)\n\n'
            
            for rule in sorted(type_rules, key=lambda r: r.complexity.value if r.complexity else 0, reverse=True):
                markdown += f'''### {rule.name}

**ID:** `{rule.id}`  
**Complexity:** {rule.complexity.name if rule.complexity else 'N/A'}  
**Source:** {rule.source.name if rule.source else 'N/A'}  
**Business Context:** {rule.business_context or 'N/A'}  

**Description:** {rule.description}

'''
                
                if rule.location:
                    markdown += f'''**Location:**
- File: `{rule.location.file_path}`
- Class: `{rule.location.class_name or 'N/A'}`
- Method: `{rule.location.method_name or 'N/A'}`

'''
                
                if rule.evidence and rule.evidence.code_snippet:
                    markdown += f'''**Code Evidence:**
```java
{rule.evidence.code_snippet}
```

'''
                
                if rule.tags:
                    markdown += f'''**Tags:** {', '.join(f'`{tag}`' for tag in rule.tags)}

'''
                
                markdown += '---\n\n'
        
        return markdown
    
    def _create_migration_guide_markdown(self, business_rules: List[BusinessRule], 
                                       analysis_results: Dict[str, Any]) -> str:
        """Create technical migration guide."""
        markdown = f'''# Migration Guide: Struts to GraphQL + Angular

*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

## Overview

This guide provides technical recommendations for migrating {len(business_rules)} business rules from a Struts application to a modern GraphQL + Angular architecture.

## Architecture Transition

### Current State (Struts)
- Server-side MVC architecture
- JSP templates for presentation
- Action classes for business logic
- Form beans for data binding
- XML configuration files

### Target State (GraphQL + Angular)
- GraphQL API for backend data access
- Angular SPA for frontend
- Component-based UI architecture
- TypeScript for type safety
- Reactive forms and validation

## GraphQL Schema Design

### Recommended Types

Based on the analysis, consider these GraphQL types:

'''
        
        # Analyze rules for GraphQL schema recommendations
        data_rules = [r for r in business_rules if r.rule_type == BusinessRuleType.DATA]
        workflow_rules = [r for r in business_rules if r.rule_type == BusinessRuleType.WORKFLOW]
        
        # Extract common patterns
        common_entities = {}
        for rule in data_rules:
            # Simple pattern extraction from rule names
            words = rule.name.lower().split()
            for word in words:
                if word in ['user', 'order', 'product', 'customer', 'account']:
                    common_entities[word] = common_entities.get(word, 0) + 1
        
        for entity, count in sorted(common_entities.items(), key=lambda x: x[1], reverse=True)[:5]:
            markdown += f'''#### {entity.title()}Type
```graphql
type {entity.title()} {{
  id: ID!
  # Add fields based on {count} related business rules
  createdAt: DateTime!
  updatedAt: DateTime!
}}
```

'''
        
        markdown += f'''## Angular Architecture

### Recommended Modules

'''
        
        # Group rules by business domain for module recommendations
        domains = {}
        for rule in business_rules:
            domain = self._extract_business_domain_from_name(rule.name)
            domains[domain] = domains.get(domain, 0) + 1
        
        for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:5]:
            markdown += f'''#### {domain.title()}Module
- **Components:** {count // 3 + 1} estimated components
- **Services:** {count // 5 + 1} estimated services
- **Lazy Loading:** {'Recommended' if count > 5 else 'Optional'}

'''
        
        markdown += f'''## Implementation Phases

### Phase 1: Data Layer (2-3 weeks)
1. Design GraphQL schema
2. Implement basic queries and mutations
3. Set up database layer
4. Create GraphQL resolvers

### Phase 2: Business Logic (4-6 weeks)
1. Migrate {len(workflow_rules)} workflow rules to GraphQL mutations
2. Implement business validation logic
3. Create Angular services for business operations
4. Set up error handling and logging

### Phase 3: User Interface (3-4 weeks)
1. Create Angular components
2. Implement reactive forms
3. Add client-side validation
4. Style with Angular Material

### Phase 4: Testing & Optimization (2-3 weeks)
1. Unit testing for all components
2. Integration testing
3. Performance optimization
4. Security review

## Migration Checklist

### GraphQL Backend
- [ ] Schema design complete
- [ ] Resolvers implemented
- [ ] Database integration
- [ ] Authentication/authorization
- [ ] Error handling
- [ ] Logging and monitoring

### Angular Frontend
- [ ] Project structure set up
- [ ] Routing configuration
- [ ] Component library
- [ ] Service layer
- [ ] Form validation
- [ ] State management (if needed)

### Testing
- [ ] Unit tests (80%+ coverage)
- [ ] Integration tests
- [ ] E2E tests
- [ ] Performance testing
- [ ] Security testing

## Best Practices

### GraphQL
- Use DataLoader pattern to avoid N+1 queries
- Implement query complexity analysis
- Cache frequently accessed data
- Use subscriptions for real-time features

### Angular
- Follow Angular style guide
- Use OnPush change detection strategy
- Implement lazy loading for large modules
- Use reactive forms for complex validation

'''
        
        return markdown
    
    def _generate_summary(self, business_rules: List[BusinessRule], 
                        analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis summary."""
        summary = {
            'total_rules': len(business_rules),
            'complexity_breakdown': {},
            'type_breakdown': {},
            'source_breakdown': {},
            'generated_at': datetime.now().isoformat()
        }
        
        # Count by complexity
        for rule in business_rules:
            complexity = rule.complexity.name if rule.complexity else 'UNKNOWN'
            summary['complexity_breakdown'][complexity] = summary['complexity_breakdown'].get(complexity, 0) + 1
        
        # Count by type
        for rule in business_rules:
            rule_type = rule.rule_type.name if rule.rule_type else 'UNKNOWN'
            summary['type_breakdown'][rule_type] = summary['type_breakdown'].get(rule_type, 0) + 1
        
        # Count by source
        for rule in business_rules:
            source = rule.source.name if rule.source else 'UNKNOWN'
            summary['source_breakdown'][source] = summary['source_breakdown'].get(source, 0) + 1
        
        return summary
    
    def _extract_business_domain_from_name(self, name: str) -> str:
        """Extract business domain from rule name."""
        name_lower = name.lower()
        
        if any(word in name_lower for word in ['user', 'customer', 'person', 'account']):
            return 'user'
        elif any(word in name_lower for word in ['order', 'purchase', 'transaction']):
            return 'order'
        elif any(word in name_lower for word in ['product', 'item', 'catalog']):
            return 'product'
        elif any(word in name_lower for word in ['payment', 'billing', 'invoice']):
            return 'payment'
        elif any(word in name_lower for word in ['report', 'analytics', 'metric']):
            return 'reporting'
        else:
            return 'general'
