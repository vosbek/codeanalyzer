#!/usr/bin/env python3
"""
AWS Strands Integration Tools for Struts Legacy Business Rules Analyzer
======================================================================

This module provides AWS Strands tools and integration components for
processing and organizing Struts legacy analysis results.
"""

import json
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
import networkx as nx
from datetime import datetime


@dataclass
class StrandsToolDefinition:
    """Definition for an AWS Strands tool."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    implementation: str
    category: str = "analysis"
    version: str = "1.0.0"


class BusinessRuleExplorerTool:
    """AWS Strands tool for exploring business rules interactively."""
    
    @staticmethod
    def get_tool_definition() -> StrandsToolDefinition:
        """Get the tool definition for AWS Strands."""
        return StrandsToolDefinition(
            name="business_rule_explorer",
            description="Explore and search Struts business rules with advanced filtering and categorization",
            input_schema={
                "type": "object",
                "properties": {
                    "analysis_results": {
                        "type": "object",
                        "description": "Complete analysis results from Struts analyzer"
                    },
                    "filter_criteria": {
                        "type": "object",
                        "properties": {
                            "rule_type": {"type": "string", "enum": ["validation", "workflow", "security", "data", "ui"]},
                            "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                            "source_file": {"type": "string"},
                            "complexity_min": {"type": "integer"},
                            "complexity_max": {"type": "integer"}
                        }
                    },
                    "search_query": {"type": "string", "description": "Text search in rule descriptions"}
                },
                "required": ["analysis_results"]
            },
            output_schema={
                "type": "object",
                "properties": {
                    "filtered_rules": {
                        "type": "array",
                        "items": {"type": "object"}
                    },
                    "summary": {
                        "type": "object",
                        "properties": {
                            "total_found": {"type": "integer"},
                            "by_type": {"type": "object"},
                            "by_risk": {"type": "object"}
                        }
                    }
                }
            },
            implementation="business_rule_explorer_impl"
        )
    
    @staticmethod
    def execute(analysis_results: Dict[str, Any], 
                filter_criteria: Optional[Dict[str, Any]] = None,
                search_query: Optional[str] = None) -> Dict[str, Any]:
        """Execute the business rule explorer tool."""
        
        business_rules = analysis_results.get('business_rules', [])
        filtered_rules = []
        
        for rule in business_rules:
            # Apply filters
            if filter_criteria:
                if 'rule_type' in filter_criteria and rule.get('type') != filter_criteria['rule_type']:
                    continue
                if 'risk_level' in filter_criteria and rule.get('migration_risk') != filter_criteria['risk_level']:
                    continue
                if 'source_file' in filter_criteria and filter_criteria['source_file'] not in rule.get('source_file', ''):
                    continue
                if 'complexity_min' in filter_criteria and rule.get('complexity', 0) < filter_criteria['complexity_min']:
                    continue
                if 'complexity_max' in filter_criteria and rule.get('complexity', 0) > filter_criteria['complexity_max']:
                    continue
            
            # Apply search query
            if search_query:
                search_lower = search_query.lower()
                if not any(search_lower in str(rule.get(field, '')).lower() 
                          for field in ['name', 'description', 'business_context']):
                    continue
            
            filtered_rules.append(rule)
        
        # Generate summary
        summary = {
            'total_found': len(filtered_rules),
            'by_type': {},
            'by_risk': {}
        }
        
        for rule in filtered_rules:
            rule_type = rule.get('type', 'unknown')
            risk_level = rule.get('migration_risk', 'medium')
            
            summary['by_type'][rule_type] = summary['by_type'].get(rule_type, 0) + 1
            summary['by_risk'][risk_level] = summary['by_risk'].get(risk_level, 0) + 1
        
        return {
            'filtered_rules': filtered_rules,
            'summary': summary
        }


class DependencyVisualizerTool:
    """AWS Strands tool for visualizing dependencies and relationships."""
    
    @staticmethod
    def get_tool_definition() -> StrandsToolDefinition:
        """Get the tool definition for AWS Strands."""
        return StrandsToolDefinition(
            name="dependency_visualizer",
            description="Create interactive dependency graphs and flow diagrams for Struts applications",
            input_schema={
                "type": "object",
                "properties": {
                    "analysis_results": {
                        "type": "object",
                        "description": "Complete analysis results from Struts analyzer"
                    },
                    "visualization_type": {
                        "type": "string",
                        "enum": ["action_flow", "dependency_graph", "user_journey", "risk_heatmap"]
                    },
                    "filter_options": {
                        "type": "object",
                        "properties": {
                            "max_nodes": {"type": "integer", "default": 50},
                            "min_complexity": {"type": "integer", "default": 1},
                            "include_jsp": {"type": "boolean", "default": true}
                        }
                    }
                },
                "required": ["analysis_results", "visualization_type"]
            },
            output_schema={
                "type": "object",
                "properties": {
                    "graph_data": {
                        "type": "object",
                        "properties": {
                            "nodes": {"type": "array"},
                            "edges": {"type": "array"},
                            "layout": {"type": "object"}
                        }
                    },
                    "insights": {
                        "type": "object",
                        "properties": {
                            "complexity_hotspots": {"type": "array"},
                            "dependency_cycles": {"type": "array"},
                            "isolated_components": {"type": "array"}
                        }
                    }
                }
            },
            implementation="dependency_visualizer_impl"
        )
    
    @staticmethod
    def execute(analysis_results: Dict[str, Any],
                visualization_type: str,
                filter_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute the dependency visualizer tool."""
        
        if not filter_options:
            filter_options = {}
        
        max_nodes = filter_options.get('max_nodes', 50)
        min_complexity = filter_options.get('min_complexity', 1)
        
        if visualization_type == "action_flow":
            return DependencyVisualizerTool._create_action_flow_graph(analysis_results, max_nodes)
        elif visualization_type == "dependency_graph":
            return DependencyVisualizerTool._create_dependency_graph(analysis_results, max_nodes)
        elif visualization_type == "user_journey":
            return DependencyVisualizerTool._create_user_journey_graph(analysis_results)
        elif visualization_type == "risk_heatmap":
            return DependencyVisualizerTool._create_risk_heatmap(analysis_results, min_complexity)
        else:
            raise ValueError(f"Unknown visualization type: {visualization_type}")
    
    @staticmethod
    def _create_action_flow_graph(analysis_results: Dict[str, Any], max_nodes: int) -> Dict[str, Any]:
        """Create action flow visualization data."""
        actions = analysis_results.get('action_mappings', [])[:max_nodes]
        
        nodes = []
        edges = []
        
        for action in actions:
            # Create action node
            node = {
                'id': action['path'],
                'label': action['path'].split('/')[-1],
                'type': 'action',
                'business_purpose': action.get('business_purpose', ''),
                'complexity': len(action.get('forwards', {})) + len(action.get('exceptions', {})),
                'risk_level': 'medium'  # Could be calculated based on complexity
            }
            nodes.append(node)
            
            # Create forward edges
            for forward_name, forward_path in action.get('forwards', {}).items():
                edge = {
                    'source': action['path'],
                    'target': forward_path,
                    'label': forward_name,
                    'type': 'forward'
                }
                edges.append(edge)
        
        # Identify complexity hotspots
        complexity_hotspots = sorted(
            [{'node': n['id'], 'complexity': n['complexity']} for n in nodes],
            key=lambda x: x['complexity'],
            reverse=True
        )[:5]
        
        return {
            'graph_data': {
                'nodes': nodes,
                'edges': edges,
                'layout': {'type': 'hierarchical', 'direction': 'top-bottom'}
            },
            'insights': {
                'complexity_hotspots': complexity_hotspots,
                'dependency_cycles': [],
                'isolated_components': []
            }
        }
    
    @staticmethod
    def _create_dependency_graph(analysis_results: Dict[str, Any], max_nodes: int) -> Dict[str, Any]:
        """Create dependency graph visualization data."""
        dependencies = analysis_results.get('dependencies', {})
        nodes_data = dependencies.get('nodes', [])[:max_nodes]
        edges_data = dependencies.get('edges', [])
        
        nodes = []
        edges = []
        
        # Convert to visualization format
        for node_id, node_attrs in nodes_data:
            node = {
                'id': node_id,
                'label': node_id.split('/')[-1] if '/' in node_id else node_id,
                'type': node_attrs.get('type', 'component'),
                'data': node_attrs.get('data', {})
            }
            nodes.append(node)
        
        for source, target, edge_attrs in edges_data:
            edge = {
                'source': source,
                'target': target,
                'type': edge_attrs.get('type', 'dependency'),
                'label': edge_attrs.get('name', '')
            }
            edges.append(edge)
        
        # Detect cycles
        cycles = dependencies.get('cycles', [])
        
        return {
            'graph_data': {
                'nodes': nodes,
                'edges': edges,
                'layout': {'type': 'force-directed'}
            },
            'insights': {
                'complexity_hotspots': [],
                'dependency_cycles': cycles,
                'isolated_components': []
            }
        }
    
    @staticmethod
    def _create_user_journey_graph(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create user journey visualization data."""
        actions = analysis_results.get('action_mappings', [])
        
        # Group actions by business purpose
        journeys = {}
        for action in actions:
            purpose = action.get('business_purpose', 'General')
            if purpose not in journeys:
                journeys[purpose] = []
            journeys[purpose].append(action)
        
        nodes = []
        edges = []
        
        for purpose, purpose_actions in journeys.items():
            # Create journey start node
            start_node = {
                'id': f"start_{purpose}",
                'label': f"Start: {purpose}",
                'type': 'journey_start',
                'business_purpose': purpose
            }
            nodes.append(start_node)
            
            # Add action nodes for this journey
            for action in purpose_actions:
                node = {
                    'id': action['path'],
                    'label': action['path'].split('/')[-1],
                    'type': 'action',
                    'business_purpose': purpose
                }
                nodes.append(node)
                
                # Connect to start
                edge = {
                    'source': start_node['id'],
                    'target': action['path'],
                    'type': 'journey_flow'
                }
                edges.append(edge)
        
        return {
            'graph_data': {
                'nodes': nodes,
                'edges': edges,
                'layout': {'type': 'hierarchical', 'direction': 'left-right'}
            },
            'insights': {
                'complexity_hotspots': [],
                'dependency_cycles': [],
                'isolated_components': []
            }
        }
    
    @staticmethod
    def _create_risk_heatmap(analysis_results: Dict[str, Any], min_complexity: int) -> Dict[str, Any]:
        """Create risk heatmap visualization data."""
        assessments = analysis_results.get('migration_assessment', [])
        
        nodes = []
        for assessment in assessments:
            if assessment.get('complexity_score', 0) >= min_complexity:
                node = {
                    'id': assessment['component_name'],
                    'label': assessment['component_name'].split('/')[-1],
                    'type': 'component',
                    'risk_level': assessment['risk_level'],
                    'complexity': assessment['complexity_score'],
                    'effort': assessment.get('migration_effort', 'Unknown')
                }
                nodes.append(node)
        
        # Sort by risk and complexity
        risk_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        hotspots = sorted(
            nodes,
            key=lambda x: (risk_order.get(x['risk_level'], 0), x['complexity']),
            reverse=True
        )[:10]
        
        return {
            'graph_data': {
                'nodes': nodes,
                'edges': [],
                'layout': {'type': 'grid'}
            },
            'insights': {
                'complexity_hotspots': hotspots,
                'dependency_cycles': [],
                'isolated_components': []
            }
        }


class MigrationPlannerTool:
    """AWS Strands tool for generating migration plans and recommendations."""
    
    @staticmethod
    def get_tool_definition() -> StrandsToolDefinition:
        """Get the tool definition for AWS Strands."""
        return StrandsToolDefinition(
            name="migration_planner",
            description="Generate detailed migration plans and recommendations for Struts to GraphQL/Angular transition",
            input_schema={
                "type": "object",
                "properties": {
                    "analysis_results": {
                        "type": "object",
                        "description": "Complete analysis results from Struts analyzer"
                    },
                    "migration_preferences": {
                        "type": "object",
                        "properties": {
                            "approach": {"type": "string", "enum": ["big_bang", "incremental", "strangler_fig"]},
                            "team_size": {"type": "integer"},
                            "timeline_weeks": {"type": "integer"},
                            "risk_tolerance": {"type": "string", "enum": ["low", "medium", "high"]},
                            "preserve_ui": {"type": "boolean", "default": false}
                        }
                    },
                    "constraints": {
                        "type": "object",
                        "properties": {
                            "budget": {"type": "number"},
                            "downtime_tolerance": {"type": "string"},
                            "business_priorities": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                },
                "required": ["analysis_results"]
            },
            output_schema={
                "type": "object",
                "properties": {
                    "migration_plan": {
                        "type": "object",
                        "properties": {
                            "phases": {"type": "array"},
                            "timeline": {"type": "object"},
                            "resource_requirements": {"type": "object"}
                        }
                    },
                    "recommendations": {"type": "array"},
                    "risk_mitigation": {"type": "array"}
                }
            },
            implementation="migration_planner_impl"
        )
    
    @staticmethod
    def execute(analysis_results: Dict[str, Any],
                migration_preferences: Optional[Dict[str, Any]] = None,
                constraints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute the migration planner tool."""
        
        if not migration_preferences:
            migration_preferences = {'approach': 'incremental', 'risk_tolerance': 'medium'}
        
        assessments = analysis_results.get('migration_assessment', [])
        summary = analysis_results.get('summary', {})
        
        # Generate migration phases
        phases = MigrationPlannerTool._generate_migration_phases(assessments, migration_preferences)
        
        # Generate timeline
        timeline = MigrationPlannerTool._calculate_timeline(phases, migration_preferences)
        
        # Generate resource requirements
        resources = MigrationPlannerTool._calculate_resources(assessments, migration_preferences)
        
        # Generate recommendations
        recommendations = MigrationPlannerTool._generate_recommendations(
            analysis_results, migration_preferences, constraints)
        
        # Generate risk mitigation strategies
        risk_mitigation = MigrationPlannerTool._generate_risk_mitigation(assessments)
        
        return {
            'migration_plan': {
                'phases': phases,
                'timeline': timeline,
                'resource_requirements': resources
            },
            'recommendations': recommendations,
            'risk_mitigation': risk_mitigation
        }
    
    @staticmethod
    def _generate_migration_phases(assessments: List[Dict[str, Any]], 
                                 preferences: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate migration phases based on risk and complexity."""
        approach = preferences.get('approach', 'incremental')
        
        if approach == 'big_bang':
            return [{
                'name': 'Complete Migration',
                'description': 'Migrate entire application at once',
                'components': [a['component_name'] for a in assessments],
                'duration_weeks': preferences.get('timeline_weeks', 12),
                'risk_level': 'high'
            }]
        
        # Group by risk level for incremental approach
        phases = []
        risk_groups = {'low': [], 'medium': [], 'high': [], 'critical': []}
        
        for assessment in assessments:
            risk_level = assessment.get('risk_level', 'medium')
            risk_groups[risk_level].append(assessment)
        
        # Phase 1: Low risk components (foundation)
        if risk_groups['low']:
            phases.append({
                'name': 'Foundation Phase',
                'description': 'Migrate low-risk components to establish patterns',
                'components': [a['component_name'] for a in risk_groups['low']],
                'duration_weeks': max(2, len(risk_groups['low']) // 5),
                'risk_level': 'low',
                'objectives': [
                    'Establish GraphQL schema patterns',
                    'Set up Angular component structure',
                    'Validate migration tooling'
                ]
            })
        
        # Phase 2: Medium risk components (main functionality)
        if risk_groups['medium']:
            phases.append({
                'name': 'Core Migration Phase',
                'description': 'Migrate core business functionality',
                'components': [a['component_name'] for a in risk_groups['medium']],
                'duration_weeks': max(4, len(risk_groups['medium']) // 3),
                'risk_level': 'medium',
                'objectives': [
                    'Migrate main business workflows',
                    'Implement validation patterns',
                    'Establish testing patterns'
                ]
            })
        
        # Phase 3: High risk components (complex features)
        if risk_groups['high']:
            phases.append({
                'name': 'Complex Features Phase',
                'description': 'Migrate high-complexity components',
                'components': [a['component_name'] for a in risk_groups['high']],
                'duration_weeks': max(3, len(risk_groups['high']) // 2),
                'risk_level': 'high',
                'objectives': [
                    'Refactor complex business logic',
                    'Implement advanced UI patterns',
                    'Performance optimization'
                ]
            })
        
        # Phase 4: Critical components (requires specialist attention)
        if risk_groups['critical']:
            phases.append({
                'name': 'Critical Components Phase',
                'description': 'Migrate critical/legacy components with expert support',
                'components': [a['component_name'] for a in risk_groups['critical']],
                'duration_weeks': max(4, len(risk_groups['critical']) * 2),
                'risk_level': 'critical',
                'objectives': [
                    'Specialist review and design',
                    'Comprehensive testing strategy',
                    'Rollback planning'
                ]
            })
        
        return phases
    
    @staticmethod
    def _calculate_timeline(phases: List[Dict[str, Any]], 
                          preferences: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate migration timeline."""
        total_weeks = sum(phase['duration_weeks'] for phase in phases)
        
        # Add buffer based on risk tolerance
        risk_tolerance = preferences.get('risk_tolerance', 'medium')
        buffers = {'low': 0.3, 'medium': 0.2, 'high': 0.1}
        buffer_weeks = int(total_weeks * buffers[risk_tolerance])
        
        return {
            'total_duration_weeks': total_weeks + buffer_weeks,
            'phases_duration': total_weeks,
            'buffer_weeks': buffer_weeks,
            'estimated_start': datetime.now().strftime('%Y-%m-%d'),
            'critical_path': [phase['name'] for phase in phases if phase['risk_level'] in ['high', 'critical']]
        }
    
    @staticmethod
    def _calculate_resources(assessments: List[Dict[str, Any]], 
                           preferences: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate resource requirements."""
        total_complexity = sum(a.get('complexity_score', 0) for a in assessments)
        team_size = preferences.get('team_size', 4)
        
        # Estimate effort in person-weeks
        effort_multipliers = {
            'low': 0.5,
            'medium': 1.0,
            'high': 2.0,
            'critical': 3.0
        }
        
        total_effort = 0
        for assessment in assessments:
            risk_level = assessment.get('risk_level', 'medium')
            complexity = assessment.get('complexity_score', 1)
            total_effort += complexity * effort_multipliers[risk_level]
        
        return {
            'estimated_person_weeks': total_effort,
            'recommended_team_size': max(team_size, total_effort // 20),  # Adjust based on effort
            'skill_requirements': [
                'GraphQL/Apollo expertise',
                'Angular/TypeScript development',
                'Legacy Struts knowledge',
                'Database migration experience',
                'DevOps/CI-CD setup'
            ],
            'external_dependencies': [
                'Database schema updates',
                'Infrastructure provisioning',
                'Third-party integrations',
                'Security review and testing'
            ]
        }
    
    @staticmethod
    def _generate_recommendations(analysis_results: Dict[str, Any],
                                preferences: Dict[str, Any],
                                constraints: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate migration recommendations."""
        recommendations = []
        
        summary = analysis_results.get('summary', {})
        total_actions = summary.get('total_actions', 0)
        total_rules = summary.get('total_business_rules', 0)
        
        # Architecture recommendations
        if total_actions > 50:
            recommendations.append({
                'category': 'Architecture',
                'priority': 'high',
                'title': 'Implement Modular GraphQL Schema',
                'description': 'With 50+ actions, consider splitting GraphQL schema into modules by business domain',
                'effort': 'medium',
                'benefits': ['Better maintainability', 'Team scalability', 'Reduced coupling']
            })
        
        # Testing recommendations
        if total_rules > 20:
            recommendations.append({
                'category': 'Testing',
                'priority': 'high',
                'title': 'Comprehensive Business Rule Testing',
                'description': 'Create automated tests for all identified business rules to ensure preservation',
                'effort': 'high',
                'benefits': ['Rule preservation', 'Regression prevention', 'Documentation']
            })
        
        # Team recommendations
        team_size = preferences.get('team_size', 4)
        if team_size < 3:
            recommendations.append({
                'category': 'Team',
                'priority': 'medium',
                'title': 'Consider Team Expansion',
                'description': 'Small teams may struggle with large legacy migrations',
                'effort': 'organizational',
                'benefits': ['Faster delivery', 'Knowledge distribution', 'Risk reduction']
            })
        
        return recommendations
    
    @staticmethod
    def _generate_risk_mitigation(assessments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate risk mitigation strategies."""
        risk_mitigation = []
        
        critical_components = [a for a in assessments if a.get('risk_level') == 'critical']
        high_risk_components = [a for a in assessments if a.get('risk_level') == 'high']
        
        if critical_components:
            risk_mitigation.append({
                'risk': 'Critical Component Migration Failure',
                'probability': 'medium',
                'impact': 'high',
                'mitigation_strategies': [
                    'Prototype critical components first',
                    'Engage Struts specialists for review',
                    'Implement comprehensive rollback procedures',
                    'Create detailed business rule documentation'
                ],
                'contingency_plan': 'Maintain parallel Struts system for critical functions'
            })
        
        if len(high_risk_components) > 5:
            risk_mitigation.append({
                'risk': 'Timeline Overrun Due to Complexity',
                'probability': 'high',
                'impact': 'medium',
                'mitigation_strategies': [
                    'Add 30% buffer to timeline estimates',
                    'Implement incremental delivery',
                    'Regular checkpoint reviews',
                    'Scope reduction planning'
                ],
                'contingency_plan': 'Defer non-critical high-risk components to future release'
            })
        
        return risk_mitigation


class StrandsIntegrationManager:
    """Main manager for AWS Strands integration."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.tools = {
            'business_rule_explorer': BusinessRuleExplorerTool(),
            'dependency_visualizer': DependencyVisualizerTool(),
            'migration_planner': MigrationPlannerTool()
        }
        self.config = self._load_config(config_path)
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load AWS Strands configuration."""
        default_config = {
            'aws': {
                'region': 'us-east-1',
                'profile': 'default'
            },
            'strands': {
                'enabled': True,
                'deployment_bucket': '',
                'tool_version': '1.0.0'
            }
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                user_config = yaml.safe_load(f)
            default_config.update(user_config)
        
        return default_config
    
    def get_all_tool_definitions(self) -> List[StrandsToolDefinition]:
        """Get all AWS Strands tool definitions."""
        definitions = []
        for tool_name, tool_instance in self.tools.items():
            definition = tool_instance.get_tool_definition()
            definitions.append(definition)
        return definitions
    
    def execute_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Execute a specific AWS Strands tool."""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool = self.tools[tool_name]
        return tool.execute(**kwargs)
    
    def generate_strands_manifest(self, output_path: Path) -> None:
        """Generate AWS Strands deployment manifest."""
        manifest = {
            'version': '1.0.0',
            'name': 'struts-legacy-analyzer-tools',
            'description': 'AWS Strands tools for Struts legacy business rules analysis',
            'author': 'Claude Code Assistant',
            'created': datetime.now().isoformat(),
            'tools': []
        }
        
        for definition in self.get_all_tool_definitions():
            manifest['tools'].append(asdict(definition))
        
        with open(output_path, 'w') as f:
            json.dump(manifest, f, indent=2)
    
    def generate_deployment_scripts(self, output_dir: Path) -> None:
        """Generate AWS deployment scripts for Strands tools."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate CloudFormation template
        cf_template = {
            'AWSTemplateFormatVersion': '2010-09-09',
            'Description': 'AWS Strands tools for Struts legacy analysis',
            'Resources': {
                'StrandsToolsBucket': {
                    'Type': 'AWS::S3::Bucket',
                    'Properties': {
                        'BucketName': {'Ref': 'AWS::StackName'},
                        'VersioningConfiguration': {'Status': 'Enabled'}
                    }
                },
                'StrandsExecutionRole': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'AssumeRolePolicyDocument': {
                            'Version': '2012-10-17',
                            'Statement': [{
                                'Effect': 'Allow',
                                'Principal': {'Service': 'lambda.amazonaws.com'},
                                'Action': 'sts:AssumeRole'
                            }]
                        },
                        'ManagedPolicyArns': [
                            'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
                        ]
                    }
                }
            },
            'Outputs': {
                'ToolsBucket': {
                    'Description': 'S3 bucket for Strands tools storage',
                    'Value': {'Ref': 'StrandsToolsBucket'}
                }
            }
        }
        
        with open(output_dir / 'strands-tools-infrastructure.yaml', 'w') as f:
            yaml.dump(cf_template, f, default_flow_style=False)
        
        # Generate deployment script
        deploy_script = '''#!/bin/bash
# AWS Strands Tools Deployment Script

set -e

echo "Deploying Struts Legacy Analyzer AWS Strands Tools..."

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "AWS CLI not found. Please install AWS CLI first."
    exit 1
fi

# Deploy infrastructure
echo "Deploying infrastructure..."
aws cloudformation deploy \\
    --template-file strands-tools-infrastructure.yaml \\
    --stack-name struts-analyzer-strands-tools \\
    --capabilities CAPABILITY_IAM \\
    --region ${AWS_REGION:-us-east-1}

# Get bucket name
BUCKET_NAME=$(aws cloudformation describe-stacks \\
    --stack-name struts-analyzer-strands-tools \\
    --query 'Stacks[0].Outputs[?OutputKey==`ToolsBucket`].OutputValue' \\
    --output text \\
    --region ${AWS_REGION:-us-east-1})

echo "Tools bucket: $BUCKET_NAME"

# Upload tool definitions
echo "Uploading tool definitions..."
aws s3 cp strands-tools-manifest.json s3://$BUCKET_NAME/manifest.json
aws s3 cp ../aws_strands_tools.py s3://$BUCKET_NAME/tools/

echo "Deployment complete!"
echo "Bucket: $BUCKET_NAME"
'''
        
        with open(output_dir / 'deploy.sh', 'w') as f:
            f.write(deploy_script)
        
        # Make script executable
        os.chmod(output_dir / 'deploy.sh', 0o755)


def main():
    """Main function for AWS Strands tools generation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate AWS Strands integration tools')
    parser.add_argument('--output-dir', default='./aws_strands_output', 
                       help='Output directory for generated files')
    parser.add_argument('--config', help='Configuration file path')
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    
    # Initialize manager
    manager = StrandsIntegrationManager(args.config)
    
    # Generate manifest
    manager.generate_strands_manifest(output_dir / 'strands-tools-manifest.json')
    
    # Generate deployment scripts
    manager.generate_deployment_scripts(output_dir / 'deployment')
    
    print(f"AWS Strands tools generated in: {output_dir}")
    print(f"Tools available: {list(manager.tools.keys())}")


if __name__ == '__main__':
    main()