"""
Migration Strategy Plugins
==========================

This module contains plugins that generate migration recommendations and
estimate effort for converting Struts applications to modern architectures
like GraphQL and Angular.

Plugins included:
- GraphQL migration strategy and recommendations
- Angular frontend migration planning
- Database modernization recommendations
- API design suggestions

Author: Claude Code Assistant
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

from plugins.base_plugin import MigrationPlugin, PluginResult, PluginMetadata, PluginType
from models.business_rule import (
    BusinessRule, BusinessRuleType, BusinessRuleSource,
    BusinessRuleComplexity
)


class GraphQLMigrationPlugin(MigrationPlugin):
    """Plugin for generating GraphQL migration recommendations."""
    
    def _get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="GraphQLMigrationPlugin",
            version="1.0.0",
            description="Generates GraphQL migration strategies and recommendations",
            author="Claude Code Assistant",
            plugin_type=PluginType.MIGRATION,
            supported_file_types=set(),  # Works with business rules, not files
            configuration_schema={
                'target_graphql_version': {
                    'type': 'string',
                    'default': 'latest',
                    'description': 'Target GraphQL version for migration'
                },
                'include_subscriptions': {
                    'type': 'boolean',
                    'default': True,
                    'description': 'Include GraphQL subscription recommendations'
                },
                'complexity_threshold': {
                    'type': 'string',
                    'default': 'MODERATE',
                    'description': 'Minimum complexity for detailed migration planning'
                }
            }
        )
    
    def can_handle(self, context: Dict[str, Any]) -> bool:
        """Check if GraphQL migration is applicable."""
        # Always applicable for Struts applications
        return True
    
    def execute(self, context: Dict[str, Any]) -> PluginResult:
        """Execute GraphQL migration analysis."""
        business_rules = context.get('business_rules', [])
        return self.generate_migration_recommendations(business_rules, context)
    
    def generate_migration_recommendations(self, 
                                         business_rules: List[BusinessRule],
                                         context: Dict[str, Any]) -> PluginResult:
        """Generate GraphQL migration recommendations."""
        start_time = datetime.now()
        result = PluginResult(
            plugin_name=self.metadata.name,
            success=True,
            execution_time_ms=0
        )
        
        try:
            # Analyze business rules for GraphQL patterns
            graphql_analysis = self._analyze_for_graphql_patterns(business_rules)
            result.add_extracted_data('graphql_analysis', graphql_analysis)
            
            # Generate schema recommendations
            schema_recommendations = self._generate_schema_recommendations(business_rules)
            result.add_extracted_data('schema_recommendations', schema_recommendations)
            
            # Generate resolver recommendations
            resolver_recommendations = self._generate_resolver_recommendations(business_rules)
            result.add_extracted_data('resolver_recommendations', resolver_recommendations)
            
            # Generate migration recommendations
            for recommendation in self._generate_general_recommendations(business_rules):
                result.add_recommendation(recommendation)
            
            # Calculate execution time
            end_time = datetime.now()
            result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
        except Exception as e:
            result.add_error(f"GraphQL migration analysis failed: {e}")
        
        return result
    
    def estimate_migration_effort(self, business_rules: List[BusinessRule]) -> Dict[str, Any]:
        """Estimate effort for GraphQL migration."""
        effort_estimate = {
            'total_story_points': 0,
            'estimated_weeks': 0,
            'complexity_breakdown': defaultdict(int),
            'effort_by_type': defaultdict(int),
            'recommendations': []
        }
        
        # Categorize rules by type and complexity
        for rule in business_rules:
            rule_type = rule.rule_type.name if rule.rule_type else 'UNKNOWN'
            complexity = rule.complexity.name if rule.complexity else 'MODERATE'
            
            effort_estimate['complexity_breakdown'][complexity] += 1
            effort_estimate['effort_by_type'][rule_type] += 1
        
        # Calculate story points based on complexity
        complexity_points = {
            'SIMPLE': 2,
            'MODERATE': 5,
            'COMPLEX': 8,
            'CRITICAL': 13
        }
        
        total_points = 0
        for complexity, count in effort_estimate['complexity_breakdown'].items():
            points = complexity_points.get(complexity, 5) * count
            total_points += points
        
        effort_estimate['total_story_points'] = total_points
        effort_estimate['estimated_weeks'] = max(1, total_points // 10)  # Assuming 10 story points per week
        
        # Add specific recommendations
        if effort_estimate['effort_by_type']['WORKFLOW'] > 5:
            effort_estimate['recommendations'].append(
                "Consider implementing GraphQL mutations with complex input types for workflow operations"
            )
        
        if effort_estimate['effort_by_type']['DATA'] > 10:
            effort_estimate['recommendations'].append(
                "Implement GraphQL schema federation for complex data relationships"
            )
        
        if effort_estimate['complexity_breakdown']['CRITICAL'] > 0:
            effort_estimate['recommendations'].append(
                "Plan phased migration for critical business rules with extensive testing"
            )
        
        return effort_estimate
    
    def _analyze_for_graphql_patterns(self, business_rules: List[BusinessRule]) -> Dict[str, Any]:
        """Analyze business rules for GraphQL migration patterns."""
        analysis = {
            'query_candidates': [],
            'mutation_candidates': [],
            'subscription_candidates': [],
            'custom_scalar_needs': [],
            'federation_opportunities': []
        }
        
        for rule in business_rules:
            rule_type = rule.rule_type
            
            if rule_type == BusinessRuleType.DATA:
                # Data rules typically become queries
                analysis['query_candidates'].append({
                    'rule_id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'complexity': rule.complexity.name if rule.complexity else 'MODERATE',
                    'suggested_query_name': self._suggest_query_name(rule.name)
                })
                
            elif rule_type == BusinessRuleType.WORKFLOW:
                # Workflow rules typically become mutations
                analysis['mutation_candidates'].append({
                    'rule_id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'complexity': rule.complexity.name if rule.complexity else 'MODERATE',
                    'suggested_mutation_name': self._suggest_mutation_name(rule.name)
                })
                
            elif rule_type == BusinessRuleType.BUSINESS_LOGIC:
                # Business logic might need custom resolvers
                if any(keyword in rule.description.lower() for keyword in ['real-time', 'notification', 'event']):
                    analysis['subscription_candidates'].append({
                        'rule_id': rule.id,
                        'name': rule.name,
                        'description': rule.description,
                        'suggested_subscription_name': self._suggest_subscription_name(rule.name)
                    })
            
            # Check for custom scalar opportunities
            if any(keyword in rule.description.lower() for keyword in ['date', 'time', 'currency', 'email', 'phone']):
                analysis['custom_scalar_needs'].append({
                    'rule_id': rule.id,
                    'suggested_scalar': self._suggest_custom_scalar(rule.description)
                })
        
        return analysis
    
    def _generate_schema_recommendations(self, business_rules: List[BusinessRule]) -> List[Dict[str, Any]]:
        """Generate GraphQL schema design recommendations."""
        recommendations = []
        
        # Group rules by business domain
        domains = defaultdict(list)
        for rule in business_rules:
            domain = self._extract_business_domain(rule)
            domains[domain].append(rule)
        
        # Generate type recommendations for each domain
        for domain, domain_rules in domains.items():
            type_recommendation = {
                'domain': domain,
                'suggested_types': [],
                'queries': [],
                'mutations': [],
                'interfaces': []
            }
            
            # Analyze rules in this domain
            data_rules = [r for r in domain_rules if r.rule_type == BusinessRuleType.DATA]
            workflow_rules = [r for r in domain_rules if r.rule_type == BusinessRuleType.WORKFLOW]
            
            if data_rules:
                type_recommendation['suggested_types'].append({
                    'name': f"{domain.title()}Type",
                    'description': f"GraphQL type for {domain} data",
                    'based_on_rules': [r.id for r in data_rules[:3]]  # Limit for readability
                })
                
                type_recommendation['queries'].append({
                    'name': f"get{domain.title()}",
                    'description': f"Query to retrieve {domain} data",
                    'return_type': f"{domain.title()}Type"
                })
            
            if workflow_rules:
                type_recommendation['mutations'].append({
                    'name': f"process{domain.title()}",
                    'description': f"Mutation to process {domain} workflows",
                    'return_type': f"{domain.title()}Result"
                })
            
            recommendations.append(type_recommendation)
        
        return recommendations
    
    def _generate_resolver_recommendations(self, business_rules: List[BusinessRule]) -> List[Dict[str, Any]]:
        """Generate GraphQL resolver implementation recommendations."""
        recommendations = []
        
        for rule in business_rules:
            if rule.complexity == BusinessRuleComplexity.COMPLEX or rule.complexity == BusinessRuleComplexity.CRITICAL:
                resolver_rec = {
                    'rule_id': rule.id,
                    'resolver_name': self._suggest_resolver_name(rule.name),
                    'complexity': rule.complexity.name,
                    'implementation_notes': self._generate_resolver_implementation_notes(rule),
                    'performance_considerations': self._generate_performance_considerations(rule),
                    'testing_strategy': self._generate_testing_strategy(rule)
                }
                
                recommendations.append(resolver_rec)
        
        return recommendations
    
    def _generate_general_recommendations(self, business_rules: List[BusinessRule]) -> List[str]:
        """Generate general GraphQL migration recommendations."""
        recommendations = []
        
        total_rules = len(business_rules)
        complex_rules = len([r for r in business_rules if r.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL]])
        
        if total_rules > 50:
            recommendations.append(
                "Consider implementing GraphQL schema federation to manage the large number of business rules across multiple services"
            )
        
        if complex_rules > 10:
            recommendations.append(
                "Implement comprehensive caching strategy for complex resolvers to maintain performance"
            )
        
        # Check for validation rules
        validation_rules = [r for r in business_rules if r.rule_type == BusinessRuleType.VALIDATION]
        if validation_rules:
            recommendations.append(
                f"Implement {len(validation_rules)} validation rules as GraphQL input validators or custom scalars"
            )
        
        # Check for workflow rules
        workflow_rules = [r for r in business_rules if r.rule_type == BusinessRuleType.WORKFLOW]
        if workflow_rules:
            recommendations.append(
                f"Design {len(workflow_rules)} workflow operations as GraphQL mutations with proper error handling"
            )
        
        return recommendations
    
    def _suggest_query_name(self, rule_name: str) -> str:
        """Suggest GraphQL query name based on rule name."""
        # Convert rule name to camelCase query name
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        if words:
            return words[0] + ''.join(word.capitalize() for word in words[1:])
        return "getData"
    
    def _suggest_mutation_name(self, rule_name: str) -> str:
        """Suggest GraphQL mutation name based on rule name."""
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        if words and any(action in words[0] for action in ['create', 'update', 'delete', 'process']):
            return words[0] + ''.join(word.capitalize() for word in words[1:])
        return f"process{''.join(word.capitalize() for word in words)}"
    
    def _suggest_subscription_name(self, rule_name: str) -> str:
        """Suggest GraphQL subscription name based on rule name."""
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        return f"on{''.join(word.capitalize() for word in words)}Updated"
    
    def _suggest_custom_scalar(self, description: str) -> str:
        """Suggest custom scalar type based on rule description."""
        desc_lower = description.lower()
        if 'date' in desc_lower:
            return 'Date'
        elif 'time' in desc_lower:
            return 'DateTime'
        elif 'currency' in desc_lower or 'money' in desc_lower:
            return 'Currency'
        elif 'email' in desc_lower:
            return 'EmailAddress'
        elif 'phone' in desc_lower:
            return 'PhoneNumber'
        else:
            return 'CustomScalar'
    
    def _extract_business_domain(self, rule: BusinessRule) -> str:
        """Extract business domain from rule."""
        name_lower = rule.name.lower()
        
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
    
    def _suggest_resolver_name(self, rule_name: str) -> str:
        """Suggest resolver function name."""
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        return 'resolve' + ''.join(word.capitalize() for word in words)
    
    def _generate_resolver_implementation_notes(self, rule: BusinessRule) -> List[str]:
        """Generate implementation notes for complex resolvers."""
        notes = []
        
        if rule.complexity == BusinessRuleComplexity.CRITICAL:
            notes.append("Implement with careful error handling and logging")
            notes.append("Consider implementing circuit breaker pattern")
        
        if rule.rule_type == BusinessRuleType.WORKFLOW:
            notes.append("May require orchestration of multiple service calls")
            notes.append("Consider implementing as async resolver")
        
        if 'validation' in rule.description.lower():
            notes.append("Implement input validation before processing")
        
        return notes
    
    def _generate_performance_considerations(self, rule: BusinessRule) -> List[str]:
        """Generate performance considerations."""
        considerations = []
        
        if rule.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL]:
            considerations.append("Implement DataLoader pattern to avoid N+1 queries")
            considerations.append("Consider implementing query complexity analysis")
        
        if rule.rule_type == BusinessRuleType.DATA:
            considerations.append("Implement field-level caching where appropriate")
        
        return considerations
    
    def _generate_testing_strategy(self, rule: BusinessRule) -> List[str]:
        """Generate testing strategy recommendations."""
        strategy = []
        
        strategy.append("Unit tests for resolver logic")
        strategy.append("Integration tests with GraphQL schema")
        
        if rule.complexity == BusinessRuleComplexity.CRITICAL:
            strategy.append("Load testing for performance validation")
            strategy.append("Error scenario testing")
        
        return strategy


class AngularMigrationPlugin(MigrationPlugin):
    """Plugin for generating Angular frontend migration recommendations."""
    
    def _get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="AngularMigrationPlugin",
            version="1.0.0",
            description="Generates Angular frontend migration strategies and recommendations",
            author="Claude Code Assistant",
            plugin_type=PluginType.MIGRATION,
            supported_file_types=set(),
            configuration_schema={
                'target_angular_version': {
                    'type': 'string',
                    'default': '17',
                    'description': 'Target Angular version for migration'
                },
                'include_material_design': {
                    'type': 'boolean',
                    'default': True,
                    'description': 'Include Angular Material design recommendations'
                },
                'state_management': {
                    'type': 'string',
                    'default': 'ngrx',
                    'description': 'Preferred state management solution (ngrx, akita, etc.)'
                }
            }
        )
    
    def can_handle(self, context: Dict[str, Any]) -> bool:
        """Check if Angular migration is applicable."""
        return True
    
    def execute(self, context: Dict[str, Any]) -> PluginResult:
        """Execute Angular migration analysis."""
        business_rules = context.get('business_rules', [])
        return self.generate_migration_recommendations(business_rules, context)
    
    def generate_migration_recommendations(self, 
                                         business_rules: List[BusinessRule],
                                         context: Dict[str, Any]) -> PluginResult:
        """Generate Angular migration recommendations."""
        start_time = datetime.now()
        result = PluginResult(
            plugin_name=self.metadata.name,
            success=True,
            execution_time_ms=0
        )
        
        try:
            # Analyze for Angular patterns
            angular_analysis = self._analyze_for_angular_patterns(business_rules)
            result.add_extracted_data('angular_analysis', angular_analysis)
            
            # Generate component recommendations
            component_recommendations = self._generate_component_recommendations(business_rules)
            result.add_extracted_data('component_recommendations', component_recommendations)
            
            # Generate service recommendations
            service_recommendations = self._generate_service_recommendations(business_rules)
            result.add_extracted_data('service_recommendations', service_recommendations)
            
            # Generate general recommendations
            for recommendation in self._generate_angular_recommendations(business_rules):
                result.add_recommendation(recommendation)
            
            # Calculate execution time
            end_time = datetime.now()
            result.execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
        except Exception as e:
            result.add_error(f"Angular migration analysis failed: {e}")
        
        return result
    
    def estimate_migration_effort(self, business_rules: List[BusinessRule]) -> Dict[str, Any]:
        """Estimate effort for Angular migration."""
        effort_estimate = {
            'total_story_points': 0,
            'estimated_weeks': 0,
            'component_count': 0,
            'service_count': 0,
            'complexity_breakdown': defaultdict(int),
            'recommendations': []
        }
        
        # Estimate components and services needed
        ui_rules = [r for r in business_rules if 'form' in r.name.lower() or 'ui' in r.name.lower()]
        service_rules = [r for r in business_rules if r.rule_type in [BusinessRuleType.WORKFLOW, BusinessRuleType.BUSINESS_LOGIC]]
        
        effort_estimate['component_count'] = max(len(ui_rules), len(business_rules) // 5)  # Rough estimate
        effort_estimate['service_count'] = len(service_rules)
        
        # Calculate story points
        component_points = effort_estimate['component_count'] * 3  # 3 points per component
        service_points = effort_estimate['service_count'] * 5     # 5 points per service
        
        effort_estimate['total_story_points'] = component_points + service_points
        effort_estimate['estimated_weeks'] = max(1, effort_estimate['total_story_points'] // 15)
        
        # Add recommendations
        if effort_estimate['component_count'] > 20:
            effort_estimate['recommendations'].append(
                "Consider implementing a design system with reusable components"
            )
        
        if effort_estimate['service_count'] > 10:
            effort_estimate['recommendations'].append(
                "Implement centralized state management (NgRx) for complex data flows"
            )
        
        return effort_estimate
    
    def _analyze_for_angular_patterns(self, business_rules: List[BusinessRule]) -> Dict[str, Any]:
        """Analyze business rules for Angular migration patterns."""
        analysis = {
            'component_candidates': [],
            'service_candidates': [],
            'guard_candidates': [],
            'pipe_candidates': [],
            'directive_candidates': []
        }
        
        for rule in business_rules:
            # UI-related rules become components
            if any(keyword in rule.name.lower() for keyword in ['form', 'page', 'view', 'dialog', 'modal']):
                analysis['component_candidates'].append({
                    'rule_id': rule.id,
                    'name': rule.name,
                    'suggested_component_name': self._suggest_component_name(rule.name),
                    'component_type': self._determine_component_type(rule.name)
                })
            
            # Business logic becomes services
            elif rule.rule_type in [BusinessRuleType.BUSINESS_LOGIC, BusinessRuleType.WORKFLOW]:
                analysis['service_candidates'].append({
                    'rule_id': rule.id,
                    'name': rule.name,
                    'suggested_service_name': self._suggest_service_name(rule.name),
                    'service_type': self._determine_service_type(rule)
                })
            
            # Validation rules might become guards or pipes
            elif rule.rule_type == BusinessRuleType.VALIDATION:
                if 'access' in rule.description.lower() or 'permission' in rule.description.lower():
                    analysis['guard_candidates'].append({
                        'rule_id': rule.id,
                        'name': rule.name,
                        'suggested_guard_name': self._suggest_guard_name(rule.name)
                    })
                else:
                    analysis['pipe_candidates'].append({
                        'rule_id': rule.id,
                        'name': rule.name,
                        'suggested_pipe_name': self._suggest_pipe_name(rule.name)
                    })
        
        return analysis
    
    def _generate_component_recommendations(self, business_rules: List[BusinessRule]) -> List[Dict[str, Any]]:
        """Generate Angular component recommendations."""
        recommendations = []
        
        # Group by business domain for feature modules
        domains = defaultdict(list)
        for rule in business_rules:
            if any(keyword in rule.name.lower() for keyword in ['form', 'page', 'view']):
                domain = self._extract_business_domain(rule)
                domains[domain].append(rule)
        
        for domain, domain_rules in domains.items():
            module_recommendation = {
                'module_name': f"{domain.title()}Module",
                'components': [],
                'lazy_loading': len(domain_rules) > 3
            }
            
            for rule in domain_rules:
                component_rec = {
                    'name': self._suggest_component_name(rule.name),
                    'selector': self._suggest_component_selector(rule.name),
                    'template_approach': self._suggest_template_approach(rule),
                    'lifecycle_hooks': self._suggest_lifecycle_hooks(rule),
                    'inputs_outputs': self._suggest_inputs_outputs(rule)
                }
                
                module_recommendation['components'].append(component_rec)
            
            recommendations.append(module_recommendation)
        
        return recommendations
    
    def _generate_service_recommendations(self, business_rules: List[BusinessRule]) -> List[Dict[str, Any]]:
        """Generate Angular service recommendations."""
        recommendations = []
        
        service_rules = [r for r in business_rules if r.rule_type in [BusinessRuleType.BUSINESS_LOGIC, BusinessRuleType.WORKFLOW]]
        
        for rule in service_rules:
            service_rec = {
                'name': self._suggest_service_name(rule.name),
                'injectable_scope': self._suggest_injectable_scope(rule),
                'methods': self._suggest_service_methods(rule),
                'rxjs_patterns': self._suggest_rxjs_patterns(rule),
                'error_handling': self._suggest_error_handling(rule)
            }
            
            recommendations.append(service_rec)
        
        return recommendations
    
    def _generate_angular_recommendations(self, business_rules: List[BusinessRule]) -> List[str]:
        """Generate general Angular migration recommendations."""
        recommendations = []
        
        total_rules = len(business_rules)
        complex_rules = len([r for r in business_rules if r.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL]])
        
        if total_rules > 30:
            recommendations.append(
                "Implement feature modules with lazy loading to improve initial load time"
            )
        
        if complex_rules > 5:
            recommendations.append(
                "Implement NgRx for centralized state management of complex business logic"
            )
        
        form_rules = [r for r in business_rules if 'form' in r.name.lower()]
        if form_rules:
            recommendations.append(
                f"Implement {len(form_rules)} reactive forms with Angular Validators for form handling"
            )
        
        validation_rules = [r for r in business_rules if r.rule_type == BusinessRuleType.VALIDATION]
        if validation_rules:
            recommendations.append(
                f"Create {len(validation_rules)} custom validators or pipes for business rule validation"
            )
        
        return recommendations
    
    # Helper methods for Angular naming conventions
    def _suggest_component_name(self, rule_name: str) -> str:
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        return ''.join(word.capitalize() for word in words) + 'Component'
    
    def _suggest_component_selector(self, rule_name: str) -> str:
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        return 'app-' + '-'.join(words)
    
    def _suggest_service_name(self, rule_name: str) -> str:
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        return ''.join(word.capitalize() for word in words) + 'Service'
    
    def _suggest_guard_name(self, rule_name: str) -> str:
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        return ''.join(word.capitalize() for word in words) + 'Guard'
    
    def _suggest_pipe_name(self, rule_name: str) -> str:
        words = rule_name.lower().replace('-', ' ').replace('_', ' ').split()
        return ''.join(word.capitalize() for word in words) + 'Pipe'
    
    def _determine_component_type(self, rule_name: str) -> str:
        name_lower = rule_name.lower()
        if 'form' in name_lower:
            return 'form'
        elif 'list' in name_lower or 'table' in name_lower:
            return 'list'
        elif 'detail' in name_lower or 'view' in name_lower:
            return 'detail'
        elif 'dialog' in name_lower or 'modal' in name_lower:
            return 'dialog'
        else:
            return 'page'
    
    def _determine_service_type(self, rule: BusinessRule) -> str:
        if rule.rule_type == BusinessRuleType.DATA:
            return 'data'
        elif rule.rule_type == BusinessRuleType.WORKFLOW:
            return 'business'
        else:
            return 'utility'
    
    def _suggest_injectable_scope(self, rule: BusinessRule) -> str:
        if rule.complexity == BusinessRuleComplexity.CRITICAL:
            return 'root'  # Singleton for critical services
        else:
            return 'providedIn: "root"'
    
    def _suggest_service_methods(self, rule: BusinessRule) -> List[str]:
        methods = []
        
        if rule.rule_type == BusinessRuleType.DATA:
            methods.extend(['get()', 'getAll()', 'save()', 'delete()'])
        elif rule.rule_type == BusinessRuleType.WORKFLOW:
            methods.append('process()')
        elif rule.rule_type == BusinessRuleType.VALIDATION:
            methods.append('validate()')
        
        return methods
    
    def _suggest_rxjs_patterns(self, rule: BusinessRule) -> List[str]:
        patterns = ['Observable', 'map', 'catchError']
        
        if rule.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL]:
            patterns.extend(['switchMap', 'debounceTime', 'retry'])
        
        return patterns
    
    def _suggest_error_handling(self, rule: BusinessRule) -> List[str]:
        strategies = ['catchError operator', 'global error handler']
        
        if rule.complexity == BusinessRuleComplexity.CRITICAL:
            strategies.append('retry with exponential backoff')
        
        return strategies
    
    def _suggest_template_approach(self, rule: BusinessRule) -> str:
        if 'form' in rule.name.lower():
            return 'reactive forms'
        elif rule.complexity == BusinessRuleComplexity.SIMPLE:
            return 'template-driven'
        else:
            return 'reactive'
    
    def _suggest_lifecycle_hooks(self, rule: BusinessRule) -> List[str]:
        hooks = ['OnInit']
        
        if rule.complexity in [BusinessRuleComplexity.COMPLEX, BusinessRuleComplexity.CRITICAL]:
            hooks.extend(['OnDestroy', 'OnChanges'])
        
        return hooks
    
    def _suggest_inputs_outputs(self, rule: BusinessRule) -> Dict[str, List[str]]:
        return {
            'inputs': ['data', 'config'],
            'outputs': ['dataChange', 'action']
        }
    
    def _extract_business_domain(self, rule: BusinessRule) -> str:
        """Extract business domain from rule (reuse from GraphQL plugin)."""
        name_lower = rule.name.lower()
        
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
