"""
Migration Information Model
==========================

This module defines data structures for migration-related information
including effort estimates, complexity mappings, and migration strategies.

Author: Claude Code Assistant
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime


class MigrationPriority(Enum):
    """Migration priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MigrationComplexity(Enum):
    """Migration complexity levels."""
    TRIVIAL = "trivial"
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    VERY_COMPLEX = "very_complex"


class MigrationRisk(Enum):
    """Migration risk levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MigrationEffort(Enum):
    """Migration effort levels."""
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    EXTENSIVE = "extensive"


@dataclass
class EffortEstimate:
    """Effort estimate for migration tasks."""
    story_points: int
    hours: float
    complexity: MigrationComplexity
    confidence_level: float = 0.8
    assumptions: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)


@dataclass
class MigrationStrategy:
    """Migration strategy for specific components."""
    strategy_name: str
    description: str
    target_technology: str
    approach: str  # "rewrite", "refactor", "replace", "deprecate"
    effort_estimate: EffortEstimate
    prerequisites: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)


@dataclass
class MigrationInfo:
    """Complete migration information for a business rule or component."""
    rule_id: str
    priority: MigrationPriority
    complexity: MigrationComplexity
    effort_estimate: EffortEstimate
    strategies: List[MigrationStrategy] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    notes: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def add_strategy(self, strategy: MigrationStrategy) -> None:
        """Add a migration strategy."""
        self.strategies.append(strategy)
        self.updated_at = datetime.now()
    
    def get_total_effort(self) -> EffortEstimate:
        """Calculate total effort across all strategies."""
        if not self.strategies:
            return self.effort_estimate
        
        total_points = self.effort_estimate.story_points
        total_hours = self.effort_estimate.hours
        max_complexity = self.effort_estimate.complexity
        
        for strategy in self.strategies:
            total_points += strategy.effort_estimate.story_points
            total_hours += strategy.effort_estimate.hours
            if strategy.effort_estimate.complexity.value > max_complexity.value:
                max_complexity = strategy.effort_estimate.complexity
        
        return EffortEstimate(
            story_points=total_points,
            hours=total_hours,
            complexity=max_complexity,
            confidence_level=min(s.effort_estimate.confidence_level for s in self.strategies)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'rule_id': self.rule_id,
            'priority': self.priority.value,
            'complexity': self.complexity.value,
            'effort_estimate': {
                'story_points': self.effort_estimate.story_points,
                'hours': self.effort_estimate.hours,
                'complexity': self.effort_estimate.complexity.value,
                'confidence_level': self.effort_estimate.confidence_level,
                'assumptions': self.effort_estimate.assumptions,
                'risks': self.effort_estimate.risks
            },
            'strategies': [
                {
                    'strategy_name': s.strategy_name,
                    'description': s.description,
                    'target_technology': s.target_technology,
                    'approach': s.approach,
                    'effort_estimate': {
                        'story_points': s.effort_estimate.story_points,
                        'hours': s.effort_estimate.hours,
                        'complexity': s.effort_estimate.complexity.value,
                        'confidence_level': s.effort_estimate.confidence_level
                    },
                    'prerequisites': s.prerequisites,
                    'success_criteria': s.success_criteria
                }
                for s in self.strategies
            ],
            'dependencies': self.dependencies,
            'blockers': self.blockers,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MigrationInfo':
        """Create from dictionary."""
        effort_data = data['effort_estimate']
        effort_estimate = EffortEstimate(
            story_points=effort_data['story_points'],
            hours=effort_data['hours'],
            complexity=MigrationComplexity(effort_data['complexity']),
            confidence_level=effort_data.get('confidence_level', 0.8),
            assumptions=effort_data.get('assumptions', []),
            risks=effort_data.get('risks', [])
        )
        
        strategies = []
        for strategy_data in data.get('strategies', []):
            strategy_effort = EffortEstimate(
                story_points=strategy_data['effort_estimate']['story_points'],
                hours=strategy_data['effort_estimate']['hours'],
                complexity=MigrationComplexity(strategy_data['effort_estimate']['complexity']),
                confidence_level=strategy_data['effort_estimate'].get('confidence_level', 0.8)
            )
            
            strategy = MigrationStrategy(
                strategy_name=strategy_data['strategy_name'],
                description=strategy_data['description'],
                target_technology=strategy_data['target_technology'],
                approach=strategy_data['approach'],
                effort_estimate=strategy_effort,
                prerequisites=strategy_data.get('prerequisites', []),
                success_criteria=strategy_data.get('success_criteria', [])
            )
            strategies.append(strategy)
        
        return cls(
            rule_id=data['rule_id'],
            priority=MigrationPriority(data['priority']),
            complexity=MigrationComplexity(data['complexity']),
            effort_estimate=effort_estimate,
            strategies=strategies,
            dependencies=data.get('dependencies', []),
            blockers=data.get('blockers', []),
            notes=data.get('notes', ''),
            created_at=datetime.fromisoformat(data['created_at']),
            updated_at=datetime.fromisoformat(data['updated_at'])
        )