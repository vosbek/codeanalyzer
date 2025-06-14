"""
Business Rule Search and Indexing System
========================================

This module provides search and indexing capabilities for business rules extracted
from Struts applications. It enables fast searching, filtering, and categorization
of business rules to support large-scale analysis and migration planning.

Features:
- Full-text search across business rule content
- Faceted search by rule types, complexity, migration risk
- Similarity matching for duplicate rule detection
- Tag-based organization and filtering
- Export capabilities for search results

Author: Claude Code Assistant
"""

from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import re
import json
import sqlite3
from pathlib import Path
import hashlib
from datetime import datetime

from .business_rule import BusinessRule, BusinessRuleType, BusinessRuleComplexity


@dataclass
class SearchQuery:
    """Represents a search query with filters and options."""
    text: str = ""
    rule_types: List[BusinessRuleType] = field(default_factory=list)
    complexity_levels: List[BusinessRuleComplexity] = field(default_factory=list)
    migration_risks: List[str] = field(default_factory=list)
    business_domains: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    source_files: List[str] = field(default_factory=list)
    min_impact_score: Optional[int] = None
    max_impact_score: Optional[int] = None
    limit: int = 100
    offset: int = 0
    include_similar: bool = False
    similarity_threshold: float = 0.8


@dataclass
class SearchResult:
    """Represents search results with metadata."""
    business_rules: List[BusinessRule]
    total_count: int
    facets: Dict[str, Counter] = field(default_factory=dict)
    execution_time_ms: int = 0
    query: Optional[SearchQuery] = None
    suggestions: List[str] = field(default_factory=list)


class BusinessRuleIndex:
    """
    Search index for business rules providing fast search and filtering capabilities.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize the search index."""
        self.db_path = db_path or ":memory:"
        self.connection = None
        self._initialize_database()
        
        # In-memory structures for fast access
        self._rules_by_id: Dict[str, BusinessRule] = {}
        self._text_index: Dict[str, Set[str]] = defaultdict(set)
        self._facet_index: Dict[str, Dict[str, Set[str]]] = {
            'rule_type': defaultdict(set),
            'complexity': defaultdict(set),
            'migration_risk': defaultdict(set),
            'business_domain': defaultdict(set),
            'source_file': defaultdict(set),
            'tags': defaultdict(set)
        }
        
    def _initialize_database(self):
        """Initialize SQLite database for persistent storage."""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.execute('''
            CREATE TABLE IF NOT EXISTS business_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                rule_type TEXT,
                source TEXT,
                business_domain TEXT,
                complexity TEXT,
                migration_risk TEXT,
                impact_score INTEGER,
                source_file TEXT,
                data_json TEXT,
                indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                search_content TEXT
            )
        ''')
        
        self.connection.execute('''
            CREATE TABLE IF NOT EXISTS rule_tags (
                rule_id TEXT,
                tag TEXT,
                FOREIGN KEY (rule_id) REFERENCES business_rules (id)
            )
        ''')
        
        # Create search indexes
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_rule_type ON business_rules(rule_type)
        ''')
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_complexity ON business_rules(complexity)
        ''')
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_migration_risk ON business_rules(migration_risk)
        ''')
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_business_domain ON business_rules(business_domain)
        ''')
        self.connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_impact_score ON business_rules(impact_score)
        ''')
        
        # Full-text search
        self.connection.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS rule_search_fts 
            USING fts5(id, name, description, search_content)
        ''')
        
        self.connection.commit()
    
    def add_rule(self, rule: BusinessRule) -> None:
        """Add a business rule to the index."""
        # Store in memory
        self._rules_by_id[rule.id] = rule
        
        # Update text index
        search_content = self._extract_search_content(rule)
        for word in self._tokenize_text(search_content):
            self._text_index[word].add(rule.id)
        
        # Update facet indexes
        self._facet_index['rule_type'][rule.rule_type.value].add(rule.id)
        self._facet_index['complexity'][rule.complexity.name].add(rule.id)
        self._facet_index['migration_risk'][rule.migration_risk].add(rule.id)
        self._facet_index['business_domain'][rule.business_domain].add(rule.id)
        self._facet_index['source_file'][rule.location.file_path].add(rule.id)
        
        for tag in rule.tags:
            self._facet_index['tags'][tag].add(rule.id)
        
        # Store in database
        self._store_rule_in_db(rule, search_content)
    
    def add_rules(self, rules: List[BusinessRule]) -> None:
        """Add multiple business rules to the index."""
        for rule in rules:
            self.add_rule(rule)
    
    def search(self, query: SearchQuery) -> SearchResult:
        """Search business rules based on query parameters."""
        start_time = datetime.now()
        
        # Start with all rule IDs
        candidate_ids = set(self._rules_by_id.keys())
        
        # Apply text search filter
        if query.text:
            text_ids = self._search_text(query.text)
            candidate_ids &= text_ids
        
        # Apply facet filters
        if query.rule_types:
            type_ids = set()
            for rule_type in query.rule_types:
                type_ids.update(self._facet_index['rule_type'][rule_type.value])
            candidate_ids &= type_ids
        
        if query.complexity_levels:
            complexity_ids = set()
            for complexity in query.complexity_levels:
                complexity_ids.update(self._facet_index['complexity'][complexity.name])
            candidate_ids &= complexity_ids
        
        if query.migration_risks:
            risk_ids = set()
            for risk in query.migration_risks:
                risk_ids.update(self._facet_index['migration_risk'][risk])
            candidate_ids &= risk_ids
        
        if query.business_domains:
            domain_ids = set()
            for domain in query.business_domains:
                domain_ids.update(self._facet_index['business_domain'][domain])
            candidate_ids &= domain_ids
        
        if query.tags:
            tag_ids = set()
            for tag in query.tags:
                tag_ids.update(self._facet_index['tags'][tag])
            candidate_ids &= tag_ids
        
        if query.source_files:
            file_ids = set()
            for file_path in query.source_files:
                file_ids.update(self._facet_index['source_file'][file_path])
            candidate_ids &= file_ids
        
        # Apply impact score filters
        if query.min_impact_score is not None or query.max_impact_score is not None:
            impact_ids = set()
            for rule_id in candidate_ids:
                rule = self._rules_by_id[rule_id]
                impact_score = rule.impact.total_impact_score
                
                if query.min_impact_score is not None and impact_score < query.min_impact_score:
                    continue
                if query.max_impact_score is not None and impact_score > query.max_impact_score:
                    continue
                
                impact_ids.add(rule_id)
            candidate_ids &= impact_ids
        
        # Get business rules for candidate IDs
        matching_rules = [self._rules_by_id[rule_id] for rule_id in candidate_ids]
        
        # Sort by relevance (could be enhanced with more sophisticated scoring)
        matching_rules.sort(key=lambda r: (
            r.impact.total_impact_score,
            r.complexity_score,
            r.name
        ), reverse=True)
        
        # Apply pagination
        total_count = len(matching_rules)
        start_idx = query.offset
        end_idx = start_idx + query.limit
        paginated_rules = matching_rules[start_idx:end_idx]
        
        # Calculate facets for the filtered results
        facets = self._calculate_facets(candidate_ids)
        
        # Calculate execution time
        execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return SearchResult(
            business_rules=paginated_rules,
            total_count=total_count,
            facets=facets,
            execution_time_ms=execution_time,
            query=query
        )
    
    def find_similar_rules(self, rule: BusinessRule, threshold: float = 0.8) -> List[Tuple[BusinessRule, float]]:
        """Find similar business rules based on content similarity."""
        similar_rules = []
        rule_content = self._extract_search_content(rule)
        rule_tokens = set(self._tokenize_text(rule_content))
        
        for other_id, other_rule in self._rules_by_id.items():
            if other_id == rule.id:
                continue
                
            other_content = self._extract_search_content(other_rule)
            other_tokens = set(self._tokenize_text(other_content))
            
            # Calculate Jaccard similarity
            intersection = len(rule_tokens & other_tokens)
            union = len(rule_tokens | other_tokens)
            similarity = intersection / union if union > 0 else 0.0
            
            if similarity >= threshold:
                similar_rules.append((other_rule, similarity))
        
        # Sort by similarity descending
        similar_rules.sort(key=lambda x: x[1], reverse=True)
        return similar_rules
    
    def get_rule_by_id(self, rule_id: str) -> Optional[BusinessRule]:
        """Get a business rule by its ID."""
        return self._rules_by_id.get(rule_id)
    
    def get_all_facet_values(self) -> Dict[str, List[str]]:
        """Get all available facet values."""
        facet_values = {}
        for facet_name, facet_data in self._facet_index.items():
            facet_values[facet_name] = list(facet_data.keys())
        return facet_values
    
    def get_rule_count(self) -> int:
        """Get total number of indexed rules."""
        return len(self._rules_by_id)
    
    def export_search_results(self, search_result: SearchResult, format: str = "json") -> str:
        """Export search results to various formats."""
        if format.lower() == "json":
            return self._export_as_json(search_result)
        elif format.lower() == "csv":
            return self._export_as_csv(search_result)
        elif format.lower() == "markdown":
            return self._export_as_markdown(search_result)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _extract_search_content(self, rule: BusinessRule) -> str:
        """Extract searchable content from a business rule."""
        content_parts = [
            rule.name,
            rule.description,
            rule.business_context,
            rule.business_rationale,
            rule.evidence.code_snippet,
            rule.evidence.context,
            rule.migration_notes
        ]
        
        # Add tags and dependencies
        content_parts.extend(rule.tags)
        content_parts.extend(rule.dependencies)
        content_parts.extend(rule.affected_components)
        content_parts.extend(rule.modernization_recommendations)
        
        return " ".join(filter(None, content_parts))
    
    def _tokenize_text(self, text: str) -> List[str]:
        """Tokenize text for search indexing."""
        # Convert to lowercase and split on non-alphanumeric characters
        tokens = re.findall(r'\b\w+\b', text.lower())
        
        # Filter out common stop words and short tokens
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should'}
        
        return [token for token in tokens if len(token) > 2 and token not in stop_words]
    
    def _search_text(self, query_text: str) -> Set[str]:
        """Search for rules containing the query text."""
        query_tokens = self._tokenize_text(query_text)
        if not query_tokens:
            return set(self._rules_by_id.keys())
        
        # Find rules containing all query tokens (AND search)
        result_ids = None
        for token in query_tokens:
            token_ids = self._text_index.get(token, set())
            if result_ids is None:
                result_ids = token_ids.copy()
            else:
                result_ids &= token_ids
        
        return result_ids or set()
    
    def _calculate_facets(self, rule_ids: Set[str]) -> Dict[str, Counter]:
        """Calculate facet counts for the given rule IDs."""
        facets = {}
        
        for facet_name, facet_data in self._facet_index.items():
            facet_counts = Counter()
            for facet_value, value_rule_ids in facet_data.items():
                count = len(value_rule_ids & rule_ids)
                if count > 0:
                    facet_counts[facet_value] = count
            facets[facet_name] = facet_counts
        
        return facets
    
    def _store_rule_in_db(self, rule: BusinessRule, search_content: str):
        """Store business rule in SQLite database."""
        # Insert main rule record
        self.connection.execute('''
            INSERT OR REPLACE INTO business_rules 
            (id, name, description, rule_type, source, business_domain, complexity, 
             migration_risk, impact_score, source_file, data_json, search_content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.id,
            rule.name,
            rule.description,
            rule.rule_type.value,
            rule.source.value,
            rule.business_domain,
            rule.complexity.name,
            rule.migration_risk,
            rule.impact.total_impact_score,
            rule.location.file_path,
            json.dumps(rule.to_dict()),
            search_content
        ))
        
        # Insert tags
        self.connection.execute('DELETE FROM rule_tags WHERE rule_id = ?', (rule.id,))
        for tag in rule.tags:
            self.connection.execute(
                'INSERT INTO rule_tags (rule_id, tag) VALUES (?, ?)',
                (rule.id, tag)
            )
        
        # Insert into FTS table
        self.connection.execute('''
            INSERT OR REPLACE INTO rule_search_fts 
            (id, name, description, search_content)
            VALUES (?, ?, ?, ?)
        ''', (rule.id, rule.name, rule.description, search_content))
        
        self.connection.commit()
    
    def _export_as_json(self, search_result: SearchResult) -> str:
        """Export search results as JSON."""
        export_data = {
            'total_count': search_result.total_count,
            'execution_time_ms': search_result.execution_time_ms,
            'business_rules': [rule.to_dict() for rule in search_result.business_rules],
            'facets': {k: dict(v) for k, v in search_result.facets.items()}
        }
        return json.dumps(export_data, indent=2, default=str)
    
    def _export_as_csv(self, search_result: SearchResult) -> str:
        """Export search results as CSV."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = [
            'ID', 'Name', 'Description', 'Type', 'Complexity', 'Migration Risk',
            'Business Domain', 'Source File', 'Impact Score', 'Tags'
        ]
        writer.writerow(headers)
        
        # Write data rows
        for rule in search_result.business_rules:
            writer.writerow([
                rule.id,
                rule.name,
                rule.description,
                rule.rule_type.value,
                rule.complexity.name,
                rule.migration_risk,
                rule.business_domain,
                rule.location.file_path,
                rule.impact.total_impact_score,
                ', '.join(rule.tags)
            ])
        
        return output.getvalue()
    
    def _export_as_markdown(self, search_result: SearchResult) -> str:
        """Export search results as Markdown."""
        lines = [
            f"# Business Rules Search Results",
            f"",
            f"**Total Results:** {search_result.total_count}",
            f"**Execution Time:** {search_result.execution_time_ms}ms",
            f"",
            f"## Rules",
            f""
        ]
        
        for rule in search_result.business_rules:
            lines.extend([
                f"### {rule.name}",
                f"",
                f"**ID:** {rule.id}",
                f"**Type:** {rule.rule_type.value}",
                f"**Complexity:** {rule.complexity.name}",
                f"**Migration Risk:** {rule.migration_risk}",
                f"**Source:** {rule.location.file_path}",
                f"",
                f"**Description:** {rule.description}",
                f"",
                f"**Business Context:** {rule.business_context}",
                f"",
                f"---",
                f""
            ])
        
        return "\n".join(lines)
    
    def close(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()