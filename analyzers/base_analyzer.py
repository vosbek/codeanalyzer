"""
Base Analyzer Class
===================

This module defines the abstract base class for all analyzers in the Struts analysis system.
It provides a consistent interface and common functionality that all specialized analyzers
inherit from.

The BaseAnalyzer class implements the Template Method pattern, allowing subclasses to
customize specific analysis steps while maintaining a consistent overall workflow.

Author: Claude Code Assistant
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Union, Type
from pathlib import Path
from datetime import datetime
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

import sys
sys.path.append('..')
from utils.config_utils import ConfigurationManager
from utils.logging_utils import get_logger
from utils.performance_utils import PerformanceMonitor
from utils.validation_utils import ValidationError, validate_file_path


@dataclass
class AnalysisContext:
    """Context information for analysis operations."""
    project_root: Path
    target_files: List[Path] = field(default_factory=list)
    configuration: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    performance_monitor: Optional[PerformanceMonitor] = None
    
    def __post_init__(self):
        """Initialize context with defaults."""
        if not self.project_root.exists():
            raise ValidationError(f"Project root does not exist: {self.project_root}")
        
        if self.performance_monitor is None:
            self.performance_monitor = PerformanceMonitor()


@dataclass
class AnalysisResult:
    """Standard result structure for all analyzers."""
    analyzer_name: str
    success: bool
    execution_time_seconds: float
    files_analyzed: int
    items_found: int
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def has_errors(self) -> bool:
        """Check if analysis had errors."""
        return len(self.errors) > 0
    
    @property
    def has_warnings(self) -> bool:
        """Check if analysis had warnings."""
        return len(self.warnings) > 0
    
    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)
        self.success = False
    
    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)
    
    def merge_result(self, other: 'AnalysisResult') -> None:
        """Merge another analysis result into this one."""
        self.files_analyzed += other.files_analyzed
        self.items_found += other.items_found
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        
        # Merge data dictionaries
        for key, value in other.data.items():
            if key in self.data:
                if isinstance(self.data[key], list) and isinstance(value, list):
                    self.data[key].extend(value)
                elif isinstance(self.data[key], dict) and isinstance(value, dict):
                    self.data[key].update(value)
                else:
                    self.data[f"{key}_merged"] = [self.data[key], value]
            else:
                self.data[key] = value
        
        # Update success status
        if not other.success:
            self.success = False


class BaseAnalyzer(ABC):
    """
    Abstract base class for all analyzers in the Struts analysis system.
    
    This class implements the Template Method pattern, defining the overall
    analysis workflow while allowing subclasses to customize specific steps.
    It provides common functionality such as file filtering, error handling,
    logging, and performance monitoring.
    """
    
    def __init__(self, config: ConfigurationManager):
        """
        Initialize the analyzer with configuration.
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.performance_monitor = PerformanceMonitor()
        self._supported_extensions: Set[str] = set()
        self._required_patterns: List[str] = []
        
        # Initialize analyzer-specific settings
        self._initialize_analyzer()
    
    @abstractmethod
    def _initialize_analyzer(self) -> None:
        """Initialize analyzer-specific settings and configurations."""
        pass
    
    @abstractmethod
    def can_analyze(self, file_path: Path) -> bool:
        """
        Check if this analyzer can handle the given file.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if this analyzer can handle the file, False otherwise
        """
        pass
    
    @abstractmethod
    def _analyze_file(self, file_path: Path, context: AnalysisContext) -> Dict[str, Any]:
        """
        Analyze a single file and return results.
        
        Args:
            file_path: Path to the file to analyze
            context: Analysis context
            
        Returns:
            Dictionary containing analysis results for the file
        """
        pass
    
    @abstractmethod
    def _post_process_results(self, results: List[Dict[str, Any]], 
                            context: AnalysisContext) -> Dict[str, Any]:
        """
        Post-process the aggregated results from all files.
        
        Args:
            results: List of individual file analysis results
            context: Analysis context
            
        Returns:
            Final processed analysis results
        """
        pass
    
    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """
        Main analysis method implementing the Template Method pattern.
        
        Args:
            context: Analysis context containing files and configuration
            
        Returns:
            AnalysisResult containing the analysis outcome and data
        """
        start_time = datetime.now()
        
        try:
            # Validate context
            self._validate_context(context)
            
            # Filter files that this analyzer can handle
            analyzable_files = self._filter_analyzable_files(context.target_files)
            
            if not analyzable_files:
                self.logger.info(f"No files found for {self.__class__.__name__}")
                return AnalysisResult(
                    analyzer_name=self.__class__.__name__,
                    success=True,
                    execution_time_seconds=0.0,
                    files_analyzed=0,
                    items_found=0
                )
            
            self.logger.info(f"Analyzing {len(analyzable_files)} files with {self.__class__.__name__}")
            
            # Analyze files
            if self._should_use_parallel_processing(analyzable_files):
                file_results = self._analyze_files_parallel(analyzable_files, context)
            else:
                file_results = self._analyze_files_sequential(analyzable_files, context)
            
            # Post-process results
            final_data = self._post_process_results(file_results, context)
            
            # Calculate metrics
            execution_time = (datetime.now() - start_time).total_seconds()
            items_found = self._count_items_found(final_data)
            
            result = AnalysisResult(
                analyzer_name=self.__class__.__name__,
                success=True,
                execution_time_seconds=execution_time,
                files_analyzed=len(analyzable_files),
                items_found=items_found,
                data=final_data
            )
            
            self.logger.info(
                f"{self.__class__.__name__} completed: "
                f"{len(analyzable_files)} files, {items_found} items, "
                f"{execution_time:.2f}s"
            )
            
            return result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            error_msg = f"Analysis failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            
            result = AnalysisResult(
                analyzer_name=self.__class__.__name__,
                success=False,
                execution_time_seconds=execution_time,
                files_analyzed=0,
                items_found=0
            )
            result.add_error(error_msg)
            return result
    
    def _validate_context(self, context: AnalysisContext) -> None:
        """Validate the analysis context."""
        if not context.project_root.exists():
            raise ValidationError(f"Project root does not exist: {context.project_root}")
        
        if not context.target_files:
            raise ValidationError("No target files provided for analysis")
    
    def _filter_analyzable_files(self, files: List[Path]) -> List[Path]:
        """Filter files that this analyzer can handle."""
        analyzable = []
        
        for file_path in files:
            try:
                if self._should_skip_file(file_path):
                    continue
                    
                if self.can_analyze(file_path):
                    analyzable.append(file_path)
                    
            except Exception as e:
                self.logger.warning(f"Error checking file {file_path}: {e}")
        
        return analyzable
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on configuration."""
        # Skip files that are too large
        max_size_mb = self.config.get('analysis.max_file_size_mb', 10)
        try:
            if file_path.stat().st_size > max_size_mb * 1024 * 1024:
                self.logger.warning(f"Skipping large file: {file_path}")
                return True
        except OSError:
            self.logger.warning(f"Cannot access file: {file_path}")
            return True
        
        # Skip test files if configured
        if self.config.get('analysis.skip_test_files', True):
            path_str = str(file_path).lower()
            if any(test_indicator in path_str for test_indicator in ['test', 'spec', 'mock']):
                return True
        
        # Skip backup and temporary files
        if file_path.name.startswith('.') or file_path.name.endswith(('.bak', '.tmp', '.temp')):
            return True
        
        return False
    
    def _should_use_parallel_processing(self, files: List[Path]) -> bool:
        """Determine if parallel processing should be used."""
        min_files_for_parallel = self.config.get('analysis.min_files_for_parallel', 10)
        parallel_enabled = self.config.get('analysis.parallel_enabled', True)
        
        return parallel_enabled and len(files) >= min_files_for_parallel
    
    def _analyze_files_sequential(self, files: List[Path], 
                                context: AnalysisContext) -> List[Dict[str, Any]]:
        """Analyze files sequentially."""
        results = []
        
        for file_path in tqdm(files, desc=f"Analyzing with {self.__class__.__name__}"):
            try:
                result = self._analyze_single_file_safe(file_path, context)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Error analyzing {file_path}: {e}")
        
        return results
    
    def _analyze_files_parallel(self, files: List[Path], 
                              context: AnalysisContext) -> List[Dict[str, Any]]:
        """Analyze files in parallel."""
        results = []
        max_workers = self.config.get('analysis.parallel_workers', 4)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all analysis tasks
            future_to_file = {
                executor.submit(self._analyze_single_file_safe, file_path, context): file_path
                for file_path in files
            }
            
            # Collect results as they complete
            for future in tqdm(
                as_completed(future_to_file), 
                total=len(future_to_file),
                desc=f"Analyzing with {self.__class__.__name__}"
            ):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Error analyzing {file_path}: {e}")
        
        return results
    
    def _analyze_single_file_safe(self, file_path: Path, 
                                context: AnalysisContext) -> Optional[Dict[str, Any]]:
        """Safely analyze a single file with error handling."""
        try:
            validate_file_path(file_path)
            
            with self.performance_monitor.measure(f"analyze_file_{file_path.name}"):
                result = self._analyze_file(file_path, context)
                
            # Add metadata
            if result:
                result['_metadata'] = {
                    'file_path': str(file_path),
                    'analyzer': self.__class__.__name__,
                    'analyzed_at': datetime.now().isoformat(),
                    'file_size_bytes': file_path.stat().st_size,
                    'file_modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")
            return None
    
    def _count_items_found(self, data: Dict[str, Any]) -> int:
        """Count the number of items found in the analysis data."""
        total = 0
        
        for key, value in data.items():
            if key.startswith('_'):  # Skip metadata
                continue
                
            if isinstance(value, list):
                total += len(value)
            elif isinstance(value, dict) and 'count' in value:
                total += value['count']
        
        return total
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for this analyzer."""
        return self.performance_monitor.get_stats()
    
    def reset_performance_stats(self) -> None:
        """Reset performance statistics."""
        self.performance_monitor.reset()
    
    def __str__(self) -> str:
        """String representation of the analyzer."""
        return f"{self.__class__.__name__}(supported_extensions={self._supported_extensions})"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"{self.__class__.__name__}("
            f"supported_extensions={self._supported_extensions}, "
            f"required_patterns={self._required_patterns})"
        )