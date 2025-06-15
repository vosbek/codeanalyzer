"""
Performance Monitoring Utilities
=================================

This module provides performance monitoring and optimization utilities for the
Struts analysis system. It includes timing decorators, memory profiling,
and performance metrics collection.

Features:
- Function execution timing
- Memory usage monitoring
- Performance bottleneck identification
- Resource usage tracking
- Optimization recommendations

Author: Claude Code Assistant
"""

import time
import threading
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable, Union
from functools import wraps
from datetime import datetime, timedelta
import logging
import gc
import sys


logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Represents a single performance metric."""
    name: str
    duration_seconds: float
    memory_used_mb: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_ms(self) -> float:
        """Get duration in milliseconds."""
        return self.duration_seconds * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'duration_seconds': self.duration_seconds,
            'duration_ms': self.duration_ms,
            'memory_used_mb': self.memory_used_mb,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }


@dataclass
class MemorySnapshot:
    """Represents a memory usage snapshot."""
    total_mb: float
    available_mb: float
    used_mb: float
    percent_used: float
    process_memory_mb: float
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'total_mb': self.total_mb,
            'available_mb': self.available_mb,
            'used_mb': self.used_mb,
            'percent_used': self.percent_used,
            'process_memory_mb': self.process_memory_mb,
            'timestamp': self.timestamp.isoformat()
        }


class PerformanceMonitor:
    """
    Monitors and tracks performance metrics for analysis operations.
    
    Provides timing, memory monitoring, and performance analysis
    capabilities with minimal overhead.
    """
    
    def __init__(self, auto_gc: bool = True, gc_frequency: int = 100):
        """
        Initialize performance monitor.
        
        Args:
            auto_gc: Whether to automatically trigger garbage collection
            gc_frequency: How often to trigger GC (every N measurements)
        """
        self.metrics: List[PerformanceMetric] = []
        self.memory_snapshots: List[MemorySnapshot] = []
        self.start_time = datetime.now()
        self.auto_gc = auto_gc
        self.gc_frequency = gc_frequency
        self.measurement_count = 0
        self._lock = threading.Lock()
        
        # Process monitoring
        self.process = psutil.Process()
        
        # Performance thresholds
        self.slow_operation_threshold_seconds = 5.0
        self.memory_warning_threshold_mb = 1024.0
    
    def take_memory_snapshot(self) -> MemorySnapshot:
        """Take a snapshot of current memory usage."""
        # System memory
        memory = psutil.virtual_memory()
        
        # Process memory
        process_memory = self.process.memory_info()
        
        snapshot = MemorySnapshot(
            total_mb=memory.total / 1024 / 1024,
            available_mb=memory.available / 1024 / 1024,
            used_mb=memory.used / 1024 / 1024,
            percent_used=memory.percent,
            process_memory_mb=process_memory.rss / 1024 / 1024,
            timestamp=datetime.now()
        )
        
        with self._lock:
            self.memory_snapshots.append(snapshot)
        
        return snapshot
    
    @contextmanager
    def measure(self, operation_name: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Context manager for measuring operation performance.
        
        Args:
            operation_name: Name of the operation being measured
            metadata: Optional metadata to include with the metric
        """
        start_time = time.perf_counter()
        start_memory = self.take_memory_snapshot()
        
        try:
            yield
        finally:
            end_time = time.perf_counter()
            end_memory = self.take_memory_snapshot()
            
            duration = end_time - start_time
            memory_used = end_memory.process_memory_mb - start_memory.process_memory_mb
            
            metric = PerformanceMetric(
                name=operation_name,
                duration_seconds=duration,
                memory_used_mb=memory_used,
                timestamp=datetime.now(),
                metadata=metadata or {}
            )
            
            with self._lock:
                self.metrics.append(metric)
                self.measurement_count += 1
            
            # Log slow operations
            if duration > self.slow_operation_threshold_seconds:
                logger.warning(
                    f"Slow operation detected: {operation_name} took {duration:.2f}s"
                )
            
            # Trigger garbage collection if needed
            if self.auto_gc and self.measurement_count % self.gc_frequency == 0:
                gc.collect()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        with self._lock:
            if not self.metrics:
                return {
                    'total_operations': 0,
                    'total_runtime_seconds': 0,
                    'memory_stats': {},
                    'operation_stats': {}
                }
            
            # Calculate total runtime
            total_runtime = (datetime.now() - self.start_time).total_seconds()
            
            # Calculate operation statistics
            operation_stats = self._calculate_operation_stats()
            
            # Calculate memory statistics
            memory_stats = self._calculate_memory_stats()
            
            # Identify bottlenecks
            bottlenecks = self._identify_bottlenecks()
            
            return {
                'total_operations': len(self.metrics),
                'total_runtime_seconds': total_runtime,
                'operation_stats': operation_stats,
                'memory_stats': memory_stats,
                'bottlenecks': bottlenecks,
                'gc_collections': gc.get_count(),
                'system_info': self._get_system_info()
            }
    
    def _calculate_operation_stats(self) -> Dict[str, Any]:
        """Calculate statistics for operations."""
        durations = [m.duration_seconds for m in self.metrics]
        memory_usage = [m.memory_used_mb for m in self.metrics]
        
        # Group by operation name
        operation_groups = {}
        for metric in self.metrics:
            if metric.name not in operation_groups:
                operation_groups[metric.name] = []
            operation_groups[metric.name].append(metric)
        
        # Calculate per-operation statistics
        per_operation_stats = {}
        for op_name, metrics in operation_groups.items():
            op_durations = [m.duration_seconds for m in metrics]
            op_memory = [m.memory_used_mb for m in metrics]
            
            per_operation_stats[op_name] = {
                'count': len(metrics),
                'total_duration_seconds': sum(op_durations),
                'avg_duration_seconds': sum(op_durations) / len(op_durations),
                'min_duration_seconds': min(op_durations),
                'max_duration_seconds': max(op_durations),
                'total_memory_mb': sum(op_memory),
                'avg_memory_mb': sum(op_memory) / len(op_memory),
                'min_memory_mb': min(op_memory),
                'max_memory_mb': max(op_memory)
            }
        
        return {
            'total_duration_seconds': sum(durations),
            'avg_duration_seconds': sum(durations) / len(durations),
            'min_duration_seconds': min(durations),
            'max_duration_seconds': max(durations),
            'total_memory_mb': sum(memory_usage),
            'avg_memory_mb': sum(memory_usage) / len(memory_usage),
            'per_operation': per_operation_stats
        }
    
    def _calculate_memory_stats(self) -> Dict[str, Any]:
        """Calculate memory usage statistics."""
        if not self.memory_snapshots:
            return {}
        
        process_memory = [s.process_memory_mb for s in self.memory_snapshots]
        system_memory_used = [s.used_mb for s in self.memory_snapshots]
        
        current_snapshot = self.memory_snapshots[-1]
        
        return {
            'current_process_memory_mb': current_snapshot.process_memory_mb,
            'current_system_memory_used_mb': current_snapshot.used_mb,
            'current_system_memory_percent': current_snapshot.percent_used,
            'peak_process_memory_mb': max(process_memory),
            'avg_process_memory_mb': sum(process_memory) / len(process_memory),
            'peak_system_memory_mb': max(system_memory_used),
            'memory_warning': current_snapshot.process_memory_mb > self.memory_warning_threshold_mb
        }
    
    def _identify_bottlenecks(self) -> List[Dict[str, Any]]:
        """Identify performance bottlenecks."""
        bottlenecks = []
        
        # Group metrics by operation
        operation_groups = {}
        for metric in self.metrics:
            if metric.name not in operation_groups:
                operation_groups[metric.name] = []
            operation_groups[metric.name].append(metric)
        
        # Find slow operations
        for op_name, metrics in operation_groups.items():
            total_time = sum(m.duration_seconds for m in metrics)
            avg_time = total_time / len(metrics)
            
            if avg_time > self.slow_operation_threshold_seconds:
                bottlenecks.append({
                    'type': 'slow_operation',
                    'operation': op_name,
                    'avg_duration_seconds': avg_time,
                    'total_duration_seconds': total_time,
                    'count': len(metrics),
                    'recommendation': f"Consider optimizing {op_name} - average duration is {avg_time:.2f}s"
                })
        
        # Find memory-intensive operations
        for op_name, metrics in operation_groups.items():
            avg_memory = sum(m.memory_used_mb for m in metrics) / len(metrics)
            
            if avg_memory > 100.0:  # More than 100MB average
                bottlenecks.append({
                    'type': 'memory_intensive',
                    'operation': op_name,
                    'avg_memory_mb': avg_memory,
                    'count': len(metrics),
                    'recommendation': f"Consider memory optimization for {op_name} - uses {avg_memory:.1f}MB on average"
                })
        
        return bottlenecks
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for context."""
        return {
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=None),
            'python_version': sys.version,
            'platform': sys.platform
        }
    
    def reset(self) -> None:
        """Reset all collected metrics."""
        with self._lock:
            self.metrics.clear()
            self.memory_snapshots.clear()
            self.measurement_count = 0
            self.start_time = datetime.now()
        
        # Force garbage collection
        gc.collect()
    
    def export_metrics(self, file_path: str) -> None:
        """Export metrics to a file for analysis."""
        import json
        
        stats = self.get_stats()
        
        # Add individual metrics for detailed analysis
        stats['detailed_metrics'] = [m.to_dict() for m in self.metrics]
        stats['memory_snapshots'] = [s.to_dict() for s in self.memory_snapshots]
        
        with open(file_path, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
        
        logger.info(f"Performance metrics exported to {file_path}")
    
    def get_recommendations(self) -> List[str]:
        """Get performance optimization recommendations."""
        recommendations = []
        stats = self.get_stats()
        
        # Memory recommendations
        memory_stats = stats.get('memory_stats', {})
        if memory_stats.get('memory_warning', False):
            recommendations.append(
                f"High memory usage detected ({memory_stats['current_process_memory_mb']:.1f}MB). "
                "Consider processing files in smaller batches or enabling streaming mode."
            )
        
        # Operation recommendations
        bottlenecks = stats.get('bottlenecks', [])
        for bottleneck in bottlenecks:
            recommendations.append(bottleneck['recommendation'])
        
        # General recommendations
        total_operations = stats.get('total_operations', 0)
        if total_operations > 1000:
            recommendations.append(
                "Large number of operations detected. Consider enabling parallel processing "
                "if not already enabled."
            )
        
        return recommendations


def performance_timer(operation_name: Optional[str] = None):
    """
    Decorator for timing function execution.
    
    Args:
        operation_name: Name for the operation (defaults to function name)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            name = operation_name or f"{func.__module__}.{func.__name__}"
            
            # Try to get monitor from args/kwargs or create a simple one
            monitor = None
            if args and hasattr(args[0], 'performance_monitor'):
                monitor = args[0].performance_monitor
            
            if monitor:
                with monitor.measure(name):
                    return func(*args, **kwargs)
            else:
                # Simple timing without monitor
                start_time = time.perf_counter()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    duration = time.perf_counter() - start_time
                    if duration > 1.0:  # Log slow operations
                        logger.info(f"{name} took {duration:.2f}s")
        
        return wrapper
    return decorator


@contextmanager
def memory_profiler():
    """
    Context manager for profiling memory usage.
    
    Usage:
        with memory_profiler() as profiler:
            # Your code here
            pass
        print(f"Memory used: {profiler.memory_used_mb}MB")
    """
    import tracemalloc
    
    class MemoryProfiler:
        def __init__(self):
            self.memory_used_mb = 0
            self.peak_memory_mb = 0
            self.start_memory = 0
    
    profiler = MemoryProfiler()
    
    # Get initial memory
    process = psutil.Process()
    profiler.start_memory = process.memory_info().rss / 1024 / 1024
    
    # Start tracemalloc for detailed profiling
    tracemalloc.start()
    
    try:
        yield profiler
    finally:
        # Get final memory
        current_memory = process.memory_info().rss / 1024 / 1024
        profiler.memory_used_mb = current_memory - profiler.start_memory
        
        # Get peak memory from tracemalloc
        current, peak = tracemalloc.get_traced_memory()
        profiler.peak_memory_mb = peak / 1024 / 1024
        
        tracemalloc.stop()


def optimize_garbage_collection(threshold_ratio: float = 0.8) -> None:
    """
    Optimize garbage collection settings for better performance.
    
    Args:
        threshold_ratio: Ratio for adjusting GC thresholds
    """
    # Get current thresholds
    thresholds = gc.get_threshold()
    
    # Increase thresholds to reduce GC frequency
    new_thresholds = tuple(int(t * (1 + threshold_ratio)) for t in thresholds)
    gc.set_threshold(*new_thresholds)
    
    logger.info(f"GC thresholds adjusted from {thresholds} to {new_thresholds}")


def profile_function_calls():
    """
    Decorator for profiling function calls (development use only).
    
    This should only be used during development for performance analysis.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            import cProfile
            import pstats
            import io
            
            profiler = cProfile.Profile()
            profiler.enable()
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                profiler.disable()
                
                # Print profiling results
                stream = io.StringIO()
                stats = pstats.Stats(profiler, stream=stream)
                stats.sort_stats('cumulative')
                stats.print_stats(10)  # Top 10 functions
                
                logger.debug(f"Profiling results for {func.__name__}:\n{stream.getvalue()}")
        
        return wrapper
    return decorator