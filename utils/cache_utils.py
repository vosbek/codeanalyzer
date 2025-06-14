"""
Cache Management Utilities
===========================

This module provides caching functionality for the Struts analysis system.
It implements both in-memory and disk-based caching to improve performance
when analyzing large codebases with repeated operations.

Features:
- File-based caching with content hash validation
- In-memory LRU cache for frequently accessed data
- Cache invalidation and cleanup
- Performance metrics and cache hit rates
- Configurable cache sizes and TTL

Author: Claude Code Assistant
"""

import os
import pickle
import json
import hashlib
import threading
import time
from pathlib import Path
from typing import Any, Optional, Dict, Union, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from functools import wraps, lru_cache
import weakref


logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class CacheEntry:
    """Represents a cache entry with metadata."""
    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    content_hash: Optional[str] = None
    ttl_seconds: Optional[int] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if self.ttl_seconds is None:
            return False
        return (datetime.now() - self.created_at).total_seconds() > self.ttl_seconds
    
    @property
    def age_seconds(self) -> float:
        """Get age of cache entry in seconds."""
        return (datetime.now() - self.created_at).total_seconds()
    
    def touch(self) -> None:
        """Update last accessed time and increment access count."""
        self.last_accessed = datetime.now()
        self.access_count += 1


@dataclass
class CacheStats:
    """Cache performance statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    errors: int = 0
    total_size_bytes: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    @property
    def total_requests(self) -> int:
        """Get total number of cache requests."""
        return self.hits + self.misses
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            'hits': self.hits,
            'misses': self.misses,
            'evictions': self.evictions,
            'errors': self.errors,
            'total_size_bytes': self.total_size_bytes,
            'hit_rate': self.hit_rate,
            'total_requests': self.total_requests
        }


class LRUCache(Generic[T]):
    """Thread-safe LRU cache implementation."""
    
    def __init__(self, max_size: int = 1000, default_ttl: Optional[int] = None):
        """
        Initialize LRU cache.
        
        Args:
            max_size: Maximum number of entries
            default_ttl: Default TTL in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self.stats = CacheStats()
    
    def get(self, key: str) -> Optional[T]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            if key not in self._cache:
                self.stats.misses += 1
                return None
            
            entry = self._cache[key]
            
            # Check if expired
            if entry.is_expired:
                del self._cache[key]
                self.stats.misses += 1
                self.stats.evictions += 1
                return None
            
            # Update access info
            entry.touch()
            
            # Move to end (most recently used)
            self._cache[key] = self._cache.pop(key)
            
            self.stats.hits += 1
            return entry.value
    
    def put(self, key: str, value: T, ttl: Optional[int] = None) -> None:
        """
        Put value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL in seconds (overrides default)
        """
        with self._lock:
            # Use provided TTL or default
            effective_ttl = ttl if ttl is not None else self.default_ttl
            
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                last_accessed=datetime.now(),
                access_count=1,
                ttl_seconds=effective_ttl
            )
            
            # Remove existing entry if present
            if key in self._cache:
                del self._cache[key]
            
            # Add new entry
            self._cache[key] = entry
            
            # Evict oldest entries if over limit
            while len(self._cache) > self.max_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                self.stats.evictions += 1
    
    def remove(self, key: str) -> bool:
        """
        Remove entry from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if entry was removed, False if not found
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            evicted_count = len(self._cache)
            self._cache.clear()
            self.stats.evictions += evicted_count
    
    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries.
        
        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired
            ]
            
            for key in expired_keys:
                del self._cache[key]
            
            self.stats.evictions += len(expired_keys)
            return len(expired_keys)


class DiskCache:
    """Disk-based cache with file validation."""
    
    def __init__(self, cache_dir: Union[str, Path] = ".struts_analyzer_cache",
                 max_size_mb: float = 500.0):
        """
        Initialize disk cache.
        
        Args:
            cache_dir: Directory for cache files
            max_size_mb: Maximum cache size in MB
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.max_size_bytes = int(max_size_mb * 1024 * 1024)
        self.stats = CacheStats()
        self._lock = threading.Lock()
    
    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for key."""
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.cache"
    
    def _get_meta_path(self, key: str) -> Path:
        """Get metadata file path for key."""
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.meta"
    
    def _calculate_content_hash(self, file_path: Path) -> str:
        """Calculate content hash for file validation."""
        if not file_path.exists():
            return ""
        
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""
    
    def get(self, key: str, source_file: Optional[Path] = None) -> Optional[Any]:
        """
        Get value from disk cache.
        
        Args:
            key: Cache key
            source_file: Source file for validation
            
        Returns:
            Cached value or None if not found/invalid
        """
        with self._lock:
            cache_path = self._get_cache_path(key)
            meta_path = self._get_meta_path(key)
            
            if not cache_path.exists() or not meta_path.exists():
                self.stats.misses += 1
                return None
            
            try:
                # Load metadata
                with open(meta_path, 'r') as f:
                    metadata = json.load(f)
                
                # Check TTL
                if 'ttl_seconds' in metadata and metadata['ttl_seconds'] is not None:
                    created_at = datetime.fromisoformat(metadata['created_at'])
                    if (datetime.now() - created_at).total_seconds() > metadata['ttl_seconds']:
                        self._remove_cache_files(cache_path, meta_path)
                        self.stats.misses += 1
                        self.stats.evictions += 1
                        return None
                
                # Validate source file if provided
                if source_file and source_file.exists():
                    current_hash = self._calculate_content_hash(source_file)
                    cached_hash = metadata.get('content_hash', '')
                    
                    if current_hash != cached_hash:
                        self._remove_cache_files(cache_path, meta_path)
                        self.stats.misses += 1
                        self.stats.evictions += 1
                        return None
                
                # Load cached data
                with open(cache_path, 'rb') as f:
                    data = pickle.load(f)
                
                # Update access time in metadata
                metadata['last_accessed'] = datetime.now().isoformat()
                metadata['access_count'] = metadata.get('access_count', 0) + 1
                
                with open(meta_path, 'w') as f:
                    json.dump(metadata, f)
                
                self.stats.hits += 1
                return data
                
            except Exception as e:
                logger.warning(f"Error reading cache for key {key}: {e}")
                self._remove_cache_files(cache_path, meta_path)
                self.stats.errors += 1
                self.stats.misses += 1
                return None
    
    def put(self, key: str, value: Any, source_file: Optional[Path] = None,
            ttl: Optional[int] = None) -> bool:
        """
        Put value in disk cache.
        
        Args:
            key: Cache key
            value: Value to cache
            source_file: Source file for validation
            ttl: TTL in seconds
            
        Returns:
            True if successfully cached
        """
        with self._lock:
            try:
                cache_path = self._get_cache_path(key)
                meta_path = self._get_meta_path(key)
                
                # Create metadata
                metadata = {
                    'key': key,
                    'created_at': datetime.now().isoformat(),
                    'last_accessed': datetime.now().isoformat(),
                    'access_count': 1,
                    'ttl_seconds': ttl
                }
                
                # Add content hash if source file provided
                if source_file and source_file.exists():
                    metadata['content_hash'] = self._calculate_content_hash(source_file)
                
                # Write data and metadata
                with open(cache_path, 'wb') as f:
                    pickle.dump(value, f)
                
                with open(meta_path, 'w') as f:
                    json.dump(metadata, f)
                
                # Check cache size and cleanup if needed
                self._cleanup_if_needed()
                
                return True
                
            except Exception as e:
                logger.error(f"Error caching data for key {key}: {e}")
                self.stats.errors += 1
                return False
    
    def remove(self, key: str) -> bool:
        """
        Remove entry from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if entry was removed
        """
        with self._lock:
            cache_path = self._get_cache_path(key)
            meta_path = self._get_meta_path(key)
            
            removed = False
            if cache_path.exists():
                cache_path.unlink()
                removed = True
            if meta_path.exists():
                meta_path.unlink()
                removed = True
            
            return removed
    
    def _remove_cache_files(self, cache_path: Path, meta_path: Path) -> None:
        """Remove cache and metadata files."""
        try:
            if cache_path.exists():
                cache_path.unlink()
            if meta_path.exists():
                meta_path.unlink()
        except Exception as e:
            logger.warning(f"Error removing cache files: {e}")
    
    def _cleanup_if_needed(self) -> None:
        """Cleanup cache if size limit exceeded."""
        total_size = sum(
            f.stat().st_size 
            for f in self.cache_dir.iterdir() 
            if f.is_file()
        )
        
        if total_size > self.max_size_bytes:
            self._cleanup_by_lru()
    
    def _cleanup_by_lru(self) -> None:
        """Cleanup cache using LRU strategy."""
        cache_files = []
        
        # Collect all cache files with metadata
        for cache_file in self.cache_dir.glob("*.cache"):
            meta_file = cache_file.with_suffix('.meta')
            if meta_file.exists():
                try:
                    with open(meta_file, 'r') as f:
                        metadata = json.load(f)
                    
                    last_accessed = datetime.fromisoformat(
                        metadata.get('last_accessed', metadata['created_at'])
                    )
                    
                    cache_files.append((last_accessed, cache_file, meta_file))
                except Exception:
                    # Remove corrupted files
                    self._remove_cache_files(cache_file, meta_file)
        
        # Sort by last accessed (oldest first)
        cache_files.sort(key=lambda x: x[0])
        
        # Remove oldest entries until under size limit
        current_size = sum(
            f.stat().st_size 
            for f in self.cache_dir.iterdir() 
            if f.is_file()
        )
        
        removed_count = 0
        for _, cache_file, meta_file in cache_files:
            if current_size <= self.max_size_bytes:
                break
            
            file_size = cache_file.stat().st_size + meta_file.stat().st_size
            self._remove_cache_files(cache_file, meta_file)
            current_size -= file_size
            removed_count += 1
        
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} cache entries due to size limit")
            self.stats.evictions += removed_count
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            removed_count = 0
            for cache_file in self.cache_dir.glob("*"):
                if cache_file.is_file():
                    cache_file.unlink()
                    removed_count += 1
            
            self.stats.evictions += removed_count // 2  # Approximate (cache + meta files)
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information."""
        cache_files = list(self.cache_dir.glob("*.cache"))
        total_size = sum(
            f.stat().st_size 
            for f in self.cache_dir.iterdir() 
            if f.is_file()
        )
        
        return {
            'cache_dir': str(self.cache_dir),
            'entry_count': len(cache_files),
            'total_size_bytes': total_size,
            'total_size_mb': total_size / 1024 / 1024,
            'max_size_mb': self.max_size_bytes / 1024 / 1024,
            'stats': self.stats.to_dict()
        }


class CacheManager:
    """Combined cache manager with memory and disk caching."""
    
    def __init__(self, 
                 memory_cache_size: int = 1000,
                 disk_cache_dir: Union[str, Path] = ".struts_analyzer_cache",
                 disk_cache_size_mb: float = 500.0,
                 default_ttl: Optional[int] = None):
        """
        Initialize cache manager.
        
        Args:
            memory_cache_size: Size of in-memory cache
            disk_cache_dir: Directory for disk cache
            disk_cache_size_mb: Maximum disk cache size in MB
            default_ttl: Default TTL in seconds
        """
        self.memory_cache = LRUCache(memory_cache_size, default_ttl)
        self.disk_cache = DiskCache(disk_cache_dir, disk_cache_size_mb)
        self.enabled = True
    
    def get(self, key: str, source_file: Optional[Path] = None) -> Optional[Any]:
        """
        Get value from cache (memory first, then disk).
        
        Args:
            key: Cache key
            source_file: Source file for validation
            
        Returns:
            Cached value or None if not found
        """
        if not self.enabled:
            return None
        
        # Try memory cache first
        value = self.memory_cache.get(key)
        if value is not None:
            return value
        
        # Try disk cache
        value = self.disk_cache.get(key, source_file)
        if value is not None:
            # Put in memory cache for faster access
            self.memory_cache.put(key, value)
            return value
        
        return None
    
    def put(self, key: str, value: Any, source_file: Optional[Path] = None,
            ttl: Optional[int] = None, disk_only: bool = False) -> bool:
        """
        Put value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            source_file: Source file for validation
            ttl: TTL in seconds
            disk_only: If True, only cache on disk
            
        Returns:
            True if successfully cached
        """
        if not self.enabled:
            return False
        
        success = True
        
        # Cache on disk
        if not self.disk_cache.put(key, value, source_file, ttl):
            success = False
        
        # Cache in memory unless disk_only
        if not disk_only:
            self.memory_cache.put(key, value, ttl)
        
        return success
    
    def remove(self, key: str) -> bool:
        """
        Remove entry from both caches.
        
        Args:
            key: Cache key
            
        Returns:
            True if any cache had the entry
        """
        memory_removed = self.memory_cache.remove(key)
        disk_removed = self.disk_cache.remove(key)
        return memory_removed or disk_removed
    
    def clear(self) -> None:
        """Clear both caches."""
        self.memory_cache.clear()
        self.disk_cache.clear()
    
    def cleanup(self) -> Dict[str, int]:
        """
        Cleanup expired entries.
        
        Returns:
            Dictionary with cleanup statistics
        """
        memory_cleaned = self.memory_cache.cleanup_expired()
        # Disk cache cleanup is handled automatically
        
        return {
            'memory_entries_removed': memory_cleaned,
            'disk_entries_removed': 0  # Not tracked separately
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        return {
            'memory_cache': {
                'size': self.memory_cache.size(),
                'max_size': self.memory_cache.max_size,
                'stats': self.memory_cache.stats.to_dict()
            },
            'disk_cache': self.disk_cache.get_cache_info(),
            'enabled': self.enabled
        }
    
    def enable(self) -> None:
        """Enable caching."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable caching."""
        self.enabled = False


def cached(cache_manager: CacheManager, 
          key_generator: Optional[Callable] = None,
          ttl: Optional[int] = None,
          disk_only: bool = False):
    """
    Decorator for caching function results.
    
    Args:
        cache_manager: Cache manager instance
        key_generator: Function to generate cache key
        ttl: TTL in seconds
        disk_only: If True, only use disk cache
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_generator:
                cache_key = key_generator(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            # Try to get from cache
            result = cache_manager.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_manager.put(cache_key, result, ttl=ttl, disk_only=disk_only)
            
            return result
        
        return wrapper
    return decorator