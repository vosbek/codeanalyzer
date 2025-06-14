"""
File Utilities
==============

This module provides file system utilities for the Struts analysis system.
It includes functions for file operations, pattern matching, and path handling
with proper error handling and performance optimization.

Author: Claude Code Assistant
"""

import os
import shutil
from pathlib import Path
from typing import List, Iterator, Union, Optional, Pattern, Callable, Dict, Any
import fnmatch
import re
import hashlib
import tempfile
from datetime import datetime
import logging


logger = logging.getLogger(__name__)


class FileUtils:
    """Utility class for file system operations."""
    
    @staticmethod
    def find_files_by_pattern(directory: Union[str, Path], 
                             patterns: List[str],
                             recursive: bool = True,
                             exclude_patterns: Optional[List[str]] = None) -> List[Path]:
        """
        Find files matching patterns in a directory.
        
        Args:
            directory: Directory to search
            patterns: List of file patterns (glob style)
            recursive: Whether to search recursively
            exclude_patterns: Patterns to exclude
            
        Returns:
            List of matching file paths
        """
        directory_path = Path(directory)
        if not directory_path.exists():
            return []
        
        exclude_patterns = exclude_patterns or []
        found_files = []
        
        for pattern in patterns:
            if recursive:
                matches = directory_path.rglob(pattern)
            else:
                matches = directory_path.glob(pattern)
            
            for file_path in matches:
                if file_path.is_file():
                    # Check exclude patterns
                    excluded = False
                    for exclude_pattern in exclude_patterns:
                        if fnmatch.fnmatch(str(file_path), exclude_pattern):
                            excluded = True
                            break
                    
                    if not excluded:
                        found_files.append(file_path)
        
        return sorted(set(found_files))
    
    @staticmethod
    def get_file_hash(file_path: Union[str, Path], algorithm: str = 'md5') -> str:
        """
        Calculate hash of a file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            Hex digest of file hash
        """
        hash_algo = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_algo.update(chunk)
        
        return hash_algo.hexdigest()
    
    @staticmethod
    def safe_read_file(file_path: Union[str, Path], 
                      encoding: str = 'utf-8',
                      max_size_mb: float = 100.0) -> Optional[str]:
        """
        Safely read a text file with size and encoding checks.
        
        Args:
            file_path: Path to file
            encoding: Text encoding
            max_size_mb: Maximum file size in MB
            
        Returns:
            File content or None if failed
        """
        path = Path(file_path)
        
        try:
            # Check file size
            size_mb = path.stat().st_size / 1024 / 1024
            if size_mb > max_size_mb:
                logger.warning(f"File too large ({size_mb:.1f}MB): {path}")
                return None
            
            # Try to read with specified encoding
            with open(path, 'r', encoding=encoding, errors='replace') as f:
                return f.read()
                
        except Exception as e:
            logger.error(f"Failed to read file {path}: {e}")
            return None
    
    @staticmethod
    def safe_write_file(file_path: Union[str, Path], 
                       content: str,
                       encoding: str = 'utf-8',
                       create_dirs: bool = True,
                       backup: bool = False) -> bool:
        """
        Safely write content to a file.
        
        Args:
            file_path: Path to file
            content: Content to write
            encoding: Text encoding
            create_dirs: Whether to create parent directories
            backup: Whether to backup existing file
            
        Returns:
            True if successful, False otherwise
        """
        path = Path(file_path)
        
        try:
            # Create parent directories if needed
            if create_dirs:
                path.parent.mkdir(parents=True, exist_ok=True)
            
            # Backup existing file if requested
            if backup and path.exists():
                backup_path = path.with_suffix(path.suffix + '.bak')
                shutil.copy2(path, backup_path)
                logger.info(f"Backed up existing file to {backup_path}")
            
            # Write content
            with open(path, 'w', encoding=encoding) as f:
                f.write(content)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to write file {path}: {e}")
            return False
    
    @staticmethod
    def get_file_info(file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Get comprehensive file information.
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary with file information
        """
        path = Path(file_path)
        
        if not path.exists():
            return {'exists': False}
        
        stat = path.stat()
        
        return {
            'exists': True,
            'is_file': path.is_file(),
            'is_dir': path.is_dir(),
            'size_bytes': stat.st_size,
            'size_mb': stat.st_size / 1024 / 1024,
            'created': datetime.fromtimestamp(stat.st_ctime),
            'modified': datetime.fromtimestamp(stat.st_mtime),
            'accessed': datetime.fromtimestamp(stat.st_atime),
            'extension': path.suffix,
            'name': path.name,
            'stem': path.stem,
            'parent': str(path.parent),
            'absolute_path': str(path.absolute())
        }
    
    @staticmethod
    def find_duplicates(directory: Union[str, Path], 
                       file_pattern: str = "*") -> Dict[str, List[Path]]:
        """
        Find duplicate files based on content hash.
        
        Args:
            directory: Directory to search
            file_pattern: File pattern to match
            
        Returns:
            Dictionary mapping hash to list of duplicate files
        """
        directory_path = Path(directory)
        file_hashes = {}
        
        for file_path in directory_path.rglob(file_pattern):
            if file_path.is_file():
                try:
                    file_hash = FileUtils.get_file_hash(file_path)
                    if file_hash not in file_hashes:
                        file_hashes[file_hash] = []
                    file_hashes[file_hash].append(file_path)
                except Exception as e:
                    logger.warning(f"Failed to hash file {file_path}: {e}")
        
        # Return only hashes with multiple files
        return {h: files for h, files in file_hashes.items() if len(files) > 1}
    
    @staticmethod
    def clean_directory(directory: Union[str, Path],
                       patterns: List[str],
                       dry_run: bool = True) -> List[Path]:
        """
        Clean directory by removing files matching patterns.
        
        Args:
            directory: Directory to clean
            patterns: File patterns to remove
            dry_run: If True, only return files that would be removed
            
        Returns:
            List of files that were (or would be) removed
        """
        directory_path = Path(directory)
        removed_files = []
        
        for pattern in patterns:
            for file_path in directory_path.rglob(pattern):
                if file_path.is_file():
                    removed_files.append(file_path)
                    if not dry_run:
                        try:
                            file_path.unlink()
                            logger.info(f"Removed file: {file_path}")
                        except Exception as e:
                            logger.error(f"Failed to remove file {file_path}: {e}")
        
        return removed_files


def find_files_by_pattern(directory: Union[str, Path], 
                         patterns: List[str],
                         recursive: bool = True,
                         exclude_patterns: Optional[List[str]] = None) -> List[Path]:
    """
    Convenience function to find files by pattern.
    
    Args:
        directory: Directory to search
        patterns: List of file patterns
        recursive: Whether to search recursively
        exclude_patterns: Patterns to exclude
        
    Returns:
        List of matching file paths
    """
    return FileUtils.find_files_by_pattern(directory, patterns, recursive, exclude_patterns)


def find_struts_files(directory: Union[str, Path]) -> Dict[str, List[Path]]:
    """
    Find Struts-related files in a directory.
    
    Args:
        directory: Directory to search
        
    Returns:
        Dictionary categorizing found Struts files
    """
    struts_files = {
        'config_files': [],
        'validation_files': [],
        'action_files': [],
        'jsp_files': [],
        'form_files': [],
        'properties_files': []
    }
    
    directory_path = Path(directory)
    
    # Configuration files
    config_patterns = ['*struts*.xml', '*struts-config*.xml']
    struts_files['config_files'] = find_files_by_pattern(
        directory_path, config_patterns
    )
    
    # Validation files
    validation_patterns = ['*validation*.xml', '*validator*.xml']
    struts_files['validation_files'] = find_files_by_pattern(
        directory_path, validation_patterns
    )
    
    # Java Action files
    java_files = find_files_by_pattern(directory_path, ['*.java'])
    for java_file in java_files:
        if 'action' in java_file.name.lower():
            struts_files['action_files'].append(java_file)
        elif 'form' in java_file.name.lower():
            struts_files['form_files'].append(java_file)
    
    # JSP files
    struts_files['jsp_files'] = find_files_by_pattern(
        directory_path, ['*.jsp', '*.jspx']
    )
    
    # Properties files
    struts_files['properties_files'] = find_files_by_pattern(
        directory_path, ['*.properties']
    )
    
    return struts_files


class TemporaryDirectory:
    """Context manager for temporary directories."""
    
    def __init__(self, prefix: str = "struts_analyzer_", cleanup: bool = True):
        """
        Initialize temporary directory context.
        
        Args:
            prefix: Prefix for temporary directory name
            cleanup: Whether to cleanup on exit
        """
        self.prefix = prefix
        self.cleanup = cleanup
        self.path: Optional[Path] = None
    
    def __enter__(self) -> Path:
        """Create and return temporary directory path."""
        self.path = Path(tempfile.mkdtemp(prefix=self.prefix))
        logger.debug(f"Created temporary directory: {self.path}")
        return self.path
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup temporary directory if requested."""
        if self.cleanup and self.path and self.path.exists():
            try:
                shutil.rmtree(self.path)
                logger.debug(f"Cleaned up temporary directory: {self.path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary directory {self.path}: {e}")


class FileMonitor:
    """Monitor files for changes."""
    
    def __init__(self, files: List[Union[str, Path]]):
        """
        Initialize file monitor.
        
        Args:
            files: List of files to monitor
        """
        self.files = [Path(f) for f in files]
        self.last_modified = {}
        self._update_timestamps()
    
    def _update_timestamps(self) -> None:
        """Update stored file timestamps."""
        for file_path in self.files:
            if file_path.exists():
                self.last_modified[file_path] = file_path.stat().st_mtime
            else:
                self.last_modified[file_path] = None
    
    def check_changes(self) -> List[Path]:
        """
        Check for file changes since last check.
        
        Returns:
            List of files that have changed
        """
        changed_files = []
        
        for file_path in self.files:
            if file_path.exists():
                current_mtime = file_path.stat().st_mtime
                last_mtime = self.last_modified.get(file_path)
                
                if last_mtime is None or current_mtime > last_mtime:
                    changed_files.append(file_path)
            elif self.last_modified.get(file_path) is not None:
                # File was deleted
                changed_files.append(file_path)
        
        # Update timestamps
        self._update_timestamps()
        
        return changed_files


def backup_file(file_path: Union[str, Path], 
               backup_dir: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """
    Create a backup of a file.
    
    Args:
        file_path: File to backup
        backup_dir: Directory for backup (defaults to file's directory)
        
    Returns:
        Path to backup file or None if failed
    """
    source_path = Path(file_path)
    
    if not source_path.exists():
        logger.error(f"Cannot backup non-existent file: {source_path}")
        return None
    
    # Determine backup location
    if backup_dir:
        backup_directory = Path(backup_dir)
        backup_directory.mkdir(parents=True, exist_ok=True)
        backup_path = backup_directory / f"{source_path.name}.bak"
    else:
        backup_path = source_path.with_suffix(source_path.suffix + '.bak')
    
    try:
        shutil.copy2(source_path, backup_path)
        logger.info(f"Created backup: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create backup of {source_path}: {e}")
        return None