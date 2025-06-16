#!/usr/bin/env python3
"""
Simple test of Java parsing
"""

import tempfile
from pathlib import Path
from struts_analyzer import JavaActionAnalyzer, ConfigurationManager, CacheManager

# Create simple test
temp_dir = Path(tempfile.mkdtemp())
java_file = temp_dir / "SimpleAction.java"

java_content = '''
package com.test;

import org.springframework.transaction.annotation.Transactional;

@Transactional
public class SimpleAction {
    public void execute() {
        // Business logic here
    }
}
'''

java_file.write_text(java_content)

# Test parsing
config = ConfigurationManager()
cache = CacheManager()
analyzer = JavaActionAnalyzer(config, cache)

print(f"Testing file: {java_file}")
print(f"Can parse: {analyzer.can_parse(java_file)}")

try:
    result = analyzer.parse(java_file)
    print(f"Parse successful!")
    print(f"Result keys: {list(result.keys())}")
    print(f"Business rules: {len(result.get('business_rules', []))}")
    
    for rule in result.get('business_rules', []):
        print(f"  - {rule.name}: {rule.type}")
        
except Exception as e:
    print(f"Parse failed: {e}")
    import traceback
    traceback.print_exc()

# Cleanup
import shutil
shutil.rmtree(temp_dir)