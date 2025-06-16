#!/usr/bin/env python3
"""
Debug Java Parsing Issues
=========================
"""

import tempfile
from pathlib import Path
from struts_analyzer import JavaActionAnalyzer, ConfigurationManager, CacheManager

def test_simple_java_parsing():
    """Test with a very simple Java file."""
    
    # Create a simple Java file
    temp_dir = Path(tempfile.mkdtemp())
    java_file = temp_dir / "TestAction.java"
    
    simple_java = '''package com.test;

import org.apache.struts.action.Action;
import org.springframework.transaction.annotation.Transactional;

/**
 * Business Rule: This is a test action for user management.
 */
@Transactional
public class TestAction extends Action {
    
    /**
     * Main business logic method.
     */
    public ActionForward execute() {
        // Business logic: Validate user input
        if (isValidUser()) {
            return success();
        }
        return error();
    }
    
    private boolean isValidUser() {
        return true;
    }
}
'''
    
    java_file.write_text(simple_java)
    
    print(f"📁 Created test file: {java_file}")
    print(f"📄 File size: {java_file.stat().st_size} bytes")
    
    # Test the analyzer
    config = ConfigurationManager()
    cache = CacheManager()
    analyzer = JavaActionAnalyzer(config, cache)
    
    print(f"🔍 Can parse file: {analyzer.can_parse(java_file)}")
    
    if analyzer.can_parse(java_file):
        print("🔧 Parsing file...")
        try:
            result = analyzer.parse(java_file)
            print(f"📊 Parse result keys: {result.keys()}")
            print(f"📊 Business rules found: {len(result.get('business_rules', []))}")
            
            for rule in result.get('business_rules', []):
                print(f"   • Rule: {rule}")
                
        except Exception as e:
            print(f"❌ Parse error: {e}")
            import traceback
            traceback.print_exc()
    
    # Test javalang availability
    try:
        import javalang
        print(f"✅ javalang available: {javalang}")
        
        # Try to parse the simple code
        try:
            tree = javalang.parse.parse(simple_java)
            print(f"✅ javalang parsing successful")
            print(f"   Types found: {len(tree.types) if tree.types else 0}")
            
            if tree.types:
                for type_decl in tree.types:
                    print(f"   • Class: {type_decl.name}")
                    if hasattr(type_decl, 'methods'):
                        print(f"     Methods: {len(type_decl.methods or [])}")
                        
        except Exception as e:
            print(f"❌ javalang parsing failed: {e}")
            
    except ImportError:
        print("❌ javalang not available")
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

if __name__ == "__main__":
    test_simple_java_parsing()