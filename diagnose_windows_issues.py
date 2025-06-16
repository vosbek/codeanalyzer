#!/usr/bin/env python3
"""
Windows Issues Diagnostic Script
================================

This script provides detailed diagnostics to help identify specific
issues in the Windows environment that might be causing test failures.
"""

import sys
import os
import traceback
import tempfile
from pathlib import Path

def test_basic_imports():
    """Test basic imports that are required"""
    print("[TESTING] Testing Basic Imports...")
    
    import_tests = [
        ('pathlib', lambda: __import__('pathlib')),
        ('tempfile', lambda: __import__('tempfile')),
        ('xml.etree.ElementTree', lambda: __import__('xml.etree.ElementTree')),
        ('re', lambda: __import__('re')),
        ('collections', lambda: __import__('collections')),
        ('dataclasses', lambda: __import__('dataclasses')),
    ]
    
    for name, import_func in import_tests:
        try:
            import_func()
            print(f"   [PASS] {name}")
        except Exception as e:
            print(f"   [FAIL] {name}: {e}")

def test_analyzer_imports():
    """Test importing the main analyzer components"""
    print("\n[TEST] Testing Analyzer Imports...")
    
    try:
        print("   Testing struts_analyzer import...")
        from struts_analyzer import BusinessRuleExtractor, ConfigurationManager
        print("   [PASS] struts_analyzer - main classes imported successfully")
        
        print("   Testing configuration manager...")
        config = ConfigurationManager()
        print("   [PASS] ConfigurationManager - initialized successfully")
        
        print("   Testing business rule extractor...")
        extractor = BusinessRuleExtractor(config)
        print("   [PASS] BusinessRuleExtractor - initialized successfully")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] Analyzer import failed: {e}")
        print("   [INFO] Full traceback:")
        traceback.print_exc()
        return False

def test_networkx_specifically():
    """Test NetworkX specifically since that's been problematic"""
    print("\n[NET]  Testing NetworkX specifically...")
    
    try:
        import networkx as nx
        print(f"   [PASS] NetworkX imported successfully: {nx.__version__}")
        
        # Test basic graph creation
        graph = nx.DiGraph()
        graph.add_node("test")
        graph.add_edge("test", "test2")
        print(f"   [PASS] NetworkX basic operations work (nodes: {len(graph.nodes())})")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] NetworkX test failed: {e}")
        traceback.print_exc()
        return False

def test_business_rule_engine_imports():
    """Test the new business rule engine imports"""
    print("\n[FIX] Testing Business Rule Engine Imports...")
    
    try:
        print("   Testing business_rule_engine import...")
        from business_rule_engine import BusinessRuleEngine
        print("   [PASS] business_rule_engine imported successfully")
        
        print("   Testing configuration manager for engine...")
        from utils.config_utils import ConfigurationManager
        config_data = {'analysis': {'index_path': ':memory:', 'parallel_enabled': False}}
        config = ConfigurationManager(config_data)
        print("   [PASS] ConfigurationManager with dictionary works")
        
        print("   Testing engine initialization...")
        engine = BusinessRuleEngine(config)
        print("   [PASS] BusinessRuleEngine initialized successfully")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] Business rule engine test failed: {e}")
        print("   [INFO] Full traceback:")
        traceback.print_exc()
        return False

def test_temp_file_operations():
    """Test temporary file operations that tests use"""
    print("\n[FILES] Testing Temporary File Operations...")
    
    try:
        # Test creating temp directory
        temp_dir = Path(tempfile.mkdtemp())
        print(f"   [PASS] Temp directory created: {temp_dir}")
        
        # Test creating files
        test_file = temp_dir / "test.xml"
        test_file.write_text("<?xml version='1.0'?><root></root>")
        print(f"   [PASS] Test file created: {test_file.exists()}")
        
        # Test reading files
        content = test_file.read_text()
        print(f"   [PASS] File content read: {len(content)} chars")
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        print(f"   [PASS] Cleanup successful")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] File operations test failed: {e}")
        traceback.print_exc()
        return False

def test_minimal_analysis():
    """Test a very minimal analysis to isolate the issue"""
    print("\n[TARGET] Testing Minimal Analysis...")
    
    try:
        from struts_analyzer import BusinessRuleExtractor, ConfigurationManager
        
        # Create minimal test data
        temp_dir = Path(tempfile.mkdtemp())
        web_inf = temp_dir / "WEB-INF"
        web_inf.mkdir()
        
        struts_config = web_inf / "struts-config.xml"
        struts_config.write_text('''<?xml version="1.0" encoding="UTF-8"?>
<struts-config>
    <action-mappings>
        <action path="/test" type="TestAction">
            <forward name="success" path="/success.jsp"/>
        </action>
    </action-mappings>
</struts-config>''')
        
        print(f"   [PASS] Test files created in: {temp_dir}")
        
        # Try analysis
        config = ConfigurationManager()
        extractor = BusinessRuleExtractor(config)
        
        print("   [TESTING] Running analysis...")
        results = extractor.analyze_directory(temp_dir)
        
        rule_count = len(results['business_rules'])
        print(f"   [PASS] Analysis completed: {rule_count} rules found")
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        
        return rule_count > 0
        
    except Exception as e:
        print(f"   [FAIL] Minimal analysis failed: {e}")
        print("   [INFO] Full traceback:")
        traceback.print_exc()
        return False

def main():
    """Run all diagnostic tests"""
    print("[DIAG] Windows Issues Diagnostic Report")
    print("=" * 60)
    
    tests = [
        ("Basic Imports", test_basic_imports),
        ("Analyzer Imports", test_analyzer_imports),
        ("NetworkX Specific", test_networkx_specifically),
        ("Business Rule Engine", test_business_rule_engine_imports),
        ("File Operations", test_temp_file_operations),
        ("Minimal Analysis", test_minimal_analysis),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"[PASS] {test_name} PASSED")
            else:
                print(f"[FAIL] {test_name} FAILED")
        except Exception as e:
            print(f"[CRASH] {test_name} CRASHED: {e}")
    
    print(f"\n{'='*60}")
    print(f"[INFO] DIAGNOSTIC SUMMARY: {passed}/{total} tests passed")
    print("=" * 60)
    
    if passed == total:
        print("[EXCELLENT] All diagnostics passed! The issue might be test-specific.")
        print("[TIP] Try running the validation again or check for environment differences.")
    elif passed >= total * 0.8:
        print("[WARNING]  Most diagnostics passed. Issue might be in specific components.")
        print("[TESTING] Focus on the failed tests above for troubleshooting.")
    else:
        print("[FAIL] Multiple diagnostic failures detected.")
        print("[FIX] Check Python installation, dependencies, and Windows environment.")
    
    print(f"\n[ENV]  Environment Info:")
    print(f"   Python: {sys.version}")
    print(f"   Platform: {sys.platform}")
    print(f"   Working Directory: {os.getcwd()}")
    print(f"   PATH contains Python: {'python' in os.environ.get('PATH', '').lower()}")

if __name__ == "__main__":
    main()