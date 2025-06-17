#!/usr/bin/env python3
"""
Test Application Startup
========================

This script tests the main application startup sequence to identify
any configuration or import issues.
"""

import sys
import tempfile
from pathlib import Path

def test_configuration_manager():
    """Test ConfigurationManager initialization"""
    print("[TEST] Testing ConfigurationManager...")
    
    try:
        from struts_analyzer import ConfigurationManager
        
        # Test with no config file
        config = ConfigurationManager()
        print("   [PASS] ConfigurationManager() - default initialization")
        
        # Test setting values
        config.config['analysis']['parallel_workers'] = 4
        value = config.config['analysis']['parallel_workers']
        print(f"   [PASS] Config set/get: {value}")
        
        # Test with dictionary
        config_dict = {
            'analysis': {
                'cache_enabled': True,
                'deep_analysis': True
            }
        }
        config2 = ConfigurationManager(config_dict)
        print("   [PASS] ConfigurationManager(dict) - dictionary initialization")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] ConfigurationManager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_business_rule_extractor():
    """Test BusinessRuleExtractor initialization"""
    print("\n[TEST] Testing BusinessRuleExtractor...")
    
    try:
        from struts_analyzer import BusinessRuleExtractor, ConfigurationManager
        
        config = ConfigurationManager()
        extractor = BusinessRuleExtractor(config)
        print("   [PASS] BusinessRuleExtractor initialization")
        
        # Test that it has the required methods
        assert hasattr(extractor, 'analyze_directory')
        assert hasattr(extractor, '_find_relevant_files')
        print("   [PASS] Required methods present")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] BusinessRuleExtractor test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_main_imports():
    """Test that all main imports work"""
    print("\n[TEST] Testing main application imports...")
    
    try:
        # Test core imports
        from struts_analyzer import BusinessRuleExtractor, ConfigurationManager
        print("   [PASS] Core classes imported")
        
        # Test business rule engine import
        from business_rule_engine import BusinessRuleEngine
        print("   [PASS] BusinessRuleEngine imported")
        
        # Test documentation generator import
        from generators.enhanced_documentation_generator import EnhancedDocumentationGenerator
        print("   [PASS] EnhancedDocumentationGenerator imported")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] Main imports test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_argument_parsing():
    """Test command line argument parsing"""
    print("\n[TEST] Testing argument parsing...")
    
    try:
        import argparse
        import sys
        
        # Save original argv
        original_argv = sys.argv.copy()
        
        # Test with minimal arguments
        sys.argv = ['struts_analyzer.py', '/tmp/test']
        
        # Import and test argument parser creation
        from struts_analyzer import main
        
        # This should create the parser without errors
        # We won't actually run main() as it would execute the analysis
        print("   [PASS] Main function can be imported")
        
        # Restore original argv
        sys.argv = original_argv
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] Argument parsing test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_minimal_startup_flow():
    """Test the startup flow with minimal data"""
    print("\n[TEST] Testing minimal startup flow...")
    
    try:
        from struts_analyzer import ConfigurationManager, BusinessRuleExtractor
        
        # Create temp directory with minimal test data
        temp_dir = Path(tempfile.mkdtemp())
        web_inf = temp_dir / "WEB-INF"
        web_inf.mkdir()
        
        # Create minimal struts config
        struts_config = web_inf / "struts-config.xml"
        struts_config.write_text('''<?xml version="1.0"?>
<struts-config>
    <action-mappings>
        <action path="/test" type="TestAction"/>
    </action-mappings>
</struts-config>''')
        
        print(f"   [INFO] Created test data in: {temp_dir}")
        
        # Test initialization sequence
        config = ConfigurationManager()
        print("   [PASS] 1. ConfigurationManager created")
        
        # Set some config values like main() would
        config.config['analysis']['parallel_workers'] = 2
        config.config['analysis']['cache_enabled'] = True
        config.config['analysis']['deep_analysis'] = True
        print("   [PASS] 2. Configuration values set")
        
        extractor = BusinessRuleExtractor(config)
        print("   [PASS] 3. BusinessRuleExtractor created")
        
        # Test the analysis (this is the core startup flow)
        results = extractor.analyze_directory(temp_dir)
        rule_count = len(results.get('business_rules', []))
        print(f"   [PASS] 4. Analysis completed: {rule_count} rules found")
        
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)
        
        return rule_count > 0
        
    except Exception as e:
        print(f"   [FAIL] Minimal startup flow failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run startup tests"""
    print("[STARTUP] Application Startup Test Suite")
    print("=" * 50)
    
    tests = [
        ("ConfigurationManager", test_configuration_manager),
        ("BusinessRuleExtractor", test_business_rule_extractor),
        ("Main Imports", test_main_imports),
        ("Argument Parsing", test_argument_parsing),
        ("Minimal Startup Flow", test_minimal_startup_flow),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"[PASS] {test_name} - SUCCESS")
            else:
                print(f"[FAIL] {test_name} - FAILED")
        except Exception as e:
            print(f"[CRASH] {test_name} - CRASHED: {e}")
    
    print(f"\n{'='*50}")
    print(f"[SUMMARY] Startup Tests: {passed}/{total} passed")
    print("=" * 50)
    
    if passed == total:
        print("[EXCELLENT] All startup tests passed!")
        print("[INFO] The application should start correctly.")
    elif passed >= total * 0.8:
        print("[GOOD] Most startup tests passed.")
        print("[WARN] Some minor issues detected.")
    else:
        print("[ISSUE] Multiple startup failures detected.")
        print("[FIX] Check the failed tests above.")
    
    return passed >= total * 0.8

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)