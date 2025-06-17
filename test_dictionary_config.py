#!/usr/bin/env python3
"""
Test Dictionary Configuration Support
====================================

This script tests that both ConfigurationManager classes
(simple and enhanced) properly handle dictionary input.
"""

def test_simple_config_manager():
    """Test the simple ConfigurationManager in struts_analyzer.py"""
    print("[TEST] Testing Simple ConfigurationManager (struts_analyzer.py)...")
    
    try:
        from struts_analyzer import ConfigurationManager
        
        # Test with dictionary
        config_dict = {
            'analysis': {
                'parallel_workers': 8,
                'cache_enabled': True,
                'deep_analysis': True
            },
            'custom': {
                'setting': 'test_value'
            }
        }
        
        config = ConfigurationManager(config_dict)
        print("   [PASS] Dictionary initialization successful")
        
        # Test that values were merged
        assert config.config['analysis']['parallel_workers'] == 8
        assert config.config['analysis']['cache_enabled'] == True
        assert config.config['custom']['setting'] == 'test_value'
        print("   [PASS] Dictionary values merged correctly")
        
        # Test that defaults are still present
        assert 'max_file_size_mb' in config.config['analysis']
        print("   [PASS] Default values preserved")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] Simple ConfigurationManager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_enhanced_config_manager():
    """Test the enhanced ConfigurationManager in utils/config_utils.py"""
    print("\n[TEST] Testing Enhanced ConfigurationManager (utils/config_utils.py)...")
    
    try:
        from utils.config_utils import ConfigurationManager
        
        # Test with dictionary
        config_dict = {
            'analysis': {
                'parallel_workers': 12,
                'index_path': ':memory:'
            },
            'logging': {
                'level': 'DEBUG'
            }
        }
        
        config = ConfigurationManager(config_dict)
        print("   [PASS] Dictionary initialization successful")
        
        # Test using dot notation access
        parallel_workers = config.get('analysis.parallel_workers')
        assert parallel_workers == 12
        print(f"   [PASS] Dot notation access: analysis.parallel_workers = {parallel_workers}")
        
        # Test setting values
        config.set('analysis.timeout_seconds', 600)
        timeout = config.get('analysis.timeout_seconds')
        assert timeout == 600
        print(f"   [PASS] Set/get functionality: timeout_seconds = {timeout}")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] Enhanced ConfigurationManager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_business_rule_engine_with_dict():
    """Test BusinessRuleEngine with dictionary configuration"""
    print("\n[TEST] Testing BusinessRuleEngine with dictionary config...")
    
    try:
        from business_rule_engine import BusinessRuleEngine
        from utils.config_utils import ConfigurationManager
        
        config_dict = {
            'analysis': {
                'index_path': ':memory:',
                'parallel_enabled': False,
                'cache_enabled': False
            }
        }
        
        config = ConfigurationManager(config_dict)
        engine = BusinessRuleEngine(config)
        print("   [PASS] BusinessRuleEngine initialized with dictionary config")
        
        return True
        
    except Exception as e:
        print(f"   [FAIL] BusinessRuleEngine dictionary test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all dictionary configuration tests"""
    print("[DICT] Dictionary Configuration Test Suite")
    print("=" * 50)
    
    tests = [
        ("Simple ConfigurationManager", test_simple_config_manager),
        ("Enhanced ConfigurationManager", test_enhanced_config_manager),
        ("BusinessRuleEngine", test_business_rule_engine_with_dict),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"[PASS] {test_name} - SUCCESS")
            else:
                print(f"[FAIL] {test_name} - FAILED")
        except Exception as e:
            print(f"[CRASH] {test_name} - CRASHED: {e}")
    
    print(f"\n{'='*50}")
    print(f"[SUMMARY] Dictionary Tests: {passed}/{total} passed")
    print("=" * 50)
    
    if passed == total:
        print("[EXCELLENT] All dictionary configuration tests passed!")
        print("[INFO] Both ConfigurationManager classes support dictionary input")
    else:
        print("[ISSUE] Some dictionary configuration tests failed")
        print("[FIX] Check the failed tests above")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)