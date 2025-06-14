#!/usr/bin/env python3
"""
System Structure Test
====================

This test validates that all the components of the Struts analyzer are properly
structured and can be imported. It's a lighter weight test than the full system test.

Author: Claude Code Assistant
"""

import sys
from pathlib import Path
import importlib

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all major components can be imported."""
    print("Testing imports...")
    
    results = {
        'models': [],
        'parsers': [],
        'plugins': [],
        'analyzers': [],
        'utils': [],
        'generators': []
    }
    
    # Test models
    model_modules = [
        'models.business_rule',
        'models.search_index'
    ]
    
    for module in model_modules:
        try:
            importlib.import_module(module)
            results['models'].append(f"✅ {module}")
        except Exception as e:
            results['models'].append(f"❌ {module}: {e}")
    
    # Test parsers
    parser_modules = [
        'parsers.base_parser',
        'parsers.xml_parser', 
        'parsers.java_parser',
        'parsers.jsp_parser',
        'parsers.properties_parser'
    ]
    
    for module in parser_modules:
        try:
            importlib.import_module(module)
            results['parsers'].append(f"✅ {module}")
        except Exception as e:
            results['parsers'].append(f"❌ {module}: {e}")
    
    # Test plugins
    plugin_modules = [
        'plugins.base_plugin',
        'plugins.plugin_manager',
        'plugins.framework_plugins',
        'plugins.migration_plugins',
        'plugins.documentation_plugins'
    ]
    
    for module in plugin_modules:
        try:
            importlib.import_module(module)
            results['plugins'].append(f"✅ {module}")
        except Exception as e:
            results['plugins'].append(f"❌ {module}: {e}")
    
    # Test analyzers
    analyzer_modules = [
        'analyzers.base_analyzer',
        'analyzers.struts_config_analyzer',
        'analyzers.validation_analyzer',
        'analyzers.java_action_analyzer',
        'analyzers.jsp_analyzer',
        'analyzers.properties_analyzer',
        'analyzers.interceptor_analyzer'
    ]
    
    for module in analyzer_modules:
        try:
            importlib.import_module(module)
            results['analyzers'].append(f"✅ {module}")
        except Exception as e:
            results['analyzers'].append(f"❌ {module}: {e}")
    
    # Test utilities
    util_modules = [
        'utils.config_utils',
        'utils.logging_utils',
        'utils.file_utils'
    ]
    
    for module in util_modules:
        try:
            importlib.import_module(module)
            results['utils'].append(f"✅ {module}")
        except Exception as e:
            results['utils'].append(f"❌ {module}: {e}")
    
    # Test generators
    generator_modules = [
        'generators.enhanced_documentation_generator'
    ]
    
    for module in generator_modules:
        try:
            importlib.import_module(module)
            results['generators'].append(f"✅ {module}")
        except Exception as e:
            results['generators'].append(f"❌ {module}: {e}")
    
    return results

def test_file_structure():
    """Test that all expected files exist."""
    print("Testing file structure...")
    
    project_root = Path(__file__).parent
    
    expected_files = [
        # Main files
        'struts_analyzer.py',
        'business_rule_engine.py',
        'readme.md',
        
        # Models
        'models/business_rule.py',
        'models/search_index.py',
        'models/__init__.py',
        
        # Parsers
        'parsers/base_parser.py',
        'parsers/xml_parser.py',
        'parsers/java_parser.py',
        'parsers/jsp_parser.py',
        'parsers/properties_parser.py',
        'parsers/__init__.py',
        
        # Plugins
        'plugins/base_plugin.py',
        'plugins/plugin_manager.py',
        'plugins/framework_plugins.py',
        'plugins/migration_plugins.py',
        'plugins/documentation_plugins.py',
        'plugins/__init__.py',
        
        # Analyzers
        'analyzers/base_analyzer.py',
        'analyzers/struts_config_analyzer.py',
        'analyzers/validation_analyzer.py',
        'analyzers/java_action_analyzer.py',
        'analyzers/jsp_analyzer.py',
        'analyzers/properties_analyzer.py',
        'analyzers/interceptor_analyzer.py',
        'analyzers/__init__.py',
        
        # Utils
        'utils/config_utils.py',
        'utils/logging_utils.py',
        'utils/file_utils.py',
        'utils/__init__.py',
        
        # Generators
        'generators/enhanced_documentation_generator.py',
        'generators/__init__.py'
    ]
    
    results = []
    
    for file_path in expected_files:
        full_path = project_root / file_path
        if full_path.exists():
            results.append(f"✅ {file_path}")
        else:
            results.append(f"❌ {file_path} - Missing")
    
    return results

def test_class_interfaces():
    """Test that key classes have expected methods."""
    print("Testing class interfaces...")
    
    results = []
    
    try:
        # Test BusinessRule class
        from models.business_rule import BusinessRule
        rule_methods = ['add_tag', 'to_dict', 'from_dict']
        for method in rule_methods:
            if hasattr(BusinessRule, method):
                results.append(f"✅ BusinessRule.{method}")
            else:
                results.append(f"❌ BusinessRule.{method} - Missing")
    except Exception as e:
        results.append(f"❌ BusinessRule class: {e}")
    
    try:
        # Test BaseParser class
        from parsers.base_parser import BaseParser
        parser_methods = ['can_parse', 'parse_file', 'get_priority']
        for method in parser_methods:
            if hasattr(BaseParser, method):
                results.append(f"✅ BaseParser.{method}")
            else:
                results.append(f"❌ BaseParser.{method} - Missing")
    except Exception as e:
        results.append(f"❌ BaseParser class: {e}")
    
    try:
        # Test BasePlugin class
        from plugins.base_plugin import BasePlugin
        plugin_methods = ['can_handle', 'execute', 'initialize']
        for method in plugin_methods:
            if hasattr(BasePlugin, method):
                results.append(f"✅ BasePlugin.{method}")
            else:
                results.append(f"❌ BasePlugin.{method} - Missing")
    except Exception as e:
        results.append(f"❌ BasePlugin class: {e}")
    
    try:
        # Test PluginManager class
        from plugins.plugin_manager import PluginManager
        manager_methods = ['discover_plugins', 'initialize_plugins', 'execute_framework_plugins']
        for method in manager_methods:
            if hasattr(PluginManager, method):
                results.append(f"✅ PluginManager.{method}")
            else:
                results.append(f"❌ PluginManager.{method} - Missing")
    except Exception as e:
        results.append(f"❌ PluginManager class: {e}")
    
    return results

def run_structure_test():
    """Run the complete structure test."""
    print("=== Struts Analyzer System Structure Test ===\n")
    
    # Test imports
    import_results = test_imports()
    
    print("Import Test Results:")
    for category, results in import_results.items():
        print(f"\n{category.title()}:")
        for result in results:
            print(f"  {result}")
    
    print("\n" + "="*50 + "\n")
    
    # Test file structure
    file_results = test_file_structure()
    
    print("File Structure Test Results:")
    for result in file_results:
        print(f"  {result}")
    
    print("\n" + "="*50 + "\n")
    
    # Test class interfaces
    class_results = test_class_interfaces()
    
    print("Class Interface Test Results:")
    for result in class_results:
        print(f"  {result}")
    
    print("\n" + "="*50 + "\n")
    
    # Calculate summary
    all_results = []
    for category_results in import_results.values():
        all_results.extend(category_results)
    all_results.extend(file_results)
    all_results.extend(class_results)
    
    passed = len([r for r in all_results if r.startswith("✅")])
    failed = len([r for r in all_results if r.startswith("❌")])
    total = passed + failed
    
    print("=== Summary ===")
    print(f"Total tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success rate: {(passed/total)*100:.1f}%")
    
    success = failed == 0
    print(f"\nOverall result: {'✅ PASS' if success else '❌ FAIL'}")
    
    if success:
        print("\n🎉 System structure is complete and correct!")
        print("All components are properly organized and accessible.")
    else:
        print(f"\n⚠️  Found {failed} issues that need to be addressed.")
    
    return success

if __name__ == "__main__":
    success = run_structure_test()
    sys.exit(0 if success else 1)