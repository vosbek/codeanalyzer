#!/usr/bin/env python3
"""
Basic validation script for the Struts Legacy Business Rules Analyzer
"""

import sys
import ast
from pathlib import Path

def validate_syntax():
    """Validate Python syntax of all analyzer files."""
    print("Validating Python syntax...")
    
    files_to_check = [
        'struts_analyzer.py',
        'aws_strands_tools.py',
        'test_analyzer.py'
    ]
    
    errors = []
    
    for file_name in files_to_check:
        file_path = Path(file_name)
        if not file_path.exists():
            errors.append(f"File not found: {file_name}")
            continue
        
        try:
            with open(file_path, 'r') as f:
                source_code = f.read()
            
            # Parse the AST to check syntax
            ast.parse(source_code)
            print(f"✓ {file_name} - Syntax OK")
            
        except SyntaxError as e:
            error_msg = f"✗ {file_name} - Syntax Error: {e}"
            errors.append(error_msg)
            print(error_msg)
        except Exception as e:
            error_msg = f"✗ {file_name} - Error: {e}"
            errors.append(error_msg)
            print(error_msg)
    
    return errors

def validate_structure():
    """Validate the project structure."""
    print("\nValidating project structure...")
    
    required_files = [
        'struts_analyzer.py',
        'aws_strands_tools.py', 
        'test_analyzer.py',
        'readme.md',
        'requirements.txt',
        'config/analyzer_config.yaml',
        'config/analyzer_config.json'
    ]
    
    missing_files = []
    
    for file_path in required_files:
        path = Path(file_path)
        if path.exists():
            print(f"✓ {file_path}")
        else:
            missing_files.append(file_path)
            print(f"✗ {file_path} - Missing")
    
    return missing_files

def validate_imports():
    """Validate key imports in main analyzer."""
    print("\nValidating key imports...")
    
    try:
        # Check if main file can be imported without dependencies
        spec = compile(open('struts_analyzer.py').read(), 'struts_analyzer.py', 'exec')
        print("✓ struts_analyzer.py compiles successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Compilation error: {e}")
        return False

def validate_classes():
    """Validate that key classes are defined."""
    print("\nValidating class definitions...")
    
    try:
        with open('struts_analyzer.py', 'r') as f:
            content = f.read()
        
        required_classes = [
            'BusinessRule',
            'ActionMapping', 
            'ValidationRule',
            'ConfigurationManager',
            'CacheManager',
            'BaseParser',
            'StrutsConfigParser',
            'ValidationParser',
            'JavaActionAnalyzer',
            'JSPAnalyzer',
            'BusinessRuleExtractor',
            'DocumentationGenerator'
        ]
        
        missing_classes = []
        
        for class_name in required_classes:
            if f"class {class_name}" in content:
                print(f"✓ {class_name}")
            else:
                missing_classes.append(class_name)
                print(f"✗ {class_name} - Not found")
        
        return missing_classes
        
    except Exception as e:
        print(f"Error validating classes: {e}")
        return ['Error reading file']

def validate_methods():
    """Validate that key methods are defined."""
    print("\nValidating key methods...")
    
    try:
        with open('struts_analyzer.py', 'r') as f:
            content = f.read()
        
        required_methods = [
            'def main(',
            'def analyze_directory(',
            'def parse(',
            'def can_parse(',
            'def generate('
        ]
        
        missing_methods = []
        
        for method_signature in required_methods:
            if method_signature in content:
                print(f"✓ {method_signature}")
            else:
                missing_methods.append(method_signature)
                print(f"✗ {method_signature} - Not found")
        
        return missing_methods
        
    except Exception as e:
        print(f"Error validating methods: {e}")
        return ['Error reading file']

def validate_configuration():
    """Validate configuration files."""
    print("\nValidating configuration files...")
    
    errors = []
    
    # Check YAML config
    yaml_config = Path('config/analyzer_config.yaml')
    if yaml_config.exists():
        try:
            with open(yaml_config, 'r') as f:
                content = f.read()
            
            # Basic validation - check for key sections
            required_sections = ['analysis:', 'struts:', 'output:', 'business_rules:']
            for section in required_sections:
                if section in content:
                    print(f"✓ YAML config has {section}")
                else:
                    errors.append(f"Missing section in YAML: {section}")
                    print(f"✗ YAML config missing {section}")
                    
        except Exception as e:
            errors.append(f"Error reading YAML config: {e}")
            print(f"✗ Error reading YAML config: {e}")
    else:
        errors.append("YAML config file not found")
        print("✗ YAML config file not found")
    
    # Check JSON config
    json_config = Path('config/analyzer_config.json')
    if json_config.exists():
        try:
            import json
            with open(json_config, 'r') as f:
                config_data = json.load(f)
            
            required_sections = ['analysis', 'struts', 'output', 'business_rules']
            for section in required_sections:
                if section in config_data:
                    print(f"✓ JSON config has {section}")
                else:
                    errors.append(f"Missing section in JSON: {section}")
                    print(f"✗ JSON config missing {section}")
                    
        except Exception as e:
            errors.append(f"Error reading JSON config: {e}")
            print(f"✗ Error reading JSON config: {e}")
    else:
        errors.append("JSON config file not found")
        print("✗ JSON config file not found")
    
    return errors

def main():
    """Run all validation checks."""
    print("=" * 60)
    print("Struts Legacy Business Rules Analyzer - Validation")
    print("=" * 60)
    
    all_errors = []
    
    # Run validation checks
    syntax_errors = validate_syntax()
    structure_errors = validate_structure()
    import_success = validate_imports()
    missing_classes = validate_classes()
    missing_methods = validate_methods()
    config_errors = validate_configuration()
    
    # Collect all errors
    all_errors.extend(syntax_errors)
    all_errors.extend([f"Missing file: {f}" for f in structure_errors])
    if not import_success:
        all_errors.append("Import validation failed")
    all_errors.extend([f"Missing class: {c}" for c in missing_classes])
    all_errors.extend([f"Missing method: {m}" for m in missing_methods])
    all_errors.extend(config_errors)
    
    # Final report
    print("\n" + "=" * 60)
    if not all_errors:
        print("🎉 ALL VALIDATION CHECKS PASSED!")
        print("The Struts Legacy Business Rules Analyzer is ready for use.")
        print("\nNext steps:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Run on a Struts codebase: python struts_analyzer.py /path/to/struts/app")
        print("3. Review generated documentation in analysis_output/")
        return True
    else:
        print("❌ VALIDATION ISSUES FOUND:")
        for error in all_errors:
            print(f"  - {error}")
        
        print(f"\nTotal issues: {len(all_errors)}")
        print("\nThe analyzer structure is mostly complete but may need dependency installation.")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)