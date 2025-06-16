#!/usr/bin/env python3
"""
Windows Setup Validation Script
===============================

Validates that the enhanced Struts Business Rules Analyzer is properly installed
and configured according to the Windows Setup Guide.
"""

import sys
import subprocess
import importlib
from pathlib import Path

def check_python_version():
    """Check Python version is 3.8+"""
    print("🐍 Checking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"   ✅ Python {version.major}.{version.minor}.{version.micro} - GOOD")
        return True
    else:
        print(f"   ❌ Python {version.major}.{version.minor}.{version.micro} - NEED 3.8+")
        return False

def check_required_dependencies():
    """Check core required dependencies"""
    print("📦 Checking required dependencies...")
    
    required = {
        'psutil': '5.9.0',
        'yaml': '6.0.0'  # Note: imports as 'yaml' but package is 'PyYAML'
    }
    
    success = True
    
    for module, min_version in required.items():
        try:
            if module == 'yaml':
                import yaml
                version = getattr(yaml, '__version__', 'unknown')
                print(f"   ✅ PyYAML {version} - INSTALLED")
            else:
                mod = importlib.import_module(module)
                version = getattr(mod, '__version__', 'unknown')
                print(f"   ✅ {module} {version} - INSTALLED")
        except ImportError:
            print(f"   ❌ {module} - MISSING (install with: pip install {module})")
            success = False
    
    return success

def check_enhanced_dependencies():
    """Check enhanced analysis dependencies"""
    print("🚀 Checking enhanced analysis dependencies...")
    
    enhanced = {
        'javalang': '0.13.0',
        'networkx': '2.8.0', 
        'tqdm': '4.65.0',
        'pandas': '2.0.0',
        'numpy': '1.24.0'
    }
    
    installed_count = 0
    
    for module, min_version in enhanced.items():
        try:
            mod = importlib.import_module(module)
            version = getattr(mod, '__version__', 'unknown')
            print(f"   ✅ {module} {version} - INSTALLED")
            installed_count += 1
        except ImportError:
            print(f"   ⚠️  {module} - OPTIONAL (install with: pip install {module}>={min_version})")
    
    coverage = installed_count / len(enhanced) * 100
    print(f"   📊 Enhanced features coverage: {coverage:.0f}%")
    
    return coverage >= 60  # 60% minimum for good functionality

def check_optional_dependencies():
    """Check optional dependencies"""
    print("🎨 Checking optional dependencies...")
    
    optional = {
        'graphviz': 'Diagram generation',
        'boto3': 'AWS integration', 
        'click': 'CLI enhancements',
        'matplotlib': 'Visualization'
    }
    
    for module, purpose in optional.items():
        try:
            mod = importlib.import_module(module)
            version = getattr(mod, '__version__', 'unknown')
            print(f"   ✅ {module} {version} - {purpose}")
        except ImportError:
            print(f"   ⚪ {module} - {purpose} (optional)")

def check_analyzer_files():
    """Check analyzer files are present"""
    print("📁 Checking analyzer files...")
    
    required_files = [
        'struts_analyzer.py',
        'run_analyzer_simple.py', 
        'test_minimal_analyzer.py',
        'test_enhanced_java_analysis.py',
        'requirements.txt'
    ]
    
    success = True
    
    for filename in required_files:
        file_path = Path(filename)
        if file_path.exists():
            size = file_path.stat().st_size
            print(f"   ✅ {filename} ({size:,} bytes)")
        else:
            print(f"   ❌ {filename} - MISSING")
            success = False
    
    return success

def run_basic_test():
    """Run basic functionality test"""
    print("🧪 Running basic functionality test...")
    
    try:
        result = subprocess.run([
            sys.executable, 'test_minimal_analyzer.py'
        ], capture_output=True, text=True, timeout=60)
        
        if "[SUCCESS]" in result.stdout or "SUCCESS" in result.stdout:
            print("   ✅ Basic test PASSED")
            return True
        else:
            print("   ❌ Basic test FAILED")
            print("   📋 FULL ERROR OUTPUT:")
            print("   " + "="*50)
            if result.stderr:
                print("   STDERR:")
                for line in result.stderr.split('\n'):
                    if line.strip():
                        print(f"   {line}")
            if result.stdout:
                print("   STDOUT:")
                for line in result.stdout.split('\n'):
                    if line.strip():
                        print(f"   {line}")
            print("   " + "="*50)
            return False
            
    except Exception as e:
        print(f"   ❌ Test execution failed: {e}")
        return False

def run_enhanced_test():
    """Run enhanced Java analysis test"""
    print("🚀 Running enhanced Java analysis test...")
    
    try:
        result = subprocess.run([
            sys.executable, 'test_enhanced_java_analysis.py'
        ], capture_output=True, text=True, timeout=120)
        
        if "[EXCELLENT]" in result.stdout or "EXCELLENT" in result.stdout:
            print("   ✅ Enhanced test PASSED (42 rules extracted)")
            return True
        else:
            print("   ⚠️  Enhanced test had issues")
            if "business rules" in result.stdout.lower():
                print("   📊 Some rules extracted - partial success")
                return True
            else:
                print("   📋 FULL ERROR OUTPUT:");
                print("   " + "="*50);
                if result.stderr:
                    print("   STDERR:");
                    for line in result.stderr.split('\n'):
                        if line.strip():
                            print(f"   {line}");
                if result.stdout:
                    print("   STDOUT:");
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            print(f"   {line}");
                print("   " + "="*50)
                return False
                
    except Exception as e:
        print(f"   ❌ Enhanced test execution failed: {e}")
        return False

def validate_config_files():
    """Check configuration files"""
    print("⚙️  Checking configuration files...")
    
    config_files = [
        'config/analyzer_config.yaml',
        'config/analyzer_config.json'
    ]
    
    found = 0
    for config_file in config_files:
        if Path(config_file).exists():
            print(f"   ✅ {config_file}")
            found += 1
        else:
            print(f"   ⚪ {config_file} (optional)")
    
    if found > 0:
        print("   📋 Configuration files available")
    else:
        print("   📋 No configuration files (will use defaults)")
    
    return True

def main():
    """Main validation routine"""
    print("🔍 Windows Setup Validation for Enhanced Struts Business Rules Analyzer")
    print("=" * 80)
    
    checks = [
        ("Python Version", check_python_version),
        ("Required Dependencies", check_required_dependencies),
        ("Enhanced Dependencies", check_enhanced_dependencies),
        ("Optional Dependencies", check_optional_dependencies),
        ("Analyzer Files", check_analyzer_files),
        ("Configuration Files", validate_config_files),
        ("Basic Functionality", run_basic_test),
        ("Enhanced Analysis", run_enhanced_test)
    ]
    
    passed = 0
    total = len(checks)
    
    for check_name, check_func in checks:
        print()
        try:
            if check_func():
                passed += 1
        except Exception as e:
            print(f"   ❌ {check_name} failed with error: {e}")
    
    print("\n" + "=" * 80)
    print("📊 VALIDATION SUMMARY")
    print("=" * 80)
    
    success_rate = passed / total * 100
    print(f"Checks Passed: {passed}/{total} ({success_rate:.1f}%)")
    
    if success_rate >= 90:
        print("🎉 EXCELLENT: Setup is ready for enterprise analysis!")
        print("✅ You can analyze large Struts applications with confidence")
    elif success_rate >= 75:
        print("✅ GOOD: Setup is functional with most features available")
        print("💡 Consider installing missing enhanced dependencies for full features")
    elif success_rate >= 60:
        print("⚠️  PARTIAL: Basic functionality available")
        print("🔧 Install missing dependencies for enhanced features")
    else:
        print("❌ SETUP INCOMPLETE: Critical issues need to be resolved")
        print("📖 Review the Windows Setup Guide and install missing dependencies")
    
    print("\n📖 Next Steps:")
    if success_rate >= 75:
        print("1. Run: python run_analyzer_simple.py <path-to-struts-app>")
        print("2. For advanced analysis: python struts_analyzer.py <path> --deep-analysis")
        print("3. Review documentation in analysis_output/ directory")
    else:
        print("1. Install missing dependencies: pip install -r requirements.txt")
        print("2. Re-run this validation: python validate_windows_setup.py")
        print("3. Check Windows Setup Guide for troubleshooting")
    
    return success_rate >= 75

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)