#!/usr/bin/env python3
"""
Simple test to check basic functionality without optional dependencies
"""

def test_basic_imports():
    """Test core imports that should work without external dependencies"""
    try:
        # Test models
        from models.business_rule import BusinessRule, BusinessRuleType
        print("✅ Core models import successfully")
        
        # Test utils 
        from utils.config_utils import ConfigurationManager
        from utils.logging_utils import get_logger
        print("✅ Utils import successfully")
        
        # Test basic XML parsing capability
        import xml.etree.ElementTree as ET
        test_xml = "<test><item>value</item></test>"
        root = ET.fromstring(test_xml)
        print("✅ XML parsing works")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic imports failed: {e}")
        return False

def test_business_rule_creation():
    """Test creating a basic business rule"""
    try:
        from models.business_rule import BusinessRule, BusinessRuleType, BusinessRuleSource, BusinessRuleLocation, BusinessRuleEvidence
        
        # Create required components
        location = BusinessRuleLocation(file_path="test.xml", line_number=1)
        evidence = BusinessRuleEvidence(
            code_snippet="<validation rule>",
            context="Test validation context"
        )
        
        rule = BusinessRule(
            id="test-1",
            name="Test Rule",
            description="A test business rule",
            rule_type=BusinessRuleType.VALIDATION,
            source=BusinessRuleSource.STRUTS_CONFIG,
            location=location,
            evidence=evidence
        )
        
        print(f"✅ Created business rule: {rule.name}")
        return True
        
    except Exception as e:
        print(f"❌ Business rule creation failed: {e}")
        return False

if __name__ == "__main__":
    print("=== Simple Functionality Test ===")
    
    basic_ok = test_basic_imports()
    rule_ok = test_business_rule_creation()
    
    if basic_ok and rule_ok:
        print("\n✅ Core functionality appears to work")
        print("The missing dependencies (javalang, tqdm, networkx) are needed for:")
        print("  - Advanced Java parsing (javalang)")
        print("  - Progress bars (tqdm)")  
        print("  - Dependency graphing (networkx)")
    else:
        print("\n❌ Core functionality has issues")