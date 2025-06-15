#!/usr/bin/env python3
"""
Minimal test to check business rule detection functionality
This bypasses all the complex dependencies and tests just the core functionality
"""

import os
import tempfile
from pathlib import Path

def create_test_struts_config():
    """Create a minimal struts-config.xml for testing"""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE struts-config PUBLIC "-//Apache Software Foundation//DTD Struts Configuration 1.3//EN" 
    "http://struts.apache.org/dtds/struts-config_1_3.dtd">

<struts-config>
    <form-beans>
        <form-bean name="loginForm" type="com.example.forms.LoginForm"/>
        <form-bean name="userForm" type="com.example.forms.UserForm"/>
        <form-bean name="orderForm" type="com.example.forms.OrderForm"/>
    </form-beans>
    
    <action-mappings>
        <action path="/login" 
                type="com.example.actions.LoginAction"
                name="loginForm" 
                scope="request"
                validate="true"
                input="/login.jsp">
            <forward name="success" path="/welcome.jsp"/>
            <forward name="failure" path="/login.jsp"/>
        </action>
        
        <action path="/user" 
                type="com.example.actions.UserAction"
                name="userForm" 
                scope="session"
                validate="true">
            <forward name="list" path="/userList.jsp"/>
            <forward name="edit" path="/userEdit.jsp"/>
        </action>
        
        <action path="/order" 
                type="com.example.actions.OrderAction"
                name="orderForm" 
                scope="request"
                validate="true">
            <forward name="submit" path="/orderConfirm.jsp"/>
            <forward name="edit" path="/orderEdit.jsp"/>
        </action>
    </action-mappings>
    
    <message-resources parameter="ApplicationResources"/>
</struts-config>"""

def create_test_validation_xml():
    """Create a minimal validation.xml for testing"""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE form-validation PUBLIC "-//Apache Software Foundation//DTD Commons Validator Rules Configuration 1.3.0//EN" 
    "http://jakarta.apache.org/commons/dtds/validator_1_3_0.dtd">

<form-validation>
    <formset>
        <form name="loginForm">
            <field property="username" depends="required,minlength">
                <arg position="0" key="label.username"/>
                <arg position="1" name="minlength" key="${var:minlength}" resource="false"/>
                <var>
                    <var-name>minlength</var-name>
                    <var-value>3</var-value>
                </var>
            </field>
            <field property="password" depends="required,minlength">
                <arg position="0" key="label.password"/>
                <arg position="1" name="minlength" key="${var:minlength}" resource="false"/>
                <var>
                    <var-name>minlength</var-name>
                    <var-value>6</var-value>
                </var>
            </field>
        </form>
        
        <form name="userForm">
            <field property="email" depends="required,email">
                <arg position="0" key="label.email"/>
            </field>
            <field property="age" depends="required,integer,range">
                <arg position="0" key="label.age"/>
                <arg position="1" name="range" key="${var:min}" resource="false"/>
                <arg position="2" name="range" key="${var:max}" resource="false"/>
                <var>
                    <var-name>min</var-name>
                    <var-value>18</var-value>
                </var>
                <var>
                    <var-name>max</var-name>
                    <var-value>100</var-value>
                </var>
            </field>
        </form>
        
        <form name="orderForm">
            <field property="amount" depends="required,float,min">
                <arg position="0" key="label.amount"/>
                <arg position="1" name="min" key="${var:min}" resource="false"/>
                <var>
                    <var-name>min</var-name>
                    <var-value>0.01</var-value>
                </var>
            </field>
            <field property="customerEmail" depends="required,email">
                <arg position="0" key="label.customer.email"/>
            </field>
        </form>
    </formset>
</form-validation>"""

def test_original_analyzer_simple():
    """Test the original monolithic analyzer"""
    print("Testing original struts_analyzer.py...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test files
        web_inf = temp_path / "WEB-INF"
        web_inf.mkdir()
        
        struts_config = web_inf / "struts-config.xml"
        struts_config.write_text(create_test_struts_config())
        
        validation_xml = web_inf / "validation.xml"
        validation_xml.write_text(create_test_validation_xml())
        
        print(f"Created test application in: {temp_path}")
        print(f"Files: {list(temp_path.rglob('*'))}")
        
        try:
            # Import the monolithic analyzer
            from struts_analyzer import BusinessRuleExtractor, ConfigurationManager
            
            # Create configuration
            config = ConfigurationManager()
            
            # Create extractor
            extractor = BusinessRuleExtractor(config)
            
            # Run analysis on the test directory
            results = extractor.analyze_directory(temp_path)
            
            print(f"\n=== Analysis Results ===")
            print(f"Total business rules found: {len(results['business_rules'])}")
            print(f"Action mappings found: {len(results['action_mappings'])}")
            print(f"Validation rules found: {len(results['validation_rules'])}")
            
            # Print first few business rules
            for i, rule in enumerate(results['business_rules'][:5]):
                print(f"Rule {i+1}: {rule['name']} - {rule['type']}")
            
            # Check if we found a reasonable number of rules
            total_rules = len(results['business_rules'])
            if total_rules >= 5:  # Should find at least 5 rules from our test data
                print(f"✅ SUCCESS: Found {total_rules} business rules (expected >= 5)")
                return True, total_rules
            else:
                print(f"❌ FAILURE: Only found {total_rules} business rules (expected >= 5)")
                return False, total_rules
                
        except Exception as e:
            print(f"❌ Error running analysis: {e}")
            import traceback
            traceback.print_exc()
            return False, 0

def test_new_engine():
    """Test the new business rule engine"""
    print("Testing new business_rule_engine.py...")
    
    try:
        # Try to import the new engine
        from business_rule_engine import BusinessRuleEngine
        from utils.config_utils import ConfigurationManager
        
        print("✅ New engine imports successfully")
        
        # Test with a simple configuration
        config_data = {
            'analysis': {
                'index_path': ':memory:',
                'parallel_enabled': False
            }
        }
        
        config = ConfigurationManager(config_data)
        engine = BusinessRuleEngine(config)
        
        print("✅ New engine initialized successfully")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test files
            web_inf = temp_path / "WEB-INF"
            web_inf.mkdir()
            
            struts_config = web_inf / "struts-config.xml"
            struts_config.write_text(create_test_struts_config())
            
            validation_xml = web_inf / "validation.xml"
            validation_xml.write_text(create_test_validation_xml())
            
            # Run analysis
            discovery_result = engine.analyze_application(temp_path)
            
            print(f"\n=== New Engine Results ===")
            print(f"Total business rules found: {discovery_result.total_rules}")
            print(f"Rules by type: {discovery_result.rules_by_type}")
            print(f"Business domains: {list(discovery_result.business_domains)}")
            
            if discovery_result.total_rules >= 5:
                print(f"✅ SUCCESS: New engine found {discovery_result.total_rules} business rules")
                return True, discovery_result.total_rules
            else:
                print(f"❌ FAILURE: New engine only found {discovery_result.total_rules} business rules")
                return False, discovery_result.total_rules
                
    except Exception as e:
        print(f"❌ Error with new engine: {e}")
        import traceback
        traceback.print_exc()
        return False, 0

if __name__ == "__main__":
    print("=== Minimal Business Rule Detection Test ===\n")
    
    # Test 1: Original monolithic analyzer
    try:
        original_success, original_count = test_original_analyzer_simple()
    except Exception as e:
        print(f"Original analyzer test failed: {e}")
        original_success, original_count = False, 0
    
    print("\n" + "="*50 + "\n")
    
    # Test 2: New business rule engine
    try:
        new_success, new_count = test_new_engine()
    except Exception as e:
        print(f"New engine test failed: {e}")
        new_success, new_count = False, 0
    
    print("\n=== SUMMARY ===")
    print(f"Original analyzer: {'✅ PASS' if original_success else '❌ FAIL'} ({original_count} rules)")
    print(f"New engine: {'✅ PASS' if new_success else '❌ FAIL'} ({new_count} rules)")
    
    overall_success = original_success or new_success
    print(f"\nOverall result: {'✅ SUCCESS' if overall_success else '❌ FAILURE'}")
    
    if overall_success:
        print("\n📊 ANALYSIS:")
        if original_success and new_success:
            print("Both analyzers are working! You have a choice of implementations.")
        elif original_success:
            print("The original monolithic analyzer is working well.")
            print("The new modular engine may need additional component fixes.")
        elif new_success:
            print("The new modular engine is working!")
            print("You can use this for more advanced analysis features.")
        
        if max(original_count, new_count) < 20:
            print(f"\n⚠️  NOTE: Only {max(original_count, new_count)} rules found on test data.")
            print("On a real application with 20,000 rules, you should see much higher numbers.")
            print("The low count here is expected as we're using minimal test data.")
    else:
        print("\n🔧 ISSUES TO FIX:")
        print("Both analyzers failed. Check the error messages above for details.")
        print("Common issues: missing dependencies, import errors, or configuration problems.")