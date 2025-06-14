#!/usr/bin/env python3
"""
Test script for the Struts Legacy Business Rules Analyzer
"""

import tempfile
import os
import sys
from pathlib import Path
import json

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from struts_analyzer import (
    ConfigurationManager, BusinessRuleExtractor, 
    StrutsConfigParser, ValidationParser, JavaActionAnalyzer, JSPAnalyzer
)


def create_test_struts_app():
    """Create a sample Struts application structure for testing."""
    temp_dir = Path(tempfile.mkdtemp(prefix='struts_test_'))
    
    # Create directory structure
    (temp_dir / 'WEB-INF').mkdir()
    (temp_dir / 'WEB-INF' / 'classes' / 'com' / 'example' / 'actions').mkdir(parents=True)
    (temp_dir / 'jsp').mkdir()
    
    # Create struts-config.xml
    struts_config = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE struts-config PUBLIC
    "-//Apache Software Foundation//DTD Struts Configuration 1.3//EN"
    "http://struts.apache.org/dtds/struts-config_1_3.dtd">

<struts-config>
    <form-beans>
        <form-bean name="loginForm" type="com.example.forms.LoginForm"/>
        <form-bean name="userForm" type="com.example.forms.UserForm"/>
    </form-beans>
    
    <action-mappings>
        <action path="/login" 
                type="com.example.actions.LoginAction"
                name="loginForm"
                scope="request"
                validate="true"
                input="/jsp/login.jsp">
            <forward name="success" path="/jsp/dashboard.jsp"/>
            <forward name="failure" path="/jsp/login.jsp"/>
            <exception key="system.error" path="/jsp/error.jsp" type="java.lang.Exception"/>
        </action>
        
        <action path="/user/create"
                type="com.example.actions.UserCreateAction"
                name="userForm"
                scope="request">
            <forward name="success" path="/jsp/user/list.jsp"/>
            <forward name="input" path="/jsp/user/create.jsp"/>
        </action>
        
        <action path="/user/search"
                type="com.example.actions.UserSearchAction">
            <forward name="results" path="/jsp/user/results.jsp"/>
        </action>
    </action-mappings>
    
    <global-forwards>
        <forward name="home" path="/jsp/home.jsp"/>
        <forward name="logout" path="/jsp/logout.jsp"/>
    </global-forwards>
</struts-config>'''
    
    with open(temp_dir / 'WEB-INF' / 'struts-config.xml', 'w') as f:
        f.write(struts_config)
    
    # Create validation.xml
    validation_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE form-validation PUBLIC
    "-//Apache Software Foundation//DTD Commons Validator Rules Configuration 1.3.0//EN"
    "http://jakarta.apache.org/commons/dtds/validator_1_3_0.dtd">

<form-validation>
    <formset>
        <form name="loginForm">
            <field property="username" depends="required,minlength">
                <arg0 key="login.username"/>
                <var>
                    <var-name>minlength</var-name>
                    <var-value>3</var-value>
                </var>
                <msg name="required" key="errors.required"/>
            </field>
            
            <field property="password" depends="required,minlength">
                <arg0 key="login.password"/>
                <var>
                    <var-name>minlength</var-name>
                    <var-value>6</var-value>
                </var>
            </field>
        </form>
        
        <form name="userForm">
            <field property="email" depends="required,email">
                <arg0 key="user.email"/>
            </field>
            
            <field property="age" depends="required,range">
                <arg0 key="user.age"/>
                <var>
                    <var-name>min</var-name>
                    <var-value>18</var-value>
                </var>
                <var>
                    <var-name>max</var-name>
                    <var-value>120</var-value>
                </var>
            </field>
        </form>
    </formset>
</form-validation>'''
    
    with open(temp_dir / 'WEB-INF' / 'validation.xml', 'w') as f:
        f.write(validation_xml)
    
    # Create sample Action class
    login_action = '''package com.example.actions;

import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * LoginAction handles user authentication process.
 * Business Rule: Users must provide valid credentials to access the system.
 * Requirement: Failed login attempts must be logged for security monitoring.
 */
public class LoginAction extends Action {
    
    /**
     * Main execute method for login processing.
     * Must validate user credentials against the database.
     */
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                               HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        
        LoginForm loginForm = (LoginForm) form;
        
        // Business logic: Authenticate user
        if (authenticateUser(loginForm.getUsername(), loginForm.getPassword())) {
            // Success: redirect to dashboard
            request.getSession().setAttribute("user", loginForm.getUsername());
            return mapping.findForward("success");
        } else {
            // Failure: return to login with error
            request.setAttribute("errorMessage", "Invalid credentials");
            return mapping.findForward("failure");
        }
    }
    
    /**
     * Private method to authenticate user credentials.
     * Business Rule: Password must be validated against encrypted storage.
     */
    private boolean authenticateUser(String username, String password) {
        // Business logic implementation would go here
        return username != null && password != null && password.length() >= 6;
    }
    
    /**
     * Validation method to ensure form data integrity.
     * Must validate all required fields before processing.
     */
    private boolean validateForm(LoginForm form) {
        return form.getUsername() != null && !form.getUsername().trim().isEmpty() &&
               form.getPassword() != null && form.getPassword().length() >= 6;
    }
}'''
    
    with open(temp_dir / 'WEB-INF' / 'classes' / 'com' / 'example' / 'actions' / 'LoginAction.java', 'w') as f:
        f.write(login_action)
    
    # Create sample JSP file
    login_jsp = '''<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %>
<%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html>
<html>
<head>
    <title>User Login</title>
</head>
<body>
    <%-- Business Rule: Login form must be accessible to all users --%>
    <%-- Requirement: Form must validate credentials before submission --%>
    
    <h1>Login to System</h1>
    
    <%-- Display error messages if login failed --%>
    <c:if test="${not empty errorMessage}">
        <div class="error">
            <c:out value="${errorMessage}"/>
        </div>
    </c:if>
    
    <%-- Main login form with business validation --%>
    <html:form action="/login" method="post">
        <table>
            <tr>
                <td><label for="username">Username:</label></td>
                <td>
                    <html:text property="username" size="20" maxlength="50"/>
                    <html:errors property="username"/>
                </td>
            </tr>
            <tr>
                <td><label for="password">Password:</label></td>
                <td>
                    <html:password property="password" size="20" maxlength="50"/>
                    <html:errors property="password"/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <html:submit value="Login"/>
                    <html:link action="/home">Cancel</html:link>
                </td>
            </tr>
        </table>
    </html:form>
    
    <%-- Business Rule: Show registration link only for new users --%>
    <c:if test="${empty sessionScope.user}">
        <p>
            <html:link action="/user/register">New User? Register Here</html:link>
        </p>
    </c:if>
    
    <%-- Admin panel access based on user role --%>
    <c:if test="${sessionScope.userRole eq 'admin'}">
        <p>
            <html:link action="/admin/dashboard">Admin Panel</html:link>
        </p>
    </c:if>
</body>
</html>'''
    
    with open(temp_dir / 'jsp' / 'login.jsp', 'w') as f:
        f.write(login_jsp)
    
    return temp_dir


def test_configuration_manager():
    """Test the configuration manager."""
    print("Testing ConfigurationManager...")
    
    config = ConfigurationManager()
    
    # Test default configuration
    assert config.get('analysis.parallel_workers') == 4
    assert config.get('struts.config_files') == ['struts-config.xml', 'struts.xml']
    assert config.get('nonexistent.key', 'default') == 'default'
    
    print("✓ ConfigurationManager tests passed")


def test_struts_config_parser():
    """Test the Struts configuration parser."""
    print("Testing StrutsConfigParser...")
    
    config = ConfigurationManager()
    from struts_analyzer import CacheManager
    cache = CacheManager()
    parser = StrutsConfigParser(config, cache)
    
    temp_dir = create_test_struts_app()
    config_file = temp_dir / 'WEB-INF' / 'struts-config.xml'
    
    # Test parser detection
    assert parser.can_parse(config_file)
    
    # Test parsing
    result = parser.parse(config_file)
    
    assert 'action_mappings' in result
    assert 'form_beans' in result
    assert 'business_rules' in result
    
    # Check action mappings
    actions = result['action_mappings']
    assert len(actions) == 3
    
    login_action = next(a for a in actions if a.path == '/login')
    assert login_action.action_class == 'com.example.actions.LoginAction'
    assert 'success' in login_action.forwards
    assert 'failure' in login_action.forwards
    
    # Check business rules
    business_rules = result['business_rules']
    assert len(business_rules) > 0
    
    print("✓ StrutsConfigParser tests passed")


def test_validation_parser():
    """Test the validation parser."""
    print("Testing ValidationParser...")
    
    config = ConfigurationManager()
    from struts_analyzer import CacheManager
    cache = CacheManager()
    parser = ValidationParser(config, cache)
    
    temp_dir = create_test_struts_app()
    validation_file = temp_dir / 'WEB-INF' / 'validation.xml'
    
    # Test parser detection
    assert parser.can_parse(validation_file)
    
    # Test parsing
    result = parser.parse(validation_file)
    
    assert 'validation_rules' in result
    assert 'business_rules' in result
    
    # Check validation rules
    rules = result['validation_rules']
    assert len(rules) > 0
    
    # Find username field rule
    username_rule = next(r for r in rules if r.field == 'username')
    assert username_rule.rule_type == 'required'
    assert username_rule.form_name == 'loginForm'
    
    print("✓ ValidationParser tests passed")


def test_java_action_analyzer():
    """Test the Java Action analyzer."""
    print("Testing JavaActionAnalyzer...")
    
    config = ConfigurationManager()
    from struts_analyzer import CacheManager
    cache = CacheManager()
    analyzer = JavaActionAnalyzer(config, cache)
    
    temp_dir = create_test_struts_app()
    action_file = temp_dir / 'WEB-INF' / 'classes' / 'com' / 'example' / 'actions' / 'LoginAction.java'
    
    # Test analyzer detection
    assert analyzer.can_parse(action_file)
    
    # Test analysis
    result = analyzer.parse(action_file)
    
    assert 'class_info' in result
    assert 'methods' in result
    assert 'business_rules' in result
    
    # Check class info
    class_info = result['class_info']
    assert class_info['name'] == 'LoginAction'
    assert class_info['is_action_class'] == True
    
    # Check methods
    methods = result['methods']
    execute_method = next(m for m in methods if m['name'] == 'execute')
    assert execute_method['is_execute_method'] == True
    
    # Check business rules
    business_rules = result['business_rules']
    assert len(business_rules) > 0
    
    print("✓ JavaActionAnalyzer tests passed")


def test_jsp_analyzer():
    """Test the JSP analyzer."""
    print("Testing JSPAnalyzer...")
    
    config = ConfigurationManager()
    from struts_analyzer import CacheManager
    cache = CacheManager()
    analyzer = JSPAnalyzer(config, cache)
    
    temp_dir = create_test_struts_app()
    jsp_file = temp_dir / 'jsp' / 'login.jsp'
    
    # Test analyzer detection
    assert analyzer.can_parse(jsp_file)
    
    # Test analysis
    result = analyzer.parse(jsp_file)
    
    assert 'ui_business_rules' in result
    assert 'conditional_logic' in result
    assert 'form_bindings' in result
    assert 'navigation_elements' in result
    
    # Check UI business rules
    ui_rules = result['ui_business_rules']
    assert len(ui_rules) > 0
    
    # Check conditional logic
    conditionals = result['conditional_logic']
    assert len(conditionals) > 0
    
    print("✓ JSPAnalyzer tests passed")


def test_full_analysis():
    """Test complete analysis workflow."""
    print("Testing full analysis workflow...")
    
    config = ConfigurationManager()
    extractor = BusinessRuleExtractor(config)
    
    temp_dir = create_test_struts_app()
    
    # Run full analysis
    results = extractor.analyze_directory(temp_dir)
    
    # Verify results structure
    assert 'business_rules' in results
    assert 'action_mappings' in results
    assert 'validation_rules' in results
    assert 'dependencies' in results
    assert 'migration_assessment' in results
    assert 'summary' in results
    
    # Check summary
    summary = results['summary']
    assert summary['total_business_rules'] > 0
    assert summary['total_actions'] > 0
    assert summary['total_validation_rules'] > 0
    
    # Check migration assessment
    assessments = results['migration_assessment']
    assert len(assessments) > 0
    
    login_assessment = next(a for a in assessments if a['component_name'] == '/login')
    assert login_assessment['component_type'] == 'action'
    assert login_assessment['complexity_score'] > 0
    assert login_assessment['risk_level'] in ['low', 'medium', 'high', 'critical']
    
    print("✓ Full analysis workflow tests passed")
    
    # Clean up
    import shutil
    shutil.rmtree(temp_dir)
    
    return results


def run_all_tests():
    """Run all test functions."""
    print("=" * 60)
    print("Running Struts Legacy Business Rules Analyzer Tests")
    print("=" * 60)
    
    try:
        test_configuration_manager()
        test_struts_config_parser()
        test_validation_parser()
        test_java_action_analyzer()
        test_jsp_analyzer()
        results = test_full_analysis()
        
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED! 🎉")
        print("=" * 60)
        
        # Display sample results
        print("\nSample Analysis Results:")
        print(f"Business Rules Found: {results['summary']['total_business_rules']}")
        print(f"Action Mappings: {results['summary']['total_actions']}")
        print(f"Validation Rules: {results['summary']['total_validation_rules']}")
        
        print("\nRule Types Distribution:")
        for rule_type, count in results['summary']['rule_types'].items():
            print(f"  {rule_type}: {count}")
        
        print("\nMigration Risk Summary:")
        for risk_level, count in results['summary']['migration_risk_summary'].items():
            print(f"  {risk_level}: {count}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)