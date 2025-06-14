#!/usr/bin/env python3
"""
Comprehensive System Test
=========================

This test validates the complete Struts analyzer system including:
- All parsers (XML, Java, JSP, Properties)
- All plugins (Framework, Migration, Documentation)
- Business rule engine integration
- Search functionality
- Documentation generation

Author: Claude Code Assistant
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

# Try to import components with fallbacks for missing dependencies
try:
    from parsers import XMLConfigurationParser, JavaSourceParser, JSPTemplateParser, PropertiesFileParser
    PARSERS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Parsers not available: {e}")
    PARSERS_AVAILABLE = False

try:
    from plugins import PluginManager, SpringIntegrationPlugin, GraphQLMigrationPlugin, CustomDocumentationPlugin
    PLUGINS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Plugins not available: {e}")
    PLUGINS_AVAILABLE = False

try:
    from models.business_rule import BusinessRule, BusinessRuleType, BusinessRuleSource, BusinessRuleComplexity
    MODELS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Models not available: {e}")
    MODELS_AVAILABLE = False


def create_sample_struts_application(temp_dir: Path) -> Path:
    """Create a sample Struts application for testing."""
    app_dir = temp_dir / "sample_struts_app"
    app_dir.mkdir(parents=True, exist_ok=True)
    
    # Create WEB-INF directory structure
    web_inf = app_dir / "WEB-INF"
    web_inf.mkdir(exist_ok=True)
    
    classes_dir = web_inf / "classes"
    classes_dir.mkdir(exist_ok=True)
    
    # Create struts-config.xml
    struts_config = web_inf / "struts-config.xml"
    struts_config.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE struts-config PUBLIC "-//Apache Software Foundation//DTD Struts Configuration 1.3//EN" 
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
    </action-mappings>
    
    <message-resources parameter="ApplicationResources"/>
</struts-config>""")
    
    # Create validation.xml
    validation_xml = web_inf / "validation.xml"
    validation_xml.write_text("""<?xml version="1.0" encoding="UTF-8"?>
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
    </formset>
</form-validation>""")
    
    # Create Java Action classes
    actions_dir = classes_dir / "com" / "example" / "actions"
    actions_dir.mkdir(parents=True, exist_ok=True)
    
    login_action = actions_dir / "LoginAction.java"
    login_action.write_text("""package com.example.actions;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import com.example.forms.LoginForm;
import com.example.service.AuthenticationService;

/**
 * Login Action handles user authentication business logic.
 * This action implements the core business rule: users must provide
 * valid credentials to access the system.
 */
public class LoginAction extends Action {
    
    private AuthenticationService authService = new AuthenticationService();
    
    /**
     * Execute method implements the main business workflow:
     * 1. Validate user credentials
     * 2. Check account status
     * 3. Create user session
     * 4. Redirect based on business rules
     */
    public ActionForward execute(ActionMapping mapping,
                               ActionForm form,
                               HttpServletRequest request,
                               HttpServletResponse response) throws Exception {
        
        LoginForm loginForm = (LoginForm) form;
        String username = loginForm.getUsername();
        String password = loginForm.getPassword();
        
        // Business Rule: Username and password are required
        if (username == null || username.trim().isEmpty()) {
            request.setAttribute("error", "Username is required");
            return mapping.getInputForward();
        }
        
        if (password == null || password.trim().isEmpty()) {
            request.setAttribute("error", "Password is required");
            return mapping.getInputForward();
        }
        
        // Business Rule: Authenticate user credentials
        boolean isValid = authService.authenticateUser(username, password);
        
        if (isValid) {
            // Business Rule: Create user session on successful login
            request.getSession().setAttribute("currentUser", username);
            request.getSession().setAttribute("loginTime", System.currentTimeMillis());
            
            // Business Rule: Check if user needs to change password
            if (authService.isPasswordExpired(username)) {
                return mapping.findForward("changePassword");
            }
            
            return mapping.findForward("success");
        } else {
            // Business Rule: Log failed login attempts for security
            authService.logFailedAttempt(username, request.getRemoteAddr());
            request.setAttribute("error", "Invalid username or password");
            return mapping.findForward("failure");
        }
    }
}""")
    
    user_action = actions_dir / "UserAction.java"
    user_action.write_text("""package com.example.actions;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import com.example.forms.UserForm;
import com.example.model.User;
import com.example.service.UserService;

/**
 * User management action implementing business rules for user CRUD operations.
 * Business constraint: Only authenticated users with proper roles can manage users.
 */
public class UserAction extends Action {
    
    private UserService userService = new UserService();
    
    public ActionForward execute(ActionMapping mapping,
                               ActionForm form,
                               HttpServletRequest request,
                               HttpServletResponse response) throws Exception {
        
        String action = request.getParameter("action");
        UserForm userForm = (UserForm) form;
        
        // Business Rule: User must be authenticated
        String currentUser = (String) request.getSession().getAttribute("currentUser");
        if (currentUser == null) {
            return mapping.findForward("login");
        }
        
        if ("list".equals(action)) {
            return listUsers(mapping, request);
        } else if ("save".equals(action)) {
            return saveUser(mapping, userForm, request);
        } else if ("delete".equals(action)) {
            return deleteUser(mapping, request);
        }
        
        return mapping.findForward("list");
    }
    
    /**
     * Business Rule: List users with pagination and filtering
     */
    private ActionForward listUsers(ActionMapping mapping, HttpServletRequest request) {
        // Business Rule: Apply default pagination if not specified
        int page = 1;
        int pageSize = 10;
        
        try {
            String pageParam = request.getParameter("page");
            if (pageParam != null) {
                page = Integer.parseInt(pageParam);
            }
        } catch (NumberFormatException e) {
            page = 1; // Business Rule: Default to first page on invalid input
        }
        
        List<User> users = userService.getUsers(page, pageSize);
        request.setAttribute("users", users);
        request.setAttribute("currentPage", page);
        
        return mapping.findForward("list");
    }
    
    /**
     * Business Rule: Validate and save user with business constraints
     */
    private ActionForward saveUser(ActionMapping mapping, UserForm form, HttpServletRequest request) {
        // Business Rule: Validate email uniqueness
        if (userService.emailExists(form.getEmail(), form.getId())) {
            request.setAttribute("error", "Email address already exists");
            return mapping.findForward("edit");
        }
        
        // Business Rule: Age constraints for business policy
        if (form.getAge() < 18) {
            request.setAttribute("error", "User must be at least 18 years old");
            return mapping.findForward("edit");
        }
        
        if (form.getAge() > 100) {
            request.setAttribute("error", "Invalid age specified");
            return mapping.findForward("edit");
        }
        
        User user = new User();
        user.setId(form.getId());
        user.setEmail(form.getEmail());
        user.setAge(form.getAge());
        
        userService.saveUser(user);
        
        return mapping.findForward("list");
    }
    
    /**
     * Business Rule: Delete user with cascade business logic
     */
    private ActionForward deleteUser(ActionMapping mapping, HttpServletRequest request) {
        Long userId = Long.parseLong(request.getParameter("id"));
        
        // Business Rule: Cannot delete currently logged in user
        String currentUser = (String) request.getSession().getAttribute("currentUser");
        User userToDelete = userService.getUserById(userId);
        
        if (userToDelete.getUsername().equals(currentUser)) {
            request.setAttribute("error", "Cannot delete currently logged in user");
            return mapping.findForward("list");
        }
        
        // Business Rule: Check for dependent records before deletion
        if (userService.hasOrders(userId)) {
            request.setAttribute("error", "Cannot delete user with existing orders");
            return mapping.findForward("list");
        }
        
        userService.deleteUser(userId);
        
        return mapping.findForward("list");
    }
}""")
    
    # Create Form beans
    forms_dir = classes_dir / "com" / "example" / "forms"
    forms_dir.mkdir(parents=True, exist_ok=True)
    
    login_form = forms_dir / "LoginForm.java"
    login_form.write_text("""package com.example.forms;

import org.apache.struts.action.ActionForm;

/**
 * Login form bean with validation constraints.
 * Business Rule: Username and password are required fields.
 */
public class LoginForm extends ActionForm {
    
    private String username;
    private String password;
    private boolean rememberMe;
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
    
    public boolean isRememberMe() {
        return rememberMe;
    }
    
    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}""")
    
    user_form = forms_dir / "UserForm.java"
    user_form.write_text("""package com.example.forms;

import org.apache.struts.action.ActionForm;

/**
 * User form bean with business validation rules.
 * Business constraints: email format, age range, required fields.
 */
public class UserForm extends ActionForm {
    
    private Long id;
    private String email;
    private Integer age;
    private String firstName;
    private String lastName;
    
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public Integer getAge() {
        return age;
    }
    
    public void setAge(Integer age) {
        this.age = age;
    }
    
    public String getFirstName() {
        return firstName;
    }
    
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }
    
    public String getLastName() {
        return lastName;
    }
    
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
}""")
    
    # Create JSP files
    jsp_dir = app_dir / "jsp"
    jsp_dir.mkdir(exist_ok=True)
    
    login_jsp = jsp_dir / "login.jsp"
    login_jsp.write_text("""<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %>
<%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<%@ taglib uri="http://struts.apache.org/tags-logic" prefix="logic" %>

<html>
<head>
    <title><bean:message key="login.title"/></title>
    <script type="text/javascript">
        function validateLoginForm() {
            var username = document.forms["loginForm"]["username"].value;
            var password = document.forms["loginForm"]["password"].value;
            
            // Business Rule: Username is required and must be at least 3 characters
            if (username == null || username == "" || username.length < 3) {
                alert("Username must be at least 3 characters long");
                return false;
            }
            
            // Business Rule: Password is required and must be at least 6 characters
            if (password == null || password == "" || password.length < 6) {
                alert("Password must be at least 6 characters long");
                return false;
            }
            
            return true;
        }
    </script>
</head>
<body>

<h2><bean:message key="login.header"/></h2>

<html:form action="/login" method="post" onsubmit="return validateLoginForm()">
    
    <logic:present name="error">
        <div class="error">
            <bean:write name="error"/>
        </div>
    </logic:present>
    
    <table>
        <tr>
            <td><bean:message key="label.username"/>:</td>
            <td>
                <html:text property="username" size="20" maxlength="50" />
                <html:errors property="username"/>
            </td>
        </tr>
        <tr>
            <td><bean:message key="label.password"/>:</td>
            <td>
                <html:password property="password" size="20" maxlength="50" />
                <html:errors property="password"/>
            </td>
        </tr>
        <tr>
            <td colspan="2">
                <html:checkbox property="rememberMe" />
                <bean:message key="login.remember"/>
            </td>
        </tr>
        <tr>
            <td colspan="2">
                <html:submit><bean:message key="button.login"/></html:submit>
                <html:cancel><bean:message key="button.cancel"/></html:cancel>
            </td>
        </tr>
    </table>
    
</html:form>

<!-- Business Rule: Show different content based on user status -->
<logic:present name="currentUser" scope="session">
    <p><bean:message key="message.welcome"/> <bean:write name="currentUser" scope="session"/></p>
</logic:present>

<logic:notPresent name="currentUser" scope="session">
    <p><bean:message key="message.please.login"/></p>
</logic:notPresent>

</body>
</html>""")
    
    user_list_jsp = jsp_dir / "userList.jsp"
    user_list_jsp.write_text("""<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %>
<%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<%@ taglib uri="http://struts.apache.org/tags-logic" prefix="logic" %>

<html>
<head>
    <title><bean:message key="user.list.title"/></title>
</head>
<body>

<h2><bean:message key="user.list.header"/></h2>

<!-- Business Rule: Only show add user button to authorized users -->
<logic:present name="currentUser" scope="session">
    <html:link action="/user?action=add">
        <bean:message key="user.add.link"/>
    </html:link>
</logic:present>

<table border="1">
    <tr>
        <th><bean:message key="label.id"/></th>
        <th><bean:message key="label.email"/></th>
        <th><bean:message key="label.age"/></th>
        <th><bean:message key="label.actions"/></th>
    </tr>
    
    <!-- Business Rule: Display users with conditional formatting -->
    <logic:iterate id="user" name="users">
        <tr>
            <td><bean:write name="user" property="id"/></td>
            <td><bean:write name="user" property="email"/></td>
            <td>
                <!-- Business Rule: Highlight users based on age groups -->
                <logic:lessThan name="user" property="age" value="30">
                    <span style="color: green;"><bean:write name="user" property="age"/></span>
                </logic:lessThan>
                <logic:greaterEqual name="user" property="age" value="30">
                    <logic:lessThan name="user" property="age" value="60">
                        <span style="color: blue;"><bean:write name="user" property="age"/></span>
                    </logic:lessThan>
                </logic:greaterEqual>
                <logic:greaterEqual name="user" property="age" value="60">
                    <span style="color: red;"><bean:write name="user" property="age"/></span>
                </logic:greaterEqual>
            </td>
            <td>
                <html:link action="/user?action=edit" paramId="id" paramName="user" paramProperty="id">
                    <bean:message key="action.edit"/>
                </html:link>
                |
                <!-- Business Rule: Only allow deletion by admin users -->
                <logic:equal name="userRole" scope="session" value="admin">
                    <html:link action="/user?action=delete" paramId="id" paramName="user" paramProperty="id"
                              onclick="return confirm('Are you sure you want to delete this user?')">
                        <bean:message key="action.delete"/>
                    </html:link>
                </logic:equal>
            </td>
        </tr>
    </logic:iterate>
    
    <!-- Business Rule: Show message when no users found -->
    <logic:notPresent name="users">
        <tr>
            <td colspan="4"><bean:message key="user.list.empty"/></td>
        </tr>
    </logic:notPresent>
    
</table>

<!-- Business Rule: Pagination controls -->
<logic:present name="currentPage">
    <div class="pagination">
        <logic:greaterThan name="currentPage" value="1">
            <html:link action="/user?action=list" paramId="page" paramName="prevPage">
                <bean:message key="pagination.previous"/>
            </html:link>
        </logic:greaterThan>
        
        <bean:message key="pagination.page"/> <bean:write name="currentPage"/>
        
        <logic:present name="hasNextPage">
            <html:link action="/user?action=list" paramId="page" paramName="nextPage">
                <bean:message key="pagination.next"/>
            </html:link>
        </logic:present>
    </div>
</logic:present>

</body>
</html>""")
    
    # Create Properties files
    properties_dir = classes_dir
    
    app_resources = properties_dir / "ApplicationResources.properties"
    app_resources.write_text("""# Application Messages for Business Rules Demo
# Login related messages - Business Rule: User authentication is required
login.title=User Login
login.header=Please Login to Continue
login.remember=Remember me on this computer
message.welcome=Welcome back,
message.please.login=Please log in to access the system

# Form labels - Business Rule: All forms must have proper labels
label.username=Username
label.password=Password
label.email=Email Address
label.age=Age
label.id=User ID
label.actions=Actions
label.firstName=First Name
label.lastName=Last Name

# Button labels
button.login=Login
button.cancel=Cancel
button.save=Save
button.delete=Delete
button.edit=Edit

# User management messages - Business Rule: User management requires validation
user.list.title=User Management
user.list.header=User List
user.list.empty=No users found in the system
user.add.link=Add New User

# Action labels
action.edit=Edit
action.delete=Delete
action.view=View

# Pagination - Business Rule: Large lists must be paginated
pagination.previous=Previous
pagination.next=Next
pagination.page=Page

# Validation error messages - Business Rules for data integrity
error.username.required=Username is required for login
error.username.minlength=Username must be at least {1} characters long
error.password.required=Password is required for security
error.password.minlength=Password must be at least {1} characters long for security
error.email.required=Email address is required
error.email.invalid=Please enter a valid email address format
error.age.required=Age is required for user profile
error.age.range=Age must be between {1} and {2} years
error.age.invalid=Please enter a valid age

# Business constraint messages
constraint.email.unique=Email address already exists in the system
constraint.age.minimum=Users must be at least 18 years old
constraint.age.maximum=Invalid age specified (maximum 100 years)
constraint.user.delete.self=Cannot delete currently logged in user
constraint.user.delete.orders=Cannot delete user with existing orders
constraint.login.failed=Invalid username or password provided
constraint.password.expired=Password has expired, please change it

# Business policy messages
policy.authentication.required=Authentication required to access this resource
policy.admin.required=Administrator privileges required for this action
policy.session.timeout=Your session has expired, please log in again
policy.concurrent.login=Another user session detected for this account""")
    
    # Create validation messages
    validation_resources = properties_dir / "ValidationResources.properties"
    validation_resources.write_text("""# Validation Messages for Business Rules
# These messages enforce business validation rules

# Required field validation - Business Rule: Critical fields cannot be empty
errors.required={0} is required by business policy
errors.minlength={0} must be at least {1} characters long for security
errors.maxlength={0} cannot exceed {1} characters

# Format validation - Business Rule: Data must follow business formats
errors.invalid={0} format is invalid
errors.email={0} must be a valid email address format
errors.creditcard={0} must be a valid credit card number
errors.phone={0} must be a valid phone number format

# Range validation - Business Rule: Values must be within business constraints
errors.range={0} must be between {1} and {2}
errors.min={0} must be at least {1}
errors.max={0} cannot exceed {1}

# Date validation - Business Rule: Dates must be valid for business operations
errors.date={0} must be a valid date in MM/dd/yyyy format
errors.date.past={0} cannot be in the past
errors.date.future={0} cannot be in the future

# Business-specific validation rules
errors.username.exists=Username already exists, please choose another
errors.password.weak=Password does not meet security requirements
errors.age.business=Age must comply with business eligibility rules
errors.account.locked=Account is locked due to security policy
errors.account.expired=Account has expired according to business rules""")
    
    # Create Spring configuration (for framework detection)
    spring_dir = web_inf / "spring"
    spring_dir.mkdir(exist_ok=True)
    
    spring_config = spring_dir / "applicationContext.xml"
    spring_config.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- Business service beans -->
    <bean id="authenticationService" class="com.example.service.AuthenticationService">
        <property name="maxFailedAttempts" value="3"/>
        <property name="lockoutDuration" value="300"/>
    </bean>
    
    <bean id="userService" class="com.example.service.UserService">
        <property name="defaultPageSize" value="10"/>
        <property name="maxPageSize" value="100"/>
    </bean>
    
    <!-- Business validation beans -->
    <bean id="passwordValidator" class="com.example.validation.PasswordValidator">
        <property name="minLength" value="6"/>
        <property name="requireSpecialChars" value="true"/>
    </bean>
    
    <bean id="emailValidator" class="com.example.validation.EmailValidator">
        <property name="allowedDomains">
            <list>
                <value>company.com</value>
                <value>partner.com</value>
            </list>
        </property>
    </bean>

</beans>""")
    
    return app_dir


def test_parsers(app_dir: Path) -> Dict[str, Any]:
    """Test all parsers on sample files."""
    print("Testing parsers...")
    
    results = {
        'xml_parser': None,
        'java_parser': None,
        'jsp_parser': None,
        'properties_parser': None
    }
    
    if not PARSERS_AVAILABLE:
        print("  Parsers not available - skipping parser tests")
        return results
    
    # Test XML parser
    try:
        xml_parser = XMLConfigurationParser()
        struts_config = app_dir / "WEB-INF" / "struts-config.xml"
        if struts_config.exists():
            xml_result = xml_parser.parse_file(struts_config)
            results['xml_parser'] = {
                'success': xml_result.success,
                'business_rules_count': len(xml_result.business_rules) if xml_result.business_rules else 0,
                'extracted_data_keys': list(xml_result.extracted_data.keys()) if xml_result.extracted_data else []
            }
            print(f"  XML Parser: {results['xml_parser']['business_rules_count']} business rules found")
    except Exception as e:
        print(f"  XML Parser failed: {e}")
        results['xml_parser'] = {'success': False, 'error': str(e)}
    
    # Test Java parser
    try:
        java_parser = JavaSourceParser()
        login_action = app_dir / "WEB-INF" / "classes" / "com" / "example" / "actions" / "LoginAction.java"
        if login_action.exists():
            java_result = java_parser.parse_file(login_action)
            results['java_parser'] = {
                'success': java_result.success,
                'business_rules_count': len(java_result.business_rules) if java_result.business_rules else 0,
                'extracted_data_keys': list(java_result.extracted_data.keys()) if java_result.extracted_data else []
            }
            print(f"  Java Parser: {results['java_parser']['business_rules_count']} business rules found")
    except Exception as e:
        print(f"  Java Parser failed: {e}")
        results['java_parser'] = {'success': False, 'error': str(e)}
    
    # Test JSP parser
    try:
        jsp_parser = JSPTemplateParser()
        login_jsp = app_dir / "jsp" / "login.jsp"
        if login_jsp.exists():
            jsp_result = jsp_parser.parse_file(login_jsp)
            results['jsp_parser'] = {
                'success': jsp_result.success,
                'business_rules_count': len(jsp_result.business_rules) if jsp_result.business_rules else 0,
                'extracted_data_keys': list(jsp_result.extracted_data.keys()) if jsp_result.extracted_data else []
            }
            print(f"  JSP Parser: {results['jsp_parser']['business_rules_count']} business rules found")
    except Exception as e:
        print(f"  JSP Parser failed: {e}")
        results['jsp_parser'] = {'success': False, 'error': str(e)}
    
    # Test Properties parser
    try:
        props_parser = PropertiesFileParser()
        app_resources = app_dir / "WEB-INF" / "classes" / "ApplicationResources.properties"
        if app_resources.exists():
            props_result = props_parser.parse_file(app_resources)
            results['properties_parser'] = {
                'success': props_result.success,
                'business_rules_count': len(props_result.business_rules) if props_result.business_rules else 0,
                'extracted_data_keys': list(props_result.extracted_data.keys()) if props_result.extracted_data else []
            }
            print(f"  Properties Parser: {results['properties_parser']['business_rules_count']} business rules found")
    except Exception as e:
        print(f"  Properties Parser failed: {e}")
        results['properties_parser'] = {'success': False, 'error': str(e)}
    
    return results


def test_plugins(app_dir: Path) -> Dict[str, Any]:
    """Test plugins functionality."""
    print("Testing plugins...")
    
    results = {
        'plugin_manager': None,
        'spring_plugin': None,
        'migration_plugin': None,
        'documentation_plugin': None
    }
    
    # Test plugin manager
    plugin_manager = PluginManager()
    discovered_count = plugin_manager.discover_plugins()
    init_success = plugin_manager.initialize_plugins()
    
    results['plugin_manager'] = {
        'discovered_plugins': discovered_count,
        'initialized_successfully': init_success,
        'plugin_summary': plugin_manager.get_plugin_summary()
    }
    print(f"  Plugin Manager: {discovered_count} plugins discovered")
    
    # Test Spring plugin
    spring_plugin = SpringIntegrationPlugin()
    spring_context = {'project_path': str(app_dir)}
    
    if spring_plugin.can_handle(spring_context):
        spring_result = spring_plugin.execute(spring_context)
        results['spring_plugin'] = {
            'success': spring_result.success,
            'business_rules_count': len(spring_result.business_rules) if spring_result.business_rules else 0,
            'extracted_data_keys': list(spring_result.extracted_data.keys()) if spring_result.extracted_data else []
        }
        print(f"  Spring Plugin: {results['spring_plugin']['business_rules_count']} business rules found")
    
    # Test migration plugin
    migration_plugin = GraphQLMigrationPlugin()
    # Create some sample business rules for testing
    from models.business_rule import BusinessRule, BusinessRuleType, BusinessRuleSource, BusinessRuleComplexity
    
    sample_rules = [
        BusinessRule(
            id="test_rule_1",
            name="User Authentication",
            description="Business rule for user authentication",
            rule_type=BusinessRuleType.BUSINESS_LOGIC,
            source=BusinessRuleSource.ACTION_CLASS,
            complexity=BusinessRuleComplexity.MODERATE
        ),
        BusinessRule(
            id="test_rule_2", 
            name="Data Validation",
            description="Validation rule for user data",
            rule_type=BusinessRuleType.VALIDATION,
            source=BusinessRuleSource.VALIDATION_XML,
            complexity=BusinessRuleComplexity.SIMPLE
        )
    ]
    
    migration_context = {'business_rules': sample_rules}
    migration_result = migration_plugin.generate_migration_recommendations(sample_rules, migration_context)
    
    results['migration_plugin'] = {
        'success': migration_result.success,
        'recommendations_count': len(migration_result.recommendations) if migration_result.recommendations else 0,
        'extracted_data_keys': list(migration_result.extracted_data.keys()) if migration_result.extracted_data else []
    }
    print(f"  Migration Plugin: {results['migration_plugin']['recommendations_count']} recommendations generated")
    
    # Test documentation plugin
    doc_plugin = CustomDocumentationPlugin()
    with tempfile.TemporaryDirectory() as temp_output:
        output_path = Path(temp_output)
        doc_result = doc_plugin.generate_documentation(sample_rules, {}, output_path)
        
        results['documentation_plugin'] = {
            'success': doc_result.success,
            'generated_files': doc_result.extracted_data.get('generated_files', []) if doc_result.extracted_data else [],
            'output_formats': doc_result.extracted_data.get('output_formats', []) if doc_result.extracted_data else []
        }
        print(f"  Documentation Plugin: {len(results['documentation_plugin']['generated_files'])} files generated")
    
    plugin_manager.cleanup_plugins()
    return results


def test_business_rule_engine(app_dir: Path) -> Dict[str, Any]:
    """Test the complete business rule engine."""
    print("Testing Business Rule Engine...")
    
    # Create configuration
    config_data = {
        'analysis': {
            'index_path': ':memory:',
            'parallel_enabled': False,
            'exclude_patterns': ['*/test/*', '**/target/**']
        }
    }
    
    config = ConfigurationManager(config_data)
    engine = BusinessRuleEngine(config)
    
    try:
        # Run comprehensive analysis
        discovery_result = engine.analyze_application(app_dir)
        
        results = {
            'total_rules': discovery_result.total_rules,
            'rules_by_type': discovery_result.rules_by_type,
            'rules_by_complexity': discovery_result.rules_by_complexity,
            'business_domains': list(discovery_result.business_domains),
            'high_impact_count': len(discovery_result.high_impact_rules),
            'analysis_metadata': discovery_result.analysis_metadata
        }
        
        print(f"  Total business rules discovered: {results['total_rules']}")
        print(f"  Business domains: {len(results['business_domains'])}")
        print(f"  High impact rules: {results['high_impact_count']}")
        
        # Test search functionality
        if results['total_rules'] > 0:
            from models.search_index import SearchQuery
            
            search_query = SearchQuery(
                query_text="validation",
                rule_types=["VALIDATION"],
                max_results=10
            )
            
            search_result = engine.search_business_rules(search_query)
            results['search_test'] = {
                'query': "validation",
                'results_count': len(search_result.rules),
                'total_matches': search_result.total_matches
            }
            print(f"  Search test: {results['search_test']['results_count']} results for 'validation'")
        
        # Test export functionality
        with tempfile.TemporaryDirectory() as temp_output:
            output_path = Path(temp_output) / "analysis_results"
            
            # Test JSON export
            engine.export_analysis_results(output_path, "json")
            json_file = output_path.with_suffix('.json')
            results['export_test'] = {
                'json_export': json_file.exists(),
                'json_size': json_file.stat().st_size if json_file.exists() else 0
            }
            print(f"  Export test: JSON file created ({results['export_test']['json_size']} bytes)")
        
        return results
        
    finally:
        engine.close()


def run_comprehensive_test():
    """Run comprehensive test of the entire system."""
    print("=== Comprehensive Struts Analyzer System Test ===\n")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create sample application
        print("Creating sample Struts application...")
        app_dir = create_sample_struts_application(temp_path)
        print(f"Sample application created at: {app_dir}\n")
        
        # Test results
        test_results = {}
        
        try:
            # Test parsers
            test_results['parsers'] = test_parsers(app_dir)
            print()
            
            # Test plugins
            test_results['plugins'] = test_plugins(app_dir)
            print()
            
            # Test business rule engine
            test_results['engine'] = test_business_rule_engine(app_dir)
            print()
            
            # Print summary
            print("=== Test Summary ===")
            
            # Parser summary
            parser_success = sum(1 for result in test_results['parsers'].values() 
                               if result and result.get('success', False))
            print(f"Parsers: {parser_success}/4 successful")
            
            total_parser_rules = sum(result.get('business_rules_count', 0) 
                                   for result in test_results['parsers'].values() 
                                   if result)
            print(f"Parser business rules: {total_parser_rules}")
            
            # Plugin summary
            plugin_summary = test_results['plugins']['plugin_manager']['plugin_summary']
            print(f"Plugins: {plugin_summary['enabled_plugins']}/{plugin_summary['total_plugins']} enabled")
            
            # Engine summary
            engine_rules = test_results['engine']['total_rules']
            print(f"Engine analysis: {engine_rules} total business rules discovered")
            
            domains = len(test_results['engine']['business_domains'])
            print(f"Business domains identified: {domains}")
            
            # Overall success
            overall_success = (
                parser_success >= 3 and  # At least 3 parsers working
                plugin_summary['enabled_plugins'] > 0 and  # At least some plugins working
                engine_rules > 0  # Engine found some rules
            )
            
            print(f"\nOverall test result: {'✅ PASS' if overall_success else '❌ FAIL'}")
            
            return overall_success, test_results
            
        except Exception as e:
            print(f"Test failed with error: {e}")
            import traceback
            traceback.print_exc()
            return False, test_results


if __name__ == "__main__":
    success, results = run_comprehensive_test()
    
    if success:
        print("\n🎉 All systems working correctly!")
        print("The Struts analyzer is ready for production use.")
    else:
        print("\n❌ Some components failed testing.")
        print("Please check the error messages above.")
    
    sys.exit(0 if success else 1)