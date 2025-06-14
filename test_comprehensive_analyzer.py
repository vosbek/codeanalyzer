#!/usr/bin/env python3
"""
Comprehensive Business Rule Analyzer Test Suite
================================================

This test suite validates the enhanced business rule analysis capabilities
for large Struts applications. It tests all analyzers, search functionality,
and documentation generation with sample data.

Author: Claude Code Assistant
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any
import json
import xml.etree.ElementTree as ET

from business_rule_engine import BusinessRuleEngine
from models.business_rule import BusinessRule, BusinessRuleType, BusinessRuleComplexity
from models.search_index import BusinessRuleIndex, SearchQuery
from utils.config_utils import ConfigurationManager
from analyzers.struts_config_analyzer import StrutsConfigAnalyzer
from analyzers.validation_analyzer import ValidationAnalyzer
from analyzers.java_action_analyzer import JavaActionAnalyzer
from analyzers.jsp_analyzer import JSPAnalyzer
from analyzers.properties_analyzer import PropertiesAnalyzer
from analyzers.interceptor_analyzer import InterceptorAnalyzer
from generators.enhanced_documentation_generator import EnhancedDocumentationGenerator


class TestBusinessRuleAnalyzer(unittest.TestCase):
    """Test suite for comprehensive business rule analysis."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.config = ConfigurationManager()
        self.engine = BusinessRuleEngine(self.config)
        
        # Create sample Struts application structure
        self.sample_app_dir = self.test_dir / "sample_struts_app"
        self._create_sample_struts_application()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
        if hasattr(self.engine, 'search_index'):
            self.engine.search_index.close()
    
    def _create_sample_struts_application(self):
        """Create a sample Struts application for testing."""
        app_dir = self.sample_app_dir
        app_dir.mkdir(parents=True)
        
        # Create directory structure
        (app_dir / "WEB-INF").mkdir()
        (app_dir / "WEB-INF" / "classes").mkdir()
        (app_dir / "WEB-INF" / "classes" / "com" / "example" / "actions").mkdir(parents=True)
        (app_dir / "jsp").mkdir()
        
        # Create struts-config.xml
        self._create_struts_config(app_dir / "WEB-INF" / "struts-config.xml")
        
        # Create validation.xml
        self._create_validation_config(app_dir / "WEB-INF" / "validation.xml")
        
        # Create sample Action classes
        self._create_sample_action_classes(app_dir / "WEB-INF" / "classes" / "com" / "example" / "actions")
        
        # Create sample JSP files
        self._create_sample_jsp_files(app_dir / "jsp")
        
        # Create properties files
        self._create_sample_properties(app_dir / "WEB-INF" / "classes")
        
        # Create interceptor configuration
        self._create_interceptor_config(app_dir / "WEB-INF" / "struts.xml")
    
    def _create_struts_config(self, file_path: Path):
        """Create sample struts-config.xml."""
        content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE struts-config PUBLIC
    "-//Apache Software Foundation//DTD Struts Configuration 1.3//EN"
    "http://struts.apache.org/dtds/struts-config_1_3.dtd">

<struts-config>
    
    <form-beans>
        <form-bean name="userForm" type="com.example.forms.UserForm"/>
        <form-bean name="orderForm" type="com.example.forms.OrderForm"/>
        <form-bean name="productForm" type="com.example.forms.ProductForm"/>
    </form-beans>
    
    <global-forwards>
        <forward name="login" path="/login.jsp"/>
        <forward name="home" path="/home.jsp"/>
        <forward name="error" path="/error.jsp"/>
    </global-forwards>
    
    <action-mappings>
        
        <!-- User Management Actions -->
        <action path="/login" 
                type="com.example.actions.LoginAction"
                name="userForm"
                scope="request"
                validate="true"
                input="/login.jsp">
            <forward name="success" path="/home.jsp"/>
            <forward name="failure" path="/login.jsp"/>
            <exception key="auth.error" type="SecurityException" path="/error.jsp"/>
        </action>
        
        <action path="/createUser"
                type="com.example.actions.CreateUserAction"
                name="userForm"
                scope="request"
                validate="true"
                input="/user/create.jsp">
            <forward name="success" path="/user/list.jsp"/>
            <forward name="failure" path="/user/create.jsp"/>
            <forward name="duplicate" path="/user/duplicate.jsp"/>
        </action>
        
        <!-- Order Processing Actions -->
        <action path="/createOrder"
                type="com.example.actions.CreateOrderAction"
                name="orderForm"
                scope="request"
                validate="true"
                input="/order/create.jsp">
            <forward name="success" path="/order/confirmation.jsp"/>
            <forward name="payment_required" path="/payment/form.jsp"/>
            <forward name="inventory_check" path="/inventory/verify.jsp"/>
            <exception key="payment.error" type="PaymentException" path="/payment/error.jsp"/>
            <exception key="inventory.error" type="InventoryException" path="/inventory/error.jsp"/>
        </action>
        
        <!-- Product Management Actions -->
        <action path="/productCatalog"
                type="com.example.actions.ProductCatalogAction"
                scope="request">
            <forward name="success" path="/product/catalog.jsp"/>
            <forward name="category" path="/product/category.jsp"/>
        </action>
        
        <!-- Admin Actions -->
        <action path="/adminDashboard"
                type="com.example.actions.AdminDashboardAction"
                scope="request">
            <forward name="success" path="/admin/dashboard.jsp"/>
            <exception key="permission.denied" type="SecurityException" path="/error.jsp"/>
        </action>
        
    </action-mappings>
    
</struts-config>"""
        
        with open(file_path, 'w') as f:
            f.write(content)
    
    def _create_validation_config(self, file_path: Path):
        """Create sample validation.xml."""
        content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE form-validation PUBLIC
    "-//Apache Software Foundation//DTD Commons Validator Rules Configuration 1.3.0//EN"
    "http://jakarta.apache.org/commons/dtds/validator_1_3_0.dtd">

<form-validation>
    
    <formset>
        
        <!-- User Form Validation -->
        <form name="userForm">
            <field property="username" depends="required,minlength,maxlength">
                <arg position="0" key="user.username"/>
                <var>
                    <var-name>minlength</var-name>
                    <var-value>3</var-value>
                </var>
                <var>
                    <var-name>maxlength</var-name>
                    <var-value>20</var-value>
                </var>
                <msg key="error.username.required" name="required"/>
                <msg key="error.username.length" name="minlength"/>
                <msg key="error.username.length" name="maxlength"/>
            </field>
            
            <field property="email" depends="required,email">
                <arg position="0" key="user.email"/>
                <msg key="error.email.required" name="required"/>
                <msg key="error.email.invalid" name="email"/>
            </field>
            
            <field property="password" depends="required,minlength">
                <arg position="0" key="user.password"/>
                <var>
                    <var-name>minlength</var-name>
                    <var-value>8</var-value>
                </var>
                <msg key="error.password.required" name="required"/>
                <msg key="error.password.weak" name="minlength"/>
            </field>
            
            <field property="age" depends="required,range">
                <arg position="0" key="user.age"/>
                <var>
                    <var-name>min</var-name>
                    <var-value>18</var-value>
                </var>
                <var>
                    <var-name>max</var-name>
                    <var-value>120</var-value>
                </var>
                <msg key="error.age.required" name="required"/>
                <msg key="error.age.range" name="range"/>
            </field>
        </form>
        
        <!-- Order Form Validation -->
        <form name="orderForm">
            <field property="customerEmail" depends="required,email">
                <arg position="0" key="order.customer.email"/>
                <msg key="error.customer.email.required" name="required"/>
                <msg key="error.customer.email.invalid" name="email"/>
            </field>
            
            <field property="totalAmount" depends="required,range">
                <arg position="0" key="order.total"/>
                <var>
                    <var-name>min</var-name>
                    <var-value>0.01</var-value>
                </var>
                <var>
                    <var-name>max</var-name>
                    <var-value>10000.00</var-value>
                </var>
                <msg key="error.order.total.required" name="required"/>
                <msg key="error.order.total.range" name="range"/>
            </field>
            
            <field property="paymentMethod" depends="required">
                <arg position="0" key="order.payment.method"/>
                <msg key="error.payment.method.required" name="required"/>
            </field>
        </form>
        
        <!-- Product Form Validation -->
        <form name="productForm">
            <field property="productName" depends="required,maxlength">
                <arg position="0" key="product.name"/>
                <var>
                    <var-name>maxlength</var-name>
                    <var-value>100</var-value>
                </var>
                <msg key="error.product.name.required" name="required"/>
                <msg key="error.product.name.length" name="maxlength"/>
            </field>
            
            <field property="price" depends="required,range">
                <arg position="0" key="product.price"/>
                <var>
                    <var-name>min</var-name>
                    <var-value>0.01</var-value>
                </var>
                <var>
                    <var-name>max</var-name>
                    <var-value>999999.99</var-value>
                </var>
                <msg key="error.product.price.required" name="required"/>
                <msg key="error.product.price.range" name="range"/>
            </field>
        </form>
        
    </formset>
    
</form-validation>"""
        
        with open(file_path, 'w') as f:
            f.write(content)
    
    def _create_sample_action_classes(self, actions_dir: Path):
        """Create sample Java Action classes."""
        
        # LoginAction.java
        login_action = """package com.example.actions;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

/**
 * Business Rule: User authentication and session management
 * This action handles user login with security validation
 */
public class LoginAction extends Action {
    
    /**
     * Business Rule: Login attempt validation
     * Must validate credentials and establish secure session
     */
    public ActionForward execute(ActionMapping mapping, ActionForm form,
            HttpServletRequest request, HttpServletResponse response) {
        
        UserForm userForm = (UserForm) form;
        
        // Business Rule: Username and password must be provided
        if (userForm.getUsername() == null || userForm.getPassword() == null) {
            return mapping.findForward("failure");
        }
        
        // Business Rule: Maximum 3 failed login attempts
        int failedAttempts = getFailedAttempts(userForm.getUsername());
        if (failedAttempts >= 3) {
            // Business Rule: Account lockout after 3 failed attempts
            lockUserAccount(userForm.getUsername());
            return mapping.findForward("failure");
        }
        
        // Business Rule: Password validation against stored hash
        if (validateCredentials(userForm.getUsername(), userForm.getPassword())) {
            // Business Rule: Successful login creates session
            createUserSession(request, userForm.getUsername());
            return mapping.findForward("success");
        } else {
            // Business Rule: Failed login increments attempt counter
            incrementFailedAttempts(userForm.getUsername());
            return mapping.findForward("failure");
        }
    }
    
    private boolean validateCredentials(String username, String password) {
        // Business logic for credential validation
        return true; // Simplified for testing
    }
    
    private void createUserSession(HttpServletRequest request, String username) {
        // Business logic for session creation
    }
    
    private int getFailedAttempts(String username) {
        // Business logic for tracking failed attempts
        return 0;
    }
    
    private void incrementFailedAttempts(String username) {
        // Business logic for incrementing failed attempts
    }
    
    private void lockUserAccount(String username) {
        // Business logic for account lockout
    }
}"""
        
        with open(actions_dir / "LoginAction.java", 'w') as f:
            f.write(login_action)
        
        # CreateOrderAction.java
        order_action = """package com.example.actions;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

/**
 * Business Rule: Order creation and processing workflow
 * Handles complex business logic for order management
 */
public class CreateOrderAction extends Action {
    
    /**
     * Business Rule: Order creation with validation and processing
     * Must validate inventory, calculate totals, and process payment
     */
    public ActionForward execute(ActionMapping mapping, ActionForm form,
            HttpServletRequest request, HttpServletResponse response) {
        
        OrderForm orderForm = (OrderForm) form;
        
        // Business Rule: Order must have at least one item
        if (orderForm.getItems() == null || orderForm.getItems().isEmpty()) {
            request.setAttribute("errorMessage", "Order must contain at least one item");
            return mapping.findForward("failure");
        }
        
        // Business Rule: Inventory validation for all items
        if (!validateInventory(orderForm)) {
            return mapping.findForward("inventory_check");
        }
        
        // Business Rule: Calculate order total with taxes and discounts
        double total = calculateOrderTotal(orderForm);
        orderForm.setTotalAmount(total);
        
        // Business Rule: Orders over $1000 require manager approval
        if (total > 1000.0) {
            if (!hasManagerApproval(orderForm)) {
                requestManagerApproval(orderForm);
                return mapping.findForward("approval_required");
            }
        }
        
        // Business Rule: Payment validation and processing
        if (!processPayment(orderForm)) {
            return mapping.findForward("payment_required");
        }
        
        // Business Rule: Create order record and update inventory
        String orderId = createOrder(orderForm);
        updateInventory(orderForm);
        
        request.setAttribute("orderId", orderId);
        return mapping.findForward("success");
    }
    
    private boolean validateInventory(OrderForm orderForm) {
        // Business logic for inventory validation
        return true;
    }
    
    private double calculateOrderTotal(OrderForm orderForm) {
        // Business logic for total calculation including tax and discounts
        double subtotal = orderForm.getSubtotal();
        double tax = subtotal * 0.08; // 8% tax rate
        double discount = calculateDiscount(orderForm);
        return subtotal + tax - discount;
    }
    
    private double calculateDiscount(OrderForm orderForm) {
        // Business Rule: Customer loyalty discount calculation
        if (orderForm.getCustomerLoyaltyLevel().equals("GOLD")) {
            return orderForm.getSubtotal() * 0.10; // 10% discount
        } else if (orderForm.getCustomerLoyaltyLevel().equals("SILVER")) {
            return orderForm.getSubtotal() * 0.05; // 5% discount
        }
        return 0.0;
    }
    
    private boolean processPayment(OrderForm orderForm) {
        // Business logic for payment processing
        return true;
    }
    
    private String createOrder(OrderForm orderForm) {
        // Business logic for order creation
        return "ORDER_" + System.currentTimeMillis();
    }
    
    private void updateInventory(OrderForm orderForm) {
        // Business logic for inventory updates
    }
    
    private boolean hasManagerApproval(OrderForm orderForm) {
        // Business logic for manager approval check
        return false;
    }
    
    private void requestManagerApproval(OrderForm orderForm) {
        // Business logic for requesting manager approval
    }
}"""
        
        with open(actions_dir / "CreateOrderAction.java", 'w') as f:
            f.write(order_action)
    
    def _create_sample_jsp_files(self, jsp_dir: Path):
        """Create sample JSP files."""
        
        # login.jsp
        login_jsp = """<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %>
<%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html>
<html>
<head>
    <title>User Login</title>
</head>
<body>
    <h1>Login</h1>
    
    <%-- Business Rule: Display error messages for failed login attempts --%>
    <c:if test="${not empty errorMessage}">
        <div class="error">
            <bean:write name="errorMessage"/>
        </div>
    </c:if>
    
    <%-- Business Rule: Login form with validation --%>
    <html:form action="/login" method="POST">
        
        <div>
            <label for="username">Username:</label>
            <%-- Business Rule: Username is required --%>
            <html:text property="username" required="true" maxlength="20"/>
            <html:errors property="username"/>
        </div>
        
        <div>
            <label for="password">Password:</label>
            <%-- Business Rule: Password must be secure --%>
            <html:password property="password" required="true" minlength="8"/>
            <html:errors property="password"/>
        </div>
        
        <%-- Business Rule: Remember me option for user convenience --%>
        <div>
            <html:checkbox property="rememberMe"/>
            <label for="rememberMe">Remember Me</label>
        </div>
        
        <div>
            <html:submit value="Login"/>
            <html:reset value="Clear"/>
        </div>
        
    </html:form>
    
    <%-- Business Rule: Link to registration for new users --%>
    <p>
        Don't have an account? 
        <html:link action="/register">Register here</html:link>
    </p>
    
</body>
</html>"""
        
        with open(jsp_dir / "login.jsp", 'w') as f:
            f.write(login_jsp)
        
        # order_form.jsp
        order_jsp = """<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %>
<%@ taglib uri="http://struts.apache.org/tags-logic" prefix="logic" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html>
<html>
<head>
    <title>Create Order</title>
</head>
<body>
    <h1>Create New Order</h1>
    
    <html:form action="/createOrder" method="POST">
        
        <%-- Business Rule: Customer information is required --%>
        <fieldset>
            <legend>Customer Information</legend>
            
            <div>
                <label>Customer Email:</label>
                <html:text property="customerEmail" size="30"/>
                <html:errors property="customerEmail"/>
            </div>
            
            <%-- Business Rule: Display loyalty status if customer exists --%>
            <c:if test="${not empty customerLoyaltyLevel}">
                <div class="loyalty-info">
                    Loyalty Level: <strong>${customerLoyaltyLevel}</strong>
                    <%-- Business Rule: Show discount information for loyalty members --%>
                    <c:choose>
                        <c:when test="${customerLoyaltyLevel == 'GOLD'}">
                            <span class="discount">10% discount applied</span>
                        </c:when>
                        <c:when test="${customerLoyaltyLevel == 'SILVER'}">
                            <span class="discount">5% discount applied</span>
                        </c:when>
                    </c:choose>
                </div>
            </c:if>
        </fieldset>
        
        <%-- Business Rule: Order items management --%>
        <fieldset>
            <legend>Order Items</legend>
            
            <logic:iterate id="item" name="orderForm" property="items" indexId="index">
                <div class="order-item">
                    <html:hidden name="item" property="productId" indexed="true"/>
                    
                    <span>Product: ${item.productName}</span>
                    <span>Price: $${item.unitPrice}</span>
                    
                    <%-- Business Rule: Quantity must be positive integer --%>
                    <label>Quantity:</label>
                    <html:text name="item" property="quantity" indexed="true" size="3"/>
                    
                    <%-- Business Rule: Show inventory warning if low stock --%>
                    <c:if test="${item.availableQuantity < 10}">
                        <span class="inventory-warning">
                            Only ${item.availableQuantity} remaining in stock
                        </span>
                    </c:if>
                </div>
            </logic:iterate>
        </fieldset>
        
        <%-- Business Rule: Payment information --%>
        <fieldset>
            <legend>Payment Information</legend>
            
            <div>
                <label>Payment Method:</label>
                <html:select property="paymentMethod">
                    <html:option value="">Select Payment Method</html:option>
                    <html:option value="CREDIT_CARD">Credit Card</html:option>
                    <html:option value="DEBIT_CARD">Debit Card</html:option>
                    <html:option value="PAYPAL">PayPal</html:option>
                </html:select>
                <html:errors property="paymentMethod"/>
            </div>
            
            <%-- Business Rule: Show order total with breakdown --%>
            <div class="order-summary">
                <div>Subtotal: $<span id="subtotal">${orderForm.subtotal}</span></div>
                <div>Tax (8%): $<span id="tax">${orderForm.tax}</span></div>
                <c:if test="${orderForm.discount > 0}">
                    <div>Discount: -$<span id="discount">${orderForm.discount}</span></div>
                </c:if>
                <div class="total">Total: $<span id="total">${orderForm.totalAmount}</span></div>
                
                <%-- Business Rule: Show manager approval requirement for large orders --%>
                <c:if test="${orderForm.totalAmount > 1000}">
                    <div class="approval-notice">
                        Orders over $1,000 require manager approval
                    </div>
                </c:if>
            </div>
        </fieldset>
        
        <div class="form-actions">
            <html:submit value="Create Order"/>
            <html:reset value="Clear Form"/>
            <html:cancel value="Cancel"/>
        </div>
        
    </html:form>
    
</body>
</html>"""
        
        with open(jsp_dir / "order_form.jsp", 'w') as f:
            f.write(order_jsp)
    
    def _create_sample_properties(self, classes_dir: Path):
        """Create sample properties files."""
        
        # ApplicationResources.properties
        app_props = """# Application Messages
app.title=Sample Struts Application
app.version=1.0.0

# User Management Messages
user.username=Username
user.email=Email Address
user.password=Password
user.age=Age
user.created.success=User account created successfully
user.login.success=Welcome back!
user.login.failure=Invalid username or password

# Validation Error Messages
error.username.required=Username is required
error.username.length=Username must be between 3 and 20 characters
error.email.required=Email address is required
error.email.invalid=Please enter a valid email address
error.password.required=Password is required
error.password.weak=Password must be at least 8 characters long
error.age.required=Age is required
error.age.range=Age must be between 18 and 120

# Order Management Messages
order.customer.email=Customer Email
order.total=Order Total
order.payment.method=Payment Method
order.created.success=Order created successfully
order.inventory.insufficient=Insufficient inventory for requested items
order.payment.failed=Payment processing failed
order.approval.required=This order requires manager approval

# Order Validation Messages
error.customer.email.required=Customer email is required
error.customer.email.invalid=Please enter a valid customer email address
error.order.total.required=Order total is required
error.order.total.range=Order total must be between $0.01 and $10,000.00
error.payment.method.required=Payment method is required

# Product Management Messages
product.name=Product Name
product.price=Price
product.inventory.low=Low inventory warning
product.created.success=Product added successfully
product.updated.success=Product updated successfully

# Product Validation Messages
error.product.name.required=Product name is required
error.product.name.length=Product name cannot exceed 100 characters
error.product.price.required=Product price is required
error.product.price.range=Product price must be between $0.01 and $999,999.99

# Security Messages
security.login.required=You must log in to access this page
security.permission.denied=You do not have permission to access this resource
security.session.expired=Your session has expired, please log in again
security.account.locked=Account has been locked due to too many failed login attempts

# Business Process Messages
process.order.created=Order creation process initiated
process.payment.processing=Processing payment...
process.inventory.checking=Checking inventory availability
process.approval.pending=Waiting for manager approval
process.completion.success=Process completed successfully

# System Messages
system.maintenance=System is currently under maintenance
system.error.general=An unexpected error occurred
system.error.database=Database connection error
system.error.payment=Payment gateway error"""
        
        with open(classes_dir / "ApplicationResources.properties", 'w') as f:
            f.write(app_props)
        
        # ValidationMessages.properties
        validation_props = """# Validation Messages for Business Rules

# Username Validation Business Rules
validation.username.required=Username is a mandatory field for user identification
validation.username.format=Username must contain only letters, numbers, and underscores
validation.username.length.min=Username must be at least 3 characters for uniqueness
validation.username.length.max=Username cannot exceed 20 characters for database compatibility
validation.username.unique=Username must be unique in the system

# Email Validation Business Rules
validation.email.required=Email address is required for account verification and communication
validation.email.format=Email must be in valid format (user@domain.com) for delivery
validation.email.domain.allowed=Only company email domains are allowed for internal users
validation.email.unique=Email address must be unique per user account

# Password Security Business Rules
validation.password.required=Password is mandatory for account security
validation.password.strength.minimum=Password must be at least 8 characters for security compliance
validation.password.complexity=Password must contain uppercase, lowercase, number, and special character
validation.password.history=Password cannot be one of the last 5 passwords used
validation.password.expiry=Password must be changed every 90 days for security

# Age Validation Business Rules
validation.age.required=Age is required for age-restricted services compliance
validation.age.minimum=User must be at least 18 years old for legal compliance
validation.age.maximum=Age cannot exceed 120 years for data integrity
validation.age.format=Age must be a valid integer number

# Order Validation Business Rules
validation.order.items.required=Order must contain at least one item for processing
validation.order.amount.minimum=Order total must be at least $0.01 for payment processing
validation.order.amount.maximum=Order total cannot exceed $10,000 without special approval
validation.order.customer.verified=Customer must be verified before order processing
validation.order.inventory.available=All items must be available in inventory

# Payment Validation Business Rules
validation.payment.method.required=Payment method selection is required for order completion
validation.payment.amount.positive=Payment amount must be positive for transaction processing
validation.payment.currency.supported=Only USD currency is supported for payments
validation.payment.card.valid=Credit card must be valid and not expired
validation.payment.authorization.required=Payment must be pre-authorized before order fulfillment"""
        
        with open(classes_dir / "ValidationMessages.properties", 'w') as f:
            f.write(validation_props)
    
    def _create_interceptor_config(self, file_path: Path):
        """Create sample Struts interceptor configuration."""
        content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE struts PUBLIC
    "-//Apache Software Foundation//DTD Struts Configuration 2.5//EN"
    "http://struts.apache.org/dtds/struts-2.5.dtd">

<struts>
    
    <!-- Custom Interceptors -->
    <package name="default" extends="struts-default">
        
        <interceptors>
            
            <!-- Security Interceptor -->
            <interceptor name="security" class="com.example.interceptors.SecurityInterceptor">
                <param name="loginRequired">true</param>
                <param name="roleRequired">USER</param>
            </interceptor>
            
            <!-- Audit Interceptor -->
            <interceptor name="audit" class="com.example.interceptors.AuditInterceptor">
                <param name="logLevel">INFO</param>
                <param name="includeParameters">true</param>
            </interceptor>
            
            <!-- Business Rule Validation Interceptor -->
            <interceptor name="businessValidation" class="com.example.interceptors.BusinessValidationInterceptor">
                <param name="strictMode">true</param>
                <param name="validateBusinessRules">true</param>
            </interceptor>
            
            <!-- Performance Monitoring Interceptor -->
            <interceptor name="performance" class="com.example.interceptors.PerformanceInterceptor">
                <param name="enableProfiling">true</param>
                <param name="slowRequestThreshold">5000</param>
            </interceptor>
            
            <!-- Transaction Management Interceptor -->
            <interceptor name="transaction" class="com.example.interceptors.TransactionInterceptor">
                <param name="autoCommit">false</param>
                <param name="isolationLevel">READ_COMMITTED</param>
            </interceptor>
            
            <!-- Interceptor Stacks -->
            <interceptor-stack name="secureStack">
                <interceptor-ref name="security"/>
                <interceptor-ref name="audit"/>
                <interceptor-ref name="defaultStack"/>
            </interceptor-stack>
            
            <interceptor-stack name="businessStack">
                <interceptor-ref name="security"/>
                <interceptor-ref name="businessValidation"/>
                <interceptor-ref name="transaction"/>
                <interceptor-ref name="performance"/>
                <interceptor-ref name="defaultStack"/>
            </interceptor-stack>
            
            <interceptor-stack name="adminStack">
                <interceptor-ref name="security">
                    <param name="roleRequired">ADMIN</param>
                </interceptor-ref>
                <interceptor-ref name="audit"/>
                <interceptor-ref name="performance"/>
                <interceptor-ref name="defaultStack"/>
            </interceptor-stack>
            
        </interceptors>
        
        <!-- Default Interceptor -->
        <default-interceptor-ref name="secureStack"/>
        
        <!-- Actions with specific interceptor configurations -->
        <action name="login" class="com.example.actions.LoginAction">
            <interceptor-ref name="defaultStack"/>
            <result name="success">/home.jsp</result>
            <result name="failure">/login.jsp</result>
        </action>
        
        <action name="createOrder" class="com.example.actions.CreateOrderAction">
            <interceptor-ref name="businessStack"/>
            <result name="success">/order/confirmation.jsp</result>
            <result name="failure">/order/create.jsp</result>
        </action>
        
        <action name="adminDashboard" class="com.example.actions.AdminDashboardAction">
            <interceptor-ref name="adminStack"/>
            <result name="success">/admin/dashboard.jsp</result>
        </action>
        
    </package>
    
</struts>"""
        
        with open(file_path, 'w') as f:
            f.write(content)
    
    def test_comprehensive_analysis(self):
        """Test comprehensive business rule analysis."""
        print("\n=== Testing Comprehensive Business Rule Analysis ===")
        
        # Run the analysis
        discovery_result = self.engine.analyze_application(self.sample_app_dir)
        
        # Validate results
        self.assertIsNotNone(discovery_result)
        self.assertGreater(discovery_result.total_rules, 0)
        self.assertGreater(len(discovery_result.business_domains), 0)
        
        print(f"✓ Total business rules discovered: {discovery_result.total_rules}")
        print(f"✓ Business domains identified: {len(discovery_result.business_domains)}")
        print(f"✓ High-impact rules: {len(discovery_result.high_impact_rules)}")
        print(f"✓ Migration-critical rules: {len(discovery_result.migration_critical_rules)}")
        
        # Test rule distribution
        self.assertIn('validation', discovery_result.rules_by_type)
        self.assertIn('business_logic', discovery_result.rules_by_type)
        
        print("✓ Rule type distribution validated")
    
    def test_search_functionality(self):
        """Test business rule search capabilities."""
        print("\n=== Testing Search Functionality ===")
        
        # First run analysis to populate search index
        discovery_result = self.engine.analyze_application(self.sample_app_dir)
        
        # Test basic text search
        query = SearchQuery(text="validation", limit=10)
        results = self.engine.search_business_rules(query)
        
        self.assertGreater(results.total_count, 0)
        self.assertLessEqual(len(results.business_rules), 10)
        
        print(f"✓ Text search returned {results.total_count} results")
        
        # Test filtered search
        query = SearchQuery(
            rule_types=[BusinessRuleType.VALIDATION],
            complexity_levels=[BusinessRuleComplexity.SIMPLE],
            limit=5
        )
        results = self.engine.search_business_rules(query)
        
        print(f"✓ Filtered search returned {results.total_count} validation rules")
        
        # Test faceted search results
        self.assertIn('rule_type', results.facets)
        self.assertIn('complexity', results.facets)
        
        print("✓ Faceted search functionality validated")
    
    def test_similarity_detection(self):
        """Test business rule similarity detection."""
        print("\n=== Testing Similarity Detection ===")
        
        # Run analysis
        discovery_result = self.engine.analyze_application(self.sample_app_dir)
        
        if discovery_result.total_rules > 1:
            # Get a sample rule
            sample_rule_id = self.engine.all_business_rules[0].id
            
            # Find similar rules
            similar_rules = self.engine.find_similar_rules(sample_rule_id, threshold=0.5)
            
            print(f"✓ Found {len(similar_rules)} similar rules for sample rule")
            
            # Test duplicate detection
            duplicates = discovery_result.duplicate_rules
            print(f"✓ Detected {len(duplicates)} potential duplicate rule pairs")
        else:
            print("✓ Similarity detection test skipped (insufficient rules)")
    
    def test_documentation_generation(self):
        """Test enhanced documentation generation."""
        print("\n=== Testing Documentation Generation ===")
        
        # Run analysis
        discovery_result = self.engine.analyze_application(self.sample_app_dir)
        
        # Generate documentation
        doc_generator = EnhancedDocumentationGenerator(self.config)
        docs_dir = self.test_dir / "documentation"
        
        doc_generator.generate_comprehensive_documentation(
            discovery_result,
            self.engine.all_business_rules,
            self.engine.search_index,
            docs_dir
        )
        
        # Validate generated files
        expected_files = [
            docs_dir / "executive" / "executive_summary.md",
            docs_dir / "business" / "business_rule_catalog.md",
            docs_dir / "technical" / "migration_guide.md",
            docs_dir / "interactive" / "index.html",
            docs_dir / "exports" / "business_rules.csv"
        ]
        
        for file_path in expected_files:
            self.assertTrue(file_path.exists(), f"Expected file not generated: {file_path}")
            self.assertGreater(file_path.stat().st_size, 0, f"Generated file is empty: {file_path}")
        
        print("✓ All expected documentation files generated")
        
        # Test interactive HTML contains search functionality
        html_content = (docs_dir / "interactive" / "index.html").read_text()
        self.assertIn("Business Rules Analysis", html_content)
        self.assertIn("searchInput", html_content)
        
        print("✓ Interactive HTML documentation validated")
    
    def test_individual_analyzers(self):
        """Test individual analyzer components."""
        print("\n=== Testing Individual Analyzers ===")
        
        # Test Struts Config Analyzer
        config_analyzer = StrutsConfigAnalyzer(self.config)
        config_file = self.sample_app_dir / "WEB-INF" / "struts-config.xml"
        
        self.assertTrue(config_analyzer.can_analyze(config_file))
        print("✓ Struts Config Analyzer validation passed")
        
        # Test Validation Analyzer
        validation_analyzer = ValidationAnalyzer(self.config)
        validation_file = self.sample_app_dir / "WEB-INF" / "validation.xml"
        
        self.assertTrue(validation_analyzer.can_analyze(validation_file))
        print("✓ Validation Analyzer validation passed")
        
        # Test Java Action Analyzer
        java_analyzer = JavaActionAnalyzer(self.config)
        java_file = self.sample_app_dir / "WEB-INF" / "classes" / "com" / "example" / "actions" / "LoginAction.java"
        
        self.assertTrue(java_analyzer.can_analyze(java_file))
        print("✓ Java Action Analyzer validation passed")
        
        # Test JSP Analyzer
        jsp_analyzer = JSPAnalyzer(self.config)
        jsp_file = self.sample_app_dir / "jsp" / "login.jsp"
        
        self.assertTrue(jsp_analyzer.can_analyze(jsp_file))
        print("✓ JSP Analyzer validation passed")
        
        # Test Properties Analyzer
        props_analyzer = PropertiesAnalyzer(self.config)
        props_file = self.sample_app_dir / "WEB-INF" / "classes" / "ApplicationResources.properties"
        
        self.assertTrue(props_analyzer.can_analyze(props_file))
        print("✓ Properties Analyzer validation passed")
        
        # Test Interceptor Analyzer
        interceptor_analyzer = InterceptorAnalyzer(self.config)
        interceptor_file = self.sample_app_dir / "WEB-INF" / "struts.xml"
        
        self.assertTrue(interceptor_analyzer.can_analyze(interceptor_file))
        print("✓ Interceptor Analyzer validation passed")
    
    def test_export_capabilities(self):
        """Test export capabilities."""
        print("\n=== Testing Export Capabilities ===")
        
        # Run analysis
        discovery_result = self.engine.analyze_application(self.sample_app_dir)
        
        # Test JSON export
        json_output = self.test_dir / "export_test.json"
        self.engine.export_analysis_results(json_output, format="json")
        
        self.assertTrue(json_output.with_suffix('.json').exists())
        print("✓ JSON export successful")
        
        # Validate JSON content
        with open(json_output.with_suffix('.json'), 'r') as f:
            json_data = json.load(f)
        
        self.assertIn('discovery_summary', json_data)
        self.assertIn('business_rules', json_data)
        self.assertGreater(len(json_data['business_rules']), 0)
        
        print("✓ JSON export content validated")
        
        # Test YAML export
        yaml_output = self.test_dir / "export_test.yaml"
        self.engine.export_analysis_results(yaml_output, format="yaml")
        
        self.assertTrue(yaml_output.with_suffix('.yaml').exists())
        print("✓ YAML export successful")
        
        # Test Markdown export
        md_output = self.test_dir / "export_test.md"
        self.engine.export_analysis_results(md_output, format="markdown")
        
        self.assertTrue(md_output.with_suffix('.md').exists())
        
        # Validate Markdown content
        md_content = md_output.with_suffix('.md').read_text()
        self.assertIn("Comprehensive Business Rules Analysis Report", md_content)
        self.assertIn("business rules", md_content.lower())
        
        print("✓ Markdown export successful and validated")
    
    def test_performance_with_large_dataset(self):
        """Test performance with larger dataset."""
        print("\n=== Testing Performance with Larger Dataset ===")
        
        # Create additional sample files to simulate larger application
        for i in range(10):
            additional_action = f"""package com.example.actions;

public class TestAction{i} extends Action {{
    // Business Rule: Test action {i} business logic
    public ActionForward execute(ActionMapping mapping, ActionForm form,
            HttpServletRequest request, HttpServletResponse response) {{
        
        // Business Rule: Validation for test action {i}
        if (form == null) {{
            return mapping.findForward("failure");
        }}
        
        // Business Rule: Processing logic for action {i}
        processBusinessLogic{i}(form);
        
        return mapping.findForward("success");
    }}
    
    private void processBusinessLogic{i}(ActionForm form) {{
        // Business logic implementation {i}
    }}
}}"""
            
            action_file = (self.sample_app_dir / "WEB-INF" / "classes" / "com" / "example" / "actions" / f"TestAction{i}.java")
            with open(action_file, 'w') as f:
                f.write(additional_action)
        
        # Measure analysis time
        import time
        start_time = time.time()
        
        discovery_result = self.engine.analyze_application(self.sample_app_dir)
        
        end_time = time.time()
        analysis_time = end_time - start_time
        
        print(f"✓ Analysis completed in {analysis_time:.2f} seconds")
        print(f"✓ Total rules discovered: {discovery_result.total_rules}")
        print(f"✓ Performance: {discovery_result.total_rules / analysis_time:.1f} rules/second")
        
        # Validate performance is reasonable (should process at least 10 rules per second)
        self.assertGreater(discovery_result.total_rules / analysis_time, 10)
        
        print("✓ Performance test passed")


def run_comprehensive_tests():
    """Run the comprehensive test suite."""
    print("Starting Comprehensive Business Rule Analyzer Test Suite")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestBusinessRuleAnalyzer)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\nOVERALL RESULT: {'PASSED' if success else 'FAILED'}")
    
    return success


if __name__ == "__main__":
    success = run_comprehensive_tests()
    exit(0 if success else 1)