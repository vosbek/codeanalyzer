#!/usr/bin/env python3
"""
Test Enhanced Java Analysis Capabilities
========================================

Tests the new comprehensive Java business rule extraction with realistic Java code examples.
"""

import tempfile
import shutil
from pathlib import Path
from struts_analyzer import BusinessRuleExtractor, ConfigurationManager

def create_comprehensive_test_java_files():
    """Create realistic Java files with various business rule patterns."""
    temp_dir = Path(tempfile.mkdtemp())
    
    # Create directory structure
    src_dir = temp_dir / "src" / "main" / "java" / "com" / "company" / "app"
    src_dir.mkdir(parents=True)
    
    # Create a complex Action class with business logic
    action_class = src_dir / "UserManagementAction.java"
    action_code = '''package com.company.app;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.access.annotation.Secured;
import org.springframework.cache.annotation.Cacheable;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * Business Rule: User management operations must maintain data integrity
 * and follow security protocols for user account modifications.
 * This class handles all user-related business operations.
 */
@Secured("ROLE_ADMIN")
@Transactional
public class UserManagementAction extends Action {
    
    @NotNull
    @Size(min=1, max=100)
    private String userRepository;
    
    private WebServiceTemplate userValidationService;
    
    private EntityManager entityManager;
    
    /**
     * Main execution method for user management operations.
     * Business Rule: All user operations must be validated and logged.
     */
    @Transactional(rollbackFor = {UserValidationException.class, DataIntegrityException.class})
    @Secured("ROLE_USER_ADMIN") 
    public ActionForward execute(ActionMapping mapping, ActionForm form,
                               HttpServletRequest request, HttpServletResponse response)
                               throws UserValidationException, SecurityException {
        
        String operation = request.getParameter("operation");
        
        try {
            // Business logic: Validate user permissions before any operation
            if (!validateUserPermissions(request)) {
                throw new SecurityException("Insufficient permissions for user operation");
            }
            
            // Business logic: Different operations based on request
            if ("create".equals(operation)) {
                return handleUserCreation(mapping, form, request);
            } else if ("update".equals(operation)) {
                return handleUserUpdate(mapping, form, request);
            } else if ("delete".equals(operation)) {
                return handleUserDeletion(mapping, form, request);
            } else if ("search".equals(operation)) {
                return handleUserSearch(mapping, form, request);
            }
            
            // Business rule: Log all user operations for audit trail
            auditLogger.logUserOperation(operation, getCurrentUser(request));
            
        } catch (UserValidationException e) {
            // Business rule: User validation failures must be logged and user notified
            logger.error("User validation failed: " + e.getMessage());
            saveErrorMessage(request, "user.validation.error");
            return mapping.findForward("error");
        } catch (DataIntegrityException e) {
            // Business rule: Data integrity issues require transaction rollback
            logger.error("Data integrity violation: " + e.getMessage());
            return mapping.findForward("system_error");
        }
        
        return mapping.findForward("success");
    }
    
    /**
     * Validates user data according to business rules.
     * Business rule: User email must be unique in the system.
     * Business rule: User passwords must meet security requirements.
     */
    public boolean validateUserData(UserForm userForm) throws UserValidationException {
        // Business logic: Check email uniqueness
        if (isEmailAlreadyExists(userForm.getEmail())) {
            throw new UserValidationException("Email already exists in system");
        }
        
        // Business logic: Validate password strength
        if (!isPasswordValid(userForm.getPassword())) {
            throw new UserValidationException("Password does not meet security requirements");
        }
        
        // Business logic: Validate user role permissions
        for (String role : userForm.getRoles()) {
            if (!isValidRole(role)) {
                throw new UserValidationException("Invalid role: " + role);
            }
        }
        
        return true;
    }
    
    /**
     * Handles user creation with business validation.
     * Business rule: New users must be assigned to default role.
     * Business rule: User creation requires email notification.
     */
    @Transactional
    @Cacheable("userCache")
    private ActionForward handleUserCreation(ActionMapping mapping, ActionForm form, 
                                           HttpServletRequest request) throws Exception {
        
        UserForm userForm = (UserForm) form;
        
        // Business rule: Validate all required fields
        validateRequiredFields(userForm);
        
        // Business rule: Auto-assign default role for new users
        if (userForm.getRoles().isEmpty()) {
            userForm.addRole("USER");
        }
        
        // Integration: Call external user validation service
        ValidationResult result = userValidationService.validateUser(userForm);
        if (!result.isValid()) {
            throw new UserValidationException(result.getErrorMessage());
        }
        
        // Data access: Insert user into database
        String sql = "INSERT INTO users (email, password, first_name, last_name, created_date) VALUES (?, ?, ?, ?, ?)";
        jdbcTemplate.update(sql, userForm.getEmail(), userForm.getPassword(), 
                          userForm.getFirstName(), userForm.getLastName(), new Date());
        
        // Integration: Send welcome email notification
        notificationService.sendWelcomeEmail(userForm.getEmail());
        
        return mapping.findForward("user_created");
    }
    
    /**
     * Batch processes user updates.
     * Business rule: Batch operations must be atomic.
     */
    public void processBatchUserUpdates(List<UserUpdateRequest> updates) {
        for (UserUpdateRequest update : updates) {
            try {
                // Business logic: Each update must be validated individually
                if (validateUpdateRequest(update)) {
                    updateUser(update);
                } else {
                    logger.warn("Invalid update request for user: " + update.getUserId());
                }
            } catch (Exception e) {
                // Business rule: Individual failures don't stop batch processing
                logger.error("Failed to update user " + update.getUserId(), e);
                continue;
            }
        }
    }
    
    /**
     * Integration with external systems for user synchronization.
     */
    private void synchronizeWithExternalSystems(User user) {
        try {
            // Integration: LDAP synchronization
            ldapService.syncUser(user);
            
            // Integration: CRM system update
            HttpClient httpClient = new HttpClient();
            String crmResponse = httpClient.post("/api/users", user.toJson());
            
            // Integration: Message queue notification
            MessageProducer producer = jmsTemplate.createProducer();
            producer.send(createUserSyncMessage(user));
            
        } catch (Exception e) {
            logger.error("External system synchronization failed", e);
            // Business rule: External sync failures don't fail user operations
        }
    }
    
    /**
     * Stored procedure call for complex user analytics.
     */
    public UserAnalytics generateUserAnalytics(String userId) {
        // Data access: Call stored procedure for complex analytics
        String sql = "CALL generate_user_analytics(?, ?)";
        return jdbcTemplate.queryForObject(sql, UserAnalytics.class, userId, new Date());
    }
}

/**
 * Custom business exception for user validation failures.
 */
class UserValidationException extends Exception {
    public UserValidationException(String message) {
        super(message);
    }
}

/**
 * Custom business exception for data integrity violations.
 */
class DataIntegrityException extends Exception {
    public DataIntegrityException(String message) {
        super(message);
    }
}
'''
    
    action_class.write_text(action_code)
    
    # Create a service class with integration patterns
    service_class = src_dir / "UserService.java"
    service_code = '''package com.company.app;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Business service for user management operations.
 * Business rule: All user services must maintain audit trail.
 */
@Service
@Transactional
public class UserService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private WebServiceTemplate soapService;
    
    @Autowired 
    private KafkaTemplate<String, Object> kafkaTemplate;
    
    private DataSource dataSource;
    
    /**
     * Business rule: User profile updates require approval workflow.
     * Integration rule: Profile changes are synchronized with external HR system.
     */
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @Cacheable(value = "userProfiles", key = "#userId")
    public UserProfile updateUserProfile(String userId, ProfileUpdateRequest request) 
            throws ProfileUpdateException {
        
        try {
            // Business validation: Check if user can update profile
            if (!canUserUpdateProfile(userId, request)) {
                throw new ProfileUpdateException("User not authorized to update profile");
            }
            
            // Integration: Call external validation service
            ValidationResponse response = restTemplate.postForObject(
                "/api/validate-profile", request, ValidationResponse.class);
            
            if (!response.isValid()) {
                throw new ProfileUpdateException(response.getErrorMessage());
            }
            
            // Data access: Update user profile in database
            String updateSql = "UPDATE user_profiles SET first_name = ?, last_name = ?, " +
                             "phone = ?, updated_date = ? WHERE user_id = ?";
            jdbcTemplate.update(updateSql, request.getFirstName(), request.getLastName(),
                              request.getPhone(), new Date(), userId);
            
            // Integration: Notify external systems via message queue
            ProfileChangeEvent event = new ProfileChangeEvent(userId, request);
            kafkaTemplate.send("user-profile-changes", event);
            
            return getUserProfile(userId);
            
        } catch (Exception e) {
            logger.error("Profile update failed for user: " + userId, e);
            throw new ProfileUpdateException("Failed to update user profile", e);
        }
    }
    
    /**
     * Message listener for processing user synchronization events.
     * Business rule: User sync failures must be retried up to 3 times.
     */
    @JmsListener(destination = "user-sync-queue")
    @Transactional
    public void processUserSyncEvent(UserSyncEvent event) {
        int retryCount = 0;
        int maxRetries = 3;
        
        while (retryCount < maxRetries) {
            try {
                // Integration: Sync with external user directory
                ExternalUserService externalService = new ExternalUserService();
                externalService.syncUser(event.getUserData());
                
                // Business rule: Mark sync as successful
                markSyncCompleted(event.getUserId());
                break;
                
            } catch (ExternalServiceException e) {
                retryCount++;
                if (retryCount >= maxRetries) {
                    logger.error("User sync failed after " + maxRetries + " attempts", e);
                    markSyncFailed(event.getUserId(), e.getMessage());
                } else {
                    logger.warn("User sync attempt " + retryCount + " failed, retrying...", e);
                    try {
                        Thread.sleep(1000 * retryCount); // Exponential backoff
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
    }
    
    /**
     * Repository pattern for user data access.
     * Business rule: All database operations must be logged for compliance.
     */
    @Repository("userRepository")
    public class UserRepository {
        
        @Autowired
        private EntityManager entityManager;
        
        /**
         * Custom query for finding users with complex business criteria.
         */
        @Query("SELECT u FROM User u WHERE u.status = 'ACTIVE' AND u.lastLoginDate > :cutoffDate")
        public List<User> findActiveUsersAfterDate(@Param("cutoffDate") Date cutoffDate) {
            // Business rule: Only return users who have been active recently
            return entityManager.createQuery(
                "SELECT u FROM User u WHERE u.status = 'ACTIVE' AND u.lastLoginDate > :cutoffDate", 
                User.class)
                .setParameter("cutoffDate", cutoffDate)
                .getResultList();
        }
        
        /**
         * Batch operation for user data cleanup.
         * Business rule: Data retention policy requires archiving old user data.
         */
        public int archiveInactiveUsers(int inactiveDays) {
            // Calculate cutoff date for inactive users
            Date cutoffDate = new Date(System.currentTimeMillis() - (inactiveDays * 24 * 60 * 60 * 1000L));
            
            // Data access: Archive inactive users
            String archiveSql = "INSERT INTO archived_users SELECT * FROM users WHERE last_login_date < ?";
            int archivedCount = jdbcTemplate.update(archiveSql, cutoffDate);
            
            // Data access: Delete archived users from active table
            String deleteSql = "DELETE FROM users WHERE last_login_date < ?";
            jdbcTemplate.update(deleteSql, cutoffDate);
            
            logger.info("Archived " + archivedCount + " inactive users");
            return archivedCount;
        }
    }
}
'''
    
    service_class.write_text(service_code)
    
    return temp_dir

def test_enhanced_java_analysis():
    """Test the enhanced Java analysis capabilities."""
    print("🧪 Testing Enhanced Java Business Rule Analysis")
    print("=" * 60)
    
    # Create test files
    test_dir = create_comprehensive_test_java_files()
    
    try:
        # Initialize analyzer
        config = ConfigurationManager()
        extractor = BusinessRuleExtractor(config)
        
        print(f"📁 Test directory: {test_dir}")
        print(f"📄 Created comprehensive Java test files")
        
        # Run analysis
        print("🔍 Running enhanced analysis...")
        results = extractor.analyze_directory(test_dir)
        
        # Display results
        business_rules = results['business_rules']
        print(f"\n📊 Enhanced Analysis Results:")
        print(f"Total Business Rules Found: {len(business_rules)}")
        
        # Group rules by type
        rules_by_type = {}
        for rule in business_rules:
            rule_type = rule['type']
            if rule_type not in rules_by_type:
                rules_by_type[rule_type] = []
            rules_by_type[rule_type].append(rule)
        
        print(f"\n📈 Rules by Type:")
        for rule_type, type_rules in sorted(rules_by_type.items()):
            print(f"  • {rule_type.replace('_', ' ').title()}: {len(type_rules)} rules")
        
        # Show examples of different rule types
        print(f"\n🔍 Example Business Rules Found:")
        for rule_type, type_rules in sorted(rules_by_type.items()):
            if type_rules:  # Show first rule of each type
                rule = type_rules[0]
                print(f"\n  📌 {rule_type.replace('_', ' ').title()} Rule:")
                print(f"     Name: {rule['name']}")
                print(f"     Description: {rule['description'][:80]}{'...' if len(rule['description']) > 80 else ''}")
                print(f"     Location: {rule['source_location']}")
                if rule.get('migration_risk'):
                    print(f"     Migration Risk: {rule['migration_risk'].upper()}")
        
        # Analyze integration rules specifically
        integration_rules = [r for r in business_rules if r['type'] == 'integration']
        if integration_rules:
            print(f"\n🔗 Integration Rules Analysis:")
            print(f"   Found {len(integration_rules)} integration points")
            for rule in integration_rules[:3]:  # Show first 3
                print(f"   • {rule['name']}: {rule['business_context']}")
        
        # Analyze security rules
        security_rules = [r for r in business_rules if r['type'] == 'security']
        if security_rules:
            print(f"\n🔒 Security Rules Analysis:")
            print(f"   Found {len(security_rules)} security constraints")
            for rule in security_rules[:3]:  # Show first 3
                print(f"   • {rule['name']}: {rule['description'][:60]}{'...' if len(rule['description']) > 60 else ''}")
        
        # Analyze transaction rules
        transaction_rules = [r for r in business_rules if r['type'] == 'transaction']
        if transaction_rules:
            print(f"\n💾 Transaction Rules Analysis:")
            print(f"   Found {len(transaction_rules)} transaction boundaries")
            for rule in transaction_rules[:3]:  # Show first 3
                print(f"   • {rule['name']}: {rule['business_context']}")
        
        # Check for high-complexity rules
        complex_rules = [r for r in business_rules if r.get('complexity', 1) >= 3]
        if complex_rules:
            print(f"\n⚡ High-Complexity Rules:")
            print(f"   Found {len(complex_rules)} complex business rules")
            for rule in complex_rules[:3]:  # Show first 3
                print(f"   • {rule['name']} (Complexity: {rule.get('complexity', 1)})")
        
        # Migration risk analysis
        high_risk_rules = [r for r in business_rules if r.get('migration_risk') in ['high', 'critical']]
        if high_risk_rules:
            print(f"\n⚠️  High Migration Risk Rules:")
            print(f"   Found {len(high_risk_rules)} high-risk components")
            for rule in high_risk_rules[:3]:  # Show first 3
                print(f"   • {rule['name']} ({rule.get('migration_risk', 'unknown').upper()} risk)")
        
        print(f"\n✅ Enhanced Analysis Completed Successfully!")
        print(f"📊 Total Rules Extracted: {len(business_rules)}")
        
        # Validate we found comprehensive rules
        expected_types = ['security', 'transaction', 'integration', 'validation', 'business_logic']
        found_types = set(rules_by_type.keys())
        
        coverage = len(found_types.intersection(expected_types)) / len(expected_types) * 100
        print(f"🎯 Business Rule Coverage: {coverage:.1f}% ({len(found_types.intersection(expected_types))}/{len(expected_types)} types)")
        
        if coverage >= 60:
            print("🎉 EXCELLENT: Comprehensive business rule extraction achieved!")
        elif coverage >= 40:
            print("✅ GOOD: Solid business rule extraction")
        else:
            print("⚠️  NEEDS IMPROVEMENT: Limited business rule extraction")
            
        return len(business_rules) > 10  # Success if we found many rules
        
    except Exception as e:
        print(f"❌ Error during enhanced analysis: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        shutil.rmtree(test_dir)

if __name__ == "__main__":
    success = test_enhanced_java_analysis()
    exit(0 if success else 1)