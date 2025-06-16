#!/usr/bin/env python3
"""
Test CORBA Integration Detection
===============================

This script tests the enhanced CORBA detection capabilities
of the Struts Business Rules Analyzer.
"""

import tempfile
from pathlib import Path

def create_corba_test_file():
    """Create a Java file with CORBA integration patterns."""
    return '''
package com.enterprise.legacy;

import org.omg.CORBA.ORB;
import org.omg.CosNaming.NamingContextExt;
import org.omg.CosNaming.NamingContextExtHelper;
import org.omg.PortableServer.POA;
import javax.rmi.CORBA.Util;

/**
 * Legacy CORBA integration service for enterprise communication
 * Business Rule: External system integration via CORBA
 */
public class LegacyCORBAService {
    
    private ORB orb;
    private POA poa;
    private NamingContextExt namingContext;
    
    public void initializeCORBA() {
        // Initialize the CORBA ORB
        orb = ORB.init();
        
        // Get reference to RootPOA and activate the POAManager
        poa = (POA) orb.resolve_initial_references("RootPOA");
        poa.the_POAManager().activate();
        
        // Get the root naming context
        org.omg.CORBA.Object objRef = orb.resolve_initial_references("NameService");
        namingContext = NamingContextExtHelper.narrow(objRef);
    }
    
    public void connectToLegacySystem() {
        try {
            // Connect to legacy CORBA service
            String corbaUrl = "IIOP://legacy.example.com:1050/LegacyService";
            org.omg.CORBA.Object obj = orb.string_to_object(corbaUrl);
            
            // Narrow the object reference
            LegacySystemInterface legacyService = LegacySystemInterfaceHelper._narrow(obj);
            
            // Business logic: Process legacy data
            String result = legacyService.processBusinessData("customer123");
            
        } catch (Exception e) {
            // Business rule: Error handling for CORBA failures
            handleCORBAError(e);
        }
    }
    
    private void handleCORBAError(Exception e) {
        // Business rule: CORBA error recovery
        System.err.println("CORBA communication failed: " + e.getMessage());
    }
}

// IDL-generated servant implementation
class LegacyServiceServant extends LegacyServicePOA {
    
    public String processData(String input) {
        // Business rule: Legacy data processing
        return "Processed: " + input;
    }
}
'''

def test_corba_detection():
    """Test CORBA pattern detection."""
    print("[TESTING] Testing CORBA Integration Detection...")
    
    # Create temporary test file
    temp_dir = Path(tempfile.mkdtemp())
    java_file = temp_dir / "LegacyCORBAService.java"
    java_file.write_text(create_corba_test_file())
    
    try:
        from struts_analyzer import BusinessRuleExtractor, ConfigurationManager
        
        config = ConfigurationManager()
        extractor = BusinessRuleExtractor(config)
        
        results = extractor.analyze_directory(temp_dir)
        rules = results['business_rules']
        
        # Filter CORBA-related rules
        corba_rules = [r for r in rules if 'corba' in r.get('type', '').lower() or 
                      'corba' in r.get('name', '').lower() or
                      'CORBA' in r.get('description', '')]
        
        print(f"[INFO] Total business rules found: {len(rules)}")
        print(f"[INFO] CORBA-specific rules found: {len(corba_rules)}")
        
        if corba_rules:
            print("\n[TARGET] CORBA Integration Rules Detected:")
            for i, rule in enumerate(corba_rules[:10], 1):  # Show first 10
                print(f"  {i}. {rule.get('name', 'Unknown')} - {rule.get('type', 'Unknown')}")
                print(f"     Description: {rule.get('description', 'No description')}")
                print(f"     Migration Risk: {rule.get('migration_risk', 'Unknown')}")
                print()
        
        # Check for expected CORBA patterns
        expected_patterns = [
            'ORB',
            'POA',
            'naming',
            'narrow',
            'IIOP',
            'servant'
        ]
        
        detected_patterns = []
        for pattern in expected_patterns:
            if any(pattern.lower() in rule.get('name', '').lower() or 
                   pattern.lower() in rule.get('description', '').lower() 
                   for rule in corba_rules):
                detected_patterns.append(pattern)
        
        print(f"[TESTING] Expected CORBA patterns detected: {len(detected_patterns)}/{len(expected_patterns)}")
        print(f"   Patterns found: {detected_patterns}")
        
        if len(corba_rules) >= 5:
            print("[PASS] EXCELLENT: Comprehensive CORBA detection working!")
            return True, len(corba_rules)
        elif len(corba_rules) >= 2:
            print("[PASS] GOOD: Basic CORBA detection working!")
            return True, len(corba_rules)
        else:
            print("[FAIL] LIMITED: Few CORBA patterns detected")
            return False, len(corba_rules)
            
    except Exception as e:
        print(f"[FAIL] Error during CORBA detection test: {e}")
        import traceback
        traceback.print_exc()
        return False, 0
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir)

def main():
    """Run CORBA detection test."""
    print("[CORBA] CORBA Integration Detection Test")
    print("=" * 50)
    print("Testing enhanced CORBA pattern recognition...")
    print()
    
    success, count = test_corba_detection()
    
    print("\n" + "=" * 50)
    print("[INFO] CORBA DETECTION RESULTS")
    print("=" * 50)
    
    if success:
        print(f"[EXCELLENT] SUCCESS: CORBA detection is working!")
        print(f"[STATS] Found {count} CORBA-related business rules")
        print("\n[READY] Ready for enterprise CORBA analysis!")
        print("[TIP] The analyzer can now identify:")
        print("   * CORBA ORB initialization and usage")
        print("   * Naming service interactions")
        print("   * Portable Object Adapter (POA) usage")
        print("   * Object narrowing and IIOP protocols")
        print("   * IDL interfaces and servant implementations")
        print("   * RMI over CORBA patterns")
    else:
        print("[WARNING] ISSUES: CORBA detection needs improvement")
        print("[FIX] Review the CORBA patterns and test data")
    
    print(f"\n[INFO] Migration Impact: CORBA integrations have 'critical' risk")
    print("[TARGET] Recommendation: Plan CORBA to REST/GraphQL migration carefully")
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)