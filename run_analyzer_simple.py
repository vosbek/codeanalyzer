#!/usr/bin/env python3
"""
Simple script to run the Struts Business Rules Analyzer
This provides a clean interface with error handling and clear output
"""

import sys
import os
from pathlib import Path

def main():
    """Main entry point for the analyzer"""
    
    if len(sys.argv) != 2:
        print("Usage: python3 run_analyzer_simple.py <struts_application_directory>")
        print("Example: python3 run_analyzer_simple.py /path/to/my/struts/app")
        sys.exit(1)
    
    app_directory = Path(sys.argv[1])
    
    if not app_directory.exists():
        print(f"❌ Error: Directory does not exist: {app_directory}")
        sys.exit(1)
    
    if not app_directory.is_dir():
        print(f"❌ Error: Not a directory: {app_directory}")
        sys.exit(1)
    
    print(f"🔍 Analyzing Struts application: {app_directory}")
    print("=" * 60)
    
    try:
        # Import the analyzer
        from struts_analyzer import BusinessRuleExtractor, ConfigurationManager
        
        print("✅ Analyzer loaded successfully")
        
        # Create configuration
        config = ConfigurationManager()
        
        # Create extractor  
        extractor = BusinessRuleExtractor(config)
        
        print(f"📁 Scanning directory: {app_directory}")
        
        # Run analysis
        results = extractor.analyze_directory(app_directory)
        
        # Display results
        print("\n" + "=" * 60)
        print("📊 ANALYSIS RESULTS")
        print("=" * 60)
        
        total_rules = len(results['business_rules'])
        action_mappings = len(results['action_mappings'])
        validation_rules = len(results['validation_rules'])
        
        print(f"Total Business Rules Found: {total_rules:,}")
        print(f"Action Mappings: {action_mappings:,}")
        print(f"Validation Rules: {validation_rules:,}")
        
        if total_rules == 0:
            print("\n⚠️  WARNING: No business rules found!")
            print("   This could mean:")
            print("   - Wrong directory (should contain WEB-INF/struts-config.xml)")
            print("   - No Struts configuration files present")
            print("   - Files are in unexpected locations")
            print(f"   - Check that {app_directory} contains a Struts application")
        else:
            print(f"\n✅ SUCCESS: Found {total_rules} business rules")
            
            # Show rule breakdown by type
            rule_types = {}
            for rule in results['business_rules']:
                rule_type = rule.get('type', 'unknown')
                rule_types[rule_type] = rule_types.get(rule_type, 0) + 1
            
            print("\n📈 Rules by Type:")
            for rule_type, count in sorted(rule_types.items()):
                print(f"   • {rule_type.title()}: {count}")
            
            # Show first few rules as examples
            print("\n📋 Example Business Rules:")
            for i, rule in enumerate(results['business_rules'][:5]):
                print(f"   {i+1}. {rule['name']} ({rule['type']})")
                print(f"      Location: {rule['source_file']}")
                if rule.get('description'):
                    desc = rule['description'][:60] + "..." if len(rule['description']) > 60 else rule['description']
                    print(f"      Description: {desc}")
                print()
        
        # Generate output files
        output_dir = Path("analysis_output")
        output_dir.mkdir(exist_ok=True)
        
        # Save JSON results
        import json
        with open(output_dir / "business_rules.json", 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"💾 Results saved to: {output_dir.absolute()}")
        print(f"   • business_rules.json - Complete analysis data")
        
        # Simple CSV export for stakeholders
        import csv
        with open(output_dir / "business_rules_summary.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Name', 'Type', 'Source File', 'Description', 'Migration Risk'])
            
            for rule in results['business_rules']:
                writer.writerow([
                    rule.get('name', ''),
                    rule.get('type', ''),
                    rule.get('source_file', ''),
                    rule.get('description', '')[:100],  # Truncate for CSV
                    rule.get('migration_risk', 'medium')
                ])
        
        print(f"   • business_rules_summary.csv - Stakeholder summary")
        
        if total_rules > 100:
            print(f"\n🎯 RECOMMENDATION:")
            print(f"   Your application has {total_rules} business rules.")
            print(f"   Consider breaking down the migration into phases:")
            print(f"   • Phase 1: Critical rules ({len([r for r in results['business_rules'] if r.get('migration_risk') == 'critical'])} rules)")
            print(f"   • Phase 2: High-risk rules ({len([r for r in results['business_rules'] if r.get('migration_risk') == 'high'])} rules)")
            print(f"   • Phase 3: Remaining rules")
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("\n🔧 SOLUTION:")
        print("   Install required dependencies:")
        print("   pip install psutil PyYAML")
        sys.exit(1)
    
    except Exception as e:
        print(f"❌ Analysis Error: {e}")
        print("\n🔧 DEBUG INFO:")
        print(f"   - Application directory: {app_directory}")
        print(f"   - Directory exists: {app_directory.exists()}")
        print(f"   - Directory contents: {list(app_directory.iterdir())[:5]}")
        print("\n   Run with --verbose for more details")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()