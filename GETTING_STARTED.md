# Getting Started Guide: Struts Business Rules Analyzer

This guide will help you quickly start analyzing your Struts applications and extracting business rules for migration planning.

## 📋 Prerequisites

### System Requirements
- **Python 3.8+**: The analyzer is built with Python and requires version 3.8 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended for large applications)
- **Storage**: At least 1GB free space for analysis results and search index
- **Operating System**: Linux, macOS, or Windows with WSL

### Struts Application Requirements
- **Struts Framework**: Version 1.x or 2.x applications
- **File Access**: Read access to the complete application directory
- **File Types**: The analyzer works with XML configs, Java sources, JSP templates, and properties files

## 🚀 Quick Start (5 minutes)

### Step 1: Download and Setup
```bash
# Clone the repository
git clone [repository-url]
cd struts-analyzer

# Verify Python version
python3 --version  # Should be 3.8+

# Create and activate virtual environment (recommended)
python3 -m venv analyzer-env
source analyzer-env/bin/activate  # On Windows: analyzer-env\Scripts\activate

# Install required dependencies
pip install pyyaml tqdm psutil javalang networkx beautifulsoup4

# Test the installation
python test_system_structure.py
```

### Step 2: Analyze Your First Application
```bash
# Run basic analysis (ensure virtual environment is activated)
python struts_analyzer.py /path/to/your/struts/app --output ./analysis-results

# Example with a typical Struts app structure:
python struts_analyzer.py /opt/myapp/webapp --output ./myapp-analysis
```

### Step 3: View Results
```bash
# Open the generated documentation
cd analysis-results
ls -la  # You'll see various output files

# View the executive summary (business-focused)
cat executive_summary.md

# View the comprehensive analysis
cat business_rules_analysis.md
```

## 📊 Understanding the Output

### Generated Files
After analysis, you'll find these key files:

```
analysis-results/
├── executive_summary.md          # Business stakeholder summary
├── business_rules_analysis.md    # Comprehensive technical analysis  
├── business_rules.json          # Machine-readable rule data
├── business_rules.csv           # Spreadsheet-compatible export
├── migration_guide.md           # Step-by-step migration recommendations
├── dependency_analysis.json     # Component relationships
└── search_index.db              # Full-text search database
```

### Key Metrics to Look For

#### 1. Total Business Rules Count
```bash
# Quick check of what was found
grep "Total Business Rules" executive_summary.md
# Example output: "Total Business Rules Identified: 1,247"
```

#### 2. Complexity Breakdown
```bash
# See complexity distribution
grep -A 5 "Complexity Analysis" executive_summary.md
# Look for: SIMPLE, MODERATE, COMPLEX, CRITICAL counts
```

#### 3. High-Impact Rules
```bash
# Find critical business rules
grep -A 10 "High-Impact Rules" executive_summary.md
```

## 🔧 Common Usage Patterns

### Pattern 1: Business Stakeholder Analysis
```bash
# Generate business-focused documentation
python3 struts_analyzer.py /path/to/app \
    --output ./business-analysis \
    --docs executive \
    --format markdown,html
```

### Pattern 2: Developer Migration Planning
```bash
# Generate technical migration guide
python3 struts_analyzer.py /path/to/app \
    --output ./migration-plan \
    --docs technical \
    --export json \
    --include-code-examples
```

### Pattern 3: Large Application Analysis
```bash
# For applications with 100k+ lines of code
python3 struts_analyzer.py /path/to/large/app \
    --output ./large-app-analysis \
    --parallel \
    --exclude-patterns "*/test/*,**/target/**" \
    --complexity-threshold MODERATE
```

## 🔍 Using the Search System

### Programmatic Search
```python
from business_rule_engine import BusinessRuleEngine
from models.search_index import SearchQuery
from utils.config_utils import ConfigurationManager

# Initialize the engine
config = ConfigurationManager({'analysis': {'index_path': './analysis_index.db'}})
engine = BusinessRuleEngine(config)

# Analyze application (creates search index)
results = engine.analyze_application('/path/to/struts/app')

# Search for authentication-related rules
query = SearchQuery(
    query_text="authentication login security",
    rule_types=["VALIDATION", "WORKFLOW"],
    max_results=20
)

search_results = engine.search_business_rules(query)
for rule in search_results.rules:
    print(f"Found: {rule.name}")
    print(f"  Type: {rule.rule_type.name}")
    print(f"  File: {rule.location.file_path}")
    print(f"  Confidence: {rule.evidence.confidence_score}")
    print()

engine.close()
```

### Search Examples
```python
# Find validation rules
validation_query = SearchQuery(
    query_text="required field validation",
    rule_types=["VALIDATION"],
    complexity_filter=["MODERATE", "COMPLEX"]
)

# Find workflow rules  
workflow_query = SearchQuery(
    query_text="business process workflow",
    rule_types=["WORKFLOW", "BUSINESS_LOGIC"],
    business_domains=["order_processing", "user_management"]
)

# Find high-risk migration items
risky_query = SearchQuery(
    query_text="complex business logic",
    complexity_filter=["COMPLEX", "CRITICAL"],
    max_results=50
)
```

## 🎯 Migration Planning Workflow

### Phase 1: Discovery (Week 1)
```bash
# 1. Run initial analysis
python3 struts_analyzer.py /path/to/app --output ./phase1-discovery

# 2. Review executive summary with business stakeholders
# Focus on: Total rules, complexity distribution, business domains

# 3. Identify high-impact areas
grep -A 20 "High-Impact Rules" ./phase1-discovery/executive_summary.md
```

### Phase 2: Assessment (Week 2-3)
```bash
# 1. Generate detailed technical analysis
python3 struts_analyzer.py /path/to/app \
    --output ./phase2-assessment \
    --docs all \
    --export json,csv

# 2. Review migration recommendations
cat ./phase2-assessment/migration_guide.md

# 3. Estimate effort for each business domain
python3 -c "
import json
with open('./phase2-assessment/business_rules.json') as f:
    data = json.load(f)
    
domains = {}
for rule in data['business_rules']:
    domain = rule.get('business_context', 'Unknown')
    complexity = rule.get('complexity', 'MODERATE')
    if domain not in domains:
        domains[domain] = {'SIMPLE': 0, 'MODERATE': 0, 'COMPLEX': 0, 'CRITICAL': 0}
    domains[domain][complexity] += 1

for domain, counts in domains.items():
    total = sum(counts.values())
    print(f'{domain}: {total} rules - {counts}')
"
```

### Phase 3: Planning (Week 4)
```bash
# 1. Use plugin system for specific recommendations
python3 -c "
from plugins import GraphQLMigrationPlugin, AngularMigrationPlugin
from models.business_rule import BusinessRule
import json

# Load analyzed rules
with open('./phase2-assessment/business_rules.json') as f:
    rules_data = json.load(f)['business_rules']

# Generate GraphQL recommendations  
graphql_plugin = GraphQLMigrationPlugin()
graphql_recs = graphql_plugin.generate_migration_recommendations(rules_data[:10], {})
print('GraphQL Recommendations:', len(graphql_recs.recommendations))

# Generate Angular recommendations
angular_plugin = AngularMigrationPlugin() 
angular_recs = angular_plugin.generate_migration_recommendations(rules_data[:10], {})
print('Angular Recommendations:', len(angular_recs.recommendations))
"
```

## 🛠️ Advanced Configuration

### Custom Configuration File
Create `analyzer_config.yaml`:
```yaml
analysis:
  index_path: "./custom_analysis.db"
  parallel_enabled: true
  parallel_workers: 6
  exclude_patterns:
    - "*/test/*"
    - "**/target/**" 
    - "**/node_modules/**"
    - "**/.git/**"

search:
  similarity_threshold: 0.85
  max_results: 100

plugins:
  framework_detection: true
  migration_analysis: true
  documentation_generation: true

documentation:
  generate_executive_summary: true
  include_code_examples: true
  stakeholder_focus: "mixed"  # business, technical, mixed
  output_formats: ["html", "markdown", "json"]

migration:
  target_technologies: ["graphql", "angular"]
  estimate_effort: true
  confidence_threshold: 0.7
```

### Using Custom Configuration
```bash
python3 struts_analyzer.py /path/to/app \
    --config analyzer_config.yaml \
    --output ./custom-analysis
```

## 🔧 Troubleshooting

### Common Issues

#### 1. "No business rules found"
```bash
# Check if Struts files are detected
python3 -c "
from pathlib import Path
import glob

app_path = '/path/to/your/app'
print('Struts config files:')
for f in Path(app_path).glob('**/struts-config.xml'):
    print(f'  {f}')
    
print('Java Action files:')  
for f in Path(app_path).glob('**/*Action.java'):
    print(f'  {f}')
    
print('JSP files:')
for f in Path(app_path).glob('**/*.jsp'):
    print(f'  {f}')
"
```

#### 2. Import errors or missing dependencies
```bash
# Test system structure (ensure virtual environment is activated)
python test_system_structure.py

# If you see import errors, install missing dependencies:
pip install pyyaml tqdm psutil javalang networkx beautifulsoup4

# Common import issues and fixes:
# ❌ "No module named 'yaml'" → Install pyyaml
# ❌ "No module named 'tqdm'" → Install tqdm  
# ❌ "No module named 'psutil'" → Install psutil
# ❌ "attempted relative import beyond top-level package" → Fixed in v1.2+

# Check for enhanced Java parsing capability
python -c "
try:
    import javalang
    print('✅ javalang available - enhanced Java parsing enabled')
except ImportError:
    print('⚠️  javalang not available - using regex-based Java parsing')
"

# Expected output after fixes:
# All tests should pass: "Overall result: ✅ PASS"
```

#### 3. Large application performance
```bash
# Use parallel processing and filtering
python3 struts_analyzer.py /path/to/large/app \
    --output ./large-analysis \
    --parallel \
    --workers 8 \
    --exclude-patterns "*/test/*,**/generated/**,**/target/**" \
    --max-files-per-type 1000
```

### Getting Help

#### 1. Check System Status
```bash
# Verify all components (ensure virtual environment is activated)
python test_system_structure.py

# Check specific component
python -c "
from parsers import XMLConfigurationParser
parser = XMLConfigurationParser()
print(f'XML Parser available: {parser is not None}')
"
```

#### 2. Debug Mode
```bash
# Run with verbose logging
python struts_analyzer.py /path/to/app \
    --output ./debug-analysis \
    --verbose \
    --debug
```

#### 3. Generate Sample Analysis
```bash
# Use the test system to generate a sample
python test_complete_system.py
# This creates a sample Struts app and analyzes it
```

## 🎓 Next Steps

### 1. Explore Generated Documentation
- **Executive Summary**: Share with business stakeholders
- **Migration Guide**: Use for sprint planning
- **Technical Analysis**: Review with development team

### 2. Plan Migration Phases
- Start with SIMPLE complexity rules
- Group by business domain
- Use effort estimates for timeline planning

### 3. Set Up Regular Analysis
```bash
# Create a script for ongoing analysis
cat > analyze_app.sh << 'EOF'
#!/bin/bash
# Activate virtual environment
source analyzer-env/bin/activate

DATE=$(date +%Y%m%d)
python struts_analyzer.py /path/to/app \
    --output ./analysis-$DATE \
    --docs all \
    --export json
echo "Analysis complete: ./analysis-$DATE"
EOF

chmod +x analyze_app.sh
```

### 4. Extend with Custom Plugins
```python
# Create custom business logic analyzers
from plugins.base_plugin import FrameworkPlugin

class CustomBusinessRulePlugin(FrameworkPlugin):
    def detect_framework(self, project_path):
        # Your custom detection logic
        return True
    
    def analyze_framework_usage(self, project_path, context):
        # Your custom analysis logic
        return PluginResult(...)
```

## 📞 Support

- **Documentation**: Check the main README.md for comprehensive information
- **Setup Guides**: 
  - `UBUNTU_SETUP.md` for Ubuntu/Linux installation
  - `WINDOWS_SETUP.md` for Windows installation
- **Testing**: Run `python test_system_structure.py` to verify installation (with virtual environment activated)
- **Dependencies**: Install all required packages with `pip install pyyaml tqdm psutil javalang networkx beautifulsoup4`
- **Issues**: Most issues are related to:
  - Virtual environment not activated
  - Missing dependencies (run the pip install command above)
  - Import path issues (fixed in latest version)

---

*Happy analyzing! This tool will help you understand your Struts application's business logic and plan a successful migration to modern technologies.*