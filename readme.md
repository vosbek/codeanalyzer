# Struts Legacy Business Rules Analyzer

A comprehensive tool for extracting business rules, dependencies, and architectural complexity from Struts legacy applications to inform GraphQL/Angular migration strategies.

## 🎯 Purpose

This analyzer is specifically designed to help organizations understand their Struts legacy applications at a business level, enabling informed migration decisions to modern technologies like GraphQL and Angular. Unlike generic code analyzers, this tool focuses on:

- **Business Rules Extraction**: Identifies and documents all business logic embedded in Struts configurations and code
- **Migration Risk Assessment**: Provides detailed complexity scoring and migration effort estimates
- **Stakeholder Communication**: Generates documentation that business stakeholders can understand
- **Dependency Mapping**: Creates comprehensive dependency graphs showing interconnected business processes

## 🚀 Key Features

### Business Rules Analysis
- **Struts Configuration Parsing**: Deep analysis of `struts-config.xml`, `validation.xml`, and related files
- **Action Class Analysis**: Extracts business logic from Java Action classes using AST parsing
- **JSP UI Analysis**: Identifies UI business rules and conditional logic in JSP files
- **Validation Rules**: Comprehensive extraction of form validation and business constraints
- **Comment Mining**: Extracts business requirements from code comments

### Migration Planning
- **Risk Assessment**: Automated scoring of migration complexity and risk levels
- **Effort Estimation**: Realistic time estimates for migrating each component
- **Phased Migration Plans**: Generates incremental migration strategies
- **Technology Mapping**: Specific recommendations for GraphQL/Angular equivalents

### Documentation Generation
- **Executive Summary**: High-level overview for business stakeholders
- **Technical Documentation**: Detailed analysis for development teams
- **Migration Assessment**: Component-by-component migration recommendations
- **Dependency Graphs**: Visual representations of system relationships

### AWS Strands Integration
- **Interactive Tools**: Business rule explorer, dependency visualizer, migration planner
- **Cloud Deployment**: AWS Strands tools for collaborative analysis
- **Team Collaboration**: Shared analysis workspace for migration teams

## 📋 Requirements

### System Requirements
- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended for large codebases)
- 1GB free disk space

### Dependencies
```bash
# Core dependencies (required)
pip install pyyaml tqdm psutil javalang networkx beautifulsoup4

# Optional for enhanced features
pip install graphviz>=0.20.0  # For dependency diagrams
pip install boto3>=1.26.0     # For AWS Strands integration
```

## 🛠 Installation

### Quick Setup

1. **Clone or download the analyzer**:
   ```bash
   git clone <repository-url>
   cd struts-analyzer
   ```

2. **Create virtual environment (recommended)**:
   ```bash
   python3 -m venv analyzer-env
   source analyzer-env/bin/activate  # Windows: analyzer-env\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install pyyaml tqdm psutil javalang networkx beautifulsoup4
   ```

4. **Verify installation**:
   ```bash
   python test_system_structure.py
   # Expected output: "Overall result: ✅ PASS"
   ```

### Platform-Specific Setup

- **Ubuntu/Linux**: See `UBUNTU_SETUP.md` for detailed setup instructions
- **Windows**: See `WINDOWS_SETUP.md` for Windows-specific installation steps
- **Getting Started**: See `GETTING_STARTED.md` for a comprehensive quick-start guide

## 📖 Usage

### Basic Analysis

Analyze a Struts application directory:

```bash
python struts_analyzer.py /path/to/struts/application
```

### Advanced Options

```bash
# Specify output directory
python struts_analyzer.py /path/to/struts/app --output ./my_analysis

# Use custom configuration
python struts_analyzer.py /path/to/struts/app --config config/my_config.yaml

# Parallel processing for large codebases
python struts_analyzer.py /path/to/struts/app --parallel 8

# Verbose output for debugging
python struts_analyzer.py /path/to/struts/app --verbose

# Generate specific output format
python struts_analyzer.py /path/to/struts/app --format json
```

### Configuration

Create a custom configuration file to customize the analysis:

```yaml
# analyzer_config.yaml
analysis:
  max_file_size_mb: 15
  parallel_workers: 6
  skip_test_files: true

business_rules:
  extract_from_comments: true
  include_ui_rules: true
  categorize_by_domain: true

migration:
  risk_thresholds:
    critical: 20
    high: 12
    medium: 6
    low: 0

output:
  include_diagrams: true
  stakeholder_friendly: true
```

## 📊 Output Structure

The analyzer generates a comprehensive analysis output:

```
analysis_output/
├── executive_summary.md          # High-level overview for stakeholders
├── business_rules.md            # Detailed business rules documentation
├── action_flows.md              # User journey and action flow analysis
├── migration_assessment.md      # Component-by-component migration plan
├── dependency_graph.png         # Visual dependency diagram
├── analysis_results.json        # Raw analysis data
└── analysis_results.yaml        # Human-readable analysis data
```

### Executive Summary Example

The executive summary provides stakeholder-friendly insights:

- **Total Business Rules**: 247 rules identified across 5 categories
- **Migration Risk**: 15% high/critical risk, 60% medium risk, 25% low risk
- **Effort Estimate**: 12-16 weeks with a 4-person team
- **Key Recommendations**: Incremental migration starting with low-risk components

### Business Rules Documentation

Each business rule includes:
- **Description**: Plain English explanation of the business logic
- **Source Location**: Exact file and line number
- **Business Context**: Why this rule exists and its business impact
- **Migration Risk**: Assessment of migration complexity
- **Dependencies**: Related components and rules

### Migration Assessment

For each component:
- **Complexity Score**: Objective measure based on forwards, validations, exceptions
- **Risk Level**: Low, Medium, High, or Critical
- **Effort Estimate**: Realistic time estimate in hours/days
- **Specific Recommendations**: Technology-specific migration guidance
- **Potential Blockers**: Issues that could complicate migration

## 🏗 Architecture

The analyzer uses a modular, extensible architecture:

### Core Components

1. **Configuration Manager**: Handles all configuration options and user preferences
2. **Cache Manager**: Improves performance by caching parsed results
3. **Parser Framework**: Extensible system for adding new file type parsers
4. **Business Rule Extractor**: Orchestrates the analysis workflow
5. **Documentation Generator**: Creates stakeholder-friendly output

### Parser System

- **StrutsConfigParser**: Handles `struts-config.xml` and related configuration files
- **ValidationParser**: Processes `validation.xml` and validation rules
- **JavaActionAnalyzer**: Analyzes Java Action classes using AST parsing
- **JSPAnalyzer**: Extracts UI business rules from JSP files

### Extensibility

Add new parsers by extending the `BaseParser` class:

```python
class CustomParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix == '.custom'
    
    def parse(self, file_path: Path) -> Dict[str, Any]:
        # Your parsing logic here
        return results
```

## 🔧 Advanced Features

### Performance Optimization

For large codebases (1000+ files):

1. **Enable Parallel Processing**: Use `--parallel 8` or more workers
2. **Configure File Size Limits**: Set `max_file_size_mb` in configuration
3. **Use Caching**: Enable caching for repeated analyses
4. **Exclude Test Files**: Skip test directories to reduce processing time

### AWS Strands Integration

Deploy interactive analysis tools to AWS Strands:

```bash
# Generate AWS Strands tools
python aws_strands_tools.py --output-dir ./strands_deployment

# Deploy to AWS (requires AWS CLI configured)
cd strands_deployment/deployment
./deploy.sh
```

Available Strands tools:
- **Business Rule Explorer**: Interactive filtering and search
- **Dependency Visualizer**: Dynamic dependency graphs
- **Migration Planner**: Customized migration plan generation

### Integration with CI/CD

Monitor business rule changes over time:

```bash
# Run analysis in CI pipeline
python struts_analyzer.py $CODEBASE_PATH --format json --output ./reports

# Compare with previous analysis
python compare_analyses.py ./reports/previous.json ./reports/current.json
```

## 🧪 Testing

The analyzer includes comprehensive tests:

```bash
# Run all tests
python test_analyzer.py

# Run specific test categories
python -m pytest tests/test_parsers.py
python -m pytest tests/test_business_rules.py
python -m pytest tests/test_migration_assessment.py
```

## 🤝 Contributing

### Development Setup

1. **Clone the repository**
2. **Install development dependencies**:
   ```bash
   pip install -r requirements-dev.txt
   ```
3. **Run tests** to ensure everything works
4. **Follow coding standards**: PEP 8, comprehensive docstrings, type hints

### Adding New Features

1. **Parser Development**: Add new file type parsers for additional Struts components
2. **Business Rule Types**: Extend business rule categorization
3. **Migration Strategies**: Add new target technology mappings
4. **Output Formats**: Create additional documentation formats

## 📋 Limitations

- **Struts Version Support**: Optimized for Struts 1.x and 2.x
- **Language Support**: Java Action classes only (no Groovy/Scala support)
- **Dynamic Configuration**: May miss runtime-configured actions
- **Third-party Plugins**: Limited support for custom Struts plugins

## 🆘 Troubleshooting

### Common Issues

**Memory Issues with Large Codebases**:
```bash
# Reduce parallel workers and enable file size limits
python struts_analyzer.py /path/to/app --parallel 2 --config config/large_codebase.yaml
```

**Java Parsing Errors**:
```bash
# Enable verbose logging to identify problematic files
python struts_analyzer.py /path/to/app --verbose
```

**Missing Dependencies**:
```bash
# Install all optional dependencies
pip install -r requirements.txt
pip install graphviz boto3
```

### Performance Tuning

For optimal performance:

1. **Use SSDs** for faster file I/O
2. **Allocate sufficient RAM** (8GB+ for large projects)
3. **Enable caching** for repeated analyses
4. **Exclude irrelevant directories** (tests, documentation)

## 📄 License

This project is provided as-is for educational and evaluation purposes. Please review your organization's policies regarding code analysis tools.

## 🙋 Support

For questions, issues, or feature requests:

1. **Check the troubleshooting section** above
2. **Review the configuration options** in `config/analyzer_config.yaml`
3. **Run the test suite** to verify installation
4. **Enable verbose logging** for detailed diagnostics

## 🗺 Roadmap

### Near-term Enhancements
- **Spring Integration**: Support for Spring-based Struts applications
- **Tiles Analysis**: Enhanced support for Apache Tiles
- **Performance Dashboard**: Real-time analysis progress tracking
- **API Documentation**: REST API for programmatic access

### Long-term Vision
- **Multi-language Support**: Support for other legacy frameworks
- **AI-powered Insights**: Machine learning for migration recommendations
- **Cloud-native Deployment**: Kubernetes-based analysis clusters
- **Integration Hub**: Connectors for popular development tools

---

**Built with ❤️ for legacy system modernization**

This analyzer represents thousands of hours of Struts expertise distilled into an automated tool. It's designed to accelerate your migration journey while preserving the critical business logic that powers your applications. 