# Windows Setup Guide

This guide provides step-by-step instructions for setting up the Struts Business Rules Analyzer on a fresh Windows machine.

## Prerequisites

### 1. Python Installation
- Download Python 3.8 or higher from [python.org](https://www.python.org/downloads/)
- During installation, check "Add Python to PATH"
- Verify installation: Open Command Prompt and run `python --version`

### 2. Git (Optional but Recommended)
- Download Git from [git-scm.com](https://git-scm.com/download/win)
- Follow the installation wizard with default settings

## Installation Steps

### Step 1: Get the Analyzer Code
If using Git:
```cmd
git clone <repository-url>
cd struts-analyzer
```

If downloading manually:
- Download and extract the ZIP file
- Open Command Prompt and navigate to the extracted folder

### Step 2: Set Up Virtual Environment (Recommended)
```cmd
python -m venv analyzer-env
analyzer-env\Scripts\activate
```

### Step 3: Install Dependencies
```cmd
pip install pyyaml tqdm psutil javalang networkx beautifulsoup4
```

If you encounter errors, install dependencies manually:
```cmd
pip install pyyaml>=6.0
pip install tqdm>=4.65.0
pip install psutil>=5.9.0
pip install javalang>=0.13.0
pip install networkx>=2.8.0
pip install beautifulsoup4>=4.12.0
```

### Optional Dependencies (Enhanced Features)
```cmd
pip install javalang>=0.13.0
pip install tree-sitter>=0.20.0
pip install graphviz>=0.20.0
```

### Step 4: Verify Installation
```cmd
python test_system_structure.py
```

## Usage on Windows

### Basic Analysis
```cmd
python struts_analyzer.py C:\path\to\your\struts\application
```

### Analysis with Output Directory
```cmd
python struts_analyzer.py C:\path\to\struts\app --output C:\analysis-results
```

### Advanced Usage
```cmd
python struts_analyzer.py C:\path\to\struts\app --config config\analyzer_config.yaml --parallel 4
```

## Windows-Specific Notes

### File Path Handling
- Use forward slashes (/) or double backslashes (\\\\) in configuration files
- Example: `"C:/projects/myapp"` or `"C:\\\\projects\\\\myapp"`

### Performance Considerations
- Windows Defender may slow down file scanning. Consider adding the analyzer folder to exclusions
- Use SSD storage for better performance with large codebases
- Close unnecessary applications during analysis of large projects

### PowerShell Alternative
If using PowerShell instead of Command Prompt:
```powershell
# Activate virtual environment
.\\analyzer-env\\Scripts\\Activate.ps1

# Run analysis
python struts_analyzer.py "C:\\path\\to\\struts\\app"
```

## Troubleshooting

### Common Issues

**Error: 'python' is not recognized**
- Reinstall Python and ensure "Add to PATH" is checked
- Or use `py` instead of `python`

**Permission Errors**
- Run Command Prompt as Administrator
- Or use `--user` flag: `pip install --user -r requirements.txt`

**Long Path Issues**
- Enable long path support in Windows 10/11:
  - Open Group Policy Editor (gpedit.msc)
  - Navigate to: Computer Configuration > Administrative Templates > System > Filesystem
  - Enable "Enable Win32 long paths"

**Memory Issues with Large Applications**
- Increase virtual memory (pagefile)
- Use `--parallel 2` for reduced memory usage
- Close other applications during analysis

### Environment Variables
Set these in Windows if needed:
```cmd
set PYTHONPATH=%CD%
set ANALYZER_CONFIG=config\analyzer_config.yaml
```

## Next Steps

1. **Test with Sample Data**: Run the system tests to ensure everything works
2. **Configure Analysis**: Modify `config\analyzer_config.yaml` for your needs
3. **Analyze Your Application**: Point the tool at your Struts application directory
4. **Review Results**: Check the generated documentation in the output directory

## Support

If you encounter issues:
1. Check this troubleshooting section
2. Ensure all dependencies are properly installed
3. Verify your Python version is 3.8+
4. Try running with `--verbose` flag for detailed error information

The analyzer has been tested on Windows 10 and Windows 11 with Python 3.8-3.12.