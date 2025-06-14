# Ubuntu Setup Guide

This guide provides step-by-step instructions for setting up the Struts Business Rules Analyzer on Ubuntu Linux.

## Prerequisites

### 1. System Update
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Python Installation
Ubuntu 20.04+ comes with Python 3.8+, but you may need to install additional packages:
```bash
# Check Python version
python3 --version

# Install Python development tools
sudo apt install python3-dev python3-pip python3-venv build-essential -y

# Install additional dependencies for compilation
sudo apt install libffi-dev libssl-dev libbz2-dev libreadline-dev libsqlite3-dev -y
```

### 3. Git Installation
```bash
sudo apt install git -y
```

### 4. Optional: Graphviz for Visualization
```bash
sudo apt install graphviz graphviz-dev -y
```

## Installation Steps

### Step 1: Get the Analyzer Code
```bash
# Clone the repository
git clone <repository-url>
cd struts-analyzer

# Or if downloading manually:
# wget <download-url> -O struts-analyzer.zip
# unzip struts-analyzer.zip
# cd struts-analyzer
```

### Step 2: Set Up Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv analyzer-env

# Activate virtual environment
source analyzer-env/bin/activate

# Upgrade pip
pip install --upgrade pip
```

### Step 3: Install Dependencies
```bash
# Install core dependencies
pip install pyyaml tqdm psutil javalang networkx beautifulsoup4
```

If you encounter errors, install dependencies manually:
```bash
# Core AWS and analysis dependencies
pip install boto3>=1.26.0 botocore>=1.34.0
pip install strands-agents>=0.1.0

# Data processing
pip install networkx>=2.8.0 pandas>=2.0.0 numpy>=1.24.0

# Visualization
pip install matplotlib>=3.5.0 graphviz>=0.20.0

# Utilities
pip install click>=8.1.0 tqdm>=4.65.0
pip install python-dotenv>=1.0.0 pathlib2>=2.3.7

# Development tools
pip install pytest>=7.4.0 black>=23.0.0 mypy>=1.5.0
```

### Optional Dependencies (Enhanced Features)
```bash
# Java parsing (enhanced analysis)
pip install javalang>=0.13.0

# Tree-sitter for advanced parsing
pip install tree-sitter>=0.20.0
```

### Step 4: Verify Installation
```bash
python test_system_structure.py
```

## Usage on Ubuntu

### Basic Analysis
```bash
python struts_analyzer.py /path/to/your/struts/application
```

### Analysis with Output Directory
```bash
python struts_analyzer.py /path/to/struts/app --output ./analysis-results
```

### Advanced Usage
```bash
# Use all CPU cores for parallel processing
python struts_analyzer.py /path/to/struts/app \
    --config config/analyzer_config.yaml \
    --parallel $(nproc)
```

### Permission Handling
```bash
# If analyzing system directories, you may need sudo
sudo python struts_analyzer.py /opt/myapp --output ~/analysis-results
sudo chown -R $USER:$USER ~/analysis-results
```

## Ubuntu-Specific Optimizations

### Performance Tuning
```bash
# Check available memory
free -h

# Monitor CPU usage during analysis
htop

# Use ionice for disk-intensive operations
ionice -c 3 python struts_analyzer.py /path/to/large/app
```

### Large Codebase Analysis
```bash
# For applications with 100k+ files
python struts_analyzer.py /path/to/large/app \
    --output ./large-analysis \
    --parallel $(nproc) \
    --exclude-patterns "*/test/*,**/target/**,**/node_modules/**"
```

### File System Considerations
```bash
# For very large outputs, consider using a dedicated partition
mkdir /tmp/struts-analysis
python struts_analyzer.py /path/to/app --output /tmp/struts-analysis

# Or use external storage
mkdir /mnt/external/struts-analysis
python struts_analyzer.py /path/to/app --output /mnt/external/struts-analysis
```

## Environment Configuration

### Shell Environment
Add to your `~/.bashrc` or `~/.zshrc`:
```bash
# Struts Analyzer environment
export STRUTS_ANALYZER_HOME="$HOME/struts-analyzer"
export PYTHONPATH="$STRUTS_ANALYZER_HOME:$PYTHONPATH"
alias analyze-struts="python $STRUTS_ANALYZER_HOME/struts_analyzer.py"

# Activate virtual environment automatically
alias analyzer-env="source $STRUTS_ANALYZER_HOME/analyzer-env/bin/activate"
```

### System Service (Optional)
Create a systemd service for regular analysis:
```bash
# Create service file
sudo tee /etc/systemd/system/struts-analyzer.service << EOF
[Unit]
Description=Struts Application Analyzer
After=network.target

[Service]
Type=oneshot
User=$USER
WorkingDirectory=$HOME/struts-analyzer
Environment=PATH=$HOME/struts-analyzer/analyzer-env/bin:/usr/bin:/bin
ExecStart=$HOME/struts-analyzer/analyzer-env/bin/python struts_analyzer.py /path/to/app --output /var/log/struts-analysis

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable struts-analyzer.service
sudo systemctl start struts-analyzer.service
```

## Docker Alternative

### Using Docker (Containerized Setup)
```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    build-essential libffi-dev libssl-dev \
    graphviz graphviz-dev git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY . .
CMD ["python3", "struts_analyzer.py"]
EOF

# Build and run
docker build -t struts-analyzer .
docker run -v /path/to/struts/app:/input -v ./results:/output struts-analyzer /input --output /output
```

## Troubleshooting

### Common Issues

**Permission Denied Errors**
```bash
# Fix ownership
sudo chown -R $USER:$USER /path/to/analyzer

# Or run with proper permissions
sudo -E python struts_analyzer.py /path/to/app
```

**Memory Issues**
```bash
# Check memory usage
cat /proc/meminfo | grep MemAvailable

# Monitor during execution
watch -n 1 'free -h && ps aux | grep python | head -5'

# Reduce memory usage
python struts_analyzer.py /path/to/app --parallel 2 --max-file-size 10
```

**Missing Dependencies**
```bash
# Install system packages
sudo apt install python3-dev libxml2-dev libxslt1-dev

# Reinstall Python packages
pip install --upgrade --force-reinstall -r requirements.txt
```

**Java Parsing Issues**
```bash
# Install OpenJDK for better Java support
sudo apt install openjdk-11-jdk -y

# Verify Java installation
java -version
javac -version
```

**File Encoding Issues**
```bash
# Set locale for proper file handling
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

# Add to ~/.bashrc for persistence
echo "export LC_ALL=C.UTF-8" >> ~/.bashrc
echo "export LANG=C.UTF-8" >> ~/.bashrc
```

### Performance Optimization

**SSD Optimization**
```bash
# Check if using SSD
lsblk -d -o name,rota

# Enable TRIM for SSDs
sudo systemctl enable fstrim.timer
```

**CPU Optimization**
```bash
# Use all available cores
export OMP_NUM_THREADS=$(nproc)

# Set CPU governor to performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

**I/O Optimization**
```bash
# Use faster I/O scheduler for analysis
echo mq-deadline | sudo tee /sys/block/sda/queue/scheduler

# Increase file descriptor limits
ulimit -n 65536
```

## Development Setup

### Additional Development Tools
```bash
# Install development dependencies
sudo apt install vim tmux htop tree jq -y

# Code formatting and linting
pip install black flake8 isort pre-commit

# Set up pre-commit hooks
pre-commit install
```

### IDE Integration
```bash
# For VS Code
sudo apt install code -y
code --install-extension ms-python.python

# For PyCharm (snap)
sudo snap install pycharm-community --classic
```

## Monitoring and Logging

### Analysis Logging
```bash
# Create log directory
mkdir -p ~/struts-analysis-logs

# Run with detailed logging
python struts_analyzer.py /path/to/app \
    --output ./results \
    --verbose \
    --log-file ~/struts-analysis-logs/analysis-$(date +%Y%m%d).log
```

### System Monitoring
```bash
# Monitor system resources during analysis
htop &
iotop &

# Log system metrics
while true; do
    echo "$(date): $(free -h | grep Mem | awk '{print $3}')" >> ~/struts-analysis-logs/memory.log
    sleep 30
done &
```

## Next Steps

1. **Test Installation**: Run `python test_system_structure.py`
2. **Configure Analysis**: Edit `config/analyzer_config.yaml`
3. **Analyze Sample Application**: Use the test data to verify functionality
4. **Performance Tuning**: Adjust settings based on your hardware
5. **Set Up Automation**: Create scripts for regular analysis runs

## Support

For Ubuntu-specific issues:

1. **Check System Logs**: `journalctl -f`
2. **Verify Dependencies**: `pip list | grep -E "(boto3|networkx|pandas)"`
3. **Test Python Environment**: `python -c "import sys; print(sys.version)"`
4. **Monitor Resources**: Use `htop`, `iotop`, and `df -h`

## Hardware Recommendations

### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4GB
- **Storage**: 10GB free space
- **OS**: Ubuntu 18.04 LTS or newer

### Recommended Configuration
- **CPU**: 8+ cores, 3.0+ GHz
- **RAM**: 16GB+
- **Storage**: SSD with 50GB+ free space
- **OS**: Ubuntu 22.04 LTS

### For Large Enterprise Applications
- **CPU**: 16+ cores, high-frequency processor
- **RAM**: 32GB+
- **Storage**: NVMe SSD with 100GB+ free space
- **Network**: Fast connection for AWS Strands integration

---

**Built for Ubuntu reliability and performance**

This setup guide ensures optimal performance of the Struts Business Rules Analyzer on Ubuntu systems, taking advantage of Linux's superior file handling and process management capabilities.