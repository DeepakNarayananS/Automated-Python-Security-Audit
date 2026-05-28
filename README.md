# 🔒 Python Security Audit Tool - Enterprise Edition v4.0

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Code Quality](https://img.shields.io/badge/SonarQube-Compliant-brightgreen.svg)](https://www.sonarqube.org/)
[![Security](https://img.shields.io/badge/Bandit-Passed-success.svg)](https://bandit.readthedocs.io/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-4.0.0-blue.svg)]()

A comprehensive, enterprise-grade Python security audit tool with **dual scanning modes**: scan a single environment OR scan all Python projects in a folder simultaneously. Generates beautiful HTML reports perfect for CISO presentations.

---

## ✨ Key Features

### 🎯 Dual Scanning Modes
- **Single Mode** - Scan current Python environment (global or venv)
- **Multi-Project Mode** - Scan all projects in a folder simultaneously
- Automatic project discovery (detects venvs, requirements.txt, Python files)
- Consolidated reporting across multiple projects

### 🛡️ Comprehensive Security Analysis
- **Vulnerability Detection** - Uses `pip-audit` for comprehensive CVE detection
- **Complete Package Analysis** - Analyzes all installed packages (typically 70-300+)
- **Dependency Tree Visualization** - Full dependency relationship mapping
- **SBOM Generation** - Software Bill of Materials in CycloneDX format
- **Smart Static Code Analysis** - Bandit security scanning with intelligent severity filtering

### 📈 Beautiful Reporting
- **Professional HTML Reports** - CISO-ready presentation format
- **Complete Data Display** - ALL packages, vulnerabilities, and outdated packages in scrollable tables
- **Risk Assessment** - Automated risk level calculation (LOW/MEDIUM/HIGH/CRITICAL)
- **Project Prioritization** - Identify high-risk projects requiring immediate attention
- **Rich Console Output** - Color-coded, easy-to-read terminal interface

### ⚡ Enterprise Ready
- Fast execution with timeout protection
- Comprehensive JSON reports for automation
- SonarQube compliant (0 bugs, 0 code smells)
- Windows compatible
- Perfect for CI/CD integration

---

## 🚀 Quick Start (2 Minutes!)

### Step 1: Install Dependencies
```bash
cd Python_Security
pip install -r requirements.txt
```

### Step 2: Run Your First Scan

#### Option A: Single Mode (Scan Current Environment)
```bash
python python_security.py
```

#### Option B: Multi-Project Mode (Scan All Projects)
```bash
python python_security.py --multi-project c:\path\to\projects
# Or short form
python python_security.py -m c:\path\to\projects
```

### Step 3: View the Report
1. Open the `python_security_audit_output/` folder
2. Find the HTML report:
   - Single mode: `security_audit_report_[timestamp].html`
   - Multi-project mode: `multi_project_security_audit_[timestamp].html`
3. Open it in your browser
4. Present to your CISO! 🎉

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Internet connection (for vulnerability database queries)

### Dependencies (5 packages)
```bash
pip install -r requirements.txt
```

**What Gets Installed:**
1. **rich** (v13.9.4) - Beautiful terminal output
2. **pip-audit** (v2.10.0) - Official PyPA vulnerability scanner
3. **pipdeptree** (v2.35.3) - Dependency tree analysis
4. **bandit** (v1.9.4) - Static security analysis with intelligent severity filtering
5. **cyclonedx-bom** (v7.3.0) - SBOM generation

All dependencies are pinned to specific versions for reproducibility and security.

---

## 📖 Usage Guide

### Command Reference

```bash
# Show help
python python_security.py --help

# Show version
python python_security.py --version

# Single mode (default) - scan current environment
python python_security.py

# Multi-project mode - scan all projects in a folder
python python_security.py --multi-project <folder_path>
python python_security.py -m <folder_path>
```

### Single Mode - Detailed

**When to use**: Audit your current Python environment or a specific project

```bash
# Scan global Python environment
python python_security.py

# Scan a specific project (activate venv first)
cd c:\projects\my-app
venv\Scripts\activate
python c:\path\to\python_security.py
```

**What it does**:
1. Scans all Python packages in current environment
2. Checks for vulnerabilities using pip-audit
3. Identifies outdated packages
4. Analyzes dependency tree
5. Generates SBOM
6. Runs Bandit static analysis
7. Creates beautiful HTML report

**Output**: `security_audit_report_[timestamp].html`

### Multi-Project Mode - Detailed

**When to use**: Audit multiple Python projects in a portfolio

```bash
python python_security.py -m c:\Users\DEEPAK\Documents\automation
```

**What it does**:
1. **Discovery Phase**: Finds all Python projects in the folder
   - Projects with virtual environments (venv, .venv, env, etc.)
   - Projects with requirements.txt
   - Projects with Python files

2. **Scanning Phase**: Scans each project separately
   - Uses project's own venv if available
   - Falls back to global Python if no venv
   - Collects packages, vulnerabilities, outdated packages

3. **Reporting Phase**: Generates consolidated report
   - Overall metrics across all projects
   - Detailed per-project breakdown with complete package lists
   - Risk assessment per project
   - Consolidated vulnerability list
   - Prioritized recommendations

**Output**: `multi_project_security_audit_[timestamp].html`

**Example folder structure**:
```
automation/                          ← Root folder (pass this path)
├── web-scraper/
│   ├── venv/                       ← Has venv ✓
│   ├── requirements.txt            ← Has requirements ✓
│   └── scraper.py
├── api-client/
│   ├── .venv/                      ← Has venv ✓
│   └── client.py
├── data-processor/
│   ├── requirements.txt            ← Has requirements ✓
│   └── processor.py
└── utils/
    └── helpers.py                  ← Has Python files ✓
```
All 4 projects will be discovered and scanned!

---

## 📊 Report Features

### Single Mode Report Includes:
- ✅ Complete package inventory (scrollable table)
- ✅ System information (platform, Python version, architecture)
- ✅ All vulnerabilities with CVE IDs and fix versions
- ✅ All outdated packages with current vs. latest versions
- ✅ Bandit static analysis with status indicators
- ✅ Dependency tree visualization
- ✅ SBOM in CycloneDX format
- ✅ Risk assessment (LOW/MEDIUM/HIGH/CRITICAL)
- ✅ Actionable recommendations

### Multi-Project Mode Report Includes:
- ✅ **All of the above, PLUS:**
- ✅ Overall metrics across all projects
- ✅ **Detailed per-project breakdown** with:
  - Complete package list (scrollable)
  - All vulnerabilities with CVE IDs
  - All outdated packages
  - Individual risk assessment
- ✅ Project prioritization by risk level
- ✅ Portfolio-wide recommendations
- ✅ Consolidated vulnerability tracking

### Visual Features:
- **Scrollable tables** - View all data without page clutter
- **Sticky headers** - Headers stay visible while scrolling
- **Color coding** - RED (high risk), YELLOW (medium), GREEN (low)
- **Hover effects** - Interactive row highlighting
- **Responsive design** - Works on all screen sizes
- **Professional layout** - CISO-ready presentation

---

## 📁 Output Structure

### Single Mode Output:
```
python_security_audit_output/
├── security_audit_report_[timestamp].html  ← Main HTML report
├── system_information.json
├── installed_packages.json
├── pip_audit_vulnerabilities.json
├── outdated_packages.json
├── dependency_tree.json
├── bandit_results.json
├── sbom.json
├── requirements_snapshot.txt
└── dependency_conflicts.txt
```

### Multi-Project Mode Output:
```
python_security_audit_output/
├── multi_project_security_audit_[timestamp].html  ← Consolidated HTML report
├── installed_packages_project1.json
├── installed_packages_project2.json
├── installed_packages_project3.json
└── ... (per-project data files)
```

---

## 🎯 Use Cases

### For CISOs & Security Teams
- **Executive Reporting** - Professional HTML reports for board presentations
- **Multi-Project Overview** - Scan entire portfolios of Python projects at once
- **Risk Assessment** - Automated risk level calculation per project and overall
- **Compliance** - SBOM generation for regulatory requirements
- **Audit Trail** - Complete JSON data for security audits
- **Prioritization** - Identify high-risk projects requiring immediate attention

### For Development Teams
- **Pre-Deployment Checks** - Scan before production releases
- **Multi-Project Management** - Audit all projects in your workspace simultaneously
- **Dependency Management** - Understand package relationships
- **Security Monitoring** - Regular vulnerability scanning
- **Technical Debt** - Track outdated packages across projects

### For DevOps/CI-CD
- **Automated Scanning** - Integrate into build pipelines
- **Quality Gates** - Block deployments with critical vulnerabilities
- **Continuous Monitoring** - Schedule regular audits
- **Compliance Automation** - Generate SBOMs automatically

---

## 💡 Best Practices

### For Single Mode:
1. **Run in venv**: Activate your project's venv before running for project-specific audit
2. **Regular scans**: Run weekly or before each deployment
3. **Review HTML**: Open the HTML report in browser for best experience
4. **Share with team**: HTML report is perfect for team reviews

### For Multi-Project Mode:
1. **Organize projects**: Keep all Python projects in one root folder
2. **Use venvs**: Each project should have its own venv for accurate scanning
3. **Prioritize**: Focus on HIGH/CRITICAL risk projects first
4. **Standardize**: Use the report to identify version inconsistencies across projects
5. **Schedule audits**: Run monthly multi-project audits for portfolio management

### Responding to Findings:

| Risk Level | Action Required | Timeline |
|------------|----------------|----------|
| 🔴 CRITICAL | Update immediately | 24 hours |
| 🟠 HIGH | Plan urgent update | 1 week |
| 🟡 MEDIUM | Schedule update | 2-4 weeks |
| 🟢 LOW | Include in next cycle | Next sprint |

---

## 🔧 Dependencies Explained

### 1. **rich** (v13.9.4)
**Purpose**: Beautiful terminal output with colors, tables, and progress indicators  
**Why**: Provides professional, easy-to-read console interface  
**Security**: Widely used, actively maintained, no known vulnerabilities

### 2. **pip-audit** (v2.10.0)
**Purpose**: Scans Python packages for known security vulnerabilities  
**Why**: Official tool from PyPA (Python Packaging Authority)  
**Security**: Checks against OSV (Open Source Vulnerabilities) database  
**Coverage**: Comprehensive CVE detection with fix recommendations

### 3. **pipdeptree** (v2.35.3)
**Purpose**: Displays package dependency tree  
**Why**: Helps understand package relationships and transitive dependencies  
**Security**: Identifies hidden vulnerable dependencies  
**Features**: JSON output, circular dependency detection

### 4. **bandit** (v1.9.4)
**Purpose**: Static security analysis for Python code  
**Why**: Industry-standard tool for finding common security issues  
**Security**: Detects OWASP Top 10 vulnerabilities  
**Coverage**: SQL injection, hardcoded passwords, insecure functions  
**Smart Features**: 
- First scans for MEDIUM/HIGH severity issues
- If none found, automatically scans for LOW severity issues
- Includes Status column: ✓ Safe Usage, ⚠ Review, ⚠ Fix Recommended, ❌ Fix Required
- Color-coded severity levels in HTML report

### 5. **cyclonedx-bom** (v7.3.0)
**Purpose**: Software Bill of Materials (SBOM) generation  
**Why**: Creates industry-standard SBOM in CycloneDX format  
**Security**: Essential for compliance and supply chain security  
**Coverage**: Complete package inventory with metadata

---

## 🛠️ Troubleshooting

### "Module not found" error?
```bash
pip install -r requirements.txt
```

### "No projects found" in multi-project mode?
- Make sure the folder contains Python projects
- Projects need venv, requirements.txt, or .py files

### "pip-audit failed"?
- Ensure internet connection (needs to query vulnerability database)

### Scan takes too long?
- Normal! Each project takes 1-3 minutes
- The tool has timeout protection
- For 10 projects, expect 10-30 minutes

### Some projects fail to scan?
- Check if project venvs are properly set up
- Failed projects are marked in the report
- Review console output for specific errors

### Want to scan a specific project?
```bash
cd c:\path\to\your\project
python c:\path\to\python_security.py
```

---

## 📈 What Makes This Tool Special

### Dual Scanning Modes
- ✅ **Single Mode** - Scan current Python environment (global or venv)
- ✅ **Multi-Project Mode** - Scan all projects in a folder simultaneously
- ✅ Automatic project discovery (detects venvs, requirements.txt, Python files)
- ✅ Consolidated reporting across multiple projects

### Comprehensive Coverage
- ✅ Scans **ALL** packages (no limits, no truncation)
- ✅ Handles 70-300+ packages efficiently per environment
- ✅ Comprehensive vulnerability scanning with pip-audit
- ✅ Complete dependency analysis
- ✅ Shows **ALL** vulnerabilities and outdated packages in scrollable HTML tables

### Enterprise Features
- ✅ **Beautiful HTML reports** for executive presentations with complete data
- ✅ **Multi-project consolidated reports** showing portfolio-wide security posture
- ✅ Professional design suitable for CISO review
- ✅ Automated risk assessment per project and overall
- ✅ Actionable recommendations with proper timestamps
- ✅ Smart Bandit analysis with status indicators
- ✅ Project prioritization based on risk levels

### Code Quality
- ✅ **SonarQube Compliant** - Zero bugs, zero code smells
- ✅ Secure implementation - No shell injection risks
- ✅ Type hints throughout
- ✅ Comprehensive error handling

### Performance
- ✅ Fast execution with efficient algorithms
- ✅ Timeout protection for reliability
- ✅ Handles large package counts
- ✅ Clean, optimized code

---

## 🔒 Security Features

### Secure by Design
✅ **No Shell Injection** - Never uses `shell=True`  
✅ **Command Injection Prevention** - Commands passed as lists  
✅ **Input Validation** - All inputs validated  
✅ **Timeout Protection** - Prevents hanging operations  
✅ **Error Handling** - Graceful failure with detailed logging

### Vulnerability Detection
✅ **Comprehensive Scanning** - pip-audit for thorough CVE detection  
✅ **CVE Database** - Checks against OSV (Open Source Vulnerabilities) database  
✅ **Fix Recommendations** - Suggests specific versions to upgrade  
✅ **Transitive Dependencies** - Detects vulnerabilities in sub-dependencies  
✅ **Complete Results** - ALL vulnerabilities shown in scrollable HTML tables

---

## 🆚 Comparison

| Feature | This Tool | Manual Checks | Other Tools |
|---------|-----------|---------------|-------------|
| Single Environment Scan | ✅ Yes | ❌ No | ✅ Yes |
| Multi-Project Scan | ✅ Yes | ❌ No | ❌ No |
| Complete Data Display | ✅ All (scrollable) | ❌ No | ⚠️ Truncated |
| Consolidated Reports | ✅ Yes | ❌ No | ❌ No |
| HTML Reports | ✅ Yes | ❌ No | ⚠️ Basic |
| Smart Bandit Analysis | ✅ Yes (with status) | ❌ No | ⚠️ Basic |
| Project Prioritization | ✅ Yes | ❌ No | ❌ No |
| CISO Ready | ✅ Yes | ❌ No | ⚠️ Partial |
| Speed | ⚡ Fast | 🐌 Slow | ⚡ Fast |
| Ease of Use | 😊 Simple | 😓 Complex | 😐 Moderate |
| Windows Support | ✅ Yes | ⚠️ Varies | ⚠️ Varies |

---

## 📚 Common Questions (FAQ)

**Q: How long does a scan take?**  
A: 2-5 minutes for single mode with 70-300+ packages. For multi-project mode, 1-3 minutes per project.

**Q: Does it scan virtual environments?**  
A: In single mode, it scans the active environment. In multi-project mode, it scans each project's venv if available.

**Q: How do I scan multiple projects at once?**  
A: Use multi-project mode: `python python_security.py --multi-project c:\path\to\projects`. The tool will discover all Python projects in that folder and generate a consolidated report.

**Q: What counts as a "project" in multi-project mode?**  
A: Any folder containing a virtual environment (venv, .venv, etc.), requirements.txt file, or Python (.py) files.

**Q: Can I scan projects with different Python versions?**  
A: Yes! Each project is scanned using its own virtual environment's Python interpreter if available, otherwise the global Python.

**Q: Will it show all my packages and vulnerabilities in the HTML report?**  
A: Yes! The HTML report includes complete scrollable tables with ALL installed packages, ALL vulnerabilities, and ALL outdated packages - no limits or truncation.

**Q: Is the HTML report safe to share?**  
A: Yes, but review for sensitive information (hostnames, paths) before sharing externally.

**Q: How often should I run this?**  
A: Weekly for active projects, monthly for stable systems.

**Q: What if I find critical vulnerabilities?**  
A: Update affected packages immediately: `pip install --upgrade package_name`

**Q: Can I integrate this into CI/CD?**  
A: Yes! Run the script in your pipeline and check the exit code. The tool is designed for automation.

---

## 📝 Real-World Examples

### Example 1: Pre-Deployment Check
```bash
# Scan your current project before deploying
cd c:\projects\my-app
python c:\path\to\python_security.py
```

### Example 2: Portfolio Audit
```bash
# Scan all your company's Python projects
python python_security.py -m c:\company\python-projects
```

### Example 3: Weekly Security Review
```bash
# Schedule this in Task Scheduler (Windows)
python python_security.py -m c:\projects > audit_log.txt
```

### Example 4: CI/CD Integration
```bash
# Add to your build pipeline
python python_security.py
if %ERRORLEVEL% NEQ 0 (
    echo Security audit failed
    exit /b 1
)
```

---

## 🎓 Version History

### Version 4.0.0 (Current) - Multi-Project Support
- ✅ Multi-project scanning mode
- ✅ Automatic project discovery
- ✅ Consolidated HTML reports
- ✅ Per-project risk assessment
- ✅ Command-line interface with argparse
- ✅ Enhanced reporting with detailed per-project sections
- ✅ Complete package lists for each project
- ✅ All vulnerabilities and outdated packages shown

### Version 3.0.0 - SonarQube Compliant
- ✅ Single environment scanning
- ✅ Removed Safety (redundant with pip-audit)
- ✅ Fixed HTML timestamp display
- ✅ Fixed scrollable tables for all data
- ✅ Smart Bandit severity filtering
- ✅ SonarQube compliance (0 bugs, 0 code smells)

---

## ✅ Quality Assurance

This tool has been thoroughly tested and verified:

- ✅ **SonarQube**: Zero bugs, zero vulnerabilities, zero code smells
- ✅ **Bandit**: Passed security analysis
- ✅ **Type Checking**: Full type hint coverage
- ✅ **PEP 8**: Compliant code style
- ✅ **Error Handling**: Comprehensive exception handling
- ✅ **Documentation**: Fully documented codebase
- ✅ **Real-World Testing**: Tested with 70-300+ package environments
- ✅ **Windows Compatible**: Fixed Unicode encoding issues for Windows systems
- ✅ **Multi-Project Tested**: Verified with multiple project portfolios

**Status**: Production Ready | Enterprise Grade | Security Verified

---

## 📄 License

MIT License - Feel free to use and modify as needed.

---

## 🎉 Get Started Now!

### Single Mode (Scan Current Environment)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run your first audit
python python_security.py

# 3. Open the HTML report
# Check python_security_audit_output/ directory
# Open security_audit_report_[timestamp].html in your browser
```

### Multi-Project Mode (Scan All Projects)
```bash
# 1. Install dependencies (if not already done)
pip install -r requirements.txt

# 2. Run multi-project audit
python python_security.py --multi-project c:\path\to\your\projects

# 3. Open the consolidated HTML report
# Check python_security_audit_output/ directory
# Open multi_project_security_audit_[timestamp].html in your browser
```

**That's it!** You now have a comprehensive security audit with a beautiful HTML report ready for your CISO.

---

**Made with ❤️ for Enterprise Python Security**

*Scan smarter, present better, secure faster. Now with multi-project support!*

**Version 4.0.0** | Enterprise Grade | SonarQube Compliant | Multi-Project Ready
