# AWMFA - Automated Windows Memory Forensics Analysis

<div align="center">

[![Python](https://img.shields.io/badge/Python-2.7-blue.svg)](https://www.python.org/downloads/)
[![Volatility](https://img.shields.io/badge/Volatility-2.6+-green.svg)](https://github.com/volatilityfoundation/volatility)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

</div>

## Overview

AWMFA (Automated Windows Memory Forensics Analysis) is a Python-based automation framework designed to streamline Windows memory dump analysis using the Volatility Framework. The tool reduces analysis time significantly by automating plugin execution and providing intelligent threat detection without requiring deep Windows internals knowledge.

### Core Capabilities

- Automated execution of multiple Volatility plugins with configurable threading
- Significantly faster analysis compared to manual Volatility usage
- Heuristic-based detection of suspicious processes and system artifacts
- No deep Windows internals knowledge required - automated detection rules
- Multi-format report generation (TXT, HTML, PDF)
- Optional integration with VTScanX API for hash-based malware identification
- Customizable detection rules and process behavior baselines

### Key Benefits

- **Time Reduction:** Automated parallel plugin execution saves hours of manual analysis
- **Ease of Use:** No need for deep Windows internals expertise
- **Comprehensive Coverage:** 14 plugins executed automatically with single command
- **Smart Detection:** Heuristic scoring system identifies threats automatically

### Target Audience

- Digital forensics investigators
- Incident response teams
- Security operations centers
- Malware analysts
- Law enforcement agencies

---

## Detection Capabilities

### Process Analysis
- Typosquatting detection
- Parent-child relationship validation
- Instance count anomalies
- Execution path verification
- Hidden process detection (pslist vs psscan comparison)

### Code Injection Detection
- DLL injection patterns via load order analysis
- Process hollowing
- Missing DLL entries in PEB structures
- RWX memory regions via malfind plugin

### System-Level Analysis
- SSDT hook detection
- Suspicious kernel modules
- Network connections
- Handle analysis for suspicious objects

### Command Line Analysis
- PowerShell obfuscation patterns
- Base64 encoded payloads
- Suspicious tool usage

---

## Installation

### Prerequisites
- Python 2.7
- Volatility Framework 2.6 or higher
- Memory dump files (.vmem, .raw, .dmp, .mem)

### Installation Steps

#### Step 1: Install Volatility Framework

```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python2.7 vol.py --info
```

Verify that Volatility is properly installed and accessible.

#### Step 2: Clone AWMFA Repository

```bash
git clone https://github.com/yourusername/Windows-Memory-Forensics-Automation.git
```

#### Step 3: Place AWMFA Files in Volatility Directory

Copy all AWMFA files into your Volatility installation directory:

```bash
# Linux/Mac
cp -r Windows-Memory-Forensics-Automation/* /path/to/volatility/

# Windows
xcopy /E /I Windows-Memory-Forensics-Automation\* C:\path\to\volatility\
```

**Required files to copy:**
- `automate.py` (main script)
- `config.py` (configuration file)
- `DNH_Verify.py` (DLL, Network, Handles verification)
- `NPIP_Verify.py` (Name, Parent, Instance, Path verification)
- `requirements.txt` (dependencies)
- `template.html` (HTML report template)

#### Step 4: Install Python Dependencies

```bash
cd /path/to/volatility
pip install -r requirements.txt
```

#### Step 5: Configure VTScanX API (Optional)

Edit `config.py` to add your VTScanX API key:

```python
VTSCANX_API_KEY = "your_api_key_here"
VT_SCAN_THRESHOLD = 10
```

Register for an API key at: https://github.com/abhishek-kadavala1/VTScanX. VTScanX is a Python-based tool which scans malware samples while bypassing API limitations.

---

## Usage

### Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `-f`, `--file` | Memory dump file (required) |
| `-p`, `--profile` | Volatility profile (auto-detected if omitted) |
| `--scan-procdump` | Dump and scan all processes |
| `--scan-dlldump` | Dump and scan all DLLs |
| `--scan-suspicious-proc` | Scan only flagged processes |
| `--scan-suspicious-dll` | Scan DLLs from flagged processes |
| `--generate-txt` | Generate plain text report |
| `--generate-html` | Generate HTML report |
| `--generate-pdf` | Generate PDF report |
| `--report-name` | Report filename (no extension) |
| `--report-dir` | Report output directory |
| `--include-plugins` | Add specific plugins to report |
| `--all-include-plugins` | Include all Volatility output |

### Basic Commands

```bash
# Basic analysis (auto-detect profile)
python2.7 automate.py -f memory.dmp

# Specify profile manually
python2.7 automate.py -f memory.dmp -p Win10x64_19041

# Generate HTML report
python2.7 automate.py -f memory.dmp --generate-html

# Generate PDF report
python2.7 automate.py -f memory.dmp --generate-pdf
```

### Advanced Options

```bash
# Scan all processes with VirusTotal
python2.7 automate.py -f memory.dmp --scan-procdump --generate-html

# Scan only suspicious processes (recommended)
python2.7 automate.py -f memory.dmp --scan-suspicious-proc --generate-html

# Scan suspicious DLLs
python2.7 automate.py -f memory.dmp --scan-suspicious-dll --generate-html

# Custom report name and location
python2.7 automate.py -f memory.dmp \
    --generate-html \
    --report-name case_001 \
    --report-dir ./reports/

# Include additional plugins
python2.7 automate.py -f memory.dmp \
    --generate-html \
    --include-plugins shimcache userassist
```

---

## Technical Architecture

### Analysis Workflow

1. **Profile Detection Phase**
   - Executes Volatility `imageinfo` plugin to identify compatible memory profiles
   - Supports manual profile specification via command-line argument
   - Validates profile compatibility with memory dump format

2. **Plugin Execution Phase**
   - Parallel execution of 14 core Volatility plugins using threading:
     - Process enumeration: pslist, pstree, psscan, psxview
     - Process details: cmdline, hollowfind, handles
     - DLL analysis: dlllist, ldrmodules
     - Network analysis: netscan (version-dependent)
     - Kernel analysis: ssdt, modules, modscan
     - Code injection: malfind
   - Output captured and parsed into structured data format

3. **Data Analysis Phase**
   - Plugin output parsed into pandas DataFrame structures
   - Cross-reference analysis between multiple plugin outputs
   - Application of detection heuristics and scoring algorithms

4. **Threat Detection Phase**
   - Process name validation and typosquatting detection
   - Parent-child relationship verification
   - Execution path validation against known-good baselines
   - DLL injection pattern recognition
   - Hidden artifact identification

5. **VirusTotal Integration Phase** (Optional)
   - Process and DLL memory dumping for suspicious entities
   - SHA256 hash calculation
   - VTScanX API queries with local result caching
   - Threshold-based flagging system

6. **Report Generation Phase**
   - Console output with color-coded severity indicators
   - Text report generation for documentation
   - HTML report generation with tabular data presentation
   - PDF report generation with formatted layouts

### Detection Scoring Methodology

| Detection Category | Severity Score | Description |
|-------------------|---------------|-------------|
| DLLInjected | 10 | DLL loaded before ntdll.dll in load order |
| IncorrectParent | 10 | Process parent does not match expected value |
| Svchost_K | 10 | svchost.exe without -k parameter |
| HollowedProcess | 9 | PEB path differs from VAD path (process hollowing) |
| RWX_MemoryPermissions | 8 | Memory region with write and execute permissions |
| PathMismatch | 8 | Process execution path differs from expected location |
| ProcessNameSimilar | 7 | Process name similar to legitimate system process |
| HiddenProcess | 6 | Process not visible in standard process list |
| SuspiciousCommandPattern | 5 | Command line contains malicious patterns |
| Base64Detected | 2 | Base64-encoded content in command line |

---

## Configuration

### Basic Configuration

Configuration settings are defined in `config.py`:

```python
# VTScanX API Configuration
VTSCANX_API_KEY = "your_api_key"
VT_SCAN_THRESHOLD = 10

# Detection Priority Scoring
CATEGORY_PRIORITIES = {
    "DLLInjected": 10,
    "IncorrectParent": 10,
    # Additional categories defined in config.py
}

# Suspicious Path Definitions
SUSPICIOUS_PATHS = [
    "C:\\Users\\",
    "C:\\Temp\\",
    # Additional paths can be added
]
```

### Custom Process Behavior Rules

Define expected process behavior patterns in `config.py`:

```python
windows_processes = {
    "myapp.exe": {
        "parent": ["services.exe"],
        "children": [],
        "can_be_orphan": False,
        "instances": 1,
        "path": r"C:\Program Files\MyApp\myapp.exe"
    }
}
```

Configuration parameters:
- `parent`: List of valid parent process names
- `children`: List of expected child process names
- `can_be_orphan`: Boolean indicating if process can exist without parent
- `instances`: Expected instance count (-1 for unlimited)
- `path`: Full file system path to executable

---

## Output Examples

### Console Output Format

```
================================================================================
                     Suspicious Process Summary
================================================================================
| No. | Process Name              | PID        | Suspicious Score |
--------------------------------------------------------------------------------
| 1   | taskh0st.exe              | 1892       | 87               |
| 2   | svch0st.exe               | 2456       | 45               |
================================================================================

Process Name: taskh0st.exe [Hidden]
PID: 1892
Reasons:
     - score: 67, Popular Threat Category: trojan
     - ProcessNameSimilar: Looks similar to 'taskhost.exe'
     - PathMismatch: expected c:\windows\system32\taskhost.exe but found c:\users\public\taskh0st.exe
     - Injected DLLs detected before expected order:
        c:\users\public\evil.dll
     - Invalid memory protection: PAGE_EXECUTE_READWRITE
--------------------------------------------------

[+] SSDT Hooking Report
Function Name: NtCreateFile
Address: 0xF8A00120
Hooked By: rootkit.sys
--------------------------------------------------
```

### Report Formats

**HTML Report Contents:**
- Summary table of suspicious processes with risk scores
- Detailed findings for each flagged process
- SSDT hook detection results
- Suspicious kernel module listings
- Network connection analysis
- Optional inclusion of raw Volatility plugin output

**PDF Report Contents:**
- Executive summary with file metadata and hash values
- Risk distribution analysis
- Detailed process-level findings
- System artifact analysis
- Formatted tables and structured layout

---

## License

MIT License - Free for personal and commercial use with attribution.

---

## Contact

### Developers

**Abhishek Kadavala**  
LinkedIn: [linkedin.com/in/abhishek-kadaval](https://www.linkedin.com/in/abhishek-kadaval)

**Bhavik Shah**  
LinkedIn: [linkedin.com/in/bhavik-shah](https://www.linkedin.com/in/bhavikshah04/)

For questions, bug reports, or feature requests, please open an issue on GitHub.

---

**AWMFA - Automated Windows Memory Forensics Analysis**

