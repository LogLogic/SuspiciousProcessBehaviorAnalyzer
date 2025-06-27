# Suspicious Process & Behavior Analyzer

A Python script to analyze Sysmon-style process logs for suspicious behavior such as encoded PowerShell usage, suspicious parent-child process chains, execution from untrusted locations, and network-related command execution.

---
## Features

- **Process Tree Construction**: Reconstructs process hierarchies using Process ID (PID) and Parent Process ID (PPID).  
- **Encoded PowerShell Detection**: Flags PowerShell executions with encoded commands (e.g., `-enc`, `-EncodedCommand`).  
- **Suspicious Parent-Child Chains**: Detects known attack chains like `explorer.exe → cmd.exe → powershell.exe → rundll32.exe`.  
- **Risky Execution Paths**: Identifies processes running from locations like `AppData`, `Temp`, `Downloads`, and `Roaming`.  
- **Suspicious Network Commands**: Detects network activity via tools like `invoke-webrequest`, `curl`, `wget`, `bitsadmin`, and `certutil`.  
- **Alert Reporting**: Generates a clear, readable alert summary and saves to `detection_report.txt`.  
- **Command-Line Friendly**: Accepts input/output paths and optional flags for verbosity or skipping reports.  
- **Modular & Extensible**: Clean, structured codebase ready for advanced rules and integration.

---
## Requirements

- Python 3.x installed  
- JSON-formatted Sysmon-style process log file (sample provided)

---
## Setup

1. Clone or download this repository  
2. Place your Sysmon-style JSON log file as:  
   sample_logs/sample_sysmon.json

---
### Running the Script

In your terminal or command prompt, navigate to the project folder and run:

python3 process_tree.py

The script will:

Parse the log file

Build the process tree

Analyze for suspicious behavior

Print results in the terminal

Save alerts to detection_report.txt
