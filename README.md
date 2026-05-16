PythonBashLinuxLicense

🛡️ Endpoint Security Hardening Framework
A proactive, anomaly-based EDR CLI for Linux Servers
📖 Overview
The Endpoint Security Hardening Framework is a proactive security monitoring and threat response tool designed specifically for Debian-based Linux environments. Moving beyond traditional signature-based detection, this framework utilizes behavioral analysis, cryptographic file hashing, and statistical anomaly detection to identify zero-day exploits, unauthorized modifications, and sophisticated persistent threats.

Built with a modular, multi-threaded Python architecture, it automates the early detection and safe remediation of suspicious activities—functioning as a lightweight, open-source alternative to commercial Endpoint Detection and Response (EDR) agents.

✨ Key Features
🔮 Anomaly-Based Detection: Uses sliding time windows to establish baselines for user logins, network traffic, and process spawning, alerting on statistical deviations.
🔐 Cryptographic File Integrity (FIM): Monitors critical system directories (/etc, /usr/bin, /boot) using SHA-256 hashing to detect unauthorized modifications, permission changes, or hidden file creation.
🕵️ Advanced Process Monitoring: Actively identifies processes executing from suspicious directories (/tmp, /dev/shm), known malicious naming patterns (cryptominers, penetration tools), and reverse shell indicators.
🚨 Automated Threat Remediation: Features a safe, queue-based remediation engine capable of automatically killing processes, quarantining malicious files, and blocking IP addresses via iptables.
🛠️ Service Hardening Auditor: Scans system configurations (e.g., SSH sshd_config, cron permissions) against security best practices and reports non-compliance.
⚙️ Native Linux Integration: Leverages native Debian utilities (auditd, systemd, dpkg) and includes a comprehensive systemd service and timer setup for persistent daemon monitoring.
🏗️ System Architecture
The framework is built using a decoupled, modular architecture to ensure high performance and easy extensibility:

endpoint-security-framework/├── setup.sh                # Master installer (dependencies, systemd, auditd)├── config/│   └── config.yaml         # Centralized configuration engine├── src/│   ├── cli.py              # Interactive CLI interface (Click framework)│   ├── main.py             # Core Orchestrator & threading manager│   ├── core/│   │   ├── process_monitor.py      # Real-time process anomaly detection│   │   ├── file_integrity.py       # SHA-256 FIM & baseline manager│   │   ├── anomaly_detector.py     # Behavioral analysis & sliding windows│   │   ├── threat_remediator.py    # Automated response & quarantine engine│   │   └── logger.py               # Structured JSON logging & alerting│   ├── modules/│   │   ├── network_monitor.py      # Port & connection tracking│   │   ├── user_monitor.py         # UID 0 checks & SSH key auditing│   │   └── service_hardener.py     # SSH/Cron security posture checks│   └── utils/│       ├── system_utils.py         # OS-level wrappers (psutil, subprocess)│       └── config_loader.py        # YAML parser & dataclass hydrator└── scripts/    └── baseline_creator.sh
🚀 Installation
Requires a Debian-based distribution (Ubuntu, Debian, Kali Linux) and root privileges.

bash

# 1. Clone the repository
git clone https://github.com/ShivamPatel8800/endpoint-security-framework.git
cd endpoint-security-framework

# 2. Run the automated installer
chmod +x setup.sh
sudo ./setup.sh
The installer automatically handles: Python venv creation, system package installation (auditd, clamav, aide), systemd daemon setup, user isolation, and secure directory provisioning.

📋 Usage & Commands
All CLI commands require sudo due to the necessity of reading protected system files and managing processes.

1. Initialize the Environment
Before monitoring can begin, the framework must establish a cryptographic baseline of your filesystem.

bash

sudo esf baseline create
# Output: Baseline created: 39,603 files in 10 directories
2. Run a Full Security Scan
Executes a single pass of all detection modules (Process, FIM, Hardening, Users).

bash

sudo esf scan
3. View System Status
Displays OS information, baseline status, and the most recent high-severity alerts.

bash

sudo esf status
4. Continuous Daemon Mode
Spawns multi-threaded background processes to monitor the system in real-time.

bash

sudo esf monitor --continuous
# (Press Ctrl+C to gracefully shutdown and save states)
5. Verify File Integrity
Checks the current state of the filesystem against the saved baseline.

bash

# Verify entire system
sudo esf baseline verify

# Verify a specific suspicious file
sudo esf baseline verify --file /usr/bin/ls
6. Threat Management
View triggered alerts and the history of automated remediation actions taken by the framework.

bash

sudo esf threats
🔍 Detection Capabilities Deep-Dive
Category
Detection Technique
Example Trigger
File System	SHA-256 Hash Comparison	Unauthorized modification to /etc/passwd or /usr/bin/ssh
Process	Path & Argument Parsing	Executing binaries from /tmp or bash reverse-shell patterns (/dev/tcp)
Process	Resource Anomaly	Sustained 90%+ CPU usage for >3 sampling intervals (Cryptomining)
Authentication	Sliding Window Counter	>5 failed SSH logins from a single IP within 300 seconds (Brute-force)
Network	Port & Flow Analysis	Established connection to known C2 ports (4444, 31337)
Privilege	User & File Auditing	Creation of non-root user with UID 0, or hidden files in sudoers.d
Configuration	Regex Policy Checking	SSH PermitRootLogin set to yes

⚙️ Configuration
The framework is highly tunable via /etc/esf/config.yaml.

You can modify:

Scan Intervals: Adjust how often the FIM and Process monitors poll the system.
Thresholds: Change CPU/Memory limits, max failed login attempts, and connection limits.
Exclusions: Add directories to ignore (e.g., /var/log/*) or whitelist trusted processes/users.
Auto-Remediation: Toggle auto_remediate: true in the remediation block to allow the system to automatically kill processes or quarantine files without manual confirmation (Use with caution).
🛠️ Tech Stack
Language: Python 3.13, Bash
Core Libraries: psutil (System metrics), click (CLI parsing), PyYAML (Config), watchdog (FS events)
System Integration: systemd, auditd, iptables, aide, clamav
Data Storage: Local SQLite / JSON files for baselining
📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

<div align="center">
Built with 🐍 by <a href="https://github.com/ShivamPatel8800">Shivam Patel</a>
</div>
```
