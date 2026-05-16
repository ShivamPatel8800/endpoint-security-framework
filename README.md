<div align="center">

```
███████╗███████╗███████╗
██╔════╝██╔════╝██╔════╝
█████╗  ███████╗█████╗  
██╔══╝  ╚════██║██╔══╝  
███████╗███████║██║     
╚══════╝╚══════╝╚═╝     
```

# 🛡️ Endpoint Security Hardening Framework

**A proactive, anomaly-based EDR CLI for Linux Servers**

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Bash](https://img.shields.io/badge/Bash-Script-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/Debian-Based-A81D33?style=for-the-badge&logo=debian&logoColor=white)](https://debian.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Ubuntu%20%7C%20Kali-222222?style=for-the-badge&logo=linux&logoColor=white)](https://kernel.org)

</div>

---

## 📖 Overview

The **Endpoint Security Hardening Framework** is a proactive security monitoring and threat response tool designed specifically for **Debian-based Linux environments**. Moving beyond traditional signature-based detection, this framework utilizes **behavioral analysis**, **cryptographic file hashing**, and **statistical anomaly detection** to identify zero-day exploits, unauthorized modifications, and sophisticated persistent threats.

Built with a modular, multi-threaded Python architecture, it automates the early detection and safe remediation of suspicious activities — functioning as a **lightweight, open-source alternative to commercial EDR agents**.

---

## ✨ Key Features

| Feature | Description |
|--------|-------------|
| 🔮 **Anomaly-Based Detection** | Sliding time windows establish behavioral baselines for logins, network traffic, and process spawning — alerts fire on statistical deviations |
| 🔐 **Cryptographic File Integrity (FIM)** | SHA-256 monitoring of `/etc`, `/usr/bin`, `/boot` — detects unauthorized edits, permission changes, and hidden file creation |
| 🕵️ **Advanced Process Monitoring** | Identifies binaries in `/tmp`, `/dev/shm`, known malicious naming patterns (cryptominers, pentest tools), and reverse shell indicators |
| 🚨 **Automated Threat Remediation** | Queue-based engine that kills processes, quarantines files, and blocks IPs via `iptables` |
| 🛠️ **Service Hardening Auditor** | Scans SSH `sshd_config`, cron permissions, and other configs against security best practices |
| ⚙️ **Native Linux Integration** | Leverages `auditd`, `systemd`, `dpkg`; includes full systemd daemon and timer setup for persistent monitoring |

---

## 🏗️ System Architecture

```
endpoint-security-framework/
│
├── setup.sh                        # Master installer (dependencies, systemd, auditd)
├── config/
│   └── config.yaml                 # Centralized configuration engine
│
├── src/
│   ├── cli.py                      # Interactive CLI interface (Click framework)
│   ├── main.py                     # Core Orchestrator & threading manager
│   │
│   ├── core/
│   │   ├── process_monitor.py      # Real-time process anomaly detection
│   │   ├── file_integrity.py       # SHA-256 FIM & baseline manager
│   │   ├── anomaly_detector.py     # Behavioral analysis & sliding windows
│   │   ├── threat_remediator.py    # Automated response & quarantine engine
│   │   └── logger.py               # Structured JSON logging & alerting
│   │
│   ├── modules/
│   │   ├── network_monitor.py      # Port & connection tracking
│   │   ├── user_monitor.py         # UID 0 checks & SSH key auditing
│   │   └── service_hardener.py     # SSH/Cron security posture checks
│   │
│   └── utils/
│       ├── system_utils.py         # OS-level wrappers (psutil, subprocess)
│       └── config_loader.py        # YAML parser & dataclass hydrator
│
└── scripts/
    └── baseline_creator.sh
```

---

## 🚀 Installation

> ⚠️ **Requirements:** Debian-based distribution (Ubuntu, Debian, Kali Linux) and **root privileges**.

```bash
# 1. Clone the repository
git clone https://github.com/ShivamPatel8800/endpoint-security-framework.git
cd endpoint-security-framework

# 2. Run the automated installer
chmod +x setup.sh
sudo ./setup.sh
```

The installer automatically handles:
- ✅ Python virtual environment creation
- ✅ System package installation (`auditd`, `clamav`, `aide`)
- ✅ `systemd` daemon setup
- ✅ User isolation & secure directory provisioning

---

## 📋 Usage & Commands

> All CLI commands require `sudo` due to the necessity of reading protected system files and managing processes.

### 1. 🗂️ Initialize the Environment

Establish a cryptographic baseline of your filesystem before monitoring begins.

```bash
sudo esf baseline create
# Output: Baseline created: 39,603 files in 10 directories
```

### 2. 🔍 Run a Full Security Scan

Execute a single pass of all detection modules (Process, FIM, Hardening, Users).

```bash
sudo esf scan
```

### 3. 📊 View System Status

Display OS information, baseline status, and the most recent high-severity alerts.

```bash
sudo esf status
```

### 4. 🔄 Continuous Daemon Mode

Spawn multi-threaded background processes for real-time monitoring.

```bash
sudo esf monitor --continuous
# Press Ctrl+C to gracefully shutdown and save states
```

### 5. ✅ Verify File Integrity

Check the current filesystem state against the saved baseline.

```bash
# Verify entire system
sudo esf baseline verify

# Verify a specific suspicious file
sudo esf baseline verify --file /usr/bin/ls
```

### 6. ⚡ Threat Management

View triggered alerts and the history of automated remediation actions.

```bash
sudo esf threats
```

---

## 🔍 Detection Capabilities

| Category | Detection Technique | Example Trigger |
|----------|--------------------|--------------------|
| 🗂️ **File System** | SHA-256 Hash Comparison | Unauthorized modification to `/etc/passwd` or `/usr/bin/ssh` |
| 🔁 **Process** | Path & Argument Parsing | Binaries executing from `/tmp` or `bash` reverse-shell patterns (`/dev/tcp`) |
| 💻 **Process** | Resource Anomaly | Sustained 90%+ CPU for >3 intervals — cryptomining indicator |
| 🔑 **Authentication** | Sliding Window Counter | >5 failed SSH logins from a single IP within 300 seconds (brute-force) |
| 🌐 **Network** | Port & Flow Analysis | Established connection to known C2 ports (`4444`, `31337`) |
| 👤 **Privilege** | User & File Auditing | Non-root user created with UID 0, or hidden files in `sudoers.d` |
| ⚙️ **Configuration** | Regex Policy Checking | SSH `PermitRootLogin` set to `yes` |

---

## ⚙️ Configuration

The framework is highly tunable via `/etc/esf/config.yaml`.

```yaml
# Example config.yaml options

monitoring:
  scan_interval: 30          # FIM polling interval (seconds)
  process_poll_rate: 5       # Process monitor poll rate

thresholds:
  cpu_limit: 90              # % CPU before alerting
  max_failed_logins: 5       # Failed logins before brute-force alert
  login_window_seconds: 300  # Sliding window for login tracking

exclusions:
  directories:
    - /var/log/*
  trusted_processes:
    - /usr/bin/python3

remediation:
  auto_remediate: false      # ⚠️ Set true to enable automated response
```

**Tunable parameters:**
- **Scan Intervals** — How often FIM and Process monitors poll the system
- **Thresholds** — CPU/memory limits, failed login caps, connection limits
- **Exclusions** — Directories to ignore or trusted processes/users to whitelist
- **Auto-Remediation** — Toggle automatic kill/quarantine without confirmation *(use with caution)*

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Python 3.13, Bash |
| **Core Libraries** | `psutil` · `click` · `PyYAML` · `watchdog` |
| **System Integration** | `systemd` · `auditd` · `iptables` · `aide` · `clamav` |
| **Data Storage** | SQLite / JSON (local baselining) |

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Built with 🐍 by [**Shivam Patel**](https://github.com/ShivamPatel8800)

*Protecting Linux, one baseline at a time.*

</div>
