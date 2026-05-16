"""
Process Monitoring Module for the Endpoint Security Framework.

Monitors running processes for suspicious activity including:
- Processes running from temporary directories
- Processes with no executable path
- Known malicious process names
- Unusual CPU/memory usage
- Process injection indicators
"""

import os
import time
import threading
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import psutil
except ImportError:
    psutil = None

from ..utils.system_utils import (
    get_process_list,
    ProcessInfo,
    kill_process
)
from .logger import (
    ESFLogger,
    AlertSeverity,
    AlertCategory,
    get_logger
)


@dataclass
class ProcessAlert:
    """Alert generated for a suspicious process."""
    timestamp: datetime
    process: ProcessInfo
    alert_type: str
    description: str
    severity: str
    remediation: Optional[str] = None


@dataclass
class ProcessBaseline:
    """Baseline for normal process behavior."""
    process_names: Set[str] = field(default_factory=set)
    average_cpu: Dict[str, float] = field(default_factory=dict)
    average_memory: Dict[str, float] = field(default_factory=dict)
    typical_paths: Set[str] = field(default_factory=set)
    sample_count: int = 0
    last_updated: datetime = field(default_factory=datetime.now)


class ProcessMonitor:
    """
    Monitors system processes for suspicious activity.
    
    Features:
    - Real-time process monitoring
    - Suspicious path detection
    - Known malicious name detection
    - Resource usage anomaly detection
    - Process baseline learning
    - Auto-remediation capabilities
    """
    
    # Known suspicious paths
    DEFAULT_SUSPICIOUS_PATHS = [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/.hidden",
        "/run/user",
        "/var/run"
    ]
    
    # Known malicious process names/patterns
    DEFAULT_MALICIOUS_NAMES = [
        "cryptominer", "xmrig", "minerd", "kworkerds",
        "kdevtmpfsi", "kinsing", "masscan", "sqlmap",
        "aircrack-ng", "ettercap", "wireshark"
    ]
    
    # Legitimate system processes
    DEFAULT_WHITELIST = [
        "sshd", "nginx", "apache2", "mysql", "mariadbd",
        "postgres", "redis-server", "docker", "containerd",
        "snapd", "systemd", "bash", "sh", "python3",
        "node", "java", "cron", "atd", "rsyslogd",
        "journalctl", "agetty", "login"
    ]
    
    def __init__(
        self,
        config: Dict[str, Any],
        logger: Optional[ESFLogger] = None
    ):
        """
        Initialize Process Monitor.
        
        Args:
            config: Process monitor configuration
            logger: Optional logger instance
        """
        self._config = config
        self._logger = logger or get_logger("process_monitor")
        
        # Configuration values
        self._enabled = config.get("enabled", True)
        self._scan_interval = config.get("scan_interval", 30)
        
        # Detection settings
        self._suspicious_paths = set(self.DEFAULT_SUSPICIOUS_PATHS)
        self._malicious_names = set(self.DEFAULT_MALICIOUS_NAMES)
        self._whitelist_processes = set(self.DEFAULT_WHITELIST)
        self._whitelist_users = {"root", "www-data", "mysql", "postgres", "esf", "daemon"}
        self._cpu_threshold = 90
        self._memory_threshold = 80
        
        # Parse config for detection settings
        self._parse_config()
        
        # State tracking
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._alerts: List[ProcessAlert] = []
        self._seen_processes: Dict[int, float] = {}  # PID -> first seen time
        self._high_resource_processes: Dict[int, Dict] = {}  # PID -> resource info
        self._baseline = ProcessBaseline()
        self._callbacks: List[Callable[[ProcessAlert], None]] = []
        
        # Lock for thread safety
        self._lock = threading.RLock()
    
    def _parse_config(self) -> None:
        """Parse configuration settings."""
        # Parse alert_on rules
        for alert_rule in self._config.get("alert_on", []):
            rule_type = alert_rule.get("type")
            
            if rule_type == "suspicious_path":
                self._suspicious_paths.update(alert_rule.get("paths", []))
            
            elif rule_type == "known_malicious_names":
                self._malicious_names.update(alert_rule.get("names", []))
            
            elif rule_type == "unusual_cpu":
                self._cpu_threshold = alert_rule.get("threshold", 90)
            
            elif rule_type == "unusual_memory":
                self._memory_threshold = alert_rule.get("threshold", 80)
        
        # Parse whitelist
        whitelist = self._config.get("whitelist", {})
        self._whitelist_processes.update(whitelist.get("processes", []))
        self._whitelist_users.update(whitelist.get("users", []))
    
    def start(self) -> None:
        """Start the process monitor."""
        if not self._enabled:
            self._logger.warning("Process monitor is disabled in configuration")
            return
        
        if self._running:
            self._logger.warning("Process monitor is already running")
            return
        
        if psutil is None:
            self._logger.error("psutil module not available, process monitoring disabled")
            return
        
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="ProcessMonitor",
            daemon=True
        )
        self._monitor_thread.start()
        self._logger.info("Process monitor started")
    
    def stop(self) -> None:
        """Stop the process monitor."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10)
        self._logger.info("Process monitor stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                self._scan_processes()
                time.sleep(self._scan_interval)
            except Exception as e:
                self._logger.error(f"Error in process monitor loop: {e}")
                time.sleep(5)
    
    def _scan_processes(self) -> List[ProcessAlert]:
        """
        Scan all running processes for suspicious activity.
        
        Returns:
            List of generated alerts
        """
        alerts = []
        processes = get_process_list()
        current_pids = set()
        
        for proc in processes:
            current_pids.add(proc.pid)
            
            # Track new processes
            if proc.pid not in self._seen_processes:
                self._seen_processes[proc.pid] = time.time()
            
            # Skip whitelisted processes
            if self._is_whitelisted(proc):
                continue
            
            # Run all detection checks
            alert = (
                self._check_suspicious_path(proc) or
                self._check_malicious_name(proc) or
                self._check_no_executable(proc) or
                self._check_high_cpu(proc) or
                self._check_high_memory(proc) or
                self._check_suspicious_arguments(proc)
            )
            
            if alert:
                alerts.append(alert)
                with self._lock:
                    self._alerts.append(alert)
                
                # Trigger callbacks
                for callback in self._callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        self._logger.error(f"Callback error: {e}")
        
        # Clean up old PIDs
        with self._lock:
            dead_pids = set(self._seen_processes.keys()) - current_pids
            for pid in dead_pids:
                del self._seen_processes[pid]
                self._high_resource_processes.pop(pid, None)
        
        # Update baseline
        self._update_baseline(processes)
        
        return alerts
    
    def _is_whitelisted(self, proc: ProcessInfo) -> bool:
        """Check if process should be skipped."""
        # Check process name
        if proc.name in self._whitelist_processes:
            return True
        
        # Check user
        if proc.username in self._whitelist_users:
            return True
        
        # Check if kernel thread
        if not proc.exe and proc.pid > 1:
            return True
        
        return False
    
    def _check_suspicious_path(self, proc: ProcessInfo) -> Optional[ProcessAlert]:
        """Check if process is running from a suspicious path."""
        if not proc.exe:
            return None
        
        try:
            exe_path = os.path.realpath(proc.exe)
            
            for suspicious in self._suspicious_paths:
                if exe_path.startswith(suspicious):
                    alert = ProcessAlert(
                        timestamp=datetime.now(),
                        process=proc,
                        alert_type="suspicious_path",
                        description=f"Process '{proc.name}' (PID: {proc.pid}) running from suspicious path: {exe_path}",
                        severity="high",
                        remediation="Investigate the process and kill if malicious. Check for persistence mechanisms."
                    )
                    
                    self._logger.log_alert(
                        AlertSeverity.HIGH,
                        AlertCategory.PROCESS,
                        "Suspicious Process Path",
                        alert.description,
                        "process_monitor",
                        {
                            "pid": proc.pid,
                            "name": proc.name,
                            "exe": proc.exe,
                            "path": exe_path,
                            "user": proc.username
                        },
                        alert.remediation
                    )
                    
                    return alert
        except (OSError, ValueError):
            pass
        
        return None
    
    def _check_malicious_name(self, proc: ProcessInfo) -> Optional[ProcessAlert]:
        """Check if process has a known malicious name."""
        name_lower = proc.name.lower()
        cmdline_str = " ".join(proc.cmdline).lower() if proc.cmdline else ""
        
        for malicious in self._malicious_names:
            if malicious.lower() in name_lower or malicious.lower() in cmdline_str:
                alert = ProcessAlert(
                    timestamp=datetime.now(),
                    process=proc,
                    alert_type="malicious_name",
                    description=f"Process with known malicious name detected: '{proc.name}' (PID: {proc.pid})",
                    severity="critical",
                    remediation="Immediately kill the process and investigate for persistence. Check for rootkits."
                )
                
                self._logger.log_alert(
                    AlertSeverity.CRITICAL,
                    AlertCategory.MALWARE,
                    "Malicious Process Detected",
                    alert.description,
                    "process_monitor",
                    {
                        "pid": proc.pid,
                        "name": proc.name,
                        "cmdline": proc.cmdline,
                        "user": proc.username,
                        "matched_pattern": malicious
                    },
                    alert.remediation
                )
                
                return alert
        
        return None
    
    def _check_no_executable(self, proc: ProcessInfo) -> Optional[ProcessAlert]:
        """Check if process has no associated executable."""
        # Skip kernel threads (PID 2+ with no exe is normal)
        if proc.pid <= 2 or not proc.exe:
            return None
        
        # Some legitimate processes may not have exe accessible
        # Only alert if process is consuming resources
        if proc.cpu_percent > 0 or proc.memory_percent > 0:
            alert = ProcessAlert(
                timestamp=datetime.now(),
                process=proc,
                alert_type="no_executable",
                description=f"Process '{proc.name}' (PID: {proc.pid}) has no accessible executable path but is consuming resources",
                severity="medium",
                remediation="Investigate the process. This could indicate process injection or hiding."
            )
            
            self._logger.log_alert(
                AlertSeverity.MEDIUM,
                AlertCategory.PROCESS,
                "Process Without Executable",
                alert.description,
                "process_monitor",
                {
                    "pid": proc.pid,
                    "name": proc.name,
                    "cpu_percent": proc.cpu_percent,
                    "memory_percent": proc.memory_percent,
                    "user": proc.username
                },
                alert.remediation
            )
            
            return alert
        
        return None
    
    def _check_high_cpu(self, proc: ProcessInfo) -> Optional[ProcessAlert]:
        """Check for abnormally high CPU usage."""
        if proc.cpu_percent < self._cpu_threshold:
            self._high_resource_processes.pop(proc.pid, None)
            return None
        
        # Track high CPU usage over time
        now = time.time()
        if proc.pid not in self._high_resource_processes:
            self._high_resource_processes[proc.pid] = {
                "start_time": now,
                "max_cpu": proc.cpu_percent,
                "samples": 1
            }
        else:
            info = self._high_resource_processes[proc.pid]
            info["max_cpu"] = max(info["max_cpu"], proc.cpu_percent)
            info["samples"] += 1
        
        # Alert after sustained high CPU (3+ samples)
        info = self._high_resource_processes[proc.pid]
        if info["samples"] >= 3:
            duration = now - info["start_time"]
            
            alert = ProcessAlert(
                timestamp=datetime.now(),
                process=proc,
                alert_type="high_cpu",
                description=f"Process '{proc.name}' (PID: {proc.pid}) sustained high CPU usage: {proc.cpu_percent:.1f}% for {duration:.0f}s",
                severity="medium",
                remediation="Investigate if this is expected behavior. Could indicate cryptomining or processing loop."
            )
            
            self._logger.log_alert(
                AlertSeverity.MEDIUM,
                AlertCategory.PROCESS,
                "High CPU Usage Detected",
                alert.description,
                "process_monitor",
                {
                    "pid": proc.pid,
                    "name": proc.name,
                    "cpu_percent": proc.cpu_percent,
                    "duration_seconds": duration,
                    "samples": info["samples"],
                    "user": proc.username
                },
                alert.remediation
            )
            
            # Reset to avoid repeated alerts
            self._high_resource_processes[proc.pid] = {
                "start_time": now,
                "max_cpu": proc.cpu_percent,
                "samples": 0
            }
            
            return alert
        
        return None
    
    def _check_high_memory(self, proc: ProcessInfo) -> Optional[ProcessAlert]:
        """Check for abnormally high memory usage."""
        if proc.memory_percent < self._memory_threshold:
            return None
        
        alert = ProcessAlert(
            timestamp=datetime.now(),
            process=proc,
            alert_type="high_memory",
            description=f"Process '{proc.name}' (PID: {proc.pid}) high memory usage: {proc.memory_percent:.1f}%",
            severity="medium",
            remediation="Investigate for memory leaks or malicious memory consumption."
        )
        
        self._logger.log_alert(
            AlertSeverity.MEDIUM,
            AlertCategory.PROCESS,
            "High Memory Usage Detected",
            alert.description,
            "process_monitor",
            {
                "pid": proc.pid,
                "name": proc.name,
                "memory_percent": proc.memory_percent,
                "user": proc.username
            },
            alert.remediation
        )
        
        return alert
    
    def _check_suspicious_arguments(self, proc: ProcessInfo) -> Optional[ProcessAlert]:
        """Check for suspicious command-line arguments."""
        if not proc.cmdline:
            return None
        
        cmdline_str = " ".join(proc.cmdline).lower()
        
        # Suspicious patterns
        suspicious_patterns = [
            ("reverse shell", ["bash -i", "/dev/tcp", "nc -e", "mkfifo", "sh -i"]),
            ("encoded command", ["base64 -d", "eval", "python -c"]),
            ("network scanning", ["-p-", "--masscan", "nmap -sS"]),
            ("credential dumping", ["mimikatz", "pwdump", "shadowcopy"]),
            ("privilege escalation", ["chmod 4777", "chmod u+s", "setuid"]),
        ]
        
        for alert_name, patterns in suspicious_patterns:
            for pattern in patterns:
                if pattern.lower() in cmdline_str:
                    alert = ProcessAlert(
                        timestamp=datetime.now(),
                        process=proc,
                        alert_type="suspicious_arguments",
                        description=f"Process '{proc.name}' (PID: {proc.pid}) with suspicious arguments: {alert_name}",
                        severity="high",
                        remediation=f"Immediately investigate and terminate if malicious. Possible {alert_name} attempt."
                    )
                    
                    self._logger.log_alert(
                        AlertSeverity.HIGH,
                        AlertCategory.PROCESS,
                        f"Suspicious Arguments: {alert_name}",
                        alert.description,
                        "process_monitor",
                        {
                            "pid": proc.pid,
                            "name": proc.name,
                            "cmdline": proc.cmdline,
                            "matched_pattern": pattern,
                            "user": proc.username
                        },
                        alert.remediation
                    )
                    
                    return alert
        
        return None
    
    def _update_baseline(self, processes: List[ProcessInfo]) -> None:
        """Update process behavior baseline."""
        with self._lock:
            for proc in processes:
                if self._is_whitelisted(proc):
                    self._baseline.process_names.add(proc.name)
                    if proc.exe:
                        self._baseline.typical_paths.add(os.path.dirname(proc.exe))
                    
                    name = proc.name
                    if name not in self._baseline.average_cpu:
                        self._baseline.average_cpu[name] = []
                        self._baseline.average_memory[name] = []
                    
                    self._baseline.average_cpu[name].append(proc.cpu_percent)
                    self._baseline.average_memory[name].append(proc.memory_percent)
                    
                    # Keep only last 100 samples
                    if len(self._baseline.average_cpu[name]) > 100:
                        self._baseline.average_cpu[name] = self._baseline.average_cpu[name][-100:]
                    if len(self._baseline.average_memory[name]) > 100:
                        self._baseline.average_memory[name] = self._baseline.average_memory[name][-100:]
            
            self._baseline.sample_count += 1
            if self._baseline.sample_count % 100 == 0:
                self._baseline.last_updated = datetime.now()
    
    def add_alert_callback(self, callback: Callable[[ProcessAlert], None]) -> None:
        """Add a callback to be called when an alert is generated."""
        self._callbacks.append(callback)
    
    def get_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[ProcessAlert]:
        """Get stored alerts with optional filtering."""
        with self._lock:
            alerts = self._alerts.copy()
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return alerts[-limit:]
    
    def get_baseline_stats(self) -> Dict[str, Any]:
        """Get baseline statistics."""
        with self._lock:
            stats = {
                "sample_count": self._baseline.sample_count,
                "last_updated": self._baseline.last_updated.isoformat(),
                "unique_processes": len(self._baseline.process_names),
                "typical_paths": list(self._baseline.typical_paths)[:20]
            }
            
            # Calculate averages
            avg_cpu = {}
            avg_memory = {}
            for name, samples in self._baseline.average_cpu.items():
                if samples:
                    avg_cpu[name] = sum(samples) / len(samples)
            for name, samples in self._baseline.average_memory.items():
                if samples:
                    avg_memory[name] = sum(samples) / len(samples)
            
            stats["average_cpu"] = avg_cpu
            stats["average_memory"] = avg_memory
            
            return stats
    
    def scan_once(self) -> List[ProcessAlert]:
        """Perform a single scan and return alerts."""
        return self._scan_processes()
    
    def get_process_summary(self) -> Dict[str, Any]:
        """Get a summary of current processes."""
        processes = get_process_list()
        
        summary = {
            "total_processes": len(processes),
            "by_user": defaultdict(int),
            "total_cpu": 0.0,
            "total_memory": 0.0,
            "top_cpu": [],
            "top_memory": []
        }
        
        for proc in processes:
            summary["by_user"][proc.username] += 1
            summary["total_cpu"] += proc.cpu_percent
            summary["total_memory"] += proc.memory_percent
        
        # Get top processes by CPU
        sorted_by_cpu = sorted(processes, key=lambda p: p.cpu_percent, reverse=True)
        summary["top_cpu"] = [
            {"pid": p.pid, "name": p.name, "cpu": p.cpu_percent}
            for p in sorted_by_cpu[:10]
        ]
        
        # Get top processes by memory
        sorted_by_memory = sorted(processes, key=lambda p: p.memory_percent, reverse=True)
        summary["top_memory"] = [
            {"pid": p.pid, "name": p.name, "memory": p.memory_percent}
            for p in sorted_by_memory[:10]
        ]
        
        summary["by_user"] = dict(summary["by_user"])
        
        return summary
