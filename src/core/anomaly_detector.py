"""
Anomaly Detection Module for the Endpoint Security Framework.

Implements statistical and rule-based anomaly detection for:
- Login behavior
- Network activity
- File system activity
- Process behavior
- Privilege escalation
"""

import os
import time
import threading
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics

from ..utils.system_utils import (
    get_network_connections,
    ConnectionInfo,
    get_user_list,
    UserInfo,
    run_command
)
from .logger import (
    ESFLogger,
    AlertSeverity,
    AlertCategory,
    get_logger
)


@dataclass
class AnomalyEvent:
    """Represents a detected anomaly."""
    timestamp: datetime
    anomaly_type: str
    severity: str
    description: str
    details: Dict[str, Any]
    remediation: Optional[str] = None


@dataclass
class LoginEvent:
    """Represents a login event."""
    timestamp: datetime
    username: str
    ip_address: str
    success: bool
    service: str


@dataclass
class NetworkEvent:
    """Represents a network connection event."""
    timestamp: datetime
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    pid: int
    process_name: str


class SlidingWindow:
    """Sliding window for tracking events over time."""
    
    def __init__(self, duration_seconds: int, max_size: int = 10000):
        self._duration = duration_seconds
        self._max_size = max_size
        self._events: deque = deque(maxlen=max_size)
    
    def add(self, event: Any) -> None:
        """Add an event to the window."""
        self._events.append((time.time(), event))
    
    def get_events(self) -> List[Any]:
        """Get events within the time window."""
        cutoff = time.time() - self._duration
        return [e for t, e in self._events if t >= cutoff]
    
    def count(self) -> int:
        """Count events in the window."""
        return len(self.get_events())
    
    def clear(self) -> None:
        """Clear all events."""
        self._events.clear()


class AnomalyDetector:
    """
    Detects anomalous behavior using statistical analysis and rules.
    
    Features:
    - Login anomaly detection (brute force, unusual times)
    - Network anomaly detection (unusual ports, connection floods)
    - File system anomaly detection (mass file operations)
    - Process anomaly detection (fork bombs, unusual processes)
    - Privilege escalation detection
    - Configurable thresholds and learning mode
    """
    
    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 6667, 7777, 8888, 9999,
        31337, 12345, 1337, 4443, 5554, 6668,
        1234, 2345, 3456, 4567, 5678, 6789
    }
    
    def __init__(
        self,
        config: Dict[str, Any],
        logger: Optional[ESFLogger] = None
    ):
        """
        Initialize Anomaly Detector.
        
        Args:
            config: Anomaly detection configuration
            logger: Optional logger instance
        """
        self._config = config
        self._logger = logger or get_logger("anomaly_detector")
        
        # Configuration
        self._enabled = config.get("enabled", True)
        self._learning_period = config.get("learning_period", 86400)
        self._start_time = time.time()
        
        # Detection methods configuration
        self._detection_methods = {}
        for method in config.get("detection_methods", []):
            if method.get("enabled", True):
                self._detection_methods[method["name"]] = method.get("parameters", {})
        
        # Login tracking
        self._failed_logins = SlidingWindow(300)  # 5 minute window
        self._login_events: List[LoginEvent] = []
        self._login_baseline: Dict[str, List[int]] = defaultdict(list)  # username -> hour of day
        
        # Network tracking
        self._connection_events = SlidingWindow(60)
        self._outbound_connections = SlidingWindow(60)
        self._port_connections: Dict[int, int] = defaultdict(int)
        self._network_baseline: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        
        # File tracking
        self._file_creations = SlidingWindow(60)
        self._file_modifications = SlidingWindow(60)
        self._hidden_files_created = SlidingWindow(60)
        
        # Process tracking
        self._new_processes = SlidingWindow(60)
        self._process_forks = SlidingWindow(10)
        
        # State
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._anomalies: List[AnomalyEvent] = []
        self._callbacks: List[callable] = []
        self._lock = threading.RLock()
        
        # Previous state for comparison
        self._prev_connections: Dict[str, ConnectionInfo] = {}
        self._prev_process_count = 0
    
    @property
    def is_learning(self) -> bool:
        """Check if still in learning period."""
        return (time.time() - self._start_time) < self._learning_period
    
    def start(self) -> None:
        """Start anomaly detection."""
        if not self._enabled:
            self._logger.warning("Anomaly detection is disabled")
            return
        
        if self._running:
            self._logger.warning("Anomaly detector is already running")
            return
        
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._detect_loop,
            name="AnomalyDetector",
            daemon=True
        )
        self._monitor_thread.start()
        
        if self.is_learning:
            self._logger.info(
                f"Anomaly detector started in LEARNING mode "
                f"({self._learning_period}s remaining)"
            )
        else:
            self._logger.info("Anomaly detector started in DETECTION mode")
    
    def stop(self) -> None:
        """Stop anomaly detection."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10)
        self._logger.info("Anomaly detector stopped")
    
    def _detect_loop(self) -> None:
        """Main detection loop."""
        while self._running:
            try:
                self._detect_anomalies()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                self._logger.error(f"Error in anomaly detection loop: {e}")
                time.sleep(10)
    
    def _detect_anomalies(self) -> List[AnomalyEvent]:
        """Run all anomaly detection checks."""
        anomalies = []
        
        if self.is_learning:
            self._update_baselines()
            return anomalies
        
        # Run all enabled detection methods
        if "login_anomaly" in self._detection_methods:
            anomalies.extend(self._detect_login_anomalies())
        
        if "network_anomaly" in self._detection_methods:
            anomalies.extend(self._detect_network_anomalies())
        
        if "file_anomaly" in self._detection_methods:
            anomalies.extend(self._detect_file_anomalies())
        
        if "process_anomaly" in self._detection_methods:
            anomalies.extend(self._detect_process_anomalies())
        
        if "privilege_anomaly" in self._detection_methods:
            anomalies.extend(self._detect_privilege_anomalies())
        
        # Store anomalies
        with self._lock:
            self._anomalies.extend(anomalies)
            if len(self._anomalies) > 1000:
                self._anomalies = self._anomalies[-1000:]
        
        # Trigger callbacks
        for anomaly in anomalies:
            for callback in self._callbacks:
                try:
                    callback(anomaly)
                except Exception as e:
                    self._logger.error(f"Callback error: {e}")
        
        return anomalies
    
    def _update_baselines(self) -> None:
        """Update baselines during learning period."""
        # Track login patterns
        self._parse_auth_log()
        
        # Track network patterns
        connections = get_network_connections()
        for conn in connections:
            key = conn.process_name
            self._network_baseline[key][conn.remote_port] += 1
    
    def _parse_auth_log(self) -> None:
        """Parse auth.log for login events."""
        auth_log_path = "/var/log/auth.log"
        if not os.path.exists(auth_log_path):
            return
        
        try:
            # Read last 1000 lines of auth.log
            result = run_command(["tail", "-1000", auth_log_path])
            if result[0] != 0:
                return
            
            for line in result[1].split("\n"):
                self._parse_auth_line(line)
        except Exception:
            pass
    
    def _parse_auth_line(self, line: str) -> None:
        """Parse a single auth.log line."""
        import re
        
        # Failed password
        match = re.search(
            r'(\w+ \d+ \d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\S+)',
            line
        )
        if match:
            event = LoginEvent(
                timestamp=datetime.now(),  # Approximate
                username=match.group(2),
                ip_address=match.group(3),
                success=False,
                service="ssh"
            )
            self._failed_logins.add(event)
            self._login_events.append(event)
            
            if self.is_learning:
                self._login_baseline[event.username].append(datetime.now().hour)
            return
        
        # Accepted password/public key
        match = re.search(
            r'(\w+ \d+ \d+:\d+:\d+).*Accepted (\S+) for (\S+) from (\S+)',
            line
        )
        if match:
            event = LoginEvent(
                timestamp=datetime.now(),
                username=match.group(3),
                ip_address=match.group(4),
                success=True,
                service="ssh"
            )
            self._login_events.append(event)
            
            if self.is_learning:
                self._login_baseline[event.username].append(datetime.now().hour)
    
    def _detect_login_anomalies(self) -> List[AnomalyEvent]:
        """Detect login anomalies."""
        anomalies = []
        params = self._detection_methods.get("login_anomaly", {})
        max_failed = params.get("max_failed_logins", 5)
        
        # Check for brute force
        failed = self._failed_logins.get_events()
        if len(failed) >= max_failed:
            # Group by IP
            by_ip: Dict[str, List[LoginEvent]] = defaultdict(list)
            for event in failed:
                by_ip[event.ip_address].append(event)
            
            for ip, events in by_ip.items():
                if len(events) >= max_failed:
                    anomaly = AnomalyEvent(
                        timestamp=datetime.now(),
                        anomaly_type="brute_force",
                        severity="high",
                        description=f"Possible brute force attack from {ip}: {len(events)} failed logins",
                        details={
                            "source_ip": ip,
                            "failed_count": len(events),
                            "target_users": list(set(e.username for e in events)),
                            "window_seconds": 300
                        },
                        remediation="Consider blocking the IP with iptables. Review affected accounts."
                    )
                    anomalies.append(anomaly)
                    
                    self._logger.log_alert(
                        AlertSeverity.HIGH,
                        AlertCategory.AUTHENTICATION,
                        "Brute Force Attack Detected",
                        anomaly.description,
                        "anomaly_detector",
                        anomaly.details,
                        anomaly.remediation
                    )
        
        # Check for unusual login times
        unusual_hours = params.get("unusual_hours", {"start": 0, "end": 6})
        start_hour = unusual_hours.get("start", 0)
        end_hour = unusual_hours.get("end", 6)
        current_hour = datetime.now().hour
        
        if start_hour <= current_hour <= end_hour:
            # Check recent successful logins
            recent_logins = [
                e for e in self._login_events[-100:]
                if e.success and (datetime.now() - e.timestamp).total_seconds() < 3600
            ]
            
            for login in recent_logins:
                # Check if this user normally logs in at this hour
                user_hours = self._login_baseline.get(login.username, [])
                if user_hours and current_hour not in user_hours:
                    anomaly = AnomalyEvent(
                        timestamp=datetime.now(),
                        anomaly_type="unusual_login_time",
                        severity="medium",
                        description=f"User {login.username} logged in at unusual hour from {login.ip_address}",
                        details={
                            "username": login.username,
                            "ip_address": login.ip_address,
                            "hour": current_hour,
                            "normal_hours": list(set(user_hours))
                        },
                        remediation="Verify if this login was authorized."
                    )
                    anomalies.append(anomaly)
                    
                    self._logger.log_alert(
                        AlertSeverity.MEDIUM,
                        AlertCategory.AUTHENTICATION,
                        "Unusual Login Time",
                        anomaly.description,
                        "anomaly_detector",
                        anomaly.details,
                        anomaly.remediation
                    )
        
        return anomalies
    
    def _detect_network_anomalies(self) -> List[AnomalyEvent]:
        """Detect network anomalies."""
        anomalies = []
        params = self._detection_methods.get("network_anomaly", {})
        max_connections = params.get("max_connections", 1000)
        unusual_ports = set(params.get("unusual_ports", [])) | self.SUSPICIOUS_PORTS
        outbound_limit = params.get("outbound_connection_limit", 100)
        
        connections = get_network_connections()
        
        # Check connection count
        if len(connections) > max_connections:
            anomaly = AnomalyEvent(
                timestamp=datetime.now(),
                anomaly_type="connection_flood",
                severity="high",
                description=f"Unusual number of connections: {len(connections)}",
                details={
                    "connection_count": len(connections),
                    "threshold": max_connections
                },
                remediation="Investigate for DDoS participation or connection exhaustion attack."
            )
            anomalies.append(anomaly)
            
            self._logger.log_alert(
                AlertSeverity.HIGH,
                AlertCategory.NETWORK,
                "Connection Flood",
                anomaly.description,
                "anomaly_detector",
                anomaly.details,
                anomaly.remediation
            )
        
        # Check for suspicious ports
        for conn in connections:
            if conn.remote_port in unusual_ports and conn.status == "ESTABLISHED":
                anomaly = AnomalyEvent(
                    timestamp=datetime.now(),
                    anomaly_type="suspicious_port",
                    severity="high",
                    description=f"Connection to suspicious port {conn.remote_port} from {conn.process_name}",
                    details={
                        "local": f"{conn.local_ip}:{conn.local_port}",
                        "remote": f"{conn.remote_ip}:{conn.remote_port}",
                        "pid": conn.pid,
                        "process": conn.process_name
                    },
                    remediation="Investigate the process and connection. May indicate C2 communication."
                )
                anomalies.append(anomaly)
                
                self._logger.log_alert(
                    AlertSeverity.HIGH,
                    AlertCategory.NETWORK,
                    "Suspicious Port Connection",
                    anomaly.description,
                    "anomaly_detector",
                    anomaly.details,
                    anomaly.remediation
                )
        
        # Check outbound connection limit
        outbound = [
            c for c in connections
            if c.remote_ip not in ("127.0.0.1", "::1", "0.0.0.0")
            and not c.remote_ip.startswith("10.")
            and not c.remote_ip.startswith("192.168.")
            and not c.remote_ip.startswith("172.16.")
            and c.status == "ESTABLISHED"
        ]
        
        if len(outbound) > outbound_limit:
            anomaly = AnomalyEvent(
                timestamp=datetime.now(),
                anomaly_type="excessive_outbound",
                severity="medium",
                description=f"Excessive outbound connections: {len(outbound)}",
                details={
                    "outbound_count": len(outbound),
                    "threshold": outbound_limit,
                    "destinations": list(set(c.remote_ip for c in outbound[:20]))
                },
                remediation="Investigate for data exfiltration or botnet activity."
            )
            anomalies.append(anomaly)
            
            self._logger.log_alert(
                AlertSeverity.MEDIUM,
                AlertCategory.NETWORK,
                "Excessive Outbound Connections",
                anomaly.description,
                "anomaly_detector",
                anomaly.details,
                anomaly.remediation
            )
        
        return anomalies
    
    def _detect_file_anomalies(self) -> List[AnomalyEvent]:
        """Detect file system anomalies."""
        anomalies = []
        params = self._detection_methods.get("file_anomaly", {})
        max_creations = params.get("max_file_creations", 100)
        hidden_threshold = params.get("hidden_files_threshold", 10)
        
        # Check for mass file creations
        creations = self._file_creations.count()
        if creations > max_creations:
            anomaly = AnomalyEvent(
                timestamp=datetime.now(),
                anomaly_type="mass_file_creation",
                severity="medium",
                description=f"Mass file creation detected: {creations} files in 60 seconds",
                details={
                    "file_count": creations,
                    "threshold": max_creations
                },
                remediation="Investigate for ransomware or log filling attack."
            )
            anomalies.append(anomaly)
            
            self._logger.log_alert(
                AlertSeverity.MEDIUM,
                AlertCategory.FILE_INTEGRITY,
                "Mass File Creation",
                anomaly.description,
                "anomaly_detector",
                anomaly.details,
                anomaly.remediation
            )
        
        # Check for hidden file creation
        hidden = self._hidden_files_created.count()
        if hidden > hidden_threshold:
            anomaly = AnomalyEvent(
                timestamp=datetime.now(),
                anomaly_type="hidden_files",
                severity="high",
                description=f"Multiple hidden files created: {hidden} in 60 seconds",
                details={
                    "hidden_count": hidden,
                    "threshold": hidden_threshold
                },
                remediation="Investigate for rootkit or malware hiding files."
            )
            anomalies.append(anomaly)
            
            self._logger.log_alert(
                AlertSeverity.HIGH,
                AlertCategory.FILE_INTEGRITY,
                "Hidden Files Created",
                anomaly.description,
                "anomaly_detector",
                anomaly.details,
                anomaly.remediation
            )
        
        return anomalies
    
    def _detect_process_anomalies(self) -> List[AnomalyEvent]:
        """Detect process anomalies."""
        anomalies = []
        params = self._detection_methods.get("process_anomaly", {})
        max_new = params.get("max_new_processes", 50)
        fork_threshold = params.get("fork_bomb_threshold", 100)
        
        # Check for excessive new processes
        new_procs = self._new_processes.count()
        if new_procs > max_new:
            anomaly = AnomalyEvent(
                timestamp=datetime.now(),
                anomaly_type="process_spawn_flood",
                severity="medium",
                description=f"Excessive process spawning: {new_procs} in 60 seconds",
                details={
                    "process_count": new_procs,
                    "threshold": max_new
                },
                remediation="Investigate for fork bomb or script running amok."
            )
            anomalies.append(anomaly)
            
            self._logger.log_alert(
                AlertSeverity.MEDIUM,
                AlertCategory.PROCESS,
                "Excessive Process Spawning",
                anomaly.description,
                "anomaly_detector",
                anomaly.details,
                anomaly.remediation
            )
        
        # Check for fork bomb pattern
        forks = self._process_forks.count()
        if forks > fork_threshold:
            anomaly = AnomalyEvent(
                timestamp=datetime.now(),
                anomaly_type="fork_bomb",
                severity="critical",
                description=f"Fork bomb detected: {forks} forks in 10 seconds",
                details={
                    "fork_count": forks,
                    "threshold": fork_threshold
                },
                remediation="Immediately investigate and kill the parent process."
            )
            anomalies.append(anomaly)
            
            self._logger.log_alert(
                AlertSeverity.CRITICAL,
                AlertCategory.PROCESS,
                "Fork Bomb Detected",
                anomaly.description,
                "anomaly_detector",
                anomaly.details,
                anomaly.remediation
            )
        
        return anomalies
    
    def _detect_privilege_anomalies(self) -> List[AnomalyEvent]:
        """Detect privilege escalation anomalies."""
        anomalies = []
        params = self._detection_methods.get("privilege_anomaly", {})
        
        # Check for new UID 0 accounts
        if params.get("alert_on_uid_0_creation", True):
            users = get_user_list()
            for user in users:
                if user.uid == 0 and user.username != "root":
                    anomaly = AnomalyEvent(
                        timestamp=datetime.now(),
                        anomaly_type="uid_zero_account",
                        severity="critical",
                        description=f"Non-root account with UID 0 detected: {user.username}",
                        details={
                            "username": user.username,
                            "uid": user.uid,
                            "home": user.home,
                            "shell": user.shell
                        },
                        remediation="Immediately investigate. This is a critical security issue."
                    )
                    anomalies.append(anomaly)
                    
                    self._logger.log_alert(
                        AlertSeverity.CRITICAL,
                        AlertCategory.PRIVILEGE_ESCALATION,
                        "UID 0 Account Detected",
                        anomaly.description,
                        "anomaly_detector",
                        anomaly.details,
                        anomaly.remediation
                    )
        
        # Check sudoers files for unauthorized changes
        if params.get("monitor_new_sudoers", True):
            sudoers_dirs = ["/etc/sudoers.d", "/etc/sudoers"]
            for sudoers_path in sudoers_dirs:
                if os.path.isdir(sudoers_path):
                    for f in os.listdir(sudoers_path):
                        if f.endswith(".tmp") or f.startswith("."):
                            anomaly = AnomalyEvent(
                                timestamp=datetime.now(),
                                anomaly_type="suspicious_sudoers",
                                severity="high",
                                description=f"Suspicious file in sudoers.d: {f}",
                                details={
                                    "path": os.path.join(sudoers_path, f),
                                    "file": f
                                },
                                remediation="Investigate the file for unauthorized privilege escalation."
                            )
                            anomalies.append(anomaly)
                            
                            self._logger.log_alert(
                                AlertSeverity.HIGH,
                                AlertCategory.PRIVILEGE_ESCALATION,
                                "Suspicious Sudoers File",
                                anomaly.description,
                                "anomaly_detector",
                                anomaly.details,
                                anomaly.remediation
                            )
        
        return anomalies
    
    def record_file_creation(self, filepath: str) -> None:
        """Record a file creation event."""
        self._file_creations.add(filepath)
        if os.path.basename(filepath).startswith("."):
            self._hidden_files_created.add(filepath)
    
    def record_process_spawn(self, pid: int) -> None:
        """Record a process spawn event."""
        self._new_processes.add(pid)
    
    def record_fork(self, ppid: int) -> None:
        """Record a fork event."""
        self._process_forks.add(ppid)
    
    def add_callback(self, callback: callable) -> None:
        """Add callback for anomalies."""
        self._callbacks.append(callback)
    
    def get_anomalies(self, limit: int = 100, anomaly_type: Optional[str] = None) -> List[AnomalyEvent]:
        """Get stored anomalies."""
        with self._lock:
            anomalies = self._anomalies.copy()
        
        if anomaly_type:
            anomalies = [a for a in anomalies if a.anomaly_type == anomaly_type]
        
        return anomalies[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "is_learning": self.is_learning,
            "learning_remaining_seconds": max(0, self._learning_period - (time.time() - self._start_time)),
            "total_anomalies": len(self._anomalies),
            "current_failed_logins": self._failed_logins.count(),
            "current_connections": self._connection_events.count(),
            "current_file_creations": self._file_creations.count(),
            "current_new_processes": self._new_processes.count(),
            "detection_methods_enabled": list(self._detection_methods.keys())
        }
