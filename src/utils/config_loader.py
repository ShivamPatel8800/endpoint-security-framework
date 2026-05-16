"""
Configuration loader and validator for the Endpoint Security Framework.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ProcessMonitorConfig:
    """Process monitoring configuration."""
    enabled: bool = True
    scan_interval: int = 30
    suspicious_paths: list = field(default_factory=lambda: ["/tmp", "/var/tmp", "/dev/shm"])
    malicious_names: list = field(default_factory=list)
    cpu_threshold: int = 90
    memory_threshold: int = 80
    whitelist_processes: list = field(default_factory=list)
    whitelist_users: list = field(default_factory=list)


@dataclass
class FileIntegrityConfig:
    """File integrity monitoring configuration."""
    enabled: bool = True
    scan_interval: int = 300
    hash_algorithm: str = "sha256"
    monitor_directories: list = field(default_factory=list)
    exclude_patterns: list = field(default_factory=list)
    alert_on_changes: list = field(default_factory=lambda: ["modified", "deleted", "created"])


@dataclass
class AnomalyDetectionConfig:
    """Anomaly detection configuration."""
    enabled: bool = True
    learning_period: int = 86400
    max_failed_logins: int = 5
    max_connections: int = 1000
    suspicious_ports: list = field(default_factory=list)
    max_new_processes: int = 50
    max_file_creations: int = 100


@dataclass
class RemediationConfig:
    """Threat remediation configuration."""
    enabled: bool = True
    auto_remediate: bool = False
    quarantine_dir: str = "/var/lib/esf/quarantine"
    quarantine_retention_days: int = 30


@dataclass
class NetworkMonitorConfig:
    """Network monitoring configuration."""
    enabled: bool = True
    scan_interval: int = 60
    suspicious_ports: list = field(default_factory=list)
    block_suspicious: bool = False


@dataclass
class NotificationConfig:
    """Notification configuration."""
    log_file_enabled: bool = True
    syslog_enabled: bool = True
    email_enabled: bool = False
    webhook_enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    email_recipients: list = field(default_factory=list)


@dataclass
class Config:
    """Main configuration container."""
    general: Dict[str, Any] = field(default_factory=dict)
    paths: Dict[str, str] = field(default_factory=dict)
    process_monitor: ProcessMonitorConfig = field(default_factory=ProcessMonitorConfig)
    file_integrity: FileIntegrityConfig = field(default_factory=FileIntegrityConfig)
    anomaly_detection: AnomalyDetectionConfig = field(default_factory=AnomalyDetectionConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)
    network_monitor: NetworkMonitorConfig = field(default_factory=NetworkMonitorConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    raw_config: Dict[str, Any] = field(default_factory=dict)


class ConfigLoader:
    """
    Configuration loader with validation and default values.
    """
    
    DEFAULT_CONFIG_PATHS = [
        "/etc/esf/config.yaml",
        "./config/config.yaml",
        "./config.yaml",
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        self._config_path = config_path
        self._raw_config: Dict[str, Any] = {}
        self._config: Optional[Config] = None
    
    def load(self) -> Config:
        """
        Load configuration from file.
        
        Returns:
            Parsed and validated Config object
        """
        config_path = self._find_config_file()
        
        if config_path is None:
            raise FileNotFoundError(
                f"Configuration file not found. Searched: {self.DEFAULT_CONFIG_PATHS}"
            )
        
        with open(config_path, "r") as f:
            self._raw_config = yaml.safe_load(f) or {}
        
        self._config = self._parse_config(self._raw_config)
        return self._config
    
    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in standard locations."""
        if self._config_path and os.path.exists(self._config_path):
            return self._config_path
        
        for path in self.DEFAULT_CONFIG_PATHS:
            if os.path.exists(path):
                return path
        
        return None
    
    def _parse_config(self, raw: Dict[str, Any]) -> Config:
        """Parse raw configuration into typed Config object."""
        config = Config()
        config.raw_config = raw
        
        # General settings
        config.general = raw.get("general", {})
        config.paths = raw.get("paths", {})
        
        # Process monitor
        pm = raw.get("process_monitor", {})
        config.process_monitor = ProcessMonitorConfig(
            enabled=pm.get("enabled", True),
            scan_interval=pm.get("scan_interval", 30),
            suspicious_paths=self._extract_suspicious_paths(pm),
            malicious_names=self._extract_malicious_names(pm),
            cpu_threshold=self._extract_cpu_threshold(pm),
            memory_threshold=self._extract_memory_threshold(pm),
            whitelist_processes=self._extract_whitelist_processes(pm),
            whitelist_users=self._extract_whitelist_users(pm),
        )
        
        # File integrity
        fi = raw.get("file_integrity", {})
        config.file_integrity = FileIntegrityConfig(
            enabled=fi.get("enabled", True),
            scan_interval=fi.get("scan_interval", 300),
            hash_algorithm=fi.get("hash_algorithm", "sha256"),
            monitor_directories=fi.get("monitor_directories", []),
            exclude_patterns=fi.get("exclude_patterns", []),
            alert_on_changes=fi.get("alert_on_changes", ["modified", "deleted", "created"]),
        )
        
        # Anomaly detection
        ad = raw.get("anomaly_detection", {})
        config.anomaly_detection = AnomalyDetectionConfig(
            enabled=ad.get("enabled", True),
            learning_period=ad.get("learning_period", 86400),
            max_failed_logins=self._extract_max_failed_logins(ad),
            max_connections=self._extract_max_connections(ad),
            suspicious_ports=self._extract_suspicious_ports(ad),
            max_new_processes=self._extract_max_new_processes(ad),
            max_file_creations=self._extract_max_file_creations(ad),
        )
        
        # Remediation
        rem = raw.get("remediation", {})
        config.remediation = RemediationConfig(
            enabled=rem.get("enabled", True),
            auto_remediate=rem.get("auto_remediate", False),
            quarantine_dir=config.paths.get("quarantine_dir", "/var/lib/esf/quarantine"),
            quarantine_retention_days=rem.get("quarantine_retention_days", 30),
        )
        
        # Network monitor
        nm = raw.get("network_monitor", {})
        config.network_monitor = NetworkMonitorConfig(
            enabled=nm.get("enabled", True),
            scan_interval=nm.get("scan_interval", 60),
            suspicious_ports=nm.get("suspicious_ports", []),
            block_suspicious=nm.get("block_suspicious_ips", False),
        )
        
        # Notifications
        notif = raw.get("notifications", {})
        methods = notif.get("methods", {})
        log_file = methods.get("log_file", {})
        syslog = methods.get("syslog", {})
        email = methods.get("email", {})
        webhook = methods.get("webhook", {})
        
        config.notifications = NotificationConfig(
            log_file_enabled=log_file.get("enabled", True),
            syslog_enabled=syslog.get("enabled", True),
            email_enabled=email.get("enabled", False),
            webhook_enabled=webhook.get("enabled", False),
            smtp_host=email.get("smtp_host", "localhost"),
            smtp_port=email.get("smtp_port", 587),
            email_recipients=email.get("recipients", []),
        )
        
        return config
    
    def _extract_suspicious_paths(self, pm: Dict) -> list:
        """Extract suspicious paths from config."""
        paths = ["/tmp", "/var/tmp", "/dev/shm"]
        for alert_on in pm.get("alert_on", []):
            if alert_on.get("type") == "suspicious_path":
                paths.extend(alert_on.get("paths", []))
        return list(set(paths))
    
    def _extract_malicious_names(self, pm: Dict) -> list:
        """Extract malicious process names from config."""
        names = []
        for alert_on in pm.get("alert_on", []):
            if alert_on.get("type") == "known_malicious_names":
                names.extend(alert_on.get("names", []))
        return names
    
    def _extract_cpu_threshold(self, pm: Dict) -> int:
        """Extract CPU threshold from config."""
        for alert_on in pm.get("alert_on", []):
            if alert_on.get("type") == "unusual_cpu":
                return alert_on.get("threshold", 90)
        return 90
    
    def _extract_memory_threshold(self, pm: Dict) -> int:
        """Extract memory threshold from config."""
        for alert_on in pm.get("alert_on", []):
            if alert_on.get("type") == "unusual_memory":
                return alert_on.get("threshold", 80)
        return 80
    
    def _extract_whitelist_processes(self, pm: Dict) -> list:
        """Extract whitelisted process names."""
        return pm.get("whitelist", {}).get("processes", [])
    
    def _extract_whitelist_users(self, pm: Dict) -> list:
        """Extract whitelisted users."""
        return pm.get("whitelist", {}).get("users", [])
    
    def _extract_max_failed_logins(self, ad: Dict) -> int:
        """Extract max failed logins threshold."""
        for method in ad.get("detection_methods", []):
            if method.get("name") == "login_anomaly":
                return method.get("parameters", {}).get("max_failed_logins", 5)
        return 5
    
    def _extract_max_connections(self, ad: Dict) -> int:
        """Extract max connections threshold."""
        for method in ad.get("detection_methods", []):
            if method.get("name") == "network_anomaly":
                return method.get("parameters", {}).get("max_connections", 1000)
        return 1000
    
    def _extract_suspicious_ports(self, ad: Dict) -> list:
        """Extract suspicious ports list."""
        ports = []
        for method in ad.get("detection_methods", []):
            if method.get("name") == "network_anomaly":
                ports.extend(method.get("parameters", {}).get("unusual_ports", []))
        return list(set(ports))
    
    def _extract_max_new_processes(self, ad: Dict) -> int:
        """Extract max new processes threshold."""
        for method in ad.get("detection_methods", []):
            if method.get("name") == "process_anomaly":
                return method.get("parameters", {}).get("max_new_processes", 50)
        return 50
    
    def _extract_max_file_creations(self, ad: Dict) -> int:
        """Extract max file creations threshold."""
        for method in ad.get("detection_methods", []):
            if method.get("name") == "file_anomaly":
                return method.get("parameters", {}).get("max_file_creations", 100)
        return 100
    
    @property
    def raw(self) -> Dict[str, Any]:
        """Get raw configuration dictionary."""
        return self._raw_config
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get a specific configuration section."""
        return self._raw_config.get(section, {})
    
    def save_default_config(self, path: str) -> None:
        """Save a default configuration file."""
        default_config = {
            "general": {
                "framework_name": "Endpoint Security Framework",
                "version": "1.0.0",
                "debug_mode": False,
                "log_level": "INFO"
            },
            "paths": {
                "log_dir": "/var/log/esf",
                "db_dir": "/var/lib/esf",
                "alert_dir": "/var/lib/esf/alerts",
                "baseline_dir": "/var/lib/esf/baselines",
                "quarantine_dir": "/var/lib/esf/quarantine"
            },
            "process_monitor": {
                "enabled": True,
                "scan_interval": 30
            },
            "file_integrity": {
                "enabled": True,
                "scan_interval": 300,
                "hash_algorithm": "sha256",
                "monitor_directories": [
                    {"path": "/etc", "recursive": True},
                    {"path": "/usr/bin", "recursive": True},
                    {"path": "/usr/sbin", "recursive": True}
                ]
            },
            "anomaly_detection": {
                "enabled": True,
                "learning_period": 86400
            },
            "remediation": {
                "enabled": True,
                "auto_remediate": False
            },
            "network_monitor": {
                "enabled": True,
                "scan_interval": 60
            },
            "notifications": {
                "enabled": True,
                "methods": {
                    "log_file": {"enabled": True},
                    "syslog": {"enabled": True},
                    "email": {"enabled": False},
                    "webhook": {"enabled": False}
                }
            }
        }
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
