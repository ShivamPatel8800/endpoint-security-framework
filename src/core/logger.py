"""
Enhanced logging module for the Endpoint Security Framework.

Provides structured logging with multiple output destinations,
alert tracking, and audit trail capabilities.
"""

import logging
import logging.handlers
import os
import sys
import json
import socket
import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from enum import Enum


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(Enum):
    """Alert categories."""
    PROCESS = "process"
    FILE_INTEGRITY = "file_integrity"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE = "malware"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    REMEDIATION = "remediation"


@dataclass
class Alert:
    """Structured alert data."""
    timestamp: str
    severity: str
    category: str
    title: str
    description: str
    source: str
    host: str
    details: Dict[str, Any]
    remediation: Optional[str] = None
    alert_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert alert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class AlertFormatter(logging.Formatter):
    """Custom formatter for structured log output."""
    
    def format(self, record: logging.LogRecord) -> str:
        # Create base log entry
        log_entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "host": socket.gethostname(),
        }
        
        # Add extra fields if present
        if hasattr(record, "alert_data"):
            log_entry["alert"] = record.alert_data
        if hasattr(record, "source"):
            log_entry["source"] = record.source
        if hasattr(record, "category"):
            log_entry["category"] = record.category
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str)


class ConsoleFormatter(logging.Formatter):
    """Colored formatter for console output."""
    
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class ESFLogger:
    """
    Main logger class for the Endpoint Security Framework.
    
    Provides unified logging with:
    - Console output with colors
    - File logging with rotation
    - Alert-specific logging
    - Syslog integration
    - Alert tracking and storage
    """
    
    _instance = None
    _loggers: Dict[str, logging.Logger] = {}
    _alerts: List[Alert] = []
    _alert_file_handler: Optional[logging.Handler] = None
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern for logger."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(
        self,
        log_dir: str = "/var/log/esf",
        log_level: str = "INFO",
        config: Optional[Dict] = None
    ):
        if hasattr(self, "_initialized") and self._initialized:
            return
        
        self._log_dir = Path(log_dir)
        self._log_level = getattr(logging, log_level.upper(), logging.INFO)
        self._config = config or {}
        self._hostname = socket.gethostname()
        
        # Create log directory if it doesn't exist
        self._log_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize handlers
        self._setup_handlers()
        
        self._initialized = True
    
    def _setup_handlers(self) -> None:
        """Set up all logging handlers."""
        # Get notification config
        notifications = self._config.get("notifications", {})
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self._log_level)
        console_formatter = ConsoleFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(console_formatter)
        
        # Main file handler with rotation
        main_log_path = self._log_dir / "esf.log"
        file_handler = logging.handlers.RotatingFileHandler(
            main_log_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10
        )
        file_handler.setLevel(self._log_level)
        file_formatter = AlertFormatter()
        file_handler.setFormatter(file_formatter)
        
        # Error file handler
        error_log_path = self._log_dir / "esf-error.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        
        # Alert file handler
        alert_log_path = self._log_dir / "alerts.log"
        self._alert_file_handler = logging.handlers.RotatingFileHandler(
            alert_log_path,
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=20
        )
        self._alert_file_handler.setLevel(logging.WARNING)
        self._alert_file_handler.setFormatter(file_formatter)
        
        # Syslog handler (if enabled)
        syslog_handler = None
        syslog_config = notifications.get("syslog", {})
        if syslog_config.get("enabled", False):
            try:
                syslog_handler = logging.handlers.SysLogHandler(
                    address="/dev/log",
                    facility=logging.handlers.SysLogHandler.LOG_AUTH
                )
                syslog_handler.setLevel(logging.WARNING)
                syslog_handler.setFormatter(
                    logging.Formatter("%(name)s: %(message)s")
                )
            except Exception:
                pass
        
        # Store base handlers
        self._base_handlers = [console_handler, file_handler, error_handler]
        if self._alert_file_handler:
            self._base_handlers.append(self._alert_file_handler)
        if syslog_handler:
            self._base_handlers.append(syslog_handler)
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        Get or create a logger with the specified name.
        
        Args:
            name: Logger name (typically module name)
            
        Returns:
            Configured logger instance
        """
        if name in self._loggers:
            return self._loggers[name]
        
        logger = logging.getLogger(f"esf.{name}")
        logger.setLevel(self._log_level)
        
        # Remove existing handlers to prevent duplicates
        logger.handlers.clear()
        
        # Add base handlers
        for handler in self._base_handlers:
            logger.addHandler(handler)
        
        # Prevent propagation to root logger
        logger.propagate = False
        
        self._loggers[name] = logger
        return logger
    
    def log_alert(
        self,
        severity: AlertSeverity,
        category: AlertCategory,
        title: str,
        description: str,
        source: str,
        details: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None
    ) -> Alert:
        """
        Log a security alert.
        
        Args:
            severity: Alert severity level
            category: Alert category
            title: Brief alert title
            description: Detailed description
            source: Source module that generated the alert
            details: Additional details as dictionary
            remediation: Suggested remediation steps
            
        Returns:
            Created Alert object
        """
        # Create alert object
        alert = Alert(
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
            severity=severity.value,
            category=category.value,
            title=title,
            description=description,
            source=source,
            host=self._hostname,
            details=details or {},
            remediation=remediation
        )
        
        # Generate alert ID
        alert.alert_id = f"ESF-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{id(alert) % 10000:04d}"
        
        # Map severity to log level
        level_map = {
            AlertSeverity.CRITICAL: logging.CRITICAL,
            AlertSeverity.HIGH: logging.ERROR,
            AlertSeverity.MEDIUM: logging.WARNING,
            AlertSeverity.LOW: logging.INFO,
            AlertSeverity.INFO: logging.DEBUG,
        }
        
        log_level = level_map.get(severity, logging.WARNING)
        
        # Log to appropriate logger
        logger = self.get_logger(source)
        logger.log(
            log_level,
            f"[{severity.value.upper()}] {title}: {description}",
            extra={
                "alert_data": alert.to_dict(),
                "source": source,
                "category": category.value
            }
        )
        
        # Store alert in memory
        self._alerts.append(alert)
        
        # Keep only last 1000 alerts in memory
        if len(self._alerts) > 1000:
            self._alerts = self._alerts[-1000:]
        
        return alert
    
    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        category: Optional[AlertCategory] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Alert]:
        """
        Get stored alerts with optional filtering.
        
        Args:
            severity: Filter by severity
            category: Filter by category
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip
            
        Returns:
            List of Alert objects
        """
        alerts = self._alerts.copy()
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity.value]
        if category:
            alerts = [a for a in alerts if a.category == category.value]
        
        return alerts[offset:offset + limit]
    
    def get_alert_count(self, severity: Optional[AlertSeverity] = None) -> int:
        """Get count of stored alerts."""
        if severity:
            return len([a for a in self._alerts if a.severity == severity.value])
        return len(self._alerts)
    
    def clear_alerts(self) -> int:
        """Clear stored alerts and return count of cleared alerts."""
        count = len(self._alerts)
        self._alerts.clear()
        return count
    
    def save_alerts_to_file(self, filepath: str) -> None:
        """Save all alerts to a JSON file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, "w") as f:
            json.dump(
                [a.to_dict() for a in self._alerts],
                f,
                indent=2,
                default=str
            )
    
    def shutdown(self) -> None:
        """Clean shutdown of all handlers."""
        for logger in self._loggers.values():
            for handler in logger.handlers:
                try:
                    handler.close()
                except Exception:
                    pass


def get_logger(name: str, config: Optional[Dict] = None) -> logging.Logger:
    """
    Convenience function to get a logger.
    
    Args:
        name: Logger name
        config: Optional configuration dictionary
        
    Returns:
        Configured logger instance
    """
    logger_instance = ESFLogger(
        log_dir=config.get("paths", {}).get("log_dir", "/var/log/esf") if config else "/var/log/esf",
        log_level=config.get("general", {}).get("log_level", "INFO") if config else "INFO",
        config=config
    )
    return logger_instance.get_logger(name)


def log_alert(
    severity: AlertSeverity,
    category: AlertCategory,
    title: str,
    description: str,
    source: str,
    details: Optional[Dict[str, Any]] = None,
    remediation: Optional[str] = None,
    config: Optional[Dict] = None
) -> Alert:
    """
    Convenience function to log an alert.
    
    Args:
        severity: Alert severity level
        category: Alert category
        title: Brief alert title
        description: Detailed description
        source: Source module
        details: Additional details
        remediation: Suggested remediation
        config: Optional configuration
        
    Returns:
        Created Alert object
    """
    logger_instance = ESFLogger(
        log_dir=config.get("paths", {}).get("log_dir", "/var/log/esf") if config else "/var/log/esf",
        log_level=config.get("general", {}).get("log_level", "INFO") if config else "INFO",
        config=config
    )
    return logger_instance.log_alert(
        severity=severity,
        category=category,
        title=title,
        description=description,
        source=source,
        details=details,
        remediation=remediation
    )
