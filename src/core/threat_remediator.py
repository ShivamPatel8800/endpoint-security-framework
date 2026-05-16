"""
Threat Remediation Module for the Endpoint Security Framework.

Provides automated and semi-automated threat response capabilities
including process termination, file quarantine, and service management.
"""

import os
import json
import time
import shutil
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..utils.system_utils import (
    kill_process,
    quarantine_file,
    run_command,
    get_service_status,
    ensure_directory
)
from .logger import (
    ESFLogger,
    AlertSeverity,
    AlertCategory,
    get_logger
)


class RemediationAction(Enum):
    """Types of remediation actions."""
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    REMOVE_FILE = "remove_file"
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    DISABLE_SERVICE = "disable_service"
    ENABLE_SERVICE = "enable_service"
    REMOVE_SSH_KEY = "remove_ssh_key"
    REMOVE_CRON = "remove_cron"
    RESTORE_FILE = "restore_file"
    CUSTOM_COMMAND = "custom_command"


@dataclass
class RemediationResult:
    """Result of a remediation action."""
    success: bool
    action: str
    target: str
    timestamp: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RemediationRule:
    """Rule for automatic remediation."""
    trigger: str
    action: RemediationAction
    require_confirmation: bool = True
    parameters: Dict[str, Any] = field(default_factory=dict)


class ThreatRemediator:
    """
    Handles threat remediation actions.
    """
    
    def __init__(
        self,
        config: Dict[str, Any],
        paths_config: Dict[str, str],
        logger: Optional[ESFLogger] = None
    ):
        self._config = config
        self._paths_config = paths_config
        self._logger = logger or get_logger("threat_remediator")
        
        self._enabled = config.get("enabled", True)
        self._auto_remediate = config.get("auto_remediate", False)
        self._quarantine_dir = paths_config.get("quarantine_dir", "/var/lib/esf/quarantine")
        self._retention_days = config.get("quarantine_retention_days", 30)
        
        self._rules: List[RemediationRule] = []
        for action_config in config.get("actions", []):
            try:
                rule = RemediationRule(
                    trigger=action_config["trigger"],
                    action=RemediationAction(action_config["action"]),
                    require_confirmation=action_config.get("require_confirmation", True),
                    parameters=action_config.get("parameters", {})
                )
                self._rules.append(rule)
            except (KeyError, ValueError) as e:
                get_logger("threat_remediator").warning(f"Invalid remediation rule: {e}")
        
        self._history: List[RemediationResult] = []
        self._pending_confirmations: List[Dict[str, Any]] = []
        self._confirmation_callback: Optional[Callable] = None
        self._lock = threading.RLock()
        
        ensure_directory(self._quarantine_dir)
    
    def handle_threat(
        self,
        threat_type: str,
        target: str,
        details: Dict[str, Any],
        auto: Optional[bool] = None
    ) -> Optional[RemediationResult]:
        if not self._enabled:
            return None
        
        rule = self._find_rule(threat_type)
        if not rule:
            return None
        
        should_auto = auto if auto is not None else self._auto_remediate
        if rule.require_confirmation and not should_auto:
            return self._request_confirmation(rule, target, details)
        
        return self._execute_action(rule.action, target, rule.parameters)
    
    def _find_rule(self, threat_type: str) -> Optional[RemediationRule]:
        for rule in self._rules:
            if rule.trigger == threat_type:
                return rule
        return None
    
    def _request_confirmation(
        self,
        rule: RemediationRule,
        target: str,
        details: Dict[str, Any]
    ) -> None:
        pending = {
            "rule": rule,
            "target": target,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "id": f"REM-{int(time.time())}"
        }
        
        with self._lock:
            self._pending_confirmations.append(pending)
        
        self._logger.warning(
            f"Remediation requires confirmation: {rule.action.value} on {target} "
            f"(ID: {pending['id']})"
        )
        
        if self._confirmation_callback:
            self._confirmation_callback(pending)
        
        return None

    def confirm_action(self, action_id: str, approved: bool) -> Optional[RemediationResult]:
        with self._lock:
            for i, pending in enumerate(self._pending_confirmations):
                if pending["id"] == action_id:
                    self._pending_confirmations.pop(i)
                    
                    if approved:
                        rule = pending["rule"]
                        target = pending["target"]
                        return self._execute_action(rule.action, target, rule.parameters)
                    else:
                        self._logger.info(f"Remediation denied: {action_id}")
                        return RemediationResult(
                            success=False,
                            action="denied",
                            target=pending["target"],
                            timestamp=datetime.now().isoformat(),
                            message="Action denied by user"
                        )
        return None

    def _execute_action(
        self,
        action: RemediationAction,
        target: str,
        params: Dict[str, Any]
    ) -> RemediationResult:
        timestamp = datetime.now().isoformat()
        
        try:
            if action == RemediationAction.KILL_PROCESS:
                return self._kill_process(target, timestamp)
            elif action == RemediationAction.QUARANTINE_FILE:
                return self._quarantine_file(target, timestamp)
            elif action == RemediationAction.BLOCK_IP:
                return self._block_ip(target, timestamp)
            elif action == RemediationAction.UNBLOCK_IP:
                return self._unblock_ip(target, timestamp)
            elif action == RemediationAction.DISABLE_SERVICE:
                return self._disable_service(target, timestamp)
            elif action == RemediationAction.REMOVE_SSH_KEY:
                return self._remove_ssh_key(target, params, timestamp)
            elif action == RemediationAction.REMOVE_CRON:
                return self._remove_cron(target, params, timestamp)
            else:
                return RemediationResult(
                    success=False,
                    action=action.value,
                    target=target,
                    timestamp=timestamp,
                    message=f"Unknown action: {action.value}"
                )
        except Exception as e:
            self._logger.error(f"Remediation failed for {action.value} on {target}: {e}")
            return RemediationResult(
                success=False,
                action=action.value,
                target=target,
                timestamp=timestamp,
                message=str(e)
            )

    def _kill_process(self, pid_str: str, timestamp: str) -> RemediationResult:
        pid = int(pid_str)
        
        if pid <= 1:
            return RemediationResult(
                success=False,
                action="kill_process",
                target=pid_str,
                timestamp=timestamp,
                message="Cannot kill system critical processes (PID <= 1)"
            )
        
        success = kill_process(pid, force=True)
        
        result = RemediationResult(
            success=success,
            action="kill_process",
            target=pid_str,
            timestamp=timestamp,
            message=f"Process {pid} killed" if success else f"Failed to kill process {pid}"
        )
        
        self._logger.log_alert(
            AlertSeverity.HIGH if success else AlertSeverity.MEDIUM,
            AlertCategory.REMEDIATION,
            "Process Terminated" if success else "Process Termination Failed",
            result.message,
            "threat_remediator",
            {"pid": pid}
        )
        
        with self._lock:
            self._history.append(result)
        
        return result

    def _quarantine_file(self, filepath: str, timestamp: str) -> RemediationResult:
        if not os.path.exists(filepath):
            return RemediationResult(
                success=False,
                action="quarantine_file",
                target=filepath,
                timestamp=timestamp,
                message="File does not exist"
            )
        
        quarantine_path = quarantine_file(filepath, self._quarantine_dir)
        
        success = quarantine_path is not None
        result = RemediationResult(
            success=success,
            action="quarantine_file",
            target=filepath,
            timestamp=timestamp,
            message=f"Quarantined to {quarantine_path}" if success else "Quarantine failed",
            details={"quarantine_path": quarantine_path} if success else {}
        )
        
        self._logger.log_alert(
            AlertSeverity.HIGH,
            AlertCategory.REMEDIATION,
            "File Quarantined" if success else "Quarantine Failed",
            result.message,
            "threat_remediator",
            {"original_path": filepath, "quarantine_path": quarantine_path}
        )
        
        with self._lock:
            self._history.append(result)
        
        return result

    def _block_ip(self, ip_address: str, timestamp: str) -> RemediationResult:
        returncode, stdout, stderr = run_command([
            "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"
        ])
        
        success = returncode == 0
        result = RemediationResult(
            success=success,
            action="block_ip",
            target=ip_address,
            timestamp=timestamp,
            message=f"IP {ip_address} blocked" if success else f"Failed to block IP: {stderr}"
        )
        
        self._logger.log_alert(
            AlertSeverity.HIGH,
            AlertCategory.REMEDIATION,
            "IP Blocked" if success else "IP Block Failed",
            result.message,
            "threat_remediator",
            {"ip": ip_address}
        )
        
        with self._lock:
            self._history.append(result)
        
        return result

    def _unblock_ip(self, ip_address: str, timestamp: str) -> RemediationResult:
        returncode, stdout, stderr = run_command([
            "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"
        ])
        
        success = returncode == 0
        result = RemediationResult(
            success=success,
            action="unblock_ip",
            target=ip_address,
            timestamp=timestamp,
            message=f"IP {ip_address} unblocked" if success else f"Failed to unblock IP: {stderr}"
        )
        
        with self._lock:
            self._history.append(result)
        
        return result

    def _disable_service(self, service_name: str, timestamp: str) -> RemediationResult:
        r1, _, _ = run_command(["systemctl", "stop", service_name])
        r2, _, _ = run_command(["systemctl", "disable", service_name])
        
        success = r1 == 0 and r2 == 0
        result = RemediationResult(
            success=success,
            action="disable_service",
            target=service_name,
            timestamp=timestamp,
            message=f"Service {service_name} disabled" if success else "Failed to disable service"
        )
        
        self._logger.log_alert(
            AlertSeverity.HIGH,
            AlertCategory.REMEDIATION,
            "Service Disabled",
            result.message,
            "threat_remediator",
            {"service": service_name}
        )
        
        with self._lock:
            self._history.append(result)
        
        return result

    def _remove_ssh_key(self, target: str, params: Dict, timestamp: str) -> RemediationResult:
        username = params.get("user", "root")
        key_pattern = params.get("key_pattern", target)
        auth_keys_path = f"/home/{username}/.ssh/authorized_keys"
        
        if username == "root":
            auth_keys_path = "/root/.ssh/authorized_keys"
            
        if not os.path.exists(auth_keys_path):
            return RemediationResult(
                success=False,
                action="remove_ssh_key",
                target=target,
                timestamp=timestamp,
                message="authorized_keys file not found"
            )
        
        try:
            with open(auth_keys_path, "r") as f:
                lines = f.readlines()
            
            new_lines = [l for l in lines if key_pattern not in l]
            
            with open(auth_keys_path, "w") as f:
                f.writelines(new_lines)
                
            success = len(lines) != len(new_lines)
            return RemediationResult(
                success=success,
                action="remove_ssh_key",
                target=target,
                timestamp=timestamp,
                message=f"Removed {len(lines) - len(new_lines)} matching keys"
            )
        except Exception as e:
            return RemediationResult(
                success=False,
                action="remove_ssh_key",
                target=target,
                timestamp=timestamp,
                message=str(e)
            )

    def _remove_cron(self, target: str, params: Dict, timestamp: str) -> RemediationResult:
        username = params.get("user", None)
        cmd = ["crontab", "-r"]
        if username:
            cmd.extend(["-u", username])
            
        returncode, _, stderr = run_command(cmd)
        success = returncode == 0
        
        return RemediationResult(
            success=success,
            action="remove_cron",
            target=target,
            timestamp=timestamp,
            message=f"Cron jobs removed for {'user ' + username if username else 'current user'}" if success else f"Failed: {stderr}"
        )

    def set_confirmation_callback(self, callback: Callable) -> None:
        self._confirmation_callback = callback

    def get_pending_confirmations(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._pending_confirmations.copy()

    def get_history(self, limit: int = 100) -> List[RemediationResult]:
        with self._lock:
            return self._history[-limit:]
