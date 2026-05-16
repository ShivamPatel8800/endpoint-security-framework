"""
User Monitor Module
"""

import os
import re
import threading
import time
from typing import Dict, List, Any, Optional

from ..utils.system_utils import get_user_list, run_command
from ..core.logger import ESFLogger, AlertSeverity, AlertCategory, get_logger

class UserMonitor:
    def __init__(self, config: Dict[str, Any], logger: Optional[ESFLogger] = None):
        self._config = config.get("user_monitor", {})
        self._logger = logger or get_logger("user_monitor")
        self._enabled = self._config.get("enabled", True)
        self._scan_interval = 60
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_uids = set()
        self._init_known_users()

    def _init_known_users(self):
        users = get_user_list()
        self._known_uids = {u.uid for u in users}

    def start(self):
        if not self._enabled: return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="UserMonitor")
        self._thread.start()
        self._logger.info("User monitor started")

    def stop(self):
        self._running = False
        if self._thread: self._thread.join(timeout=10)

    def _loop(self):
        while self._running:
            self.check_users()
            self.check_ssh_keys()
            time.sleep(self._scan_interval)

    def check_users(self) -> List[Dict]:
        alerts = []
        users = get_user_list()
        current_uids = {u.uid for u in users}
        
        # Check for new UID 0 users
        for user in users:
            if user.uid == 0 and user.username != "root":
                self._logger.log_alert(
                    AlertSeverity.CRITICAL,
                    AlertCategory.PRIVILEGE_ESCALATION,
                    "UID 0 User Detected",
                    f"User {user.username} has UID 0",
                    "user_monitor",
                    {"username": user.username, "home": user.home}
                )
                alerts.append({"type": "uid_zero", "user": user.username})
            
            # Check for new users
            if user.uid >= 1000 and user.uid not in self._known_uids:
                self._logger.log_alert(
                    AlertSeverity.MEDIUM,
                    AlertCategory.AUTHENTICATION,
                    "New User Created",
                    f"New user {user.username} (UID: {user.uid})",
                    "user_monitor",
                    {"username": user.username, "uid": user.uid, "shell": user.shell}
                )
                alerts.append({"type": "new_user", "user": user.username})
                
        self._known_uids = current_uids
        return alerts

    def check_ssh_keys(self) -> List[Dict]:
        alerts = []
        auth_files = ["/root/.ssh/authorized_keys"]
        
        # Get all user home dirs
        users = get_user_list()
        for u in users:
            if u.uid >= 1000 and u.shell != "/usr/sbin/nologin":
                auth_files.append(f"{u.home}/.ssh/authorized_keys")

        for filepath in auth_files:
            if not os.path.exists(filepath): continue
            
            try:
                with open(filepath, 'r') as f:
                    lines = [l.strip() for l in f.readlines() if l.strip() and not l.startswith('#')]
                
                # Basic anomaly: empty keys or malformed
                for line in lines:
                    parts = line.split()
                    if len(parts) < 2:
                        alerts.append({"type": "malformed_key", "path": filepath})
                        self._logger.warning(f"Malformed SSH key in {filepath}")
            except Exception:
                pass
                
        return alerts
