"""
Service Hardener Module
"""

import os
import re
from typing import Dict, List, Any, Optional

from ..utils.system_utils import run_command
from ..core.logger import ESFLogger, get_logger

class ServiceHardener:
    def __init__(self, config: Dict[str, Any], logger: Optional[ESFLogger] = None):
        self._config = config.get("service_hardening", {})
        self._logger = logger or get_logger("service_hardener")
        self._ssh_config_path = "/etc/ssh/sshd_config"

    def check_ssh_hardening(self) -> Dict[str, Any]:
        """Check SSH configuration against recommended settings."""
        if not os.path.exists(self._ssh_config_path):
            return {"error": "sshd_config not found"}

        recommended = self._config.get("services", {}).get("ssh", {}).get("recommended_settings", {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PermitEmptyPasswords": "no",
            "X11Forwarding": "no"
        })

        results = {"compliant": [], "non_compliant": [], "missing": []}
        
        with open(self._ssh_config_path, 'r') as f:
            content = f.read()
            
        for setting, expected in recommended.items():
            # Match setting (case insensitive)
            match = re.search(rf'^\s*{setting}\s+(.+)$', content, re.MULTILINE | re.IGNORECASE)
            if match:
                actual = match.group(1).strip().lower()
                if actual == expected.lower():
                    results["compliant"].append({setting: actual})
                else:
                    results["non_compliant"].append({setting: {"expected": expected, "actual": actual}})
            else:
                results["missing"].append(setting)
                
        return results

    def check_cron_permissions(self) -> Dict[str, Any]:
        """Check cron directory permissions."""
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron/crontabs"]
        results = {}
        
        for dir_path in cron_dirs:
            if os.path.exists(dir_path):
                stat_info = os.stat(dir_path)
                mode = oct(stat_info.st_mode)[-3:]
                results[dir_path] = {
                    "permissions": mode,
                    "secure": stat_info.st_mode & 0o022 == 0  # No write for others/group
                }
            else:
                results[dir_path] = {"error": "Not found"}
                
        return results

    def run_all_checks(self) -> Dict[str, Any]:
        return {
            "ssh": self.check_ssh_hardening(),
            "cron": self.check_cron_permissions()
        }
