"""
Network Monitor Module
"""

import threading
import time
from typing import Dict, List, Any, Optional
from collections import defaultdict

from ..utils.system_utils import get_network_connections, ConnectionInfo
from ..core.logger import ESFLogger, AlertSeverity, AlertCategory, get_logger

class NetworkMonitor:
    def __init__(self, config: Dict[str, Any], logger: Optional[ESFLogger] = None):
        self._config = config.get("network_monitor", {})
        self._logger = logger or get_logger("network_monitor")
        self._enabled = self._config.get("enabled", True)
        self._scan_interval = self._config.get("scan_interval", 60)
        self._suspicious_ports = set(self._config.get("suspicious_ports", []))
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._connections_state: Dict[str, ConnectionInfo] = {}
        self._anomaly_callback = None

    def set_anomaly_callback(self, callback):
        self._anomaly_callback = callback

    def start(self):
        if not self._enabled: return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="NetworkMonitor")
        self._thread.start()
        self._logger.info("Network monitor started")

    def stop(self):
        self._running = False
        if self._thread: self._thread.join(timeout=10)

    def _loop(self):
        while self._running:
            self.scan()
            time.sleep(self._scan_interval)

    def scan(self) -> Dict[str, Any]:
        current_conns = get_network_connections()
        stats = {
            "total": len(current_conns),
            "established": 0,
            "listening": 0,
            "suspicious": []
        }
        
        current_ids = set()
        for conn in current_conns:
            conn_id = f"{conn.local_ip}:{conn.local_port}-{conn.remote_ip}:{conn.remote_port}"
            current_ids.add(conn_id)
            
            if conn.status == "ESTABLISHED": stats["established"] += 1
            if conn.status == "LISTEN": stats["listening"] += 1
            
            if conn.remote_port in self._suspicious_ports and conn.status == "ESTABLISHED":
                stats["suspicious"].append({
                    "local": f"{conn.local_ip}:{conn.local_port}",
                    "remote": f"{conn.remote_ip}:{conn.remote_port}",
                    "pid": conn.pid,
                    "process": conn.process_name
                })
                self._logger.log_alert(
                    AlertSeverity.HIGH,
                    AlertCategory.NETWORK,
                    "Suspicious Port Connection",
                    f"Connection to port {conn.remote_port} by {conn.process_name}",
                    "network_monitor",
                    {"local": conn.local_ip, "remote": conn.remote_ip, "port": conn.remote_port, "pid": conn.pid}
                )
        
        self._connections_state = {cid: c for cid, c in zip(current_ids, current_conns)}
        return stats
