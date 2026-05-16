"""
Main Orchestrator for Endpoint Security Framework
"""

import signal
import sys
import os
from typing import Dict, Any, Optional

from .utils.config_loader import ConfigLoader
from .core.logger import ESFLogger, get_logger
from .core.process_monitor import ProcessMonitor
from .core.file_integrity import FileIntegrityMonitor
from .core.anomaly_detector import AnomalyDetector
from .core.threat_remediator import ThreatRemediator
from .modules.network_monitor import NetworkMonitor
from .modules.user_monitor import UserMonitor
from .modules.service_hardener import ServiceHardener
from .utils.system_utils import get_system_info, ensure_directory

class ESFOrchestrator:
    def __init__(self, config_path: str = "/etc/esf/config.yaml"):
        self.config_path = config_path
        self._setup_directories()
        
        # Load Config
        self.loader = ConfigLoader(config_path)
        try:
            self.config = self.loader.load()
        except FileNotFoundError:
            print(f"Error: Config file not found at {config_path}")
            sys.exit(1)
            
        # Setup Logger
        self.logger = ESFLogger(
            log_dir=self.config.paths.get("log_dir", "/var/log/esf"),
            log_level=self.config.general.get("log_level", "INFO"),
            config=self.config.raw_config
        )
        self.main_logger = get_logger("main", self.config.raw_config)
        
        self.main_logger.info("Initializing Endpoint Security Framework...")
        
        # Initialize Modules
        self.process_monitor = ProcessMonitor(
            self.loader.get_section("process_monitor"),
            logger=self.logger
        )
        
        self.file_integrity = FileIntegrityMonitor(
            self.loader.get_section("file_integrity"),
            self.config.paths,
            logger=self.logger
        )
        
        self.anomaly_detector = AnomalyDetector(
            self.loader.get_section("anomaly_detection"),
            logger=self.logger
        )
        
        self.threat_remediator = ThreatRemediator(
            self.loader.get_section("remediation"),
            self.config.paths,
            logger=self.logger
        )
        
        self.network_monitor = NetworkMonitor(
            self.config.raw_config,
            logger=self.logger
        )
        
        self.user_monitor = UserMonitor(
            self.config.raw_config,
            logger=self.logger
        )
        
        self.service_hardener = ServiceHardener(
            self.config.raw_config,
            logger=self.logger
        )
        
        # Wire up callbacks
        self.anomaly_detector.add_callback(self._handle_anomaly)

    def _setup_directories(self):
        # Fallback directory creation for local testing
        dirs = [
            "/var/log/esf", "/var/lib/esf", "/var/lib/esf/alerts",
            "/var/lib/esf/baselines", "/var/lib/esf/quarantine"
        ]
        for d in dirs:
            try:
                ensure_directory(d)
            except PermissionError:
                # Fallback to local directory if not root
                local_d = f"./esf_data/{d.split('/')[-1]}"
                ensure_directory(local_d)

    def _handle_anomaly(self, anomaly):
        """Callback when anomaly detector finds something."""
        if hasattr(anomaly, 'details'):
            # Auto-remediate if configured
            self.threat_remediator.handle_threat(
                threat_type=anomaly.anomaly_type,
                target=str(anomaly.details.get('pid') or anomaly.details.get('source_ip') or 'unknown'),
                details=anomaly.details
            )

    def get_system_info(self) -> Dict[str, Any]:
        info = get_system_info()
        return {
            "hostname": info.hostname,
            "os_name": info.os_name,
            "kernel_version": info.kernel_version,
            "is_debian_based": info.is_debian_based
        }

    def start_all(self):
        """Start all monitoring threads."""
        self.main_logger.info("Starting all monitoring modules...")
        self.process_monitor.start()
        self.anomaly_detector.start()
        self.network_monitor.start()
        self.user_monitor.start()
        # File integrity usually runs on interval, not continuous thread by default
        # self.file_integrity.start()

    def stop_all(self):
        """Stop all monitoring threads."""
        self.main_logger.info("Stopping all modules...")
        self.process_monitor.stop()
        self.anomaly_detector.stop()
        self.network_monitor.stop()
        self.user_monitor.stop()
        self.logger.shutdown()

    def run_single_cycle(self):
        """Run one scan cycle of all modules."""
        self.process_monitor.scan_once()
        self.anomaly_detector._detect_anomalies()
        self.network_monitor.scan()
        self.user_monitor.check_users()
        self.file_integrity.check_integrity()

def main():
    """Entry point for the script."""
    import argparse
    parser = argparse.ArgumentParser(description="Endpoint Security Framework")
    parser.add_argument('--config', '-c', default='/etc/esf/config.yaml', help='Config file path')
    parser.add_argument('--scan', action='store_true', help='Run single scan and exit')
    
    args = parser.parse_args()
    
    esf = ESFOrchestrator(args.config)
    
    if args.scan:
        esf.run_single_cycle()
    else:
        # Default: start as daemon
        def signal_handler(sig, frame):
            esf.stop_all()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        esf.start_all()
        signal.pause() # Wait indefinitely

if __name__ == '__main__':
    main()
