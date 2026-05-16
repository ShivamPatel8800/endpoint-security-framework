"""
File Integrity Monitoring Module for the Endpoint Security Framework.

Provides file integrity verification using cryptographic hashes to detect
unauthorized modifications to critical system files.
"""

import os
import json
import time
import threading
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict
import fnmatch

from ..utils.system_utils import (
    calculate_file_hash,
    get_file_info,
    FileInfo,
    ensure_directory
)
from .logger import (
    ESFLogger,
    AlertSeverity,
    AlertCategory,
    get_logger
)


@dataclass
class FileRecord:
    """Record of a file's integrity state."""
    path: str
    hash: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    first_seen: str
    last_checked: str
    changes: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class IntegrityAlert:
    """Alert for file integrity violation."""
    timestamp: datetime
    file_path: str
    change_type: str  # modified, deleted, created, permissions_changed, owner_changed
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    severity: str = "high"
    description: str = ""


class FileIntegrityMonitor:
    """
    Monitors file integrity using cryptographic hashes.
    
    Features:
    - SHA256 hash verification (configurable)
    - Recursive directory monitoring
    - Pattern-based exclusion
    - Baseline creation and comparison
    - Change tracking and alerting
    - SQLite database for baseline storage
    """
    
    DEFAULT_DIRECTORIES = [
        "/etc",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/lib",
        "/usr/lib",
        "/lib/x86_64-linux-gnu",
        "/boot",
    ]
    
    DEFAULT_EXCLUDES = [
        "*.log",
        "*.pid",
        "/etc/ld.so.cache",
        "/etc/mtab",
        "/etc/adjtime",
        "/etc/blkid.tab*",
        "/etc/udev/rules.d/70-persistent-*",
    ]
    
    def __init__(
        self,
        config: Dict[str, Any],
        paths_config: Dict[str, str],
        logger: Optional[ESFLogger] = None
    ):
        """
        Initialize File Integrity Monitor.
        
        Args:
            config: File integrity configuration
            paths_config: Paths configuration
            logger: Optional logger instance
        """
        self._config = config
        self._paths_config = paths_config
        self._logger = logger or get_logger("file_integrity")
        
        # Configuration
        self._enabled = config.get("enabled", True)
        self._scan_interval = config.get("scan_interval", 300)
        self._hash_algorithm = config.get("hash_algorithm", "sha256")
        self._baseline_dir = paths_config.get("baseline_dir", "/var/lib/esf/baselines")
        
        # Parse monitored directories
        self._monitor_dirs = self._parse_monitor_dirs()
        
        # Parse exclusions
        self._excludes = set(self.DEFAULT_EXCLUDES)
        self._excludes.update(config.get("exclude_patterns", []))
        
        # Alert on changes
        self._alert_on_changes = set(config.get("alert_on_changes", [
            "modified", "deleted", "created", "permissions_changed", "owner_changed"
        ]))
        
        # State
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._baseline: Dict[str, FileRecord] = {}
        self._alerts: List[IntegrityAlert] = []
        self._callbacks: List[callable] = []
        self._lock = threading.RLock()
        self._db_path = paths_config.get("db_dir", "/var/lib/esf") + "/file_integrity.db"
        self._baseline_loaded = False
        
        # Ensure directories exist
        ensure_directory(self._baseline_dir)
        ensure_directory(os.path.dirname(self._db_path))
    
    def _parse_monitor_dirs(self) -> List[Dict[str, Any]]:
        """Parse monitor directories from config."""
        dirs = []
        
        for dir_config in self._config.get("monitor_directories", []):
            if isinstance(dir_config, dict):
                dirs.append({
                    "path": dir_config.get("path"),
                    "recursive": dir_config.get("recursive", True),
                    "file_types": dir_config.get("file_types", ["*"])
                })
            elif isinstance(dir_config, str):
                dirs.append({
                    "path": dir_config,
                    "recursive": True,
                    "file_types": ["*"]
                })
        
        # Add defaults if none configured
        if not dirs:
            for path in self.DEFAULT_DIRECTORIES:
                if os.path.exists(path):
                    dirs.append({
                        "path": path,
                        "recursive": True,
                        "file_types": ["*"]
                    })
        
        return dirs
    
    def _is_excluded(self, filepath: str) -> bool:
        """Check if file path matches exclusion patterns."""
        for pattern in self._excludes:
            if fnmatch.fnmatch(filepath, pattern):
                return True
            if fnmatch.fnmatch(os.path.basename(filepath), pattern):
                return True
        return False
    
    def _should_monitor_file(self, filepath: str, dir_config: Dict) -> bool:
        """Check if a specific file should be monitored."""
        # Check exclusions
        if self._is_excluded(filepath):
            return False
        
        # Check file types
        file_types = dir_config.get("file_types", ["*"])
        basename = os.path.basename(filepath)
        
        for pattern in file_types:
            if fnmatch.fnmatch(basename, pattern):
                return True
        
        return False
    
    def create_baseline(self) -> Dict[str, int]:
        """
        Create a new baseline of file hashes.
        
        Returns:
            Dictionary with statistics
        """
        self._logger.info("Creating file integrity baseline...")
        
        stats = {
            "files_scanned": 0,
            "files_added": 0,
            "errors": 0,
            "directories": 0
        }
        
        new_baseline: Dict[str, FileRecord] = {}
        now = datetime.now().isoformat()
        
        for dir_config in self._monitor_dirs:
            dir_path = dir_config["path"]
            recursive = dir_config["recursive"]
            
            if not os.path.exists(dir_path):
                self._logger.warning(f"Directory does not exist: {dir_path}")
                continue
            
            stats["directories"] += 1
            
            try:
                if recursive:
                    for root, dirs, files in os.walk(dir_path, followlinks=False):
                        # Skip hidden directories
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            stats["files_scanned"] += 1
                            
                            if not self._should_monitor_file(filepath, dir_config):
                                continue
                            
                            record = self._create_file_record(filepath, now)
                            if record:
                                new_baseline[filepath] = record
                                stats["files_added"] += 1
                else:
                    for item in os.listdir(dir_path):
                        filepath = os.path.join(dir_path, item)
                        if os.path.isfile(filepath):
                            stats["files_scanned"] += 1
                            
                            if not self._should_monitor_file(filepath, dir_config):
                                continue
                            
                            record = self._create_file_record(filepath, now)
                            if record:
                                new_baseline[filepath] = record
                                stats["files_added"] += 1
                                
            except PermissionError as e:
                self._logger.warning(f"Permission denied accessing: {dir_path}")
                stats["errors"] += 1
            except Exception as e:
                self._logger.error(f"Error scanning {dir_path}: {e}")
                stats["errors"] += 1
        
        # Save baseline
        with self._lock:
            self._baseline = new_baseline
            self._save_baseline()
        
        self._logger.info(
            f"Baseline created: {stats['files_added']} files in "
            f"{stats['directories']} directories"
        )
        
        return stats
    
    def _create_file_record(self, filepath: str, timestamp: str) -> Optional[FileRecord]:
        """Create a FileRecord for a file."""
        try:
            file_hash = calculate_file_hash(filepath, self._hash_algorithm)
            if file_hash is None:
                return None
            
            stat_info = os.stat(filepath, follow_symlinks=False)
            
            return FileRecord(
                path=filepath,
                hash=file_hash,
                size=stat_info.st_size,
                mode=stat_info.st_mode,
                uid=stat_info.st_uid,
                gid=stat_info.st_gid,
                mtime=stat_info.st_mtime,
                first_seen=timestamp,
                last_checked=timestamp
            )
        except (OSError, IOError) as e:
            self._logger.debug(f"Cannot record file {filepath}: {e}")
            return None
    
    def _save_baseline(self) -> None:
        """Save baseline to file."""
        baseline_path = os.path.join(self._baseline_dir, "baseline.json")
        
        data = {
            "created": datetime.now().isoformat(),
            "algorithm": self._hash_algorithm,
            "file_count": len(self._baseline),
            "files": {
                path: asdict(record) for path, record in self._baseline.items()
            }
        }
        
        try:
            with open(baseline_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self._logger.error(f"Failed to save baseline: {e}")
    
    def _load_baseline(self) -> bool:
        """Load baseline from file."""
        baseline_path = os.path.join(self._baseline_dir, "baseline.json")
        
        if not os.path.exists(baseline_path):
            self._logger.warning("No baseline file found. Run 'esf --baseline create' first.")
            return False
        
        try:
            with open(baseline_path, "r") as f:
                data = json.load(f)
            
            self._baseline = {
                path: FileRecord(**record)
                for path, record in data.get("files", {}).items()
            }
            
            self._baseline_loaded = True
            self._logger.info(f"Loaded baseline with {len(self._baseline)} files")
            return True
            
        except Exception as e:
            self._logger.error(f"Failed to load baseline: {e}")
            return False
    
    def check_integrity(self) -> List[IntegrityAlert]:
        """
        Check current file integrity against baseline.
        
        Returns:
            List of integrity alerts
        """
        if not self._baseline_loaded:
            if not self._load_baseline():
                return []
        
        alerts = []
        now = datetime.now().isoformat()
        current_files: Set[str] = set()
        
        # Check existing files for modifications
        for dir_config in self._monitor_dirs:
            dir_path = dir_config["path"]
            recursive = dir_config["recursive"]
            
            if not os.path.exists(dir_path):
                continue
            
            try:
                if recursive:
                    for root, dirs, files in os.walk(dir_path, followlinks=False):
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            current_files.add(filepath)
                            
                            if self._is_excluded(filepath):
                                continue
                            
                            alert = self._check_file(filepath, now)
                            if alert:
                                alerts.append(alert)
                else:
                    for item in os.listdir(dir_path):
                        filepath = os.path.join(dir_path, item)
                        if os.path.isfile(filepath):
                            current_files.add(filepath)
                            
                            if self._is_excluded(filepath):
                                continue
                            
                            alert = self._check_file(filepath, now)
                            if alert:
                                alerts.append(alert)
                                
            except PermissionError:
                continue
            except Exception as e:
                self._logger.error(f"Error checking {dir_path}: {e}")
        
        # Check for deleted files
        if "deleted" in self._alert_on_changes:
            baseline_paths = set(self._baseline.keys())
            deleted_files = baseline_paths - current_files
            
            for filepath in deleted_files:
                if not self._is_excluded(filepath):
                    alert = IntegrityAlert(
                        timestamp=datetime.now(),
                        file_path=filepath,
                        change_type="deleted",
                        old_value=self._baseline[filepath].hash,
                        new_value=None,
                        severity="high",
                        description=f"Monitored file deleted: {filepath}"
                    )
                    alerts.append(alert)
                    
                    self._logger.log_alert(
                        AlertSeverity.HIGH,
                        AlertCategory.FILE_INTEGRITY,
                        "File Deleted",
                        alert.description,
                        "file_integrity",
                        {"path": filepath, "previous_hash": self._baseline[filepath].hash},
                        "Investigate why the file was deleted. Restore from backup if necessary."
                    )
        
        # Store alerts
        with self._lock:
            self._alerts.extend(alerts)
            # Keep last 1000 alerts
            if len(self._alerts) > 1000:
                self._alerts = self._alerts[-1000:]
        
        return alerts
    
    def _check_file(self, filepath: str, now: str) -> Optional[IntegrityAlert]:
        """Check a single file against baseline."""
        # New file (not in baseline)
        if filepath not in self._baseline:
            if "created" in self._alert_on_changes:
                record = self._create_file_record(filepath, now)
                if record:
                    alert = IntegrityAlert(
                        timestamp=datetime.now(),
                        file_path=filepath,
                        change_type="created",
                        old_value=None,
                        new_value=record.hash,
                        severity="medium",
                        description=f"New file created in monitored directory: {filepath}"
                    )
                    
                    self._logger.log_alert(
                        AlertSeverity.MEDIUM,
                        AlertCategory.FILE_INTEGRITY,
                        "New File Created",
                        alert.description,
                        "file_integrity",
                        {"path": filepath, "hash": record.hash, "size": record.size},
                        "Verify if this file is legitimate."
                    )
                    
                    # Add to baseline
                    with self._lock:
                        self._baseline[filepath] = record
                    
                    return alert
            return None
        
        # Existing file - check for changes
        old_record = self._baseline[filepath]
        
        try:
            stat_info = os.stat(filepath, follow_symlinks=False)
            current_hash = calculate_file_hash(filepath, self._hash_algorithm)
            
            if current_hash is None:
                return None
            
            # Check for content modification
            if current_hash != old_record.hash and "modified" in self._alert_on_changes:
                alert = IntegrityAlert(
                    timestamp=datetime.now(),
                    file_path=filepath,
                    change_type="modified",
                    old_value=old_record.hash,
                    new_value=current_hash,
                    severity="high",
                    description=f"File modified: {filepath}"
                )
                
                self._logger.log_alert(
                    AlertSeverity.HIGH,
                    AlertCategory.FILE_INTEGRITY,
                    "File Modified",
                    alert.description,
                    "file_integrity",
                    {
                        "path": filepath,
                        "old_hash": old_record.hash,
                        "new_hash": current_hash,
                        "old_size": old_record.size,
                        "new_size": stat_info.st_size
                    },
                    "Verify the modification was authorized. Check package integrity with 'dpkg --verify'."
                )
                
                # Update baseline
                with self._lock:
                    old_record.changes.append({
                        "time": now,
                        "type": "modified",
                        "old_hash": old_record.hash,
                        "new_hash": current_hash
                    })
                    old_record.hash = current_hash
                    old_record.size = stat_info.st_size
                    old_record.mtime = stat_info.st_mtime
                    old_record.last_checked = now
                
                return alert
            
            # Check for permission changes
            if stat_info.st_mode != old_record.mode and "permissions_changed" in self._alert_on_changes:
                alert = IntegrityAlert(
                    timestamp=datetime.now(),
                    file_path=filepath,
                    change_type="permissions_changed",
                    old_value=oct(old_record.mode),
                    new_value=oct(stat_info.st_mode),
                    severity="medium",
                    description=f"File permissions changed: {filepath}"
                )
                
                self._logger.log_alert(
                    AlertSeverity.MEDIUM,
                    AlertCategory.FILE_INTEGRITY,
                    "Permissions Changed",
                    alert.description,
                    "file_integrity",
                    {
                        "path": filepath,
                        "old_mode": oct(old_record.mode),
                        "new_mode": oct(stat_info.st_mode)
                    },
                    "Verify the permission change was authorized."
                )
                
                with self._lock:
                    old_record.mode = stat_info.st_mode
                    old_record.last_checked = now
                
                return alert
            
            # Check for owner changes
            if (stat_info.st_uid != old_record.uid or 
                stat_info.st_gid != old_record.gid) and "owner_changed" in self._alert_on_changes:
                alert = IntegrityAlert(
                    timestamp=datetime.now(),
                    file_path=filepath,
                    change_type="owner_changed",
                    old_value=f"{old_record.uid}:{old_record.gid}",
                    new_value=f"{stat_info.st_uid}:{stat_info.st_gid}",
                    severity="high",
                    description=f"File owner changed: {filepath}"
                )
                
                self._logger.log_alert(
                    AlertSeverity.HIGH,
                    AlertCategory.FILE_INTEGRITY,
                    "Owner Changed",
                    alert.description,
                    "file_integrity",
                    {
                        "path": filepath,
                        "old_owner": f"{old_record.uid}:{old_record.gid}",
                        "new_owner": f"{stat_info.st_uid}:{stat_info.st_gid}"
                    },
                    "Verify the owner change was authorized. Could indicate compromise."
                )
                
                with self._lock:
                    old_record.uid = stat_info.st_uid
                    old_record.gid = stat_info.st_gid
                    old_record.last_checked = now
                
                return alert
            
            # Update last checked time
            with self._lock:
                old_record.last_checked = now
            
        except (OSError, IOError) as e:
            self._logger.debug(f"Cannot check file {filepath}: {e}")
        
        return None
    
    def start(self) -> None:
        """Start continuous monitoring."""
        if not self._enabled:
            self._logger.warning("File integrity monitoring is disabled")
            return
        
        if self._running:
            self._logger.warning("File integrity monitor is already running")
            return
        
        # Load baseline
        if not self._load_baseline():
            self._logger.warning("Cannot start monitoring without baseline")
            return
        
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="FileIntegrityMonitor",
            daemon=True
        )
        self._monitor_thread.start()
        self._logger.info("File integrity monitor started")
    
    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=30)
        
        # Save updated baseline
        if self._baseline:
            self._save_baseline()
        
        self._logger.info("File integrity monitor stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                self.check_integrity()
                time.sleep(self._scan_interval)
            except Exception as e:
                self._logger.error(f"Error in integrity monitor loop: {e}")
                time.sleep(10)
    
    def add_alert_callback(self, callback: callable) -> None:
        """Add callback for alerts."""
        self._callbacks.append(callback)
    
    def get_alerts(self, limit: int = 100, change_type: Optional[str] = None) -> List[IntegrityAlert]:
        """Get stored alerts."""
        with self._lock:
            alerts = self._alerts.copy()
        
        if change_type:
            alerts = [a for a in alerts if a.change_type == change_type]
        
        return alerts[-limit:]
    
    def get_baseline_stats(self) -> Dict[str, Any]:
        """Get baseline statistics."""
        with self._lock:
            return {
                "total_files": len(self._baseline),
                "algorithm": self._hash_algorithm,
                "monitored_directories": [d["path"] for d in self._monitor_dirs],
                "exclusion_patterns": list(self._excludes),
                "total_changes_tracked": sum(
                    len(r.changes) for r in self._baseline.values()
                )
            }
    
    def get_file_record(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Get baseline record for a specific file."""
        with self._lock:
            record = self._baseline.get(filepath)
            if record:
                return asdict(record)
        return None
    
    def verify_file(self, filepath: str) -> Dict[str, Any]:
        """
        Verify a single file against baseline.
        
        Returns:
            Dictionary with verification result
        """
        result = {
            "path": filepath,
            "status": "unknown",
            "details": {}
        }
        
        with self._lock:
            record = self._baseline.get(filepath)
        
        if record is None:
            result["status"] = "not_in_baseline"
            return result
        
        if not os.path.exists(filepath):
            result["status"] = "missing"
            result["details"]["expected_hash"] = record.hash
            return result
        
        current_hash = calculate_file_hash(filepath, self._hash_algorithm)
        if current_hash is None:
            result["status"] = "error"
            return result
        
        if current_hash == record.hash:
            result["status"] = "valid"
            result["details"]["hash"] = current_hash
        else:
            result["status"] = "modified"
            result["details"]["expected_hash"] = record.hash
            result["details"]["actual_hash"] = current_hash
        
        return result
