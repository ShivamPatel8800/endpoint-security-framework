"""
System utility functions for the Endpoint Security Framework.

Provides helper functions for system operations, file operations,
and security-related utilities.
"""

import os
import hashlib
import subprocess
import socket
import platform
import re
import pwd
import grp
import stat
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import functools


@dataclass
class ProcessInfo:
    """Information about a system process."""
    pid: int
    name: str
    cmdline: List[str]
    exe: Optional[str]
    cwd: Optional[str]
    username: str
    uid: int
    gid: int
    cpu_percent: float
    memory_percent: float
    create_time: float
    status: str
    num_threads: int
    connections: int = 0
    open_files: int = 0


@dataclass
class FileInfo:
    """Information about a file."""
    path: str
    size: int
    hash: str
    mode: int
    uid: int
    gid: int
    mtime: float
    atime: float
    ctime: float
    is_symlink: bool
    symlink_target: Optional[str] = None


@dataclass
class ConnectionInfo:
    """Information about a network connection."""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    status: str
    pid: int
    process_name: str


@dataclass
class UserInfo:
    """Information about a system user."""
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    last_login: Optional[datetime]
    is_system: bool
    has_password: bool


@dataclass
class SystemInfo:
    """Overall system information."""
    hostname: str
    os_name: str
    os_version: str
    kernel_version: str
    architecture: str
    cpu_count: int
    total_memory_mb: int
    uptime_seconds: float
    is_debian_based: bool


def get_system_info() -> SystemInfo:
    """Gather system information."""
    try:
        import distro
        os_name = distro.name()
        os_version = distro.version()
    except ImportError:
        os_name = platform.linux_distribution()[0] if hasattr(platform, 'linux_distribution') else "Linux"
        os_version = platform.version()
    
    # Check if Debian-based
    is_debian = os.path.exists("/etc/debian_version")
    
    # Get uptime
    uptime = 0.0
    try:
        with open("/proc/uptime", "r") as f:
            uptime = float(f.read().split()[0])
    except Exception:
        pass
    
    # Get memory
    total_memory_mb = 0
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    total_memory_mb = int(line.split()[1]) // 1024
                    break
    except Exception:
        pass
    
    return SystemInfo(
        hostname=socket.gethostname(),
        os_name=os_name,
        os_version=os_version,
        kernel_version=platform.release(),
        architecture=platform.machine(),
        cpu_count=os.cpu_count() or 1,
        total_memory_mb=total_memory_mb,
        uptime_seconds=uptime,
        is_debian_based=is_debian
    )


def calculate_file_hash(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """
    Calculate hash of a file.
    
    Args:
        filepath: Path to the file
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        Hash string or None if error
    """
    try:
        hasher = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (IOError, OSError, ValueError):
        return None


def get_file_info(filepath: str, hash_algorithm: str = "sha256") -> Optional[FileInfo]:
    """
    Get detailed information about a file.
    
    Args:
        filepath: Path to the file
        hash_algorithm: Algorithm for file hash
        
    Returns:
        FileInfo object or None if error
    """
    try:
        path = Path(filepath)
        stat_info = path.stat()
        
        is_symlink = path.is_symlink()
        symlink_target = None
        if is_symlink:
            try:
                symlink_target = os.readlink(filepath)
            except OSError:
                pass
        
        return FileInfo(
            path=str(path.absolute()),
            size=stat_info.st_size,
            hash=calculate_file_hash(filepath, hash_algorithm) or "",
            mode=stat_info.st_mode,
            uid=stat_info.st_uid,
            gid=stat_info.st_gid,
            mtime=stat_info.st_mtime,
            atime=stat_info.st_atime,
            ctime=stat_info.st_ctime,
            is_symlink=is_symlink,
            symlink_target=symlink_target
        )
    except (OSError, IOError):
        return None


def get_process_list() -> List[ProcessInfo]:
    """
    Get list of all running processes with detailed information.
    
    Returns:
        List of ProcessInfo objects
    """
    try:
        import psutil
    except ImportError:
        return []
    
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'cwd', 'username',
                                      'uids', 'gids', 'cpu_percent', 'memory_percent',
                                      'create_time', 'status', 'num_threads']):
        try:
            info = proc.info
            
            # Get username and IDs
            username = info.get('username') or 'unknown'
            uid = info.get('uids', [0, 0, 0])[1] if info.get('uids') else 0
            gid = info.get('gids', [0, 0, 0])[1] if info.get('gids') else 0
            
            # Get connections count
            connections = 0
            try:
                connections = len(proc.connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Get open files count
            open_files = 0
            try:
                open_files = len(proc.open_files())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            processes.append(ProcessInfo(
                pid=info['pid'],
                name=info.get('name') or 'unknown',
                cmdline=info.get('cmdline') or [],
                exe=info.get('exe'),
                cwd=info.get('cwd'),
                username=username,
                uid=uid,
                gid=gid,
                cpu_percent=info.get('cpu_percent', 0) or 0,
                memory_percent=info.get('memory_percent', 0) or 0,
                create_time=info.get('create_time', 0) or 0,
                status=info.get('status', 'unknown'),
                num_threads=info.get('num_threads', 0) or 0,
                connections=connections,
                open_files=open_files
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return processes


def get_network_connections() -> List[ConnectionInfo]:
    """
    Get list of all network connections.
    
    Returns:
        List of ConnectionInfo objects
    """
    try:
        import psutil
    except ImportError:
        return []
    
    connections = []
    
    for conn in psutil.net_connections(kind='inet'):
        try:
            # Get process name
            process_name = "unknown"
            pid = conn.pid or 0
            if pid:
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Parse addresses
            local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip = conn.raddr.ip if conn.raddr else "*"
            remote_port = conn.raddr.port if conn.raddr else 0
            
            connections.append(ConnectionInfo(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=conn.type.name if conn.type else "UNKNOWN",
                status=conn.status,
                pid=pid,
                process_name=process_name
            ))
        except Exception:
            continue
    
    return connections


def get_user_list() -> List[UserInfo]:
    """
    Get list of all system users.
    
    Returns:
        List of UserInfo objects
    """
    users = []
    
    for pwd_entry in pwd.getpwall():
        # Check if system user (UID < 1000 typically)
        is_system = pwd_entry.pw_uid < 1000
        
        # Check if user has password set
        has_password = False
        try:
            with open("/etc/shadow", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if parts[0] == pwd_entry.pw_name:
                        has_password = parts[1] not in ["!", "*", "!!", "", "x"]
                        break
        except (IOError, PermissionError):
            pass
        
        # Get last login time
        last_login = None
        try:
            import utmp
            for entry in utmp.getutmp():
                if entry.ut_user == pwd_entry.pw_name and entry.ut_type == 7:  # USER_PROCESS
                    last_login = datetime.fromtimestamp(entry.ut_tv.tv_sec)
                    break
        except (ImportError, Exception):
            pass
        
        users.append(UserInfo(
            username=pwd_entry.pw_name,
            uid=pwd_entry.pw_uid,
            gid=pwd_entry.pw_gid,
            home=pwd_entry.pw_dir,
            shell=pwd_entry.pw_shell,
            last_login=last_login,
            is_system=is_system,
            has_password=has_password
        ))
    
    return users


def get_listening_ports() -> List[Dict[str, Any]]:
    """
    Get list of all listening ports.
    
    Returns:
        List of dictionaries with port information
    """
    try:
        import psutil
    except ImportError:
        return []
    
    ports = []
    
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == "LISTEN":
            process_name = "unknown"
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            ports.append({
                "port": conn.laddr.port,
                "ip": conn.laddr.ip,
                "protocol": "TCP" if conn.type == 2 else "UDP",
                "pid": conn.pid,
                "process": process_name
            })
    
    return ports


def is_process_running(name: str) -> bool:
    """Check if a process with the given name is running."""
    try:
        import psutil
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == name:
                return True
        return False
    except ImportError:
        # Fallback to pgrep
        try:
            result = subprocess.run(
                ["pgrep", "-x", name],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False


def kill_process(pid: int, force: bool = False) -> bool:
    """
    Kill a process by PID.
    
    Args:
        pid: Process ID
        force: Use SIGKILL instead of SIGTERM
        
    Returns:
        True if successful, False otherwise
    """
    try:
        import psutil
        proc = psutil.Process(pid)
        proc.kill() if force else proc.terminate()
        return True
    except ImportError:
        signal = "-9" if force else "-15"
        result = subprocess.run(["kill", signal, str(pid)], capture_output=True)
        return result.returncode == 0
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def quarantine_file(filepath: str, quarantine_dir: str) -> Optional[str]:
    """
    Move a file to quarantine directory.
    
    Args:
        filepath: Path to the file to quarantine
        quarantine_dir: Quarantine directory path
        
    Returns:
        Path to quarantined file or None if error
    """
    try:
        path = Path(filepath)
        if not path.exists():
            return None
        
        # Create quarantine directory
        q_dir = Path(quarantine_dir)
        q_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique quarantine path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_path = q_dir / f"{timestamp}_{path.name}"
        
        # Move file
        shutil.move(str(path), str(quarantine_path))
        
        # Set restricted permissions
        quarantine_path.chmod(0o000)
        
        # Create metadata file
        metadata = {
            "original_path": str(path.absolute()),
            "quarantine_path": str(quarantine_path),
            "quarantine_time": datetime.now().isoformat(),
            "original_hash": calculate_file_hash(filepath) or "",
            "original_size": path.stat().st_size if path.exists() else 0
        }
        
        import json
        with open(f"{quarantine_path}.meta", "w") as f:
            json.dump(metadata, f, indent=2)
        
        return str(quarantine_path)
    except Exception:
        return None


def run_command(
    command: List[str],
    timeout: int = 60,
    shell: bool = False
) -> Tuple[int, str, str]:
    """
    Run a system command safely.
    
    Args:
        command: Command and arguments as list
        timeout: Command timeout in seconds
        shell: Whether to run through shell
        
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def check_debian_based() -> bool:
    """Check if the system is Debian-based."""
    return os.path.exists("/etc/debian_version")


def get_package_list() -> List[str]:
    """Get list of installed packages (Debian-based)."""
    returncode, stdout, _ = run_command(["dpkg", "-l"])
    if returncode == 0:
        packages = []
        for line in stdout.split("\n")[5:]:  # Skip header lines
            parts = line.split()
            if len(parts) >= 2:
                packages.append(parts[1])
        return packages
    return []


def is_package_installed(package: str) -> bool:
    """Check if a package is installed."""
    returncode, _, _ = run_command(["dpkg", "-s", package])
    return returncode == 0


def get_service_status(service: str) -> Dict[str, Any]:
    """
    Get status of a systemd service.
    
    Args:
        service: Service name
        
    Returns:
        Dictionary with service status information
    """
    returncode, stdout, stderr = run_command([
        "systemctl", "show", service,
        "--property=ActiveState,SubState,LoadState,MainPID"
    ])
    
    status = {
        "name": service,
        "active": False,
        "running": False,
        "loaded": False,
        "pid": None
    }
    
    if returncode == 0:
        for line in stdout.strip().split("\n"):
            if "=" in line:
                key, value = line.split("=", 1)
                if key == "ActiveState":
                    status["active"] = value == "active"
                elif key == "SubState":
                    status["running"] = value == "running"
                elif key == "LoadState":
                    status["loaded"] = value == "loaded"
                elif key == "MainPID":
                    status["pid"] = int(value) if value.isdigit() else None
    
    return status


def ensure_directory(path: str, mode: int = 0o750) -> bool:
    """
    Ensure a directory exists with proper permissions.
    
    Args:
        path: Directory path
        mode: Permission mode
        
    Returns:
        True if successful
    """
    try:
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        p.chmod(mode)
        return True
    except Exception:
        return False


def validate_path(path: str, allowed_base: Optional[str] = None) -> bool:
    """
    Validate a file path for security.
    
    Args:
        path: Path to validate
        allowed_base: Optional base directory to restrict to
        
    Returns:
        True if path is valid
    """
    # Normalize the path
    normalized = os.path.normpath(path)
    
    # Check for path traversal
    if ".." in normalized.split(os.sep):
        return False
    
    # Check if within allowed base if specified
    if allowed_base:
        allowed = os.path.normpath(allowed_base)
        if not normalized.startswith(allowed):
            return False
    
    return True


def format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format seconds to human readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.0f}m {seconds%60:.0f}s"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
    else:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        return f"{days}d {hours}h"
