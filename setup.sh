#!/bin/bash
#
# Endpoint Security Hardening Framework - Installation Script
# Compatible with Debian-based systems (Ubuntu, Debian, Linux Mint, etc.)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/endpoint-security-framework"
LOG_DIR="/var/log/esf"
DB_DIR="/var/lib/esf"
ALERT_DIR="/var/lib/esf/alerts"
CONFIG_DIR="/etc/esf"
SERVICE_USER="esf"
SERVICE_NAME="esf"

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Detect Debian-based OS
check_os() {
    print_info "Checking operating system compatibility..."
    
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This script is designed for Debian-based systems only"
        exit 1
    fi
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_info "Detected: $NAME $VERSION"
    fi
    
    print_success "OS compatibility verified"
}

# Install system dependencies
install_dependencies() {
    print_info "Installing system dependencies..."
    
    apt-get update -qq
    
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        libffi-dev \
        libssl-dev \
        gcc \
        inotify-tools \
        libyaml-dev \
        psmisc \
        net-tools \
        iproute2 \
        iptables \
        libpcap-dev \
        aide-common \
        clamav \
        clamav-daemon \
        rkhunter \
        lynis \
        auditd \
        audispd-plugins \
        libaudit-dev \
        systemd \
        curl \
        wget \
        jq \
        git
    
    print_success "System dependencies installed"
}

# Create service user
create_service_user() {
    print_info "Creating service user..."
    
    if id "$SERVICE_USER" &>/dev/null; then
        print_warning "Service user $SERVICE_USER already exists"
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
        print_success "Service user $SERVICE_USER created"
    fi
}

# Create directories
create_directories() {
    print_info "Creating application directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DB_DIR"
    mkdir -p "$ALERT_DIR"
    mkdir -p "$CONFIG_DIR"
    
    print_success "Directories created"
}

# Set permissions
set_permissions() {
    print_info "Setting permissions..."
    
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$LOG_DIR"
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$DB_DIR"
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$ALERT_DIR"
    chown -R root:"$SERVICE_USER" "$CONFIG_DIR"
    chmod 750 "$INSTALL_DIR"
    chmod 750 "$LOG_DIR"
    chmod 750 "$DB_DIR"
    chmod 750 "$ALERT_DIR"
    chmod 750 "$CONFIG_DIR"
    
    print_success "Permissions set"
}

# Setup Python virtual environment
setup_python_env() {
    print_info "Setting up Python virtual environment..."
    
    python3 -m venv "$INSTALL_DIR/venv"
    
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
    
    if [[ -f "$INSTALL_DIR/requirements.txt" ]]; then
        "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
    fi
    
    print_success "Python environment configured"
}

# Copy configuration files
copy_config() {
    print_info "Setting up configuration files..."
    
    if [[ -f "$INSTALL_DIR/config/config.yaml" ]]; then
        cp "$INSTALL_DIR/config/config.yaml" "$CONFIG_DIR/config.yaml"
        
        # Set secure permissions on config
        chmod 640 "$CONFIG_DIR/config.yaml"
        chown root:"$SERVICE_USER" "$CONFIG_DIR/config.yaml"
    fi
    
    print_success "Configuration files copied"
}

# Setup systemd service
setup_systemd() {
    print_info "Setting up systemd service..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Endpoint Security Framework
Documentation=https://github.com/yourorg/endpoint-security-framework
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/src/main.py --config ${CONFIG_DIR}/config.yaml
Restart=on-failure
RestartSec=10
TimeoutStartSec=60
WorkingDirectory=${INSTALL_DIR}

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${LOG_DIR} ${DB_DIR} ${ALERT_DIR}

# Resource limits
LimitNOFILE=65536
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

    # Create timer for periodic scans
    cat > "/etc/systemd/system/${SERVICE_NAME}-scan.timer" << EOF
[Unit]
Description=Run ESF periodic security scans

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

    cat > "/etc/systemd/system/${SERVICE_NAME}-scan.service" << EOF
[Unit]
Description=ESF Periodic Security Scan

[Service]
Type=oneshot
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/src/main.py --config ${CONFIG_DIR}/config.yaml --scan
WorkingDirectory=${INSTALL_DIR}
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"
    systemctl enable "${SERVICE_NAME}-scan.timer"
    
    print_success "Systemd service configured"
}

# Setup audit rules
setup_audit() {
    print_info "Configuring audit rules..."
    
    cat > "/etc/audit/rules.d/esf.rules" << 'EOF'
## Endpoint Security Framework Audit Rules

# Monitor file modifications in critical directories
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege

# Monitor systemd and service configurations
-w /etc/systemd/ -p wa -k system_config
-w /lib/systemd/ -p wa -k system_config

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Monitor cron jobs
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor binary modifications
-w /usr/bin/ -p wa -k binaries
-w /usr/sbin/ -p wa -k binaries
-w /bin/ -p wa -k binaries
-w /sbin/ -p wa -k binaries

# Monitor library modifications
-w /usr/lib/ -p wa -k libraries
-w /lib/ -p wa -k libraries
-w /lib/x86_64-linux-gnu/ -p wa -k libraries

# Monitor temporary directories for executable files
-w /tmp/ -p x -k tmp_exec
-w /var/tmp/ -p x -k tmp_exec
-w /dev/shm/ -p x -k tmp_exec

# Monitor network configuration
-w /etc/network/ -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
-w /etc/hosts -p wa -k network_config

# Monitor PAM configuration
-w /etc/pam.d/ -p wa -k pam_config

# Monitor kernel modules
-w /etc/modprobe.d/ -p wa -k kernel_modules
-w /lib/modules/ -p wa -k kernel_modules

# Monitor login events
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/run/utmp -p wa -k logins

# Monitor package manager
-w /var/lib/dpkg/ -p wa -k package_manager
-w /var/lib/apt/ -p wa -k package_manager

# Monitor boot configuration
-w /boot/ -p wa -k boot_config
-w /etc/default/grub -p wa -k boot_config
EOF

    # Append to existing rules to preserve system rules
    augenrules --load 2>/dev/null || true
    
    print_success "Audit rules configured"
}

# Initialize AIDE database (FIXED VERSION)
setup_aide() {
    print_info "Configuring AIDE (skipping heavy database init for faster install)..."
    
    # Write a custom, optimized AIDE config that ignores high-churn directories
    # This prevents AIDE from hanging on /var/log or /dev during initialization
    cat > "/etc/aide/aide.conf" << 'EOF'
# Custom ESF AIDE Configuration
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
database_new=file:/var/lib/aide/aide.db.new

# Define groups
NORMAL = p+i+n+u+g+s+m+c+sha256
DIRS = p+i+n+u+g+s
PERM = p+i+u+g+s
LOG = p+i+n+u+g

# What to monitor strictly
/var/log/esf LOG
/etc NORMAL
/bin NORMAL
/sbin NORMAL
/usr/bin NORMAL
/usr/sbin NORMAL
/lib NORMAL
/usr/lib NORMAL
/boot NORMAL
/root NORMAL

# Explicitly ignore high-churn directories to prevent hanging
!/var/log
!/var/lib/dpkg
!/var/cache
!/dev
!/proc
!/sys
!/run
!/tmp
!/var/tmp
EOF

    print_success "AIDE configured (Run 'sudo aideinit -y -f' manually later if needed)"
}

# Setup ClamAV
setup_clamav() {
    print_info "Setting up ClamAV..."
    
    # Stop service if running to prevent freshclam db lock errors
    systemctl stop clamav-freshclam 2>/dev/null || true
    
    # Update definitions (allow failure in case of offline networks)
    freshclam 2>/dev/null || {
        print_warning "ClamAV database update failed or timed out. It will retry automatically."
    }
    
    # Enable and start services
    systemctl enable clamav-daemon 2>/dev/null || true
    systemctl enable clamav-freshclam 2>/dev/null || true
    systemctl start clamav-freshclam 2>/dev/null || true
    
    print_success "ClamAV configured"
}

# Create CLI symlink
create_cli_symlink() {
    print_info "Creating CLI command..."
    
    cat > "/usr/local/bin/esf" << EOF
#!/bin/bash
 ${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/src/cli.py "\$@"
EOF
    
    chmod +x "/usr/local/bin/esf"
    
    print_success "CLI command 'esf' created"
}

# Create baseline
create_baseline() {
    print_info "Attempting to create initial security baseline..."
    
    if [[ -f "$INSTALL_DIR/src/cli.py" ]]; then
        # Run baseline creation using the Python CLI
        ${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/src/cli.py -c ${CONFIG_DIR}/config.yaml baseline create 2>/dev/null || {
            print_warning "Automatic baseline creation failed. Please run manually: sudo esf baseline create"
        }
    else
        print_warning "Python CLI not found. Skipping automatic baseline."
    fi
    
    print_success "Baseline setup attempted"
}

# Post-installation summary
print_summary() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}Endpoint Security Framework Installation Complete${NC}"
    echo "=============================================="
    echo ""
    echo "Installation Details:"
    echo "  - Install Directory: $INSTALL_DIR"
    echo "  - Configuration: $CONFIG_DIR/config.yaml"
    echo "  - Logs: $LOG_DIR/"
    echo "  - Database: $DB_DIR/"
    echo "  - Alerts: $ALERT_DIR/"
    echo ""
    echo "Usage:"
    echo "  esf --help                    Show help"
    echo "  esf status                    Show framework status"
    echo "  esf scan                      Run security scan"
    echo "  esf baseline create           Create new baseline"
    echo "  esf baseline verify           Check file integrity"
    echo "  esf threats                   List detected threats"
    echo "  esf monitor --continuous      Start real-time monitoring"
    echo ""
    echo "Service Control:"
    echo "  systemctl start esf           Start the service"
    echo "  systemctl stop esf            Stop the service"
    echo "  systemctl status esf          Check service status"
    echo "  journalctl -u esf -f          View live logs"
    echo ""
    echo "Manual Steps Required:"
    echo "  1. Review and customize $CONFIG_DIR/config.yaml"
    echo "  2. Run 'sudo esf baseline create' to finalize initial baseline"
    echo "  3. Start the service: 'sudo systemctl start esf'"
    echo ""
    echo "=============================================="
}

# Main installation process
main() {
    echo ""
    echo "=============================================="
    echo -e "${BLUE}Endpoint Security Framework Installer${NC}"
    echo "=============================================="
    echo ""
    
    check_root
    check_os
    install_dependencies
    create_service_user
    create_directories
    set_permissions
    setup_python_env
    copy_config
    setup_systemd
    setup_audit
    setup_aide
    setup_clamav
    create_cli_symlink
    create_baseline
    print_summary
}

# Run main function
main "$@"
