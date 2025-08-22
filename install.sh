#!/bin/bash
# ONVIF Proxy Installation/Uninstallation Script
# This script installs, uninstalls, and configures the ONVIF Proxy system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/onvif-proxy"
SERVICE_USER="onvif-proxy"
LOG_DIR="/var/log/onvif-proxy"
SYSTEMD_DIR="/etc/systemd/system"
SUDOERS_FILE="/etc/sudoers.d/onvif-proxy"
CONTROL_SCRIPT="/usr/local/bin/onvif-proxy-ctl"

# Function to print colored output
print_status() {
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

stop_services_safely() {
    local services=(onvif-proxy-watchdog onvif-proxy-web onvif-proxy)
    for s in "${services[@]}"; do
        systemctl stop "$s" 2>/dev/null || true
    done
    # wait briefly for services to stop, then force kill if needed
    for s in "${services[@]}"; do
        for i in {1..10}; do
            if ! systemctl is-active --quiet "$s"; then
                break
            fi
            sleep 0.5
        done
        if systemctl is-active --quiet "$s"; then
            print_warning "Service $s still active, sending SIGTERM..."
            systemctl kill "$s" 2>/dev/null || true
            sleep 0.5
        fi
    done
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [install|uninstall]"
    echo ""
    echo "Commands:"
    echo "  install    Install ONVIF Proxy system"
    echo "  uninstall  Remove ONVIF Proxy system completely"
    echo ""
    echo "If no command is specified, 'install' is assumed."
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
       print_error "This script must be run as root (use sudo)"
       exit 1
    fi
}

# Get the directory where the script is located
get_script_dir() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
}

# Installation function
install_onvif_proxy() {
    print_status "Starting ONVIF Proxy installation..."
    
    # Stop services before installation to avoid conflicts while updating files
    print_status "Stopping ONVIF Proxy services before installation..."
    stop_services_safely

    # Update system packages
    print_status "Updating system packages..."
    apt-get update

    # Install required system packages
    print_status "Installing system dependencies..."
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        systemd \
        iproute2 \
        iputils-ping \
        net-tools \
        curl \
        wget \
        libxml2-dev \
        libxslt1-dev \
        python3-dev \
        isc-dhcp-client \
        ffmpeg

    # Install Python dependencies using system packages (more reliable)
    print_status "Installing Python dependencies..."
    apt-get install -y \
        python3-flask \
        python3-requests \
        python3-lxml \
        python3-opencv \
        python3-psutil \
        gunicorn

    # Install netifaces via pip with system package override
    print_status "Installing additional Python packages..."
    pip3 install netifaces --break-system-packages --root-user-action=ignore || {
        print_warning "Failed to install netifaces via pip, trying alternative method..."
        python3 -m pip install netifaces --break-system-packages --root-user-action=ignore
    }

    # Stop existing services before installation
    print_status "Stopping existing ONVIF Proxy services..."
    systemctl stop onvif-proxy-watchdog 2>/dev/null || true
    systemctl stop onvif-proxy-web 2>/dev/null || true
    systemctl stop onvif-proxy 2>/dev/null || true
    
    # Create service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        print_status "Creating service user: $SERVICE_USER"
        useradd --system --home-dir /var/lib/onvif-proxy --create-home --shell /bin/false $SERVICE_USER
    else
        print_status "Service user $SERVICE_USER already exists"
    fi

    # Create installation directory
    print_status "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"

    # Set proper permissions
    print_status "Setting file permissions..."
    chown -R $SERVICE_USER:$SERVICE_USER "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR/src/main_service.py"
    chmod +x "$INSTALL_DIR/src/web_interface.py"
    chmod +x "$INSTALL_DIR/src/watchdog.py"

    # Create log directory
    print_status "Creating log directory: $LOG_DIR"
    mkdir -p "$LOG_DIR"
    chown $SERVICE_USER:$SERVICE_USER "$LOG_DIR"

    # Create Gunicorn log directory
    print_status "Creating Gunicorn log directory: /var/log/onvif-proxy"
    mkdir -p "/var/log/onvif-proxy"
    chown $SERVICE_USER:$SERVICE_USER "/var/log/onvif-proxy"

    # Create run directory for PID files
    print_status "Creating run directory: /run/onvif-proxy"
    mkdir -p "/run/onvif-proxy"
    chown $SERVICE_USER:$SERVICE_USER "/run/onvif-proxy"

    # Install systemd service files
    print_status "Installing systemd service files..."
    cp "$INSTALL_DIR/onvif-proxy.service" "$SYSTEMD_DIR/"
    cp "$INSTALL_DIR/onvif-proxy-web.service" "$SYSTEMD_DIR/"
    cp "$INSTALL_DIR/onvif-proxy-watchdog.service" "$SYSTEMD_DIR/"

    # Update service files with correct paths
    sed -i "s|/home/felipe/onvif-proxy/ONVIF-Proxy|$INSTALL_DIR|g" "$SYSTEMD_DIR/onvif-proxy.service"
    sed -i "s|/home/felipe/onvif-proxy/ONVIF-Proxy|$INSTALL_DIR|g" "$SYSTEMD_DIR/onvif-proxy-web.service"
    sed -i "s|/home/felipe/onvif-proxy/ONVIF-Proxy|$INSTALL_DIR|g" "$SYSTEMD_DIR/onvif-proxy-watchdog.service"

    # Update service files to use correct user
    # Keep main service as root (needs CAP_NET_ADMIN and DHCP), run web and watchdog as service user
    sed -i "s|User=root|User=$SERVICE_USER|g" "$SYSTEMD_DIR/onvif-proxy-web.service"
    sed -i "s|Group=root|Group=$SERVICE_USER|g" "$SYSTEMD_DIR/onvif-proxy-web.service"
    sed -i "s|User=root|User=$SERVICE_USER|g" "$SYSTEMD_DIR/onvif-proxy-watchdog.service"
    sed -i "s|Group=root|Group=$SERVICE_USER|g" "$SYSTEMD_DIR/onvif-proxy-watchdog.service"

    # Enable systemd-networkd for persistent network configuration
    print_status "Enabling and starting systemd-networkd..."
    systemctl enable --now systemd-networkd

    # Reload systemd daemon
    print_status "Reloading systemd daemon..."
    systemctl daemon-reload

    # Enable services
    print_status "Enabling ONVIF Proxy services..."
    systemctl enable onvif-proxy.service
    systemctl enable onvif-proxy-web.service
    systemctl enable onvif-proxy-watchdog.service

    # Create sudoers file for network management
    print_status "Configuring sudo permissions for network management..."
    cat > "$SUDOERS_FILE" << EOF
# Allow onvif-proxy user to manage network interfaces
$SERVICE_USER ALL=(ALL) NOPASSWD: /sbin/ip
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart systemd-networkd
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/systemctl reload systemd-networkd
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart onvif-proxy
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/systemctl stop onvif-proxy
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/systemctl start onvif-proxy
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/systemctl reload-or-restart onvif-proxy
EOF

    # Set proper permissions for sudoers file
    chmod 440 "$SUDOERS_FILE"

    # Create config directory and file
    print_status "Creating configuration directory..."
    mkdir -p "/var/lib/onvif-proxy"
    chown $SERVICE_USER:$SERVICE_USER "/var/lib/onvif-proxy"
    chmod 755 "/var/lib/onvif-proxy"
    
    # Check for existing config and create backup if needed
    if [ -f "/var/lib/onvif-proxy/config.xml" ]; then
        print_status "Existing configuration file found - creating backup"
        cp "/var/lib/onvif-proxy/config.xml" "/var/lib/onvif-proxy/config.xml.backup.$(date +%Y%m%d_%H%M%S)"
        print_status "Preserving existing configuration settings"
        # Ensure proper ownership and permissions on existing config
        chown $SERVICE_USER:$SERVICE_USER "/var/lib/onvif-proxy/config.xml"
        chmod 644 "/var/lib/onvif-proxy/config.xml"
    else
        print_status "Creating default configuration file..."
        cat > "/var/lib/onvif-proxy/config.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<onvif_proxy>
    <system>
        <enabled>True</enabled>
        <base_interface>eth0</base_interface>
        <base_ip_range>192.168.1.100</base_ip_range>
        <pushover_token />
        <pushover_user />
        <web_port>5000</web_port>
    </system>
    <cameras>
    </cameras>
</onvif_proxy>
EOF
        chown $SERVICE_USER:$SERVICE_USER "/var/lib/onvif-proxy/config.xml"
        chmod 644 "/var/lib/onvif-proxy/config.xml"
    fi

    # Create startup script
    print_status "Creating management scripts..."
    cat > "$CONTROL_SCRIPT" << 'EOF'
#!/bin/bash
# ONVIF Proxy Control Script

case "$1" in
    start)
        echo "Starting ONVIF Proxy services..."
        systemctl start onvif-proxy
        systemctl start onvif-proxy-web
        systemctl start onvif-proxy-watchdog
        ;;
    stop)
        echo "Stopping ONVIF Proxy services..."
        systemctl stop onvif-proxy-watchdog
        systemctl stop onvif-proxy-web
        systemctl stop onvif-proxy
        ;;
    restart)
        echo "Restarting ONVIF Proxy services..."
        systemctl restart onvif-proxy
        systemctl restart onvif-proxy-web
        systemctl restart onvif-proxy-watchdog
        ;;
    status)
        echo "ONVIF Proxy Service Status:"
        systemctl status onvif-proxy --no-pager -l
        echo ""
        echo "Web Interface Status:"
        systemctl status onvif-proxy-web --no-pager -l
        echo ""
        echo "Watchdog Status:"
        systemctl status onvif-proxy-watchdog --no-pager -l
        ;;
    logs)
        echo "ONVIF Proxy Logs (press Ctrl+C to exit):"
        journalctl -u onvif-proxy -u onvif-proxy-web -u onvif-proxy-watchdog -f
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOF

    chmod +x "$CONTROL_SCRIPT"

    # Restart services after successful installation
    print_status "Starting ONVIF Proxy services..."
    systemctl restart onvif-proxy
    systemctl restart onvif-proxy-web
    systemctl restart onvif-proxy-watchdog
    
    # Wait a moment for web service to start
    sleep 2
    
    # Get system configuration for web port
    WEB_PORT=$(PYTHONPATH=$INSTALL_DIR python3 -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
from src.config_manager import ConfigManager
config = ConfigManager('/var/lib/onvif-proxy/config.xml')
print(config.get_system_config().get('web_port', 5000))
" 2>/dev/null || echo "5000")

    print_status "Service Management:"
    echo "  Start services:   onvif-proxy-ctl start"
    echo "  Stop services:    onvif-proxy-ctl stop"
    echo "  Restart services: onvif-proxy-ctl restart"
    echo "  Check status:     onvif-proxy-ctl status"
    echo "  View logs:        onvif-proxy-ctl logs"
    echo ""
    print_status "Web Interface:"
    echo "  URL: http://$(hostname -I | awk '{print $1}'):$WEB_PORT"
    echo "  Local: http://localhost:$WEB_PORT"
    echo ""
    print_status "Configuration:"
    echo "  Config file: /var/lib/onvif-proxy/config.xml"
    echo "  Log files: $LOG_DIR/"
    echo ""
    print_warning "Important Notes:"
    echo "1. Configure your Pushover credentials in the web interface for notifications"
    echo "2. Add your cameras through the web interface"
    echo "3. Ensure your network interface supports virtual interfaces"
    echo "4. The service user '$SERVICE_USER' has been created for security"
    echo ""
    print_success "All services are now running!"
}

# Main script logic
main() {
    check_root
    get_script_dir

    # Parse command line arguments
    case "${1:-install}" in
        install)
            install_onvif_proxy
            ;;
        uninstall)
            echo ""
            print_warning "This will completely remove ONVIF Proxy and all its components."
            read -p "Are you sure you want to continue? (y/N): " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                uninstall_onvif_proxy
            else
                print_status "Uninstallation cancelled."
            fi
            ;;
        --help|-h|help)
            show_usage
            ;;
        *)
            print_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Uninstallation function
uninstall_onvif_proxy() {
    print_status "Starting ONVIF Proxy uninstallation..."

    # Stop and disable services
    print_status "Stopping and disabling services..."
    systemctl stop onvif-proxy-watchdog 2>/dev/null || true
    systemctl stop onvif-proxy-web 2>/dev/null || true
    systemctl stop onvif-proxy 2>/dev/null || true
    
    systemctl disable onvif-proxy.service 2>/dev/null || true
    systemctl disable onvif-proxy-web.service 2>/dev/null || true
    systemctl disable onvif-proxy-watchdog.service 2>/dev/null || true

    # Remove systemd service files
    print_status "Removing systemd service files..."
    rm -f "$SYSTEMD_DIR/onvif-proxy.service"
    rm -f "$SYSTEMD_DIR/onvif-proxy-web.service"
    rm -f "$SYSTEMD_DIR/onvif-proxy-watchdog.service"

    # Reload systemd daemon
    systemctl daemon-reload

    # Remove virtual network interfaces created by the system
    print_status "Cleaning up network interfaces..."
    if [ -f "/var/lib/onvif-proxy/config.xml" ]; then
        # Try to clean up network interfaces using the config
        PYTHONPATH=/usr/lib/python3/dist-packages python3 -c "
import sys
sys.path.append('$INSTALL_DIR/src')
try:
    from config_manager import ConfigManager
    from network_manager import NetworkManager
    config = ConfigManager('/var/lib/onvif-proxy/config.xml')
    net_mgr = NetworkManager()
    cameras = config.get_cameras()
    system_config = config.get_system_config()
    base_interface = system_config.get('base_interface', 'eth0')
    for camera in cameras:
        onvif_ip = camera.get('onvif_ip')
        if onvif_ip:
            net_mgr.remove_ip_alias(base_interface, onvif_ip)
            net_mgr.remove_persistent_config(onvif_ip)
except Exception as e:
    print(f'Warning: Could not clean up network interfaces: {e}')
" 2>/dev/null || print_warning "Could not automatically clean network interfaces"
    fi

    # Remove systemd network configuration files
    print_status "Removing systemd network configurations..."
    rm -f /etc/systemd/network/onvif-*.network
    rm -f /etc/systemd/network/onvif-*.netdev
    systemctl reload systemd-networkd 2>/dev/null || true

    # Remove any remaining macvlan interfaces named onvif-*
    print_status "Removing onvif-* network interfaces..."
    for IFACE_PATH in /sys/class/net/onvif-*; do
        [ -e "$IFACE_PATH" ] || continue
        IFACE=$(basename "$IFACE_PATH")
        ip link delete "$IFACE" 2>/dev/null || true
    done

    # Remove sudoers file
    print_status "Removing sudo permissions..."
    rm -f "$SUDOERS_FILE"

    # Remove control script
    print_status "Removing management scripts..."
    rm -f "$CONTROL_SCRIPT"

    # Remove installation directory
    print_status "Removing installation directory..."
    rm -rf "$INSTALL_DIR"

    # Remove log directory
    print_status "Removing log directory..."
    rm -rf "$LOG_DIR"

    # Ask about configuration files
    echo ""
    read -p "Do you want to keep configuration files? [y/N]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Preserving configuration files in /var/lib/onvif-proxy"
        KEEP_CONFIG=true
    else
        KEEP_CONFIG=false
    fi

    # Handle configuration directory before removing user
    if [ "$KEEP_CONFIG" = false ]; then
        print_status "Removing configuration directory..."
        rm -rf "/var/lib/onvif-proxy" 2>/dev/null || true
    else
        print_status "Configuration directory preserved: /var/lib/onvif-proxy"
        # Change ownership back to root to preserve after user removal
        chown -R root:root "/var/lib/onvif-proxy" 2>/dev/null || true
    fi

    # Remove service user
    if id "$SERVICE_USER" &>/dev/null; then
        print_status "Removing service user: $SERVICE_USER"
        userdel "$SERVICE_USER" 2>/dev/null || true
    fi

    # Remove Python packages (optional - only netifaces since others might be used by other apps)
    print_status "Removing Python packages..."
    pip3 uninstall -y netifaces 2>/dev/null || true

    print_success "ONVIF Proxy uninstallation completed!"
    echo ""
    print_status "The following system packages were installed but NOT removed:"
    echo "  - python3-flask, python3-requests, python3-lxml, python3-opencv, python3-psutil"
    echo "  - libxml2-dev, libxslt1-dev, python3-dev"
    echo "  - Standard system tools (python3, systemd, iproute2, etc.)"
    echo ""
    print_status "These packages may be used by other applications."
    print_status "Remove them manually if needed: sudo apt-get remove <package-name>"
    echo ""
    print_warning "Note: Any manually created network interfaces may still exist."
    print_warning "Check with 'ip link show' and remove with 'sudo ip link delete <interface>'"
}

# Run main function
main "$@"
