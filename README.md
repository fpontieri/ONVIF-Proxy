# ONVIF Proxy

A comprehensive ONVIF proxy system that translates RTSP streams from security cameras into ONVIF-compatible virtual cameras with unique IP aliases and MAC addresses.

## Features

- **RTSP to ONVIF Translation**: Convert any RTSP stream into an ONVIF-compliant camera
- **Virtual Network Interfaces**: Each camera gets its own IP alias with unique MAC address
- **Web Management Interface**: Easy-to-use web interface for camera configuration
- **Persistent Configuration**: All settings stored in XML and survive reboots
- **Pushover Notifications**: Real-time alerts when cameras go online/offline with ping results
- **System Health Monitoring**: Watchdog service monitors system health
- **Systemd Integration**: Full systemd service integration with auto-start
- **Live Stream Testing**: Built-in connection testing and monitoring

## Quick Start

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ONVIF-Proxy
```

2. Run the installation script:
```bash
sudo ./install.sh
```

3. Access the web interface:
```
http://your-server-ip:8080
```

### Configuration

1. **System Settings**: Configure network interface, IP range, and Pushover credentials
2. **Add Cameras**: Add your RTSP cameras through the web interface
3. **Test Connections**: Use the built-in testing tools to verify camera connectivity

## Architecture

### Core Components

- **Main Service** (`main_service.py`): Coordinates all proxy components
- **ONVIF Proxy** (`onvif_proxy.py`): Handles RTSP to ONVIF translation
- **Network Manager** (`network_manager.py`): Manages IP aliases and MAC addresses
- **Web Interface** (`web_interface.py`): Flask-based management interface
- **Configuration Manager** (`config_manager.py`): XML configuration handling
- **Notification Manager** (`notification_manager.py`): Pushover integration
- **Watchdog** (`watchdog.py`): System health monitoring

### Network Configuration

Each camera is assigned:
- Unique IP address (e.g., 192.168.1.101, 192.168.1.102, ...)
- Unique MAC address (e.g., 02:00:00:00:00:01, 02:00:00:00:00:02, ...)
- Virtual network interface using macvlan

## Service Management

Use the provided control script:

```bash
# Start all services
onvif-proxy-ctl start

# Stop all services
onvif-proxy-ctl stop

# Restart services
onvif-proxy-ctl restart

# Check status
onvif-proxy-ctl status

# View logs
onvif-proxy-ctl logs
```

Or use systemctl directly:

```bash
# Individual services
systemctl start onvif-proxy
systemctl start onvif-proxy-web
systemctl start onvif-proxy-watchdog

# Check status
systemctl status onvif-proxy
```

## Configuration File

The system uses `config.xml` for all configuration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<onvif_proxy>
    <system>
        <enabled>true</enabled>
        <base_interface>eth0</base_interface>
        <base_ip_range>192.168.1.100</base_ip_range>
        <pushover_token>your_token</pushover_token>
        <pushover_user>your_user_key</pushover_user>
        <web_port>8080</web_port>
    </system>
    <cameras>
        <camera id="1">
            <name>Front Door Camera</name>
            <enabled>true</enabled>
            <rtsp_url>rtsp://192.168.1.10:554/stream</rtsp_url>
            <rtsp_username>admin</rtsp_username>
            <rtsp_password>password</rtsp_password>
            <onvif_ip>192.168.1.101</onvif_ip>
            <onvif_port>80</onvif_port>
            <mac_address>02:00:00:00:00:01</mac_address>
            <notifications_enabled>true</notifications_enabled>
        </camera>
    </cameras>
</onvif_proxy>
```

## ONVIF Endpoints

Each virtual camera exposes standard ONVIF endpoints:

- **Device Service**: `http://camera-ip:port/onvif/device_service`
- **Media Service**: `http://camera-ip:port/onvif/media_service`
- **Stream URI**: `rtsp://camera-ip:port/stream` (redirects to original RTSP)

## Notifications

The system sends Pushover notifications for:

- Camera offline/online status changes
- System service failures
- Network interface issues
- Resource usage alerts

Each notification includes:
- Timestamp
- Camera/system details
- Ping test results (5 attempts)
- Packet loss and response time statistics

## Monitoring

### Watchdog Features

- Service health monitoring
- Resource usage tracking (CPU, memory, disk)
- Network interface status
- Camera connectivity checks
- Automatic issue notifications

### Log Files

- Main service: `/var/log/onvif-proxy.log`
- Web interface: `journalctl -u onvif-proxy-web`
- Watchdog: `/var/log/onvif-proxy-watchdog.log`

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure the service user has proper sudo permissions
2. **Network Interface Issues**: Check that the base interface supports macvlan
3. **Port Conflicts**: Verify ONVIF ports are not in use by other services
4. **RTSP Connection Failures**: Test RTSP URLs manually with tools like VLC

### Debug Commands

```bash
# Check service status
onvif-proxy-ctl status

# View real-time logs
onvif-proxy-ctl logs

# Test camera connectivity
curl -X GET http://localhost:8080/camera/1/test

# Check network interfaces
ip addr show

# Verify virtual interfaces
ip link show type macvlan
```

## Security Considerations

- Service runs with minimal privileges using dedicated user account
- Network capabilities limited to required operations
- Web interface should be secured with reverse proxy in production
- RTSP credentials stored in configuration file (consider encryption)

## Requirements

### System Requirements

- Linux distribution with systemd
- Python 3.7+
- Root access for installation
- Network interface supporting macvlan

### Python Dependencies

- flask==2.3.3
- requests==2.31.0
- lxml==4.9.3
- opencv-python==4.8.1.78
- psutil==5.9.5
- netifaces==0.11.0

## License

[Add your license information here]

## Contributing

[Add contributing guidelines here]

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files
3. Test individual components
4. Create an issue with detailed information
