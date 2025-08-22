#!/usr/bin/env python3
"""
Watchdog service for ONVIF Proxy system health monitoring
Monitors the main service and sends notifications when issues are detected
"""

import time
import subprocess
import logging
import psutil
import signal
import sys
from datetime import datetime, timedelta
from config_manager import ConfigManager
from notification_manager import NotificationManager

class ONVIFProxyWatchdog:
    """Watchdog service to monitor ONVIF Proxy system health"""
    
    def __init__(self, config_path: str = "config.xml"):
        self.config_manager = ConfigManager(config_path)
        self.notification_manager = NotificationManager()
        self.running = False
        self.last_notification = {}
        self.check_interval = 60  # Check every 60 seconds
        self.notification_cooldown = 300  # 5 minutes between notifications
        
        # Setup logging - use systemd journal instead of file
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler()  # systemd will capture stdout/stderr to journal
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down watchdog...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        """Start the watchdog service"""
        self.logger.info("Starting ONVIF Proxy Watchdog")
        
        # Update notification manager credentials
        system_config = self.config_manager.get_system_config()
        self.notification_manager.update_credentials(
            system_config.get('pushover_token', ''),
            system_config.get('pushover_user', '')
        )
        
        self.running = True
        
        # Main monitoring loop
        while self.running:
            try:
                self._check_system_health()
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Error in watchdog loop: {e}")
                time.sleep(self.check_interval)
    
    def stop(self):
        """Stop the watchdog service"""
        self.logger.info("Stopping ONVIF Proxy Watchdog")
        self.running = False
    
    def _check_system_health(self):
        """Check overall system health"""
        issues = []
        
        # Check main service
        if not self._is_service_running('onvif-proxy'):
            issues.append("Main ONVIF Proxy service is not running")
        
        # Check web interface
        if not self._is_service_running('onvif-proxy-web'):
            issues.append("Web interface service is not running")
        
        # Check system resources
        resource_issues = self._check_system_resources()
        issues.extend(resource_issues)
        
        # Check network interfaces
        network_issues = self._check_network_interfaces()
        issues.extend(network_issues)
        
        # Check camera connectivity
        camera_issues = self._check_camera_connectivity()
        issues.extend(camera_issues)
        
        # Send notifications for issues
        if issues:
            self._handle_issues(issues)
        else:
            # Clear any previous issue notifications
            self._clear_issue_notifications()
    
    def _is_service_running(self, service_name: str) -> bool:
        """Check if a systemd service is running"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True, text=True
            )
            return result.returncode == 0 and result.stdout.strip() == 'active'
        except Exception as e:
            self.logger.error(f"Error checking service {service_name}: {e}")
            return False
    
    def _check_system_resources(self) -> list:
        """Check system resource usage"""
        issues = []
        
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                issues.append(f"High CPU usage: {cpu_percent:.1f}%")
            
            # Check memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                issues.append(f"High memory usage: {memory.percent:.1f}%")
            
            # Check disk usage
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                issues.append(f"High disk usage: {disk.percent:.1f}%")
            
        except Exception as e:
            self.logger.error(f"Error checking system resources: {e}")
            issues.append("Unable to check system resources")
        
        return issues
    
    def _check_network_interfaces(self) -> list:
        """Check network interface status"""
        issues = []
        
        try:
            system_config = self.config_manager.get_system_config()
            base_interface = system_config.get('base_interface', 'eth0')
            
            # Check if base interface exists and is up
            interfaces = psutil.net_if_stats()
            if base_interface not in interfaces:
                issues.append(f"Base network interface {base_interface} not found")
            elif not interfaces[base_interface].isup:
                issues.append(f"Base network interface {base_interface} is down")
            
            # Check virtual interfaces for cameras
            cameras = self.config_manager.get_cameras()
            for camera in cameras:
                if not camera.get('enabled', True):
                    continue
                
                onvif_ip = camera.get('onvif_ip')
                if onvif_ip:
                    vlan_name = f"onvif_{onvif_ip.replace('.', '_')}"
                    if vlan_name in interfaces and not interfaces[vlan_name].isup:
                        issues.append(f"Virtual interface {vlan_name} for camera {camera.get('name', camera['id'])} is down")
        
        except Exception as e:
            self.logger.error(f"Error checking network interfaces: {e}")
            issues.append("Unable to check network interfaces")
        
        return issues
    
    def _check_camera_connectivity(self) -> list:
        """Check camera connectivity issues"""
        issues = []
        
        try:
            cameras = self.config_manager.get_cameras()
            offline_cameras = []
            
            for camera in cameras:
                if not camera.get('enabled', True):
                    continue
                
                if camera.get('last_ping_status') == 'down':
                    offline_cameras.append(camera.get('name', f"Camera {camera['id']}"))
            
            if offline_cameras:
                if len(offline_cameras) == 1:
                    issues.append(f"Camera {offline_cameras[0]} is offline")
                else:
                    issues.append(f"{len(offline_cameras)} cameras are offline: {', '.join(offline_cameras)}")
        
        except Exception as e:
            self.logger.error(f"Error checking camera connectivity: {e}")
            issues.append("Unable to check camera connectivity")
        
        return issues
    
    def _handle_issues(self, issues: list):
        """Handle detected issues"""
        current_time = datetime.now()
        
        for issue in issues:
            # Check if we've already notified about this issue recently
            last_notified = self.last_notification.get(issue)
            if last_notified and (current_time - last_notified).seconds < self.notification_cooldown:
                continue
            
            # Log the issue
            self.logger.warning(f"System issue detected: {issue}")
            
            # Send notification
            self._send_issue_notification(issue)
            
            # Update last notification time
            self.last_notification[issue] = current_time
    
    def _clear_issue_notifications(self):
        """Clear old issue notifications"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.notification_cooldown * 2)
        
        # Remove old notifications
        self.last_notification = {
            issue: timestamp for issue, timestamp in self.last_notification.items()
            if timestamp > cutoff_time
        }
    
    def _send_issue_notification(self, issue: str):
        """Send notification for a system issue"""
        try:
            system_config = self.config_manager.get_system_config()
            
            if not system_config.get('pushover_token') or not system_config.get('pushover_user'):
                return
            
            title = "🚨 ONVIF Proxy System Alert"
            message = f"""System Issue Detected:

{issue}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please check the system status and logs for more details."""
            
            self.notification_manager.send_notification(title, message, priority=1)
            
        except Exception as e:
            self.logger.error(f"Failed to send issue notification: {e}")
    
    def _restart_service(self, service_name: str) -> bool:
        """Attempt to restart a failed service"""
        try:
            self.logger.info(f"Attempting to restart service: {service_name}")
            
            result = subprocess.run(
                ['sudo', 'systemctl', 'restart', service_name],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                self.logger.info(f"Successfully restarted service: {service_name}")
                return True
            else:
                self.logger.error(f"Failed to restart service {service_name}: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restarting service {service_name}: {e}")
            return False


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ONVIF Proxy Watchdog Service')
    parser.add_argument('--config', default='config.xml', help='Configuration file path')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    
    args = parser.parse_args()
    
    watchdog = ONVIFProxyWatchdog(args.config)
    
    if args.daemon:
        # Run as daemon
        watchdog.start()
    else:
        # Run interactively
        try:
            print("ONVIF Proxy Watchdog is running. Press Ctrl+C to stop.")
            watchdog.start()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            watchdog.stop()


if __name__ == '__main__':
    main()
