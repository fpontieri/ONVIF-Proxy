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
from traffic_monitor import TrafficMonitor

class ONVIFProxyWatchdog:
    """Watchdog service to monitor ONVIF Proxy system health"""
    
    def __init__(self, config_path: str = "config.xml"):
        self.config_manager = ConfigManager(config_path)
        self.notification_manager = NotificationManager()
        self.traffic_monitor = TrafficMonitor()
        self.running = False
        self.last_notification = {}
        self.notification_cooldown = 300  # 5 minutes between notifications
        self.camera_ping_results = {}  # Store ping results for cameras
        self.camera_traffic_alerts = {}  # Store last traffic alert times
        
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
        
        # Start traffic monitoring
        self.traffic_monitor.start_monitoring()
        self._initialize_camera_monitoring()
        
        # Main monitoring loop
        while self.running:
            try:
                # Get current ping interval from system config
                system_config = self.config_manager.get_system_config()
                ping_interval = system_config.get('ping_interval', 30)
                
                self._check_system_health()
                self._ping_cameras()
                self._check_traffic_health()
                
                time.sleep(ping_interval)
            except Exception as e:
                self.logger.error(f"Error in watchdog loop: {e}")
                time.sleep(30)  # Default fallback interval
    
    def stop(self):
        """Stop the watchdog service"""
        self.logger.info("Stopping ONVIF Proxy Watchdog")
        self.running = False
        self.traffic_monitor.stop_monitoring()
    
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
    
    def _ping_cameras(self):
        """Ping all enabled cameras and update their status"""
        try:
            cameras = self.config_manager.get_cameras()
            
            for camera in cameras:
                if not camera.get('enabled', True):
                    continue
                
                camera_id = camera['id']
                onvif_ip = camera.get('onvif_ip')
                
                if not onvif_ip:
                    continue
                
                # Send 3 pings to the camera
                ping_results = self._ping_host(onvif_ip, count=3)
                
                # Store results
                self.camera_ping_results[camera_id] = ping_results
                
                # Update camera config with ping status
                new_status = 'up' if ping_results['success'] else 'down'
                previous_status = camera.get('last_ping_status', 'unknown')
                
                if new_status != previous_status:
                    self.logger.info(f"Camera {camera.get('name', camera_id)} status changed: {previous_status} -> {new_status}")
                    
                    # Update camera config
                    camera_config = dict(camera)
                    camera_config['last_ping_status'] = new_status
                    camera_config['last_ping_time'] = datetime.now().isoformat()
                    camera_config['last_ping_results'] = ping_results
                    self.config_manager.update_camera(camera_id, camera_config)
                    
                    # Send notification for status change
                    self._send_camera_status_notification(camera, previous_status, new_status, ping_results)
                
        except Exception as e:
            self.logger.error(f"Error pinging cameras: {e}")
    
    def _ping_host(self, host: str, count: int = 3) -> dict:
        """Ping a host and return results"""
        try:
            import subprocess
            import re
            
            # Run ping command
            cmd = ['ping', '-c', str(count), '-W', '3', host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                # Parse ping output for statistics
                output = result.stdout
                
                # Extract packet loss
                loss_match = re.search(r'(\d+)% packet loss', output)
                packet_loss = loss_match.group(1) + '%' if loss_match else '0%'
                
                # Extract average time
                time_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms', output)
                avg_time = time_match.group(1) + 'ms' if time_match else '0ms'
                
                return {
                    "host": host,
                    "success": True,
                    "output": output,
                    "error": "",
                    "packet_loss": packet_loss,
                    "avg_time": avg_time
                }
            else:
                return {
                    "host": host,
                    "success": False,
                    "output": result.stdout,
                    "error": result.stderr,
                    "packet_loss": "100%",
                    "avg_time": "0ms"
                }
        except Exception as e:
            return {
                "host": host,
                "success": False,
                "output": "",
                "error": str(e),
                "packet_loss": "100%",
                "avg_time": "0ms"
            }
    
    def _send_camera_status_notification(self, camera: dict, old_status: str, new_status: str, ping_results: dict):
        """Send notification for camera status change"""
        try:
            system_config = self.config_manager.get_system_config()
            
            if not system_config.get('pushover_token') or not system_config.get('pushover_user'):
                return
            
            camera_name = camera.get('name', f"Camera {camera['id']}")
            
            if new_status == 'up' and system_config.get('notify_camera_online'):
                title = "📹 Camera Online"
                message = f"""Camera '{camera_name}' is now online.

IP: {camera.get('onvif_ip', 'Unknown')}
Packet Loss: {ping_results.get('packet_loss', 'Unknown')}
Avg Response: {ping_results.get('avg_time', 'Unknown')}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
                
                priority = system_config.get('notify_camera_online_priority', 0)
                self.notification_manager.send_notification(title, message, priority=priority)
                
            elif new_status == 'down' and system_config.get('notify_camera_offline'):
                title = "🚨 Camera Offline"
                message = f"""Camera '{camera_name}' is offline!

IP: {camera.get('onvif_ip', 'Unknown')}
Error: {ping_results.get('error', 'Network unreachable')}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please check the camera and network connection."""
                
                priority = system_config.get('notify_camera_offline_priority', 1)
                self.notification_manager.send_notification(title, message, priority=priority)
                
        except Exception as e:
            self.logger.error(f"Failed to send camera status notification: {e}")
    
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

    def _initialize_camera_monitoring(self):
        """Initialize traffic monitoring for all cameras"""
        try:
            cameras = self.config_manager.get_cameras()
            for camera in cameras:
                if camera.get('enabled', True):
                    camera_id = camera['id']
                    virtual_ip = camera.get('onvif_ip')
                    camera_ip = self._extract_camera_ip(camera.get('rtsp_url', ''))
                    
                    if virtual_ip and camera_ip:
                        self.traffic_monitor.add_camera(camera_id, virtual_ip, camera_ip)
                        self.logger.info(f"Added camera {camera_id} to traffic monitoring: {virtual_ip} -> {camera_ip}")
                        
        except Exception as e:
            self.logger.error(f"Error initializing camera monitoring: {e}")
    
    def _extract_camera_ip(self, rtsp_url: str) -> str:
        """Extract camera IP from RTSP URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(rtsp_url)
            return parsed.hostname
        except Exception:
            return None
    
    def _check_traffic_health(self):
        """Check RTSP traffic health for all cameras"""
        try:
            cameras = self.config_manager.get_cameras()
            current_time = time.time()
            
            for camera in cameras:
                if not camera.get('enabled', True):
                    continue
                    
                camera_id = camera['id']
                camera_name = camera.get('name', f'Camera {camera_id}')
                
                # Check if camera has recent traffic (within last 60 seconds)
                has_traffic = self.traffic_monitor.has_recent_traffic(camera_id, threshold_seconds=60)
                
                if not has_traffic:
                    # Check if we've already sent an alert recently
                    last_alert_time = self.camera_traffic_alerts.get(camera_id, 0)
                    
                    if current_time - last_alert_time > self.notification_cooldown:
                        self._send_traffic_alert(camera_id, camera_name)
                        self.camera_traffic_alerts[camera_id] = current_time
                else:
                    # Clear alert state if traffic is restored
                    if camera_id in self.camera_traffic_alerts:
                        del self.camera_traffic_alerts[camera_id]
                        self._send_traffic_restored_alert(camera_id, camera_name)
                        
        except Exception as e:
            self.logger.error(f"Error checking traffic health: {e}")
    
    def _send_traffic_alert(self, camera_id: str, camera_name: str):
        """Send alert for no RTSP traffic"""
        try:
            message = f"🚨 No RTSP traffic detected for {camera_name} (ID: {camera_id}) in the last minute"
            
            system_config = self.config_manager.get_system_config()
            if system_config.get('notify_system_error', True):
                priority = system_config.get('notify_system_error_priority', 1)
                
                success = self.notification_manager.send_notification(
                    title="ONVIF Proxy - No Traffic Alert",
                    message=message,
                    priority=priority
                )
                
                if success:
                    self.logger.warning(f"Sent no traffic alert for camera {camera_id}")
                else:
                    self.logger.error(f"Failed to send no traffic alert for camera {camera_id}")
                    
        except Exception as e:
            self.logger.error(f"Error sending traffic alert for camera {camera_id}: {e}")
    
    def _send_traffic_restored_alert(self, camera_id: str, camera_name: str):
        """Send alert when RTSP traffic is restored"""
        try:
            message = f"✅ RTSP traffic restored for {camera_name} (ID: {camera_id})"
            
            system_config = self.config_manager.get_system_config()
            if system_config.get('notify_camera_online', True):
                priority = system_config.get('notify_camera_online_priority', 0)
                
                success = self.notification_manager.send_notification(
                    title="ONVIF Proxy - Traffic Restored",
                    message=message,
                    priority=priority
                )
                
                if success:
                    self.logger.info(f"Sent traffic restored alert for camera {camera_id}")
                else:
                    self.logger.error(f"Failed to send traffic restored alert for camera {camera_id}")
                    
        except Exception as e:
            self.logger.error(f"Error sending traffic restored alert for camera {camera_id}: {e}")


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
