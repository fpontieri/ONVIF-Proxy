#!/usr/bin/env python3
"""
Main ONVIF Proxy service
Coordinates all components and manages camera proxies
"""

import logging
import signal



import sys
import time
import threading
from typing import Dict, List
from config_manager import ConfigManager
from network_manager import NetworkManager
from notification_manager import NotificationManager
from onvif_proxy import ONVIFProxyServer, StreamMonitor

class ONVIFProxyService:
    """Main service that coordinates all ONVIF proxy components"""
    
    def __init__(self, config_path: str = "/var/lib/onvif-proxy/config.xml"):
        self.config_manager = ConfigManager(config_path)
        self.network_manager = NetworkManager()
        self.notification_manager = NotificationManager()
        
        self.proxy_servers = {}  # camera_id -> ONVIFProxyServer
        self.stream_monitors = {}  # camera_id -> StreamMonitor
        self.running = False
        
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
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        """Start the ONVIF proxy service"""
        self.logger.info("Starting ONVIF Proxy Service")
        
        # Load system configuration
        system_config = self.config_manager.get_system_config()
        
        if not system_config.get('enabled', True):
            self.logger.info("Service is disabled in configuration")
            return
        
        # Update notification manager credentials
        self.notification_manager.update_credentials(
            system_config.get('pushover_token', ''),
            system_config.get('pushover_user', '')
        )
        
        self.running = True
        
        # Start camera proxies
        self._start_camera_proxies()
        
        # Start monitoring loop
        monitor_thread = threading.Thread(target=self._monitoring_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        self.logger.info("ONVIF Proxy Service started successfully")
        
        # Send startup notification
        if system_config.get('pushover_token') and system_config.get('pushover_user'):
            self.notification_manager.notify_service_up()
    
    def stop(self):
        """Stop the ONVIF proxy service"""
        self.logger.info("Stopping ONVIF Proxy Service")
        self.running = False
        
        # Stop all proxy servers
        for camera_id, proxy_server in self.proxy_servers.items():
            proxy_server.stop()
        
        # Stop all stream monitors
        for camera_id, monitor in self.stream_monitors.items():
            monitor.stop_monitoring()
        
        # Clean up network interfaces
        self._cleanup_network_interfaces()
        
        self.logger.info("ONVIF Proxy Service stopped")
    
    def _start_camera_proxies(self):
        """Start proxy servers for all enabled cameras"""
        cameras = self.config_manager.get_cameras()
        
        for camera in cameras:
            if camera.get('enabled', True):
                self._start_camera_proxy(camera)
    
    def _start_camera_proxy(self, camera_config: Dict):
        """Start proxy server for a single camera"""
        camera_id = camera_config['id']
        
        try:
            # Setup network interface
            if not self._setup_camera_network(camera_config):
                self.logger.error(f"Failed to setup network for camera {camera_id}")
                return
            
            # Start ONVIF proxy server
            proxy_server = ONVIFProxyServer(camera_config)
            if proxy_server.start():
                self.proxy_servers[camera_id] = proxy_server
                
                # Start stream monitoring
                monitor = StreamMonitor(camera_config, self._on_stream_status_change)
                monitor.start_monitoring()
                self.stream_monitors[camera_id] = monitor
                
                self.logger.info(f"Started proxy for camera {camera_config.get('name')} ({camera_id})")
            else:
                self.logger.error(f"Failed to start proxy for camera {camera_id}")
                
        except Exception as e:
            self.logger.error(f"Error starting camera proxy {camera_id}: {e}")
    
    def _setup_camera_network(self, camera_config: Dict) -> bool:
        """Setup network interface for camera"""
        system_config = self.config_manager.get_system_config()
        default_interface = system_config.get('base_interface', 'eth0')
        base_interface = camera_config.get('base_interface') or default_interface
        mac_address = camera_config.get('onvif_mac') or camera_config.get('mac_address')
        camera_id = camera_config.get('id')
        onvif_ip = camera_config.get('onvif_ip')
        
        # Generate MAC address based on camera ID if missing
        if not mac_address:
            mac_address = self.config_manager.generate_mac_for_camera_id(int(camera_id))
            self.logger.info(f"Generated MAC address {mac_address} for camera {camera_id}")
            
            # Update camera config with generated MAC
            camera_config['onvif_mac'] = mac_address
            self.config_manager.update_camera(camera_id, camera_config)
        
        # Always use static IP configuration - no DHCP
        if not onvif_ip:
            self.logger.warning(f"No ONVIF IP configured for camera {camera_id}, skipping network setup")
            return True  # Not an error, just no network interface needed
        
        # Create camera interface with static IP
        if not self.network_manager.create_camera_interface(base_interface, str(camera_id), mac_address, onvif_ip):
            self.logger.error(f"Failed to create network interface for camera {camera_id}")
            return False
        
        # Make network configuration persistent
        try:
            self.network_manager.make_persistent(f"onvif-{camera_id}", onvif_ip, mac_address)
            self.logger.info(f"Camera {camera_id} network interface created with IP {onvif_ip}")
        except Exception as e:
            self.logger.warning(f"Failed to make network config persistent for camera {camera_id}: {e}")
        
        return True
    
    def _cleanup_network_interfaces(self):
        """Clean up network interfaces for all cameras"""
        cameras = self.config_manager.get_cameras()
        for camera in cameras:
            camera_id = camera['id']
            # Remove camera interface
            self.network_manager.remove_camera_interface(camera_id)
            # Remove persistent config if IP exists
            onvif_ip = camera.get('onvif_ip')
            if onvif_ip:
                self.network_manager.remove_persistent_config(onvif_ip)
    
    def _on_stream_status_change(self, camera_config: Dict, is_available: bool):
        """Handle stream status changes"""
        camera_name = camera_config.get('name', f"Camera {camera_config['id']}")
        camera_ip = camera_config.get('rtsp_url', '').split('//')[1].split(':')[0] if '://' in camera_config.get('rtsp_url', '') else 'unknown'
        
        if not camera_config.get('notifications_enabled', True):
            return
        
        # Perform ping test
        if camera_ip != 'unknown':
            ping_results = self.network_manager.ping_host(camera_ip, 5)
        else:
            ping_results = {"success": False, "packet_loss": "100%", "avg_time": "0ms"}
        
        # Update camera status in config
        self.config_manager.update_camera(
            camera_config['id'], 
            {"last_ping_status": "up" if is_available else "down"}
        )
        
        # Send notification
        if is_available:
            self.notification_manager.notify_camera_up(camera_name, camera_ip, ping_results)
        else:
            self.notification_manager.notify_camera_down(camera_name, camera_ip, ping_results)
    
    def _monitoring_loop(self):
        """Main monitoring loop for service health"""
        while self.running:
            try:
                # Check proxy server health
                self._check_proxy_health()
                
                # Sleep for 60 seconds
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)
    
    def _check_proxy_health(self):
        """Check health of all proxy servers"""
        cameras = self.config_manager.get_cameras()
        
        for camera in cameras:
            if not camera.get('enabled', True):
                continue
                
            camera_id = camera['id']
            
            # Check if proxy server is running
            if camera_id in self.proxy_servers:
                proxy_server = self.proxy_servers[camera_id]
                if not proxy_server.is_running():
                    self.logger.warning(f"Proxy server for camera {camera_id} is not running, restarting...")
                    proxy_server.stop()
                    self._start_camera_proxy(camera)
            else:
                # Proxy server not found, start it
                self.logger.warning(f"Proxy server for camera {camera_id} not found, starting...")
                self._start_camera_proxy(camera)
    
    def reload_configuration(self):
        """Reload configuration and restart affected services"""
        self.logger.info("Reloading configuration")
        
        # Reload config
        self.config_manager.load_config()
        
        # Update notification manager
        system_config = self.config_manager.get_system_config()
        self.notification_manager.update_credentials(
            system_config.get('pushover_token', ''),
            system_config.get('pushover_user', '')
        )
        
        # Restart camera proxies
        current_cameras = set(self.proxy_servers.keys())
        new_cameras = {camera['id'] for camera in self.config_manager.get_cameras() if camera.get('enabled', True)}
        
        # Stop removed cameras
        for camera_id in current_cameras - new_cameras:
            if camera_id in self.proxy_servers:
                # Clean up network using previous config
                try:
                    prev_config = self.proxy_servers[camera_id].camera_config
                    default_interface = system_config.get('base_interface', 'eth0')
                    if prev_config.get('use_dhcp', False):
                        self.network_manager.remove_camera_interface(camera_id)
                    else:
                        base_interface = prev_config.get('base_interface') or default_interface
                        onvif_ip = prev_config.get('onvif_ip')
                        if onvif_ip:
                            self.network_manager.remove_ip_alias(base_interface, onvif_ip)
                except Exception as e:
                    self.logger.warning(f"Failed to cleanup network for camera {camera_id} on reload: {e}")
                self.proxy_servers[camera_id].stop()
                del self.proxy_servers[camera_id]
            if camera_id in self.stream_monitors:
                self.stream_monitors[camera_id].stop_monitoring()
                del self.stream_monitors[camera_id]
        
        # Start new cameras
        for camera_id in new_cameras - current_cameras:
            camera_config = self.config_manager.get_camera(camera_id)
            if camera_config:
                self._start_camera_proxy(camera_config)
        
        self.logger.info("Configuration reloaded successfully")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ONVIF Proxy Service')
    parser.add_argument('--config', default='config.xml', help='Configuration file path')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    
    args = parser.parse_args()
    
    service = ONVIFProxyService(args.config)
    
    if args.daemon:
        # Run as daemon
        service.start()
        
        # Keep running
        try:
            while service.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            service.stop()
    else:
        # Run interactively
        service.start()
        
        try:
            print("ONVIF Proxy Service is running. Press Ctrl+C to stop.")
            while service.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            service.stop()


if __name__ == '__main__':
    main()
