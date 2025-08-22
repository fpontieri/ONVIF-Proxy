#!/usr/bin/env python3
"""
Notification management for ONVIF Proxy system
Handles Pushover notifications with ping results
"""

import requests
import logging
from typing import Dict, Optional
from datetime import datetime

class NotificationManager:
    def __init__(self, pushover_token: str = "", pushover_user: str = ""):
        self.pushover_token = pushover_token
        self.pushover_user = pushover_user
        self.logger = logging.getLogger(__name__)
        self.pushover_api_url = "https://api.pushover.net/1/messages.json"
    
    def update_credentials(self, token: str, user: str):
        """Update Pushover credentials"""
        self.pushover_token = token
        self.pushover_user = user
    
    def send_notification(self, title: str, message: str, priority: int = 0, retry: int = None, expire: int = None) -> bool:
        """Send notification via Pushover"""
        if not self.pushover_token or not self.pushover_user:
            self.logger.warning("Pushover credentials not configured")
            return False
        
        try:
            data = {
                "token": self.pushover_token,
                "user": self.pushover_user,
                "title": title,
                "message": message,
                "priority": priority,
                "timestamp": int(datetime.now().timestamp())
            }
            
            # Add emergency priority parameters for priority 2
            if priority == 2:
                data["retry"] = retry or 120  # Retry every 2 minutes
                data["expire"] = expire or 10800  # Expire after 3 hours
            
            response = requests.post(self.pushover_api_url, data=data, timeout=10)
            
            if response.status_code == 200:
                self.logger.info(f"Notification sent successfully: {title}")
                return True
            else:
                self.logger.error(f"Failed to send notification: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}")
            return False
    
    def notify_camera_down(self, camera_name: str, camera_ip: str, ping_results: Dict) -> bool:
        """Send notification when camera goes down"""
        title = f"🔴 Camera Offline: {camera_name}"
        
        message = f"""Camera: {camera_name}
IP: {camera_ip}
Status: OFFLINE

Ping Results (5 attempts):
• Packet Loss: {ping_results.get('packet_loss', '100%')}
• Average Time: {ping_results.get('avg_time', '0ms')}
• Success: {'Yes' if ping_results.get('success', False) else 'No'}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        
        return self.send_notification(title, message, priority=1)
    
    def notify_camera_up(self, camera_name: str, camera_ip: str, ping_results: Dict) -> bool:
        """Send notification when camera comes back online"""
        title = f"🟢 Camera Online: {camera_name}"
        
        message = f"""Camera: {camera_name}
IP: {camera_ip}
Status: ONLINE

Ping Results (5 attempts):
• Packet Loss: {ping_results.get('packet_loss', '0%')}
• Average Time: {ping_results.get('avg_time', '0ms')}
• Success: {'Yes' if ping_results.get('success', False) else 'No'}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        
        return self.send_notification(title, message, priority=0)
    
    def notify_system_error(self, error_message: str) -> bool:
        """Send notification for system errors"""
        title = "⚠️ ONVIF Proxy System Error"
        
        message = f"""System Error Detected:

{error_message}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please check the system logs for more details."""
        
        return self.send_notification(title, message, priority=2, retry=120, expire=10800)
    
    def notify_fatal_error(self, error_message: str) -> bool:
        """Send emergency notification for fatal system errors"""
        title = "🚨 ONVIF Proxy FATAL ERROR"
        
        message = f"""FATAL ERROR - Immediate Attention Required:

{error_message}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is a critical system failure that requires immediate intervention.
Please check system status and logs immediately."""
        
        return self.send_notification(title, message, priority=2, retry=120, expire=10800)
    
    def notify_service_down(self) -> bool:
        """Send notification when main service goes down"""
        title = "🚨 ONVIF Proxy Service Down"
        
        message = f"""The ONVIF Proxy service has stopped running.

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please check the service status and logs:
• systemctl status onvif-proxy
• journalctl -u onvif-proxy -f"""
        
        return self.send_notification(title, message, priority=2, retry=120, expire=10800)
    
    def notify_service_up(self) -> bool:
        """Send notification when main service comes back up"""
        title = "✅ ONVIF Proxy Service Restored"
        
        message = f"""The ONVIF Proxy service is now running normally.

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        
        return self.send_notification(title, message, priority=0)
    
    def test_notification(self) -> bool:
        """Send test notification to verify configuration"""
        title = "🧪 ONVIF Proxy Test"
        message = f"Test notification from ONVIF Proxy system.\n\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return self.send_notification(title, message, priority=0)
