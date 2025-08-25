#!/usr/bin/env python3
"""
Configuration management for ONVIF Proxy system
Handles XML configuration file operations
"""

import xml.etree.ElementTree as ET
import os
import io
import tempfile
from typing import Dict, List, Optional

class ConfigManager:
    def __init__(self, config_path: str = "/var/lib/onvif-proxy/config.xml"):
        self.config_path = config_path
        self.tree = None
        self.root = None
        self.load_config()
    
    def reload_config(self):
        """Reload configuration from file to get latest changes"""
        try:
            self.tree = ET.parse(self.config_path)
            self.root = self.tree.getroot()
        except FileNotFoundError:
            self.create_default_config()
        except ET.ParseError as e:
            raise Exception(f"Invalid XML configuration: {e}")
    
    def _parse_bool(self, value) -> bool:
        """Parse various truthy/falsey string representations to boolean.
        Accepts True/False, true/false, 1/0, yes/no, on/off.
        """
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in ("true", "1", "yes", "on")
    
    def load_config(self):
        """Load configuration from XML file"""
        try:
            self.tree = ET.parse(self.config_path)
            self.root = self.tree.getroot()
        except FileNotFoundError:
            self.create_default_config()
        except ET.ParseError as e:
            raise Exception(f"Invalid XML configuration: {e}")
    
    def create_default_config(self):
        """Create default configuration structure"""
        self.root = ET.Element("onvif_proxy")
        
        # System configuration
        system = ET.SubElement(self.root, "system")
        ET.SubElement(system, "enabled").text = "true"
        ET.SubElement(system, "base_interface").text = "eth0"
        ET.SubElement(system, "base_ip_range").text = "192.168.1.100"
        ET.SubElement(system, "pushover_token").text = ""
        ET.SubElement(system, "pushover_user").text = ""
        ET.SubElement(system, "web_port").text = "8080"
        ET.SubElement(system, "notify_camera_offline").text = "true"
        ET.SubElement(system, "notify_camera_offline_priority").text = "0"
        ET.SubElement(system, "notify_camera_online").text = "true"
        ET.SubElement(system, "notify_camera_online_priority").text = "0"
        ET.SubElement(system, "notify_system_error").text = "true"
        ET.SubElement(system, "notify_system_error_priority").text = "1"
        ET.SubElement(system, "notify_service_restart").text = "false"
        ET.SubElement(system, "notify_service_restart_priority").text = "0"
        ET.SubElement(system, "no_traffic_alerts").text = "true"
        ET.SubElement(system, "no_traffic_minutes").text = "5"
        ET.SubElement(system, "no_traffic_priority").text = "1"
        
        # Cameras section
        ET.SubElement(self.root, "cameras")
        
        self.tree = ET.ElementTree(self.root)
        self.save_config()
    
    def save_config(self):
        """Save configuration to XML file"""
        # Reload the tree from the current root to ensure we have the latest structure
        self.tree = ET.ElementTree(self.root)
        try:
            ET.indent(self.tree, space="    ")
        except Exception:
            # Older Python versions may not support ET.indent
            pass

        # Serialize XML to bytes
        buf = io.BytesIO()
        self.tree.write(buf, encoding="UTF-8", xml_declaration=True)
        data = buf.getvalue()

        # Atomic write with fsync to ensure durability
        dirpath = os.path.dirname(self.config_path) or "."
        fd, tmppath = tempfile.mkstemp(prefix=".config.xml.", dir=dirpath)
        try:
            with os.fdopen(fd, 'wb') as tmp:
                tmp.write(data)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmppath, self.config_path)
            # fsync directory to persist rename
            try:
                dir_fd = os.open(dirpath, os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception:
                # Best effort on directory fsync
                pass
        except Exception:
            # Cleanup temp file if present
            try:
                if os.path.exists(tmppath):
                    os.unlink(tmppath)
            except Exception:
                pass
            raise
    
    def get_system_config(self) -> Dict:
        """Get system configuration"""
        system = self.root.find("system")
        if system is None:
            return {}
        
        return {
            "enabled": self._parse_bool(system.find("enabled").text if system.find("enabled") is not None else "true"),
            "base_interface": system.find("base_interface").text,
            "base_ip_range": system.find("base_ip_range").text,
            "pushover_token": system.find("pushover_token").text or "",
            "pushover_user": system.find("pushover_user").text or "",
            "web_port": int(system.find("web_port").text or 8080),
            "notify_camera_offline": self._parse_bool(system.find("notify_camera_offline").text if system.find("notify_camera_offline") is not None else "true"),
            "notify_camera_offline_priority": int(system.find("notify_camera_offline_priority").text) if system.find("notify_camera_offline_priority") is not None and system.find("notify_camera_offline_priority").text else 0,
            "notify_camera_online": self._parse_bool(system.find("notify_camera_online").text if system.find("notify_camera_online") is not None else "true"),
            "notify_camera_online_priority": int(system.find("notify_camera_online_priority").text) if system.find("notify_camera_online_priority") is not None and system.find("notify_camera_online_priority").text else 0,
            "notify_system_error": self._parse_bool(system.find("notify_system_error").text if system.find("notify_system_error") is not None else "true"),
            "notify_system_error_priority": int(system.find("notify_system_error_priority").text) if system.find("notify_system_error_priority") is not None and system.find("notify_system_error_priority").text else 1,
            "notify_service_restart": self._parse_bool(system.find("notify_service_restart").text if system.find("notify_service_restart") is not None else "false"),
            "notify_service_restart_priority": int(system.find("notify_service_restart_priority").text) if system.find("notify_service_restart_priority") is not None and system.find("notify_service_restart_priority").text else 0,
            "no_traffic_alerts": self._parse_bool(system.find("no_traffic_alerts").text if system.find("no_traffic_alerts") is not None else "true"),
            "no_traffic_minutes": int(system.find("no_traffic_minutes").text) if system.find("no_traffic_minutes") is not None and system.find("no_traffic_minutes").text else 5,
            "no_traffic_priority": int(system.find("no_traffic_priority").text) if system.find("no_traffic_priority") is not None and system.find("no_traffic_priority").text else 1
        }
    
    def update_system_config(self, config: Dict):
        """Update system configuration with new values"""
        system = self.root.find('system')
        if system is None:
            system = ET.SubElement(self.root, 'system')
            
        for key, value in config.items():
            # Skip notification-specific settings that should be in the notification config
            if key in ['pushover_token', 'pushover_user', 'notify_camera_up', 'notify_camera_down', 
                      'notify_camera_added', 'notify_camera_removed', 'notify_system_error',
                      'notify_priority', 'notify_retry', 'notify_expire']:
                continue
                
            elem = system.find(key)
            if elem is None:
                elem = ET.SubElement(system, key)
            elem.text = str(value).lower() if isinstance(value, bool) else str(value)
            
        self.save_config()
        
    def update_notification_config(self, config: Dict):
        """Update notification configuration with new values"""
        system = self.root.find('system')
        if system is None:
            system = ET.SubElement(self.root, 'system')
            
        # Map of notification settings to their default values if not provided
        notification_settings = {
            'pushover_token': '',
            'pushover_user': '',
            'notify_camera_up': False,
            'notify_camera_down': False,
            'notify_camera_added': False,
            'notify_camera_removed': False,
            'notify_system_error': False,
            'notify_priority': 0,
            'notify_retry': 300,
            'notify_expire': 3600
        }
        
        # Update with provided values
        for key, default_value in notification_settings.items():
            value = config.get(key, default_value)
            elem = system.find(key)
            if elem is None:
                elem = ET.SubElement(system, key)
            elem.text = str(value).lower() if isinstance(value, bool) else str(value)
            
        self.save_config()
    
    def get_cameras(self) -> List[Dict]:
        """Get all camera configurations"""
        cameras = []
        cameras_element = self.root.find("cameras")
        if cameras_element is None:
            return cameras
        
        for camera in cameras_element.findall("camera"):
            camera_config = {
                "id": camera.get("id"),
                "name": camera.find("name").text if camera.find("name") is not None else "",
                "enabled": self._parse_bool(camera.find("enabled").text if camera.find("enabled") is not None else True),
                "rtsp_url": camera.find("rtsp_url").text if camera.find("rtsp_url") is not None else "",
                "rtsp_username": camera.find("rtsp_username").text if camera.find("rtsp_username") is not None else "",
                "rtsp_password": camera.find("rtsp_password").text if camera.find("rtsp_password") is not None else "",
                "resolution": camera.find("resolution").text if camera.find("resolution") is not None else "",
                "fps": int(float(camera.find("fps").text)) if camera.find("fps") is not None and camera.find("fps").text and camera.find("fps").text != "None" else None,
                "bitrate_kbps": int(float(camera.find("bitrate_kbps").text)) if camera.find("bitrate_kbps") is not None and camera.find("bitrate_kbps").text and camera.find("bitrate_kbps").text != "None" else None,
                "onvif_ip": camera.find("onvif_ip").text if camera.find("onvif_ip") is not None else "",
                "onvif_port": int(camera.find("onvif_port").text) if camera.find("onvif_port") is not None else 80,
                "last_ping_status": camera.find("last_ping_status").text if camera.find("last_ping_status") is not None else "unknown",
                "notifications_enabled": self._parse_bool(camera.find("notifications_enabled").text if camera.find("notifications_enabled") is not None else True),
                "use_dhcp": self._parse_bool(camera.find("use_dhcp").text if camera.find("use_dhcp") is not None else False),
                "base_interface": camera.find("base_interface").text if camera.find("base_interface") is not None else None,
                'onvif_mac': (camera.find('onvif_mac').text if camera.find('onvif_mac') is not None and camera.find('onvif_mac').text else (camera.find('mac_address').text if camera.find('mac_address') is not None and camera.find('mac_address').text else '')),
                'onvif_interface': (camera.find('onvif_interface').text if camera.find('onvif_interface') is not None and camera.find('onvif_interface').text else f'onvif-{camera.get("id")}')
            }
            cameras.append(camera_config)
        
        return cameras
    
    def get_camera(self, camera_id: str) -> Optional[Dict]:
        """Get specific camera configuration"""
        cameras = self.get_cameras()
        for camera in cameras:
            if camera["id"] == camera_id:
                return camera
        return None
    
    def add_camera(self, camera_config: Dict) -> bool:
        """Add new camera configuration"""
        cameras_element = self.root.find("cameras")
        if cameras_element is None:
            cameras_element = ET.SubElement(self.root, "cameras")
        
        if self.get_camera(camera_config["id"]):
            return False
        
        camera = ET.SubElement(cameras_element, "camera")
        camera.set("id", camera_config["id"])
        
        for key, value in camera_config.items():
            if key != "id":
                ET.SubElement(camera, key).text = str(value)
        
        self.save_config()
        return True
    
    def update_camera(self, camera_id: str, camera_config: Dict) -> bool:
        """Update existing camera configuration"""
        cameras_element = self.root.find("cameras")
        if cameras_element is None:
            return False
        
        for camera in cameras_element.findall("camera"):
            if camera.get("id") == camera_id:
                for key, value in camera_config.items():
                    if key != "id":
                        element = camera.find(key)
                        if element is None:
                            element = ET.SubElement(camera, key)
                        element.text = str(value)
                
                self.save_config()
                return True
        
        return False
    
    def delete_camera(self, camera_id: str) -> bool:
        """Delete camera configuration"""
        cameras_element = self.root.find("cameras")
        if cameras_element is None:
            return False
        
        for camera in cameras_element.findall("camera"):
            if camera.get("id") == camera_id:
                cameras_element.remove(camera)
                self.save_config()
                return True
        
        return False
    
    def generate_next_camera_id(self) -> str:
        """Generate next available camera ID"""
        cameras = self.get_cameras()
        if not cameras:
            return "1"
        
        max_id = max([int(camera["id"]) for camera in cameras if camera["id"].isdigit()])
        return str(max_id + 1)
    
    def generate_next_ip(self) -> str:
        """Generate next available IP address"""
        system_config = self.get_system_config()
        base_ip = system_config.get("base_ip_range", "192.168.1.100")
        base_parts = base_ip.split(".")
        base_num = int(base_parts[3])
        
        cameras = self.get_cameras()
        used_ips = [camera["onvif_ip"] for camera in cameras if camera["onvif_ip"]]
        
        for i in range(1, 255):
            new_ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{base_num + i}"
            if new_ip not in used_ips:
                return new_ip
        
        return f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{base_num + len(cameras) + 1}"
    
    def generate_next_mac(self) -> str:
        """Generate next available MAC address"""
        cameras = self.get_cameras()
        used_macs = [camera.get("onvif_mac") or camera.get("mac_address") for camera in cameras if camera.get("onvif_mac") or camera.get("mac_address")]
        
        for i in range(1, 255):
            new_mac = f"02:00:00:00:00:{i:02x}"
            if new_mac not in used_macs:
                return new_mac
        
        return f"02:00:00:00:00:{len(cameras) + 1:02x}"
    
    def generate_mac_for_camera_id(self, camera_id: int) -> str:
        """Generate MAC address based on camera ID to ensure uniqueness"""
        return f"02:00:00:00:00:{camera_id:02x}"
