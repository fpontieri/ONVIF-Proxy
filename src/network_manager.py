#!/usr/bin/env python3
"""
Network interface management for ONVIF Proxy system
Handles IP aliases and MAC address configuration
"""

import subprocess
import logging
import netifaces
from typing import List, Dict, Optional

class NetworkManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        return netifaces.interfaces()
    
    def get_interface_addresses(self, interface: str) -> Dict:
        """Get current addresses for an interface"""
        try:
            return netifaces.ifaddresses(interface)
        except ValueError:
            return {}
    
    def create_ip_alias(self, interface: str, ip_address: str, mac_address: str) -> bool:
        """Create IP alias with specific MAC address"""
        try:
            # Create virtual interface with specific MAC
            alias_name = f"{interface}:{ip_address.replace('.', '_')}"
            
            # Add IP alias
            cmd = [
                "ip", "addr", "add", 
                f"{ip_address}/24", "dev", interface, 
                "label", alias_name
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.logger.error(f"Failed to create IP alias: {result.stderr}")
                return False
            
            # Set MAC address for the alias (using macvlan)
            self._create_macvlan_interface(interface, ip_address, mac_address)
            
            self.logger.info(f"Created IP alias {ip_address} on {interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating IP alias: {e}")
            return False
    
    def _create_macvlan_interface(self, parent_interface: str, ip_address: str, mac_address: str):
        """Create macvlan interface with specific MAC address (legacy: name derived from IP)"""
        try:
            vlan_name = f"onvif_{ip_address.replace('.', '_')}"
            
            # Create macvlan interface
            cmd = ["ip", "link", "add", vlan_name, "link", parent_interface, "type", "macvlan", "mode", "bridge"]
            subprocess.run(cmd, capture_output=True, text=True)
            
            # Set MAC address
            cmd = ["ip", "link", "set", "dev", vlan_name, "address", mac_address]
            subprocess.run(cmd, capture_output=True, text=True)
            
            # Assign IP address
            cmd = ["ip", "addr", "add", f"{ip_address}/24", "dev", vlan_name]
            subprocess.run(cmd, capture_output=True, text=True)
            
            # Bring interface up
            cmd = ["ip", "link", "set", vlan_name, "up"]
            subprocess.run(cmd, capture_output=True, text=True)
            
            self.logger.info(f"Created macvlan interface {vlan_name} with MAC {mac_address}")
            
        except Exception as e:
            self.logger.error(f"Error creating macvlan interface: {e}")
    
    def create_camera_interface(self, parent_interface: str, camera_id: str, mac_address: str, ip_address: Optional[str] = None) -> bool:
        """Create a per-camera macvlan interface named onvif-<camera_id> with static IP."""
        try:
            iface = f"onvif-{camera_id}"
            
            # Remove interface if it already exists
            subprocess.run(["ip", "link", "delete", iface], capture_output=True, text=True)
            
            # Create macvlan interface
            cmd = ["ip", "link", "add", iface, "link", parent_interface, "type", "macvlan", "mode", "bridge"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"Failed to create macvlan interface {iface}: {result.stderr}")
                return False
            
            # Set MAC address
            if mac_address:
                result = subprocess.run(["ip", "link", "set", "dev", iface, "address", mac_address], capture_output=True, text=True)
                if result.returncode != 0:
                    self.logger.error(f"Failed to set MAC address on {iface}: {result.stderr}")
                    return False
            
            # Disable IPv6 on the interface
            subprocess.run(["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=1"], capture_output=True, text=True)
            
            # Bring interface up first
            result = subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"Failed to bring up interface {iface}: {result.stderr}")
                return False
            
            # Assign static IP if provided
            if ip_address:
                result = subprocess.run(["ip", "addr", "add", f"{ip_address}/24", "dev", iface], capture_output=True, text=True)
                if result.returncode != 0:
                    self.logger.error(f"Failed to assign IP {ip_address} to {iface}: {result.stderr}")
                    return False
                self.logger.info(f"Created interface {iface} on {parent_interface} with MAC {mac_address} and IP {ip_address}")
            else:
                self.logger.info(f"Created interface {iface} on {parent_interface} with MAC {mac_address} (no IP)")
            
            return True
        except Exception as e:
            self.logger.error(f"Error creating camera interface onvif-{camera_id}: {e}")
            return False
    
    def acquire_dhcp(self, interface_name: str, timeout: int = 30) -> bool:
        """Acquire DHCP lease on interface. Returns True if lease obtained."""
        try:
            # Release any existing lease first
            subprocess.run(["dhclient", "-r", interface_name], capture_output=True, text=True)
            # Request a new lease, wait until address is obtained
            result = subprocess.run(["dhclient", "-1", interface_name], capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0:
                self.logger.error(f"dhclient failed on {interface_name}: {result.stderr}")
                return False
            return True
        except subprocess.TimeoutExpired:
            self.logger.error(f"DHCP acquire timeout on {interface_name}")
            return False
        except Exception as e:
            self.logger.error(f"Error acquiring DHCP on {interface_name}: {e}")
            return False
    
    def get_interface_ipv4(self, interface_name: str) -> Optional[str]:
        """Get the primary IPv4 address assigned to an interface."""
        try:
            result = subprocess.run(["ip", "addr", "show", interface_name], capture_output=True, text=True)
            if result.returncode != 0:
                return None
            import re
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
            return m.group(1) if m else None
        except Exception:
            return None
    
    def remove_ip_alias(self, interface: str, ip_address: str) -> bool:
        """Remove IP alias"""
        try:
            # Remove macvlan interface
            vlan_name = f"onvif_{ip_address.replace('.', '_')}"
            cmd = ["ip", "link", "delete", vlan_name]
            subprocess.run(cmd, capture_output=True, text=True)
            
            # Remove IP alias
            cmd = ["ip", "addr", "del", f"{ip_address}/24", "dev", interface]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.logger.warning(f"IP alias might not exist: {result.stderr}")
            
            self.logger.info(f"Removed IP alias {ip_address} from {interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing IP alias: {e}")
            return False
    
    def remove_camera_interface(self, camera_id: str) -> bool:
        """Remove per-camera macvlan interface onvif-<camera_id>."""
        try:
            iface = f"onvif-{camera_id}"
            result = subprocess.run(["ip", "link", "delete", iface], capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.warning(f"Interface {iface} might not exist: {result.stderr}")
            else:
                self.logger.info(f"Removed interface {iface}")
            return True
        except Exception as e:
            self.logger.error(f"Error removing interface onvif-{camera_id}: {e}")
            return False
    
    def list_ip_aliases(self, interface: str) -> List[str]:
        """List all IP aliases for an interface"""
        try:
            cmd = ["ip", "addr", "show", interface]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return []
            
            aliases = []
            for line in result.stdout.split('\n'):
                if 'inet ' in line and 'secondary' in line:
                    ip = line.strip().split()[1].split('/')[0]
                    aliases.append(ip)
            
            return aliases
            
        except Exception as e:
            self.logger.error(f"Error listing IP aliases: {e}")
            return []
    
    def make_persistent_config(self, interface: str, camera_id: str, ip_address: str, mac_address: str) -> bool:
        """Make network configuration persistent using systemd-networkd"""
        try:
            import os
            
            # Create systemd network configuration directory if it doesn't exist
            os.makedirs("/etc/systemd/network", exist_ok=True)
            
            iface_name = f"onvif-{camera_id}"
            
            # Create .netdev file for macvlan interface
            netdev_content = f"""[NetDev]
Name={iface_name}
Kind=macvlan
MACAddress={mac_address}

[MACVLAN]
Mode=bridge
"""
            
            netdev_path = f"/etc/systemd/network/{iface_name}.netdev"
            with open(netdev_path, 'w') as f:
                f.write(netdev_content)
            
            # Create .network file with IPv6 disabled
            network_content = f"""[Match]
Name={iface_name}

[Network]
Address={ip_address}/24
LinkLocalAddressing=no
IPv6AcceptRA=no

[Link]
RequiredForOnline=no
"""
            
            network_path = f"/etc/systemd/network/{iface_name}.network"
            with open(network_path, 'w') as f:
                f.write(network_content)
            
            # Create persistent sysctl config to disable IPv6
            sysctl_content = f"net.ipv6.conf.{iface_name}.disable_ipv6 = 1\n"
            sysctl_path = f"/etc/sysctl.d/99-onvif-{camera_id}-ipv6.conf"
            with open(sysctl_path, 'w') as f:
                f.write(sysctl_content)
            
            # Reload systemd-networkd
            subprocess.run(["systemctl", "reload", "systemd-networkd"], 
                         capture_output=True, text=True)
            
            self.logger.info(f"Made network configuration persistent for camera {camera_id} interface {iface_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error making network configuration persistent: {e}")
            return False
    
    def remove_persistent_config(self, camera_id: str) -> bool:
        """Remove persistent network configuration"""
        try:
            import os
            
            iface_name = f"onvif-{camera_id}"
            config_path = f"/etc/systemd/network/{iface_name}.network"
            netdev_path = f"/etc/systemd/network/{iface_name}.netdev"
            sysctl_path = f"/etc/sysctl.d/99-onvif-{camera_id}-ipv6.conf"
            
            if os.path.exists(config_path):
                os.remove(config_path)
            
            if os.path.exists(netdev_path):
                os.remove(netdev_path)
                
            if os.path.exists(sysctl_path):
                os.remove(sysctl_path)
            
            # Reload systemd-networkd
            subprocess.run(["systemctl", "reload", "systemd-networkd"], 
                         capture_output=True, text=True)
            
            self.logger.info(f"Removed persistent configuration for camera {camera_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing persistent configuration: {e}")
            return False
    
    def ping_host(self, host: str, count: int = 5) -> Dict:
        """Ping host and return results"""
        try:
            cmd = ["ping", "-c", str(count), host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            ping_result = {
                "host": host,
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "packet_loss": "100%",
                "avg_time": "0ms"
            }
            
            if result.returncode == 0:
                # Parse ping output for statistics
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'packet loss' in line:
                        ping_result["packet_loss"] = line.split(',')[2].strip().split()[0]
                    elif 'avg' in line and 'min/avg/max' in line:
                        ping_result["avg_time"] = line.split('/')[4] + "ms"
            
            return ping_result
            
        except subprocess.TimeoutExpired:
            return {
                "host": host,
                "success": False,
                "output": "",
                "error": "Ping timeout",
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
