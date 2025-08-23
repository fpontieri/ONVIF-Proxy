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
        
    # --- System forwarding helpers ---
    def _enable_ip_forwarding(self):
        """Enable IPv4 forwarding at runtime."""
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True, text=True)
        except Exception as e:
            self.logger.warning(f"Failed to enable ip_forward: {e}")

    def _disable_rp_filter(self, iface: str):
        """Disable rp_filter on a specific interface to avoid dropping forwarded traffic."""
        try:
            subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter=0"], capture_output=True, text=True)
        except Exception as e:
            self.logger.warning(f"Failed to disable rp_filter on {iface}: {e}")

    def _add_forward_allow_rules(self, camera_ip: str):
        """Allow RTSP flows through FORWARD chain to/from the camera."""
        try:
            # Allow new/established to camera 554
            fwd1 = [
                "iptables", "-A", "FORWARD",
                "-p", "tcp", "-d", camera_ip, "--dport", "554",
                "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED",
                "-j", "ACCEPT"
            ]
            self.logger.info(f"Adding FORWARD allow rule: {' '.join(fwd1)}")
            subprocess.run(fwd1, capture_output=True, text=True)

            # Allow established replies from camera 554
            fwd2 = [
                "iptables", "-A", "FORWARD",
                "-p", "tcp", "-s", camera_ip, "--sport", "554",
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-j", "ACCEPT"
            ]
            self.logger.info(f"Adding FORWARD allow rule: {' '.join(fwd2)}")
            subprocess.run(fwd2, capture_output=True, text=True)
        except Exception as e:
            self.logger.warning(f"Failed to add FORWARD allow rules: {e}")

    def _remove_forward_allow_rules(self, camera_ip: str):
        """Remove previously added FORWARD allow rules to/from the camera."""
        try:
            fwd1 = [
                "iptables", "-D", "FORWARD",
                "-p", "tcp", "-d", camera_ip, "--dport", "554",
                "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED",
                "-j", "ACCEPT"
            ]
            self.logger.info(f"Removing FORWARD allow rule: {' '.join(fwd1)}")
            subprocess.run(fwd1, capture_output=True, text=True)

            fwd2 = [
                "iptables", "-D", "FORWARD",
                "-p", "tcp", "-s", camera_ip, "--sport", "554",
                "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-j", "ACCEPT"
            ]
            self.logger.info(f"Removing FORWARD allow rule: {' '.join(fwd2)}")
            subprocess.run(fwd2, capture_output=True, text=True)
        except Exception as e:
            self.logger.warning(f"Failed to remove FORWARD allow rules: {e}")
    
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
    
    def create_camera_interface(self, parent_interface: str, camera_id: str, mac_address: str, ip_address: Optional[str] = None, camera_ip: Optional[str] = None) -> bool:
        """Create a per-camera macvlan interface named onvif-<camera_id> with static IP and NAT rules for RTSP."""
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

            # Networking kernel knobs
            self._enable_ip_forwarding()
            self._disable_rp_filter(iface)

            # Assign static IP if provided
            if ip_address:
                result = subprocess.run(["ip", "addr", "add", f"{ip_address}/24", "dev", iface], capture_output=True, text=True)
                if result.returncode != 0:
                    self.logger.error(f"Failed to assign IP {ip_address} to {iface}: {result.stderr}")
                    return False
                
                # Create NAT rules for RTSP proxying if camera IP is provided
                if camera_ip:
                    self._create_rtsp_nat_rules(ip_address, camera_ip)
                    self._add_forward_allow_rules(camera_ip)
                
                self.logger.info(f"Created interface {iface} on {parent_interface} with MAC {mac_address} and IP {ip_address}")
            else:
                self.logger.info(f"Created interface {iface} on {parent_interface} with MAC {mac_address} (no IP)")
            
            return True
        except Exception as e:
            self.logger.error(f"Error creating camera interface onvif-{camera_id}: {e}")
            return False
    
    def acquire_dhcp(self, interface_name: str, timeout: int = 30, camera_name: str = None) -> Optional[str]:
        """Acquire DHCP lease on interface and return assigned IP address."""
        try:
            self.logger.info(f"Starting DHCP acquisition on interface {interface_name}")
            
            # Run dhclient directly since main service runs as root
            dhclient_cmd = ["dhclient"]
            
            # Create DHCP config file for this interface with hostname
            hostname = f"onvif-{camera_name}" if camera_name else interface_name
            config_file = self._create_dhcp_config(interface_name, hostname)
            
            # Release any existing lease first
            release_result = subprocess.run(dhclient_cmd + ["-r", interface_name], capture_output=True, text=True)
            self.logger.debug(f"dhclient release result: {release_result.returncode}, stderr: {release_result.stderr}")
            
            # Request a new lease using config file
            cmd_str = " ".join(dhclient_cmd + ["-cf", config_file, "-1", "-v", interface_name])
            self.logger.info(f"Running {cmd_str} with timeout {timeout}s")
            result = subprocess.run(dhclient_cmd + ["-cf", config_file, "-1", "-v", interface_name], capture_output=True, text=True, timeout=timeout)
            
            self.logger.info(f"dhclient result: returncode={result.returncode}")
            if result.stdout:
                self.logger.info(f"dhclient stdout: {result.stdout}")
            if result.stderr:
                self.logger.info(f"dhclient stderr: {result.stderr}")
            
            if result.returncode != 0:
                self.logger.error(f"dhclient failed on {interface_name}: {result.stderr}")
                return None
            else:
                self.logger.info(f"dhclient success on {interface_name} hostname: {hostname}")
            
            # Get the assigned IP address
            assigned_ip = self.get_interface_ipv4(interface_name)
            if assigned_ip:
                self.logger.info(f"DHCP assigned IP {assigned_ip} to interface {interface_name}")
                return assigned_ip
            else:
                self.logger.error(f"No IP address found on interface {interface_name} after DHCP")
                return None
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"DHCP acquire timeout on {interface_name}")
            return None
        except Exception as e:
            self.logger.error(f"Error acquiring DHCP on {interface_name}: {e}")
            return None
        finally:
            # Clean up config file if it was created
            try:
                if 'config_file' in locals() and config_file.startswith('/tmp/'):
                    os.unlink(config_file)
            except:
                pass
    
    def _create_dhcp_config(self, interface_name: str, hostname: str = None) -> str:
        """Create DHCP config file for the interface with hostname."""
        import os
        import tempfile
        
        # Try to use system dhclient.conf first, fallback to temporary file
        system_config = "/etc/dhcp/dhclient.conf"
        
        try:
            # Check if we can write to /etc/dhcp/
            if os.access("/etc/dhcp/", os.W_OK):
                # Use persistent config file in /etc/dhcp/
                config_file = f"/etc/dhcp/dhclient-{interface_name}.conf"
                self._write_dhcp_config(config_file, interface_name, hostname, system_config)
                self.logger.debug(f"Created persistent DHCP config file: {config_file}")
                return config_file
            else:
                # Fallback: copy system config and append our config
                return self._create_temp_config_with_system_base(interface_name, hostname, system_config)
                
        except Exception as e:
            self.logger.warning(f"Failed to create persistent config, using temporary: {e}")
            return self._create_temp_config_with_system_base(interface_name, hostname, system_config)
    
    def _write_dhcp_config(self, config_file: str, interface_name: str, hostname: str = None, system_config: str = None):
        """Write DHCP config file with interface-specific hostname."""
        import os
        with open(config_file, 'w') as f:
            # Include system config if it exists
            if system_config and os.path.exists(system_config):
                try:
                    with open(system_config, 'r') as sys_f:
                        f.write("# Base system configuration\n")
                        f.write(sys_f.read())
                        f.write("\n\n")
                except:
                    pass
            
            # Add interface-specific configuration - ONLY hostname
            hostname_to_use = hostname or interface_name
            f.write(f"""# ONVIF Proxy configuration for {interface_name}
interface "{interface_name}" {{
    send host-name "{hostname_to_use}";
}}
""")
    
    def _create_temp_config_with_system_base(self, interface_name: str, hostname: str = None, system_config: str = None) -> str:
        """Create temporary config file with system base configuration."""
        import os
        import tempfile
        fd, config_file = tempfile.mkstemp(prefix=f"dhclient-{interface_name}-", suffix=".conf")
        
        try:
            with os.fdopen(fd, 'w') as f:
                # Copy system config if it exists
                if system_config and os.path.exists(system_config):
                    try:
                        with open(system_config, 'r') as sys_f:
                            f.write("# Base system configuration\n")
                            f.write(sys_f.read())
                            f.write("\n\n")
                    except:
                        pass
                
                # Add interface-specific configuration - ONLY hostname
                hostname_to_use = hostname or interface_name
                f.write(f"""# ONVIF Proxy configuration for {interface_name}
interface "{interface_name}" {{
    send host-name "{hostname_to_use}";
}}
""")
            
            self.logger.debug(f"Created temporary DHCP config file: {config_file}")
            return config_file
            
        except Exception as e:
            # Clean up on error
            try:
                os.close(fd)
                os.unlink(config_file)
            except:
                pass
            raise e
    
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
    
    def _create_rtsp_nat_rules(self, virtual_ip: str, camera_ip: str) -> bool:
        """Create iptables NAT rules for RTSP proxying (TCP only for reliability)."""
        try:
            # Ensure kernel is ready to forward
            self._enable_ip_forwarding()
            # DNAT rule: redirect TCP traffic to virtual IP port 554 to camera IP port 554
            dnat_rule = [
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-d", virtual_ip, "-p", "tcp", "--dport", "554",
                "-j", "DNAT", "--to-destination", f"{camera_ip}:554"
            ]
            self.logger.info(f"Executing DNAT rule: {' '.join(dnat_rule)}")
            result = subprocess.run(dnat_rule, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"Failed to create DNAT rule for {virtual_ip} -> {camera_ip}")
                self.logger.error(f"Command: {' '.join(dnat_rule)}")
                self.logger.error(f"Return code: {result.returncode}")
                self.logger.error(f"Stderr: {result.stderr}")
                self.logger.error(f"Stdout: {result.stdout}")
                return False
            else:
                self.logger.info(f"Successfully created DNAT rule: {virtual_ip}:554 -> {camera_ip}:554")
            
            # SNAT rule: set source to virtual IP for traffic going to camera:554
            snat_rule = [
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-d", camera_ip, "-p", "tcp", "--dport", "554",
                "-j", "SNAT", "--to-source", virtual_ip
            ]
            self.logger.info(f"Executing SNAT rule: {' '.join(snat_rule)}")
            result = subprocess.run(snat_rule, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"Failed to create SNAT rule for {virtual_ip} -> {camera_ip}")
                self.logger.error(f"Command: {' '.join(snat_rule)}")
                self.logger.error(f"Return code: {result.returncode}")
                self.logger.error(f"Stderr: {result.stderr}")
                self.logger.error(f"Stdout: {result.stdout}")
                return False
            else:
                self.logger.info(f"Successfully created SNAT rule for {virtual_ip} (dst {camera_ip}:554)")
            
            self.logger.info(f"All RTSP NAT rules created successfully: {virtual_ip}:554 -> {camera_ip}:554")
            return True
            
        except Exception as e:
            self.logger.error(f"Exception while creating RTSP NAT rules: {e}")
            return False

    def create_rtsp_nat_rules(self, virtual_ip: str, camera_ip: str) -> bool:
        """Public method to create RTSP NAT rules and add FORWARD allows."""
        created = self._create_rtsp_nat_rules(virtual_ip, camera_ip)
        if created:
            self._add_forward_allow_rules(camera_ip)
        return created

    def _remove_rtsp_nat_rules(self, virtual_ip: str, camera_ip: str) -> bool:
        """Remove iptables NAT rules for RTSP proxying."""
        try:
            # Remove FORWARD allow rules first
            self._remove_forward_allow_rules(camera_ip)
            # Remove DNAT rule
            dnat_rule = [
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-d", virtual_ip, "-p", "tcp", "--dport", "554",
                "-j", "DNAT", "--to-destination", f"{camera_ip}:554"
            ]
            self.logger.info(f"Removing DNAT rule: {' '.join(dnat_rule)}")
            result = subprocess.run(dnat_rule, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.warning(f"Failed to remove DNAT rule (may not exist): {result.stderr}")
            else:
                self.logger.info(f"Successfully removed DNAT rule: {virtual_ip}:554 -> {camera_ip}:554")
            
            # Remove SNAT rule
            snat_rule = [
                "iptables", "-t", "nat", "-D", "POSTROUTING",
                "-d", camera_ip, "-p", "tcp", "--dport", "554",
                "-j", "SNAT", "--to-source", virtual_ip
            ]
            self.logger.info(f"Removing SNAT rule: {' '.join(snat_rule)}")
            result = subprocess.run(snat_rule, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.warning(f"Failed to remove SNAT rule (may not exist): {result.stderr}")
            else:
                self.logger.info(f"Successfully removed SNAT rule for dst {camera_ip}:554")
            
            self.logger.info(f"NAT rule cleanup completed for {virtual_ip} -> {camera_ip}")
            return True
            
        except Exception as e:
            self.logger.error(f"Exception while removing RTSP NAT rules: {e}")
            return False

    # Public wrappers for NAT management
    def create_rtsp_nat_rules(self, virtual_ip: str, camera_ip: str) -> bool:
        """Public method to create RTSP NAT rules. Wraps the internal implementation."""
        return self._create_rtsp_nat_rules(virtual_ip, camera_ip)

    def remove_rtsp_nat_rules(self, virtual_ip: str, camera_ip: str) -> bool:
        """Public method to remove RTSP NAT rules. Wraps the internal implementation."""
        return self._remove_rtsp_nat_rules(virtual_ip, camera_ip)

    def remove_camera_interface(self, camera_id: str, virtual_ip: Optional[str] = None, camera_ip: Optional[str] = None) -> bool:
        """Remove per-camera macvlan interface onvif-<camera_id> and associated NAT rules."""
        try:
            # Remove NAT rules if IPs are provided
            if virtual_ip and camera_ip:
                self._remove_rtsp_nat_rules(virtual_ip, camera_ip)
            
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
