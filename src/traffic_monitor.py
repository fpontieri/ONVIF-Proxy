#!/usr/bin/env python3
"""
RTSP Traffic Monitoring Module
Tracks network traffic per camera using iptables counters and RRD storage
"""

import os
import re
import time
import logging
import subprocess
import threading
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import rrdtool
from dataclasses import dataclass

@dataclass
class TrafficStats:
    """Traffic statistics for a camera"""
    camera_id: str
    timestamp: float
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    virtual_ip: str

class TrafficMonitor:
    """Monitor RTSP traffic per camera using iptables counters and RRD storage"""
    
    def __init__(self, rrd_base_path: str = "/var/lib/onvif-proxy"):
        self.rrd_base_path = rrd_base_path
        self.logger = logging.getLogger(__name__)
        # Reduce logging level for this module to WARNING to reduce log spam
        self.logger.setLevel(logging.WARNING)
        self.running = False
        self.monitor_thread = None
        self.cameras = {}  # camera_id -> camera_info
        self.last_stats = {}  # camera_id -> TrafficStats
        self.last_screenshot = {}  # camera_id -> timestamp of last screenshot
        
        # Ensure RRD directory exists (now the same as config directory)
        os.makedirs(self.rrd_base_path, exist_ok=True)
        
        # Ensure screenshots directory exists
        self.screenshots_path = os.path.join(self.rrd_base_path, "screenshots")
        os.makedirs(self.screenshots_path, exist_ok=True)
        
    def add_camera(self, camera_id: str, virtual_ip: str, camera_ip: str, rtsp_url: str = None):
        """Add a camera to traffic monitoring"""
        self.cameras[camera_id] = {
            'virtual_ip': virtual_ip,
            'camera_ip': camera_ip,
            'rtsp_url': rtsp_url,
            'rrd_file': os.path.join(self.rrd_base_path, f"camera_{camera_id}_traffic.rrd")
        }
        
        # Initialize screenshot timestamp
        self.last_screenshot[camera_id] = 0
        
        # Ensure accounting chain and rules for this camera exist
        try:
            self._ensure_acct_chain()
            self._ensure_camera_rules(camera_ip)
        except Exception as e:
            self.logger.warning(f"[ACCT] Failed to ensure accounting rules for {camera_ip}: {e}")

        # Create RRD file if it doesn't exist
        self._create_rrd_file(camera_id)
        
    def remove_camera(self, camera_id: str):
        """Remove a camera from traffic monitoring"""
        if camera_id in self.cameras:
            # Attempt to remove accounting rules for this camera IP
            try:
                self._remove_camera_rules(self.cameras[camera_id].get('camera_ip'))
            except Exception as e:
                self.logger.warning(f"[ACCT] Failed to remove accounting rules: {e}")
            del self.cameras[camera_id]
        if camera_id in self.last_stats:
            del self.last_stats[camera_id]
        if camera_id in self.last_screenshot:
            del self.last_screenshot[camera_id]
            
    def _create_rrd_file(self, camera_id: str):
        """Create RRD file for camera traffic data"""
        rrd_file = self.cameras[camera_id]['rrd_file']
        
        if os.path.exists(rrd_file):
            return
            
        try:
            # Create RRD with 5-second resolution, storing:
            # - Last 12 hours at 5-second resolution (8640 points)
            # - Last 7 days at 1-minute resolution (10080 points) 
            # - Last 30 days at 5-minute resolution (8640 points)
            # - Last 1 year at 1-hour resolution (8760 points)
            rrdtool.create(
                rrd_file,
                '--step', '5',
                '--start', str(int(time.time()) - 1),
                'DS:rx_bytes:COUNTER:10:0:U',
                'DS:tx_bytes:COUNTER:10:0:U', 
                'DS:rx_packets:COUNTER:10:0:U',
                'DS:tx_packets:COUNTER:10:0:U',
                'RRA:AVERAGE:0.5:1:8640',      # 5s for 12h
                'RRA:AVERAGE:0.5:12:10080',    # 1m for 7d
                'RRA:AVERAGE:0.5:60:8640',     # 5m for 30d
                'RRA:AVERAGE:0.5:720:8760',    # 1h for 1y
                'RRA:MAX:0.5:12:10080',        # 1m max for 7d
                'RRA:MAX:0.5:60:8640',         # 5m max for 30d
                'RRA:MAX:0.5:720:8760'         # 1h max for 1y
            )
            self.logger.info(f"Created RRD file for camera {camera_id}: {rrd_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to create RRD file for camera {camera_id}: {e}")
            
    def _get_iptables_counters(self, virtual_ip: str, camera_ip: str) -> Optional[Tuple[int, int, int, int]]:
        """Get traffic counters for camera.
        Prefer filter/TRAFFIC_ACCT via iptables-save -c; fallback to NAT DNAT/SNAT listing.
        Sum across all matching rules to handle duplicates.
        """
        try:
            # First try accounting chain via iptables-save -c
            ipt_save_paths = ['/usr/sbin/iptables-save', '/sbin/iptables-save']
            rx_bytes = tx_bytes = rx_packets = tx_packets = 0
            acct_used = None
            for ipts in ipt_save_paths:
                cmd = ['/usr/bin/sudo', '-n', ipts, '-c', '-t', 'filter']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    out = result.stdout
                    for line in out.splitlines():
                        if ' -A TRAFFIC_ACCT ' not in line:
                            continue
                        if not line.startswith('[') or ']' not in line:
                            continue
                        try:
                            bracket = line[1:line.index(']')]
                            pkts_str, bytes_str = bracket.split(':', 1)
                            pkts = int(pkts_str)
                            byts = int(bytes_str)
                        except Exception:
                            continue
                        if f"-s {camera_ip}" in line:
                            tx_packets += pkts
                            tx_bytes += byts
                            acct_used = ipts
                        if f"-d {camera_ip}" in line:
                            rx_packets += pkts
                            rx_bytes += byts
                            acct_used = ipts
                    if acct_used:
                        self.logger.debug(f"[ACCT] Counters via TRAFFIC_ACCT ({ipts}) cam_ip={camera_ip} rx_b={rx_bytes} tx_b={tx_bytes}")
                        return rx_bytes, tx_bytes, rx_packets, tx_packets
                else:
                    self.logger.debug(f"[ACCT] iptables-save failed with {ipts}: rc={result.returncode}, err={result.stderr.strip()}")

            # Prepare command variants to handle different iptables paths (NAT fallback)
            iptables_paths = ['/usr/sbin/iptables', '/sbin/iptables']

            # Get DNAT rule counters (incoming traffic to camera)
            dnat_out = None
            dnat_path_used = None
            for ipt in iptables_paths:
                dnat_cmd = ['/usr/bin/sudo', '-n', ipt, '-t', 'nat', '-L', 'PREROUTING', '-n', '-v', '-x']
                result = subprocess.run(dnat_cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    dnat_out = result.stdout
                    dnat_path_used = ipt
                    break
                else:
                    self.logger.debug(f"DNAT iptables failed with {ipt}: rc={result.returncode}, err={result.stderr.strip()}")

            rx_bytes = 0
            rx_packets = 0
            matched_dnat = 0
            if dnat_out:
                # Log which binary succeeded and a small header of the output
                self.logger.debug(f"Using iptables at {dnat_path_used} for DNAT; first lines: {dnat_out.splitlines()[:3]}")
                for line in dnat_out.splitlines():
                    # Count all DNAT rules for the camera VIP (any port), to include RTP/RTCP dynamic ports
                    if 'DNAT' in line and virtual_ip in line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                            rx_packets += int(parts[0])
                            rx_bytes += int(parts[1])
                            matched_dnat += 1
            else:
                self.logger.debug("DNAT listing produced no output")
            self.logger.debug(f"DNAT matches for {virtual_ip}: {matched_dnat}, rx_packets={rx_packets}, rx_bytes={rx_bytes}")

            # Get SNAT rule counters (outgoing traffic from camera)
            snat_out = None
            snat_path_used = None
            for ipt in iptables_paths:
                snat_cmd = ['/usr/bin/sudo', '-n', ipt, '-t', 'nat', '-L', 'POSTROUTING', '-n', '-v', '-x']
                result = subprocess.run(snat_cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    snat_out = result.stdout
                    snat_path_used = ipt
                    break
                else:
                    self.logger.debug(f"SNAT iptables failed with {ipt}: rc={result.returncode}, err={result.stderr.strip()}")

            tx_bytes = 0
            tx_packets = 0
            matched_snat = 0
            if snat_out:
                self.logger.debug(f"Using iptables at {snat_path_used} for SNAT")
                for line in snat_out.splitlines():
                    # Count all egress NAT rules for the camera real IP (any port)
                    if (('SNAT' in line) or ('MASQUERADE' in line)) and (camera_ip in line):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                            tx_packets += int(parts[0])
                            tx_bytes += int(parts[1])
                            matched_snat += 1
            else:
                self.logger.debug("SNAT listing produced no output")
            self.logger.debug(f"SNAT matches for {camera_ip}: {matched_snat}, tx_packets={tx_packets}, tx_bytes={tx_bytes}")

            return rx_bytes, tx_bytes, rx_packets, tx_packets

        except Exception as e:
            self.logger.error(f"Failed to get iptables counters for {virtual_ip} -> {camera_ip}: {e}")
            return None

    def _ensure_acct_chain(self):
        """Ensure TRAFFIC_ACCT chain exists and is linked from FORWARD."""
        ipt_paths = ['/usr/sbin/iptables', '/sbin/iptables']
        for ipt in ipt_paths:
            # Create chain (ignore error if exists)
            subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-N', 'TRAFFIC_ACCT'],
                           capture_output=True, text=True)
            # Ensure FORWARD jump exists
            check = subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-C', 'FORWARD', '-j', 'TRAFFIC_ACCT'],
                                   capture_output=True, text=True)
            if check.returncode != 0:
                subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-I', 'FORWARD', '-j', 'TRAFFIC_ACCT'],
                               capture_output=True, text=True)
            # If we reached here with any iptables path, consider done
            break

    def _ensure_camera_rules(self, camera_ip: str):
        """Ensure source and destination accounting rules exist for camera IP."""
        ipt_paths = ['/usr/sbin/iptables', '/sbin/iptables']
        for ipt in ipt_paths:
            # Source rule
            chk_s = subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-C', 'TRAFFIC_ACCT', '-s', camera_ip],
                                   capture_output=True, text=True)
            if chk_s.returncode != 0:
                subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-A', 'TRAFFIC_ACCT', '-s', camera_ip],
                               capture_output=True, text=True)
            # Destination rule
            chk_d = subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-C', 'TRAFFIC_ACCT', '-d', camera_ip],
                                   capture_output=True, text=True)
            if chk_d.returncode != 0:
                subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-A', 'TRAFFIC_ACCT', '-d', camera_ip],
                               capture_output=True, text=True)
            break

    def _remove_camera_rules(self, camera_ip: str):
        """Remove any accounting rules for camera IP (best-effort)."""
        if not camera_ip:
            return
        ipt_paths = ['/usr/sbin/iptables', '/sbin/iptables']
        for ipt in ipt_paths:
            # Delete all occurrences by looping until not found
            while True:
                rm = subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-D', 'TRAFFIC_ACCT', '-s', camera_ip],
                                    capture_output=True, text=True)
                if rm.returncode != 0:
                    break
            while True:
                rm = subprocess.run(['/usr/bin/sudo', '-n', ipt, '-t', 'filter', '-D', 'TRAFFIC_ACCT', '-d', camera_ip],
                                    capture_output=True, text=True)
                if rm.returncode != 0:
                    break
            break
    
    def _capture_screenshot(self, camera_id: str):
        """Capture a screenshot from the camera's RTSP stream"""
        if camera_id not in self.cameras:
            return
            
        camera_info = self.cameras[camera_id]
        rtsp_url = camera_info.get('rtsp_url')
        
        if not rtsp_url:
            self.logger.debug(f"[SCREENSHOT] No RTSP URL for camera {camera_id}, skipping screenshot")
            return
            
        screenshot_file = os.path.join(self.screenshots_path, f"camera_{camera_id}_latest.jpg")
        
        try:
            # Use ffmpeg to capture a single frame
            cmd = [
                'ffmpeg',
                '-y',  # Overwrite output file
                '-rtsp_transport', 'tcp',
                '-timeout', '10000000',  # 10 second timeout in microseconds
                '-i', rtsp_url,
                '-frames:v', '1',  # Capture only 1 frame
                '-q:v', '2',  # High quality
                '-f', 'image2',
                screenshot_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and os.path.exists(screenshot_file):
                self.logger.debug(f"[SCREENSHOT] Captured screenshot for camera {camera_id}")
            else:
                self.logger.warning(f"[SCREENSHOT] Failed to capture screenshot for camera {camera_id}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"[SCREENSHOT] Screenshot capture timed out for camera {camera_id}")
        except Exception as e:
            self.logger.error(f"[SCREENSHOT] Error capturing screenshot for camera {camera_id}: {e}")
            
    def _update_rrd(self, camera_id: str, stats: TrafficStats):
        """Update RRD file with traffic statistics"""
        try:
            rrd_file = self.cameras[camera_id]['rrd_file']
            timestamp = int(stats.timestamp)
            
            rrdtool.update(
                rrd_file,
                f"{timestamp}:{stats.rx_bytes}:{stats.tx_bytes}:{stats.rx_packets}:{stats.tx_packets}"
            )
            
        except Exception as e:
            # Only log errors if they're not related to missing DS or similar common issues
            if "No such file or directory" not in str(e):
                self.logger.warning(f"Failed to update RRD for camera {camera_id}: {e}")
            return
            
    def get_current_stats(self, camera_id: str) -> Optional[TrafficStats]:
        """Get current traffic statistics for a camera"""
        if camera_id not in self.cameras:
            return None
            
        camera_info = self.cameras[camera_id]
        counters = self._get_iptables_counters(camera_info['virtual_ip'], camera_info['camera_ip'])
        
        if counters is None:
            return None
            
        rx_bytes, tx_bytes, rx_packets, tx_packets = counters
        
        return TrafficStats(
            camera_id=camera_id,
            timestamp=time.time(),
            rx_bytes=rx_bytes,
            tx_bytes=tx_bytes,
            rx_packets=rx_packets,
            tx_packets=tx_packets,
            virtual_ip=camera_info['virtual_ip']
        )
        
    def get_traffic_rate(self, camera_id: str) -> Optional[Dict[str, float]]:
        """Get current traffic rate (bytes/sec, packets/sec) for a camera"""
        current_stats = self.get_current_stats(camera_id)
        if not current_stats or camera_id not in self.last_stats:
            return None
            
        last_stats = self.last_stats[camera_id]
        time_diff = current_stats.timestamp - last_stats.timestamp
        
        if time_diff <= 0:
            return None
            
        return {
            'rx_bytes_per_sec': (current_stats.rx_bytes - last_stats.rx_bytes) / time_diff,
            'tx_bytes_per_sec': (current_stats.tx_bytes - last_stats.tx_bytes) / time_diff,
            'rx_packets_per_sec': (current_stats.rx_packets - last_stats.rx_packets) / time_diff,
            'tx_packets_per_sec': (current_stats.tx_packets - last_stats.tx_packets) / time_diff,
            'total_bytes_per_sec': ((current_stats.rx_bytes - last_stats.rx_bytes) + 
                                  (current_stats.tx_bytes - last_stats.tx_bytes)) / time_diff
        }
        
    def has_recent_traffic(self, camera_id: str, threshold_seconds: int = 60) -> bool:
        """Check if camera has had traffic in the last N seconds"""
        rates = self.get_traffic_rate(camera_id)
        if not rates:
            return False
            
        # Consider traffic recent if any rate is > 0
        return (rates['rx_bytes_per_sec'] > 0 or 
                rates['tx_bytes_per_sec'] > 0 or
                rates['rx_packets_per_sec'] > 0 or
                rates['tx_packets_per_sec'] > 0)
                
    def get_rrd_data(self, camera_id: str, start_time: str = '-1h', end_time: str = 'now') -> Optional[Dict]:
        """Get RRD data for graphing"""
        if camera_id not in self.cameras:
            return None
            
        try:
            rrd_file = self.cameras[camera_id]['rrd_file']
            if not os.path.exists(rrd_file):
                return None
                
            # Fetch data from RRD
            result = rrdtool.fetch(
                rrd_file,
                'AVERAGE',
                '--start', start_time,
                '--end', end_time
            )
            
            start, end, step = result[0]
            data_points = result[2]
            
            timestamps = []
            rx_bytes = []
            tx_bytes = []
            rx_packets = []
            tx_packets = []
            
            current_time = start
            for point in data_points:
                timestamps.append(current_time)
                rx_bytes.append(point[0] if point[0] is not None else 0)
                tx_bytes.append(point[1] if point[1] is not None else 0)
                rx_packets.append(point[2] if point[2] is not None else 0)
                tx_packets.append(point[3] if point[3] is not None else 0)
                current_time += step
                
            return {
                'timestamps': timestamps,
                'rx_bytes': rx_bytes,
                'tx_bytes': tx_bytes,
                'rx_packets': rx_packets,
                'tx_packets': tx_packets,
                'step': step
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get RRD data for camera {camera_id}: {e}")
            return None
            
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                current_time = time.time()
                
                for camera_id in list(self.cameras.keys()):
                    stats = self.get_current_stats(camera_id)
                    if stats:
                        # Diagnostic: log counters before writing to RRD
                        self.logger.info(
                            f"[TRAFFIC] cam={camera_id} vip={stats.virtual_ip} rx_b={stats.rx_bytes} tx_b={stats.tx_bytes} rx_p={stats.rx_packets} tx_p={stats.tx_packets}"
                        )
                        self._update_rrd(camera_id, stats)
                        self.last_stats[camera_id] = stats
                    
                    # Check if we need to take a screenshot (every 5 minutes = 300 seconds)
                    last_screenshot_time = self.last_screenshot.get(camera_id, 0)
                    if current_time - last_screenshot_time >= 300:  # 5 minutes
                        self._capture_screenshot(camera_id)
                        self.last_screenshot[camera_id] = current_time
                        
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in traffic monitor loop: {e}")
                time.sleep(5)
                
    def start_monitoring(self):
        """Start traffic monitoring"""
        if self.running:
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Traffic monitoring started")
        
    def stop_monitoring(self):
        """Stop traffic monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        self.logger.info("Traffic monitoring stopped")
        
    def create_graph(self, camera_id: str, output_file: str, time_range: str = '-1h', 
                    width: int = 800, height: int = 400) -> bool:
        """Create traffic graph using RRDtool"""
        if camera_id not in self.cameras:
            return False
            
        try:
            rrd_file = self.cameras[camera_id]['rrd_file']
            if not os.path.exists(rrd_file):
                return False
                
            # Create graph
            rrdtool.graph(
                output_file,
                '--start', time_range,
                '--end', 'now',
                '--width', str(width),
                '--height', str(height),
                '--title', f'Camera {camera_id} RTSP Traffic',
                '--vertical-label', 'Bytes/sec',
                '--lower-limit', '0',
                f'DEF:rx_bytes={rrd_file}:rx_bytes:AVERAGE',
                f'DEF:tx_bytes={rrd_file}:tx_bytes:AVERAGE',
                'CDEF:rx_rate=rx_bytes,8,*',  # Convert to bits
                'CDEF:tx_rate=tx_bytes,8,*',
                'AREA:rx_rate#00FF00:RX Traffic',
                'LINE2:tx_rate#FF0000:TX Traffic',
                'GPRINT:rx_rate:LAST:Current RX\\: %6.2lf %sbps',
                'GPRINT:tx_rate:LAST:Current TX\\: %6.2lf %sbps',
                'GPRINT:rx_rate:AVERAGE:Average RX\\: %6.2lf %sbps',
                'GPRINT:tx_rate:AVERAGE:Average TX\\: %6.2lf %sbps'
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create graph for camera {camera_id}: {e}")
            return False
    
    def get_traffic_summary(self, camera_id: str) -> Optional[Dict]:
        """Get traffic summary with 5-minute averages and 24-hour totals"""
        if camera_id not in self.cameras:
            return None
            
        try:
            rrd_file = self.cameras[camera_id]['rrd_file']
            if not os.path.exists(rrd_file):
                return None
            
            # Get 5-minute average data (last 5 minutes)
            result_5min = rrdtool.fetch(
                rrd_file,
                'AVERAGE',
                '--start', '-5m',
                '--end', 'now'
            )
            
            # Get 24-hour total data
            result_24h = rrdtool.fetch(
                rrd_file,
                'AVERAGE', 
                '--start', '-24h',
                '--end', 'now'
            )
            
            # Calculate 5-minute averages
            _, _, data_5min = result_5min
            rx_bytes_5min = tx_bytes_5min = rx_packets_5min = tx_packets_5min = 0
            count_5min = 0
            
            for point in data_5min:
                if point[0] is not None and point[1] is not None:
                    rx_bytes_5min += point[0]
                    tx_bytes_5min += point[1]
                    rx_packets_5min += point[2] if point[2] is not None else 0
                    tx_packets_5min += point[3] if point[3] is not None else 0
                    count_5min += 1
            
            if count_5min > 0:
                rx_bytes_5min_avg = rx_bytes_5min / count_5min
                tx_bytes_5min_avg = tx_bytes_5min / count_5min
                rx_packets_5min_avg = rx_packets_5min / count_5min
                tx_packets_5min_avg = tx_packets_5min / count_5min
            else:
                rx_bytes_5min_avg = tx_bytes_5min_avg = rx_packets_5min_avg = tx_packets_5min_avg = 0
            
            # Calculate 24-hour totals
            _, _, data_24h = result_24h
            rx_bytes_24h = tx_bytes_24h = rx_packets_24h = tx_packets_24h = 0
            
            for point in data_24h:
                if point[0] is not None and point[1] is not None:
                    rx_bytes_24h += point[0]
                    tx_bytes_24h += point[1]
                    rx_packets_24h += point[2] if point[2] is not None else 0
                    tx_packets_24h += point[3] if point[3] is not None else 0
            
            return {
                'averages_5min': {
                    'rx_bytes_per_sec': rx_bytes_5min_avg,
                    'tx_bytes_per_sec': tx_bytes_5min_avg,
                    'rx_packets_per_sec': rx_packets_5min_avg,
                    'tx_packets_per_sec': tx_packets_5min_avg
                },
                'totals_24h': {
                    'rx_bytes': rx_bytes_24h,
                    'tx_bytes': tx_bytes_24h,
                    'rx_packets': rx_packets_24h,
                    'tx_packets': tx_packets_24h
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get traffic summary for camera {camera_id}: {e}")
            return None
