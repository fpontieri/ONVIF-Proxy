#!/usr/bin/env python3
"""
Web interface for ONVIF Proxy management
Flask-based web application for camera configuration and monitoring
"""

import os
import tempfile
import re
import time
import json
import subprocess
import threading
import signal
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response, send_from_directory, make_response
from functools import wraps
import json
import xml.etree.ElementTree as ET
from src.config_manager import ConfigManager
from src.network_manager import NetworkManager
from src.notification_manager import NotificationManager
from src.traffic_monitor import TrafficMonitor
from urllib.parse import urlparse

app = Flask(__name__)
app.version = "v2.0.55 - 2025-08-25 14:45 - Fix: import os in network_manager.get_available_interfaces()"
app.secret_key = os.urandom(24)
app.debug = True

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Hardcoded app version (increment on each change) with timestamp
APP_VERSION = app.version

@app.context_processor
def inject_app_version():
    return {"app_version": APP_VERSION}

# Global instances
config_manager = ConfigManager()
network_manager = NetworkManager()
notification_manager = NotificationManager()
traffic_monitor = TrafficMonitor()

# Lightweight cache for traffic rates computed on-demand in the web process
# Structure: { camera_id: { 'timestamp': float, 'rx_bytes': int, 'tx_bytes': int,
#                           'rx_packets': int, 'tx_packets': int } }
traffic_last_stats = {}

# Ensure we always read the latest config from disk for read-only routes
def ensure_fresh_config():
    try:
        config_manager.reload_config()
    except Exception as e:
        app.logger.warning(f"[CONFIG] Failed to reload config on read: {e}")

def _extract_camera_ip(rtsp_url: str) -> str:
    """Extract camera host/IP from an RTSP URL."""
    try:
        p = urlparse(rtsp_url)
        return p.hostname
    except Exception:
        return None

def _get_iptables_counters(virtual_ip: str, camera_ip: str):
    """Read traffic counters for the camera.
    Priority 1: filter table TRAFFIC_ACCT chain (accounting rules by src/dst IP).
    Fallback: NAT table DNAT/SNAT counters.
    Returns tuple: (rx_bytes, tx_bytes, rx_packets, tx_packets) or None on error.
    """
    try:
        rx_bytes = rx_packets = tx_bytes = tx_packets = 0

        # First try TRAFFIC_ACCT via iptables-save -c (has counters)
        ipt_save_paths = ['/usr/sbin/iptables-save', '/sbin/iptables-save']
        acct_found = False
        for ipts in ipt_save_paths:
            cmd = ['/usr/bin/sudo', '-n', ipts, '-c', '-t', 'filter']
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                out = res.stdout
                # Lines look like: [packets:bytes] -A TRAFFIC_ACCT -s 192.168.1.10/32 -j RETURN
                for line in out.splitlines():
                    if ' -A TRAFFIC_ACCT ' not in line:
                        continue
                    # packets:bytes prefix
                    if not line.startswith('[') or ']' not in line:
                        continue
                    try:
                        bracket = line[1:line.index(']')]
                        pkts_str, bytes_str = bracket.split(':', 1)
                        pkts = int(pkts_str)
                        byts = int(bytes_str)
                    except Exception:
                        continue
                    # Source vs destination rule match
                    if f"-s {camera_ip}" in line:
                        tx_packets += pkts
                        tx_bytes += byts
                        acct_found = True
                    if f"-d {camera_ip}" in line:
                        rx_packets += pkts
                        rx_bytes += byts
                        acct_found = True
                if acct_found:
                    app.logger.debug(f"[TRAFFIC][WEB][ACCT] Counters via TRAFFIC_ACCT for {camera_ip}: rx_b={rx_bytes}, tx_b={tx_bytes}")
                    return rx_bytes, tx_bytes, rx_packets, tx_packets
            else:
                app.logger.debug(f"[TRAFFIC][WEB][ACCT] iptables-save failed with {ipts}: rc={res.returncode}, err={res.stderr.strip()}")

        # Fallback: Prefer absolute paths and non-interactive sudo to work under systemd (NAT counters)
        iptables_paths = ['/usr/sbin/iptables', '/sbin/iptables']

        dnat_out = None
        dnat_path_used = None
        for ipt in iptables_paths:
            dnat_cmd = ['/usr/bin/sudo', '-n', ipt, '-t', 'nat', '-L', 'PREROUTING', '-n', '-v', '-x']
            res = subprocess.run(dnat_cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                dnat_out = res.stdout
                dnat_path_used = ipt
                break
            else:
                app.logger.info(f"[TRAFFIC][WEB] DNAT iptables failed with {ipt}: rc={res.returncode}, err={res.stderr.strip()}")

        matched_dnat = 0
        if dnat_out:
            app.logger.debug(f"[TRAFFIC][WEB] Using iptables at {dnat_path_used} for DNAT")
            for line in dnat_out.splitlines():
                # Sum all DNAT rules involving this camera's virtual IP (any ports)
                if 'DNAT' in line and virtual_ip in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                        rx_packets += int(parts[0])
                        rx_bytes += int(parts[1])
                        matched_dnat += 1
        else:
            app.logger.debug("[TRAFFIC][WEB] DNAT listing produced no output")

        snat_out = None
        snat_path_used = None
        for ipt in iptables_paths:
            snat_cmd = ['/usr/bin/sudo', '-n', ipt, '-t', 'nat', '-L', 'POSTROUTING', '-n', '-v', '-x']
            res = subprocess.run(snat_cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                snat_out = res.stdout
                snat_path_used = ipt
                break
            else:
                app.logger.info(f"[TRAFFIC][WEB] SNAT iptables failed with {ipt}: rc={res.returncode}, err={res.stderr.strip()}")

        matched_snat = 0
        if snat_out:
            app.logger.debug(f"[TRAFFIC][WEB] Using iptables at {snat_path_used} for SNAT")
            for line in snat_out.splitlines():
                # Sum all egress NAT rules involving this camera's real IP (SNAT or MASQUERADE)
                if (("SNAT" in line) or ("MASQUERADE" in line)) and (camera_ip in line):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                        tx_packets += int(parts[0])
                        tx_bytes += int(parts[1])
                        matched_snat += 1
        else:
            app.logger.debug("[TRAFFIC][WEB] SNAT listing produced no output")

        # If both outputs were missing, treat as error so UI can report it
        if dnat_out is None and snat_out is None:
            return None

        app.logger.debug(f"[TRAFFIC][WEB] vip={virtual_ip} cam_ip={camera_ip} DNAT_matches={matched_dnat} SNAT_matches={matched_snat} rx_b={rx_bytes} tx_b={tx_bytes} rx_p={rx_packets} tx_p={tx_packets}")

        return rx_bytes, tx_bytes, rx_packets, tx_packets
    except Exception as e:
        app.logger.error(f"[TRAFFIC] Failed reading iptables counters {virtual_ip}->{camera_ip}: {e}")
        return None

@app.route('/')
def index():
    """Main dashboard"""
    ensure_fresh_config()
    system_config = config_manager.get_system_config()
    cameras = config_manager.get_cameras()
    
    # Get system status
    system_status = {
        'enabled': system_config.get('enabled', True),
        'total_cameras': len(cameras),
        'active_cameras': len([c for c in cameras if c.get('enabled', True)]),
        'pushover_configured': bool(system_config.get('pushover_token') and system_config.get('pushover_user'))
    }
    
    return render_template('dashboard.html', 
                         system_config=system_config, 
                         cameras=cameras,
                         system_status=system_status)

@app.route('/cameras')
def cameras():
    """Camera management page"""
    ensure_fresh_config()
    cameras = config_manager.get_cameras()
    
    # Enrich camera data with runtime information
    for camera in cameras:
        camera_id = camera['id']
        interface_name = f"onvif-{camera_id}"
        
        # Get ONVIF IP from interface if available
        if not camera.get('onvif_ip'):
            onvif_ip = network_manager.get_interface_ipv4(interface_name)
            if onvif_ip:
                camera['onvif_ip'] = onvif_ip
        
        # Ensure onvif_mac is populated
        if not camera.get('onvif_mac'):
            try:
                camera['onvif_mac'] = config_manager.generate_mac_for_camera_id(int(camera_id))
            except Exception:
                camera['onvif_mac'] = ''
        
        # Set default ping status if not present
        if not camera.get('last_ping_status'):
            camera['last_ping_status'] = 'unknown'
    
    return render_template('cameras.html', cameras=cameras)

@app.route('/camera/add', methods=['GET', 'POST'])
def add_camera():
    """Add new camera"""
    if request.method == 'POST':
        camera_id = config_manager.generate_next_camera_id()
        camera_config = {
            'id': camera_id,
            'name': request.form.get('name', ''),
            'enabled': request.form.get('enabled') == 'on',
            'base_interface': request.form.get('base_interface', ''),
            'use_dhcp': request.form.get('use_dhcp') == 'on',
            'rtsp_url': request.form.get('rtsp_url', ''),
            'rtsp_username': request.form.get('rtsp_username', ''),
            'rtsp_password': request.form.get('rtsp_password', ''),
            'resolution': request.form.get('resolution', '1280x720'),
            'fps': int(float(request.form.get('fps', 15))) if request.form.get('fps') else 15,
            'bitrate_kbps': int(float(request.form.get('bitrate_kbps', 0))) if request.form.get('bitrate_kbps') else None,
            'onvif_ip': request.form.get('onvif_ip', ''),
            'onvif_port': int(request.form.get('onvif_port', 80)),
            'onvif_mac': request.form.get('mac_address', '') or config_manager.generate_mac_for_camera_id(camera_id),  # Store as onvif_mac
            'onvif_interface': f'onvif-{camera_id}',
            'notifications_enabled': request.form.get('notifications_enabled') == 'on'
        }
        
        # Add camera to config
        try:
            ok = config_manager.add_camera(camera_config)
        except Exception as e:
            flash(f'Failed to save configuration: {str(e)}', 'error')
            # Emergency alert
            try:
                notification_manager.notify_fatal_error(f"Config write failure while adding camera {camera_config.get('name','')} (ID {camera_id}): {e}")
            except Exception:
                pass
            return redirect(url_for('cameras'))

        if ok:
            # Reload config so front-end immediately sees the new camera
            try:
                config_manager.reload_config()
            except Exception as e:
                app.logger.warning(f"[CONFIG] Reload after add failed: {e}")
            flash('Camera added successfully!', 'success')
            # Reload service configuration via systemd
            try:
                subprocess.run(['sudo', 'systemctl', 'reload-or-restart', 'onvif-proxy'], 
                             capture_output=True, text=True, timeout=10)
            except:
                pass  # Service reload is best effort
            
            return redirect(url_for('cameras'))
        else:
            flash('Failed to add camera. Camera ID might already exist.', 'error')
        
        return redirect(url_for('cameras'))
    
    # Generate defaults for new camera
    system_config = config_manager.get_system_config()
    interfaces = network_manager.get_available_interfaces()
    defaults = {
        'onvif_ip': config_manager.generate_next_ip(),
        'mac_address': config_manager.generate_next_mac(),
        'onvif_port': 80
    }
    
    return render_template('camera_form.html', 
                         camera=None, 
                         defaults=defaults, 
                         interfaces=interfaces, 
                         system_config=system_config)

@app.route('/camera/<camera_id>/edit', methods=['GET', 'POST'])
def edit_camera(camera_id):
    """Edit existing camera"""
    camera = config_manager.get_camera(camera_id)
    if not camera:
        flash('Camera not found!', 'error')
        return redirect(url_for('cameras'))
    
    if request.method == 'POST':
        camera_config = {
            'name': request.form.get('name', ''),
            'enabled': request.form.get('enabled') == 'on',
            'base_interface': request.form.get('base_interface', ''),
            'use_dhcp': request.form.get('use_dhcp') == 'on',
            'rtsp_url': request.form.get('rtsp_url', ''),
            'rtsp_username': request.form.get('rtsp_username', ''),
            'rtsp_password': request.form.get('rtsp_password', ''),
            'resolution': request.form.get('resolution', ''),
            'fps': int(float(request.form.get('fps', 0))) if request.form.get('fps') else None,
            'bitrate_kbps': int(float(request.form.get('bitrate_kbps', 0))) if request.form.get('bitrate_kbps') else None,
            'onvif_ip': request.form.get('onvif_ip', ''),
            'onvif_port': int(request.form.get('onvif_port', 80)),
            'onvif_mac': request.form.get('mac_address', '') or config_manager.generate_mac_for_camera_id(int(camera_id)),  # Store as onvif_mac
            'onvif_interface': f'onvif-{camera_id}',
            'notifications_enabled': request.form.get('notifications_enabled') == 'on'
        }
        
        # Debug logging
        app.logger.info(f"[CAMERA_EDIT] Updating camera {camera_id} with config: {camera_config}")
        
        try:
            ok = config_manager.update_camera(camera_id, camera_config)
        except Exception as e:
            flash(f'Failed to save configuration: {str(e)}', 'error')
            try:
                notification_manager.notify_fatal_error(f"Config write failure while editing camera {camera_id}: {e}")
            except Exception:
                pass
            return redirect(url_for('cameras'))

        if ok:
            # Reload config so front-end immediately reflects edits
            try:
                config_manager.reload_config()
            except Exception as e:
                app.logger.warning(f"[CONFIG] Reload after edit failed: {e}")
            flash('Camera updated successfully!', 'success')
            # Reload service configuration via systemd
            try:
                subprocess.run(['sudo', 'systemctl', 'reload-or-restart', 'onvif-proxy'], 
                             capture_output=True, text=True, timeout=10)
            except:
                pass  # Service reload is best effort
            
            return redirect(url_for('cameras'))
        else:
            flash('Failed to update camera!', 'error')
        
        return redirect(url_for('cameras'))
    
    system_config = config_manager.get_system_config()
    interfaces = network_manager.get_available_interfaces()
    return render_template('camera_form.html', 
                         camera=camera, 
                         interfaces=interfaces, 
                         system_config=system_config)

@app.route('/camera/<camera_id>/delete', methods=['POST'])
def delete_camera(camera_id):
    """Delete camera"""
    # Get camera info before deletion for logging
    camera = config_manager.get_camera(camera_id)
    camera_name = camera.get('name', f'ID {camera_id}') if camera else f'ID {camera_id}'
    
    try:
        ok = config_manager.delete_camera(camera_id)
    except Exception as e:
        flash(f'Failed to save configuration: {str(e)}', 'error')
        try:
            notification_manager.notify_fatal_error(f"Config write failure while deleting camera {camera_name} (ID {camera_id}): {e}")
        except Exception:
            pass
        return redirect(url_for('cameras'))

    if ok:
        # Reload config so front-end immediately reflects deletion
        try:
            config_manager.reload_config()
        except Exception as e:
            app.logger.warning(f"[CONFIG] Reload after delete failed: {e}")
        # Remove network interface if it exists
        try:
            network_manager.remove_camera_interface(camera_id)
            if camera.get('onvif_ip'):
                network_manager.remove_persistent_config(camera['onvif_ip'])
            app.logger.info(f"[NETWORK] Removed ONVIF interface for deleted camera {camera_id}")
        except Exception as e:
            app.logger.warning(f"[NETWORK] Error removing interface for deleted camera {camera_id}: {e}")
        
        # Log and notify camera deletion
        message = f"Camera '{camera['name']}' (ID: {camera_id}) deleted successfully"
        app.logger.info(f"[SYSTEM] {message}")
        
        # Send notification if configured
        try:
            system_config = config_manager.get_system_config()
            if system_config.get('pushover_token') and system_config.get('pushover_user'):
                notification_manager.send_notification(
                    title="ONVIF Proxy - Camera Deleted",
                    message=message,
                    priority=0
                )
        except Exception as e:
            app.logger.warning(f"[NOTIFICATION] Failed to send camera delete notification: {e}")
        
        # Reload service configuration
        reload_service_config()
        
        flash('Camera deleted successfully!', 'success')
    else:
        flash('Failed to delete camera.', 'error')
        app.logger.error(f"[CAMERA_DELETE] Failed to delete camera '{camera_name}' (ID: {camera_id})")
        
        # Send error notification
        try:
            system_config = config_manager.get_system_config()
            if system_config.get('pushover_token') and system_config.get('pushover_user'):
                notification_manager.send_notification(
                    title="ONVIF Proxy - Camera Delete Failed",
                    message=f"Failed to delete camera '{camera_name}' (ID: {camera_id})",
                    priority=1
                )
        except Exception as e:
            app.logger.warning(f"[NOTIFICATION] Failed to send camera delete error notification: {e}")
    
    return redirect(url_for('cameras'))

@app.route('/camera/<camera_id>/test')
def test_camera(camera_id):
    """Test camera connection"""
    camera = config_manager.get_camera(camera_id)
    if not camera:
        return jsonify({'success': False, 'error': 'Camera not found'})
    
    try:
        # Test RTSP connection and ping to the CAMERA host (not the local ONVIF interface)
        rtsp_url = camera.get('rtsp_url', '')
        camera_host = None
        if rtsp_url:
            try:
                parsed = urlparse(rtsp_url)
                camera_host = parsed.hostname
            except Exception:
                camera_host = None
        
        # Ping test to the camera host
        if camera_host:
            ping_results = network_manager.ping_host(camera_host)
        else:
            ping_results = {'packet_loss': '100%', 'avg_time': 'N/A', 'error': 'Invalid RTSP URL'}
        
        return jsonify({
            'success': True,
            'ping_results': ping_results,
            'rtsp_url': rtsp_url
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/camera/<camera_id>/stream')
def camera_stream(camera_id):
    """Get camera stream URL for live viewing"""
    camera = config_manager.get_camera(camera_id)
    if not camera:
        return jsonify({'success': False, 'error': 'Camera not found'})
    
    try:
        rtsp_url = camera.get('rtsp_url', '')
        if not rtsp_url:
            return jsonify({'success': False, 'error': 'No RTSP URL configured'})
        
        # Build RTSP URL with credentials if needed (mirror logic from MJPEG endpoint)
        rtsp_username = (camera.get('rtsp_username', '') or '').strip()
        rtsp_password = (camera.get('rtsp_password', '') or '').strip()
        if rtsp_username.lower() == 'none':
            rtsp_username = ''
        if rtsp_password.lower() == 'none':
            rtsp_password = ''

        def _with_auth(u: str) -> str:
            try:
                parsed = urlparse(u)
                if parsed.username:
                    return u
            except Exception:
                if '@' in u:
                    return u
            if rtsp_username and rtsp_password and '://' in u:
                proto, rest = u.split('://', 1)
                return f"{proto}://{rtsp_username}:{rtsp_password}@{rest}"
            return u

        rtsp_url_auth = _with_auth(rtsp_url)

        # Helper to sanitize URL for logs (mask credentials)
        def _sanitize(u: str) -> str:
            try:
                p = urlparse(u)
                if p.username:
                    host = p.hostname or ''
                    if p.port:
                        host = f"{host}:{p.port}"
                    path_q = (p.path or '') + (("?" + p.query) if p.query else '')
                    return f"{p.scheme}://***@{host}{path_q}"
            except Exception:
                pass
            return u

        # For now, we'll use a simple MJPEG stream endpoint
        # In a production environment, you might want to use a proper streaming server
        stream_url = f"/camera/{camera_id}/mjpeg"

        # Probe stream metadata using ffprobe (preferred), fallback to OpenCV
        probed_resolution = None
        probed_fps = None
        probed_bitrate_kbps = None

        # Try ffprobe first
        try:
            app.logger.info(f"[STREAM] Probing with ffprobe for camera {camera_id} URL={_sanitize(rtsp_url_auth)}")
            rtsp_paths = [
                '/live0',  # Common path 1
                '/live',   # Common path 2
                '/stream1', # Common path 3
                '/cam/realmonitor?channel=1&subtype=0'  # Common path for some IP cameras
            ]
            
            # Get the base URL without path
            base_url = rtsp_url
            if '://' in rtsp_url:
                protocol, rest = rtsp_url.split('://', 1)
                server = rest.split('/', 1)[0] if '/' in rest else rest
                base_url = f"{protocol}://{server}"
            
            # Try different paths until one works or we run out of options
            for path in [''] + rtsp_paths:  # Try original URL first
                test_url = f"{base_url}{path}" if path else rtsp_url
                
                # Build FFmpeg command with the current URL
                ffmpeg_cmd = [
                    'ffmpeg',
                    '-rtsp_transport', 'tcp',
                    '-timeout', '5000000',  # 5 second timeout in microseconds
                    '-i', test_url,
                    '-f', 'image2pipe',
                    '-c:v', 'mjpeg',
                    '-q:v', '5',
                    '-r', str(15),
                    '-s', '1280x720',
                    '-loglevel', 'error',
                    'pipe:1'
                ]
                
                # Test the URL with ffprobe first
                test_cmd = [
                    'ffprobe',
                    '-rtsp_transport', 'tcp',
                    '-timeout', '5000000',
                    '-i', test_url,
                    '-show_streams',
                    '-select_streams', 'v',
                    '-loglevel', 'error'
                ]
                
                try:
                    # Try to probe the stream
                    probe = subprocess.run(
                        test_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    
                    if probe.returncode == 0:
                        app.logger.info(f"[MJPEG] Successfully connected to stream at {test_url}")
                        rtsp_url = test_url  # Use this working URL
                        break
                        
                except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                    app.logger.debug(f"[MJPEG] Stream probe failed for {test_url}: {str(e)}")
                    continue

            cmd = [
                'ffprobe',
                '-hide_banner',
                '-loglevel', 'error',
                '-rtsp_transport', 'tcp',
                '-timeout', '5000000',  # 5 second timeout (in microseconds)
                '-i', rtsp_url_auth,
                '-select_streams', 'v:0',
                '-show_entries', 'stream=width,height,r_frame_rate,bit_rate',
                '-of', 'json'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
            app.logger.info(f"[STREAM] ffprobe returncode={result.returncode}")
            if result.stderr:
                app.logger.info(f"[STREAM] ffprobe stderr: {result.stderr[:1000]}")
            if result.returncode == 0 and result.stdout:
                out_preview = result.stdout[:1000]
                app.logger.info(f"[STREAM] ffprobe stdout (truncated): {out_preview}")
                data = json.loads(result.stdout)
                streams = data.get('streams') or []
                if streams:
                    s0 = streams[0]
                    w = s0.get('width')
                    h = s0.get('height')
                    if w and h:
                        probed_resolution = f"{w}x{h}"
                    # FPS can be in avg_frame_rate or r_frame_rate as fraction
                    fps_frac = s0.get('avg_frame_rate') or s0.get('r_frame_rate')
                    if isinstance(fps_frac, str) and '/' in fps_frac:
                        num, den = fps_frac.split('/')
                        try:
                            num_f = float(num)
                            den_f = float(den)
                            if den_f > 0:
                                probed_fps = round(num_f / den_f, 2)
                        except Exception:
                            pass
                    br = s0.get('bit_rate')
                    try:
                        if br is not None:
                            br_int = int(br)
                            if br_int > 0:
                                probed_bitrate_kbps = int(round(br_int / 1000))
                    except Exception:
                        pass
        except FileNotFoundError:
            # ffprobe not installed
            app.logger.warning("[STREAM] ffprobe not found on system")
        except subprocess.TimeoutExpired:
            app.logger.warning("[STREAM] ffprobe timed out while probing stream")
        except Exception as e:
            app.logger.exception(f"[STREAM] ffprobe probing error: {e}")

        # Fallback to OpenCV for resolution/FPS if needed
        if probed_resolution is None or probed_fps is None:
            try:
                import cv2
                # Prefer TCP transport via FFmpeg options for consistency
                try:
                    os.environ.setdefault('OPENCV_FFMPEG_CAPTURE_OPTIONS', 'rtsp_transport;tcp|stimeout;5000000')
                except Exception:
                    pass
                cap = None
                try:
                    app.logger.info(f"[STREAM] Probing with OpenCV CAP_FFMPEG for camera {camera_id} URL={_sanitize(rtsp_url_auth)}")
                    cap = cv2.VideoCapture(rtsp_url_auth, cv2.CAP_FFMPEG)
                except Exception:
                    app.logger.info(f"[STREAM] CAP_FFMPEG failed, falling back to default backend for camera {camera_id}")
                    cap = cv2.VideoCapture(rtsp_url_auth)
                if cap and cap.isOpened():
                    if probed_resolution is None:
                        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
                        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
                        if w > 0 and h > 0:
                            probed_resolution = f"{w}x{h}"
                    if probed_fps is None:
                        fps_val = cap.get(cv2.CAP_PROP_FPS) or 0.0
                        if fps_val and fps_val > 0:
                            probed_fps = round(float(fps_val), 2)
                    app.logger.info(f"[STREAM] OpenCV probe result res={probed_resolution} fps={probed_fps}")
                if cap:
                    cap.release()
            except Exception:
                app.logger.exception("[STREAM] OpenCV probing error")

        # Update camera config with probed values if they're not already set
        update_needed = False
        camera_updates = {}
        
        if probed_resolution and probed_resolution != camera.get('resolution'):
            camera_updates['resolution'] = probed_resolution
            update_needed = True
            
        if probed_fps is not None and probed_fps != camera.get('fps'):
            camera_updates['fps'] = probed_fps
            update_needed = True
            
        if probed_bitrate_kbps is not None and probed_bitrate_kbps != camera.get('bitrate_kbps'):
            camera_updates['bitrate_kbps'] = probed_bitrate_kbps
            update_needed = True
            
        if update_needed:
            try:
                config_manager.update_camera(camera_id, camera_updates)
                app.logger.info(f"[STREAM] Updated camera {camera_id} config with: {camera_updates}")
            except Exception as e:
                app.logger.error(f"[STREAM] Failed to update camera config: {e}")
        
        # Use the most up-to-date values (either just probed or from config if update failed)
        response = {
            'success': True,
            'stream_url': stream_url,
            'rtsp_url': rtsp_url,
            'resolution': probed_resolution or camera.get('resolution'),
            'fps': probed_fps if probed_fps is not None else camera.get('fps'),
            'bitrate_kbps': probed_bitrate_kbps if probed_bitrate_kbps is not None else camera.get('bitrate_kbps')
        }
        
        app.logger.info(f"[STREAM] Probe summary for camera {camera_id}: res={response.get('resolution')} fps={response.get('fps')} bitrate_kbps={response.get('bitrate_kbps')}")
        return jsonify(response)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/camera/<camera_id>/mjpeg')
def camera_mjpeg(camera_id):
    """MJPEG stream endpoint for camera using FFmpeg directly"""
    import subprocess
    from flask import Response, stream_with_context
    
    # Get camera configuration
    camera = config_manager.get_camera(camera_id)
    if not camera:
        return "Camera not found", 404

    def build_rtsp_url():
        """Build RTSP URL with credentials"""
        rtsp_url = camera['rtsp_url']
        if '@' not in rtsp_url and camera.get('rtsp_username') and camera.get('rtsp_password'):
            # If URL doesn't have credentials but we have them in config, add them
            if '://' in rtsp_url:
                url_parts = rtsp_url.split('://')
                rtsp_url = f"{url_parts[0]}://{camera['rtsp_username']}:{camera['rtsp_password']}@{url_parts[1]}"
            else:
                rtsp_url = f"rtsp://{camera['rtsp_username']}:{camera['rtsp_password']}@{rtsp_url}"
        
        # Ensure the URL has the rtsp:// protocol
        if not rtsp_url.startswith('rtsp://'):
            rtsp_url = f"rtsp://{rtsp_url}"
        
        # Sanitize URL for logging
        log_rtsp = rtsp_url
        if '@' in log_rtsp:
            # Hide credentials in logs
            protocol, rest = log_rtsp.split('://', 1)
            auth, server = rest.split('@', 1)
            log_rtsp = f"{protocol}://***:***@{server}"
        
        return rtsp_url, log_rtsp

    def generate():
        """Generate MJPEG stream using FFmpeg"""
        app.logger.info(f"[MJPEG] Starting MJPEG stream for camera {camera_id}")
        
        rtsp_url, log_rtsp = build_rtsp_url()
        if not rtsp_url:
            error_msg = "No RTSP URL provided in camera configuration"
            app.logger.error(f"[MJPEG] {error_msg}")
            yield f"Error: {error_msg}"
            return
        
        # Get stream parameters from stored configuration only
        resolution = camera.get('resolution', '1280x720')
        fps = camera.get('fps', 15)
        
        # Parse resolution
        width, height = 1280, 720
        if resolution and 'x' in resolution:
            try:
                width, height = map(int, resolution.lower().split('x', 1))
            except ValueError:
                app.logger.warning(f"[MJPEG] Invalid resolution format '{resolution}', using defaults")
                width, height = 1280, 720
        
        # Parse FPS
        if fps:
            try:
                fps = int(float(fps))
                fps = max(1, min(60, fps))  # Clamp to reasonable values
            except (ValueError, TypeError):
                app.logger.warning(f"[MJPEG] Invalid FPS value '{fps}', using default")
                fps = 15
        else:
            fps = 15
        
        app.logger.info(f"[MJPEG] Using stored parameters - Resolution: {width}x{height}, FPS: {fps}")
        app.logger.info(f"[MJPEG] Using RTSP URL: {log_rtsp}")
        
        # FFmpeg command - use stored parameters directly, no probing
        ffmpeg_cmd = [
            'ffmpeg',
            '-loglevel', 'warning',
            '-rtsp_transport', 'tcp',
            '-timeout', '5000000',
            '-i', rtsp_url,  # Use the RTSP URL directly
            '-f', 'image2pipe',
            '-c:v', 'mjpeg',
            '-q:v', '5',
            '-s', f'{width}x{height}',
            '-fflags', 'nobuffer',
            '-threads', '2',
            'pipe:1'
        ]
        
        app.logger.info(f"[MJPEG] Starting FFmpeg with stored parameters")
        
        try:
            process = subprocess.Popen(
                ffmpeg_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=10**8,
                start_new_session=True
            )
            app.logger.info(f"[MJPEG] FFmpeg process started, PID: {process.pid}")
            
            # Check if process started successfully
            time.sleep(1)
            if process.poll() is not None:
                error = process.stderr.read().decode('utf-8', 'ignore')
                exit_code = process.returncode
                app.logger.error(f"[MJPEG] FFmpeg exited with code {exit_code}: {error}")
                yield f"Error: FFmpeg exited with code {exit_code} - {error}"
                return
            
            # Read FFmpeg stderr in a separate thread to prevent blocking
            def log_stderr():
                while process and process.poll() is None:
                    line = process.stderr.readline()
                    if not line:
                        break
                    app.logger.debug(f"[FFmpeg] {line.decode('utf-8', 'ignore').strip()}")
            
            import threading
            stderr_thread = threading.Thread(target=log_stderr, daemon=True)
            stderr_thread.start()
        
            # MJPEG frame markers
            SOI = b'\xff\xd8'  # Start of Image
            EOI = b'\xff\xd9'   # End of Image
            
            frame_count = 0
            last_log_time = time.time()
            buffer = bytearray()
            
            while True:
                # Read data from FFmpeg
                chunk = process.stdout.read(4096)
                if not chunk:
                    app.logger.error("[MJPEG] No data received from FFmpeg")
                    break
                    
                buffer += chunk
                
                # Process complete frames in buffer
                while True:
                    # Find start of frame
                    soi = buffer.find(SOI)
                    if soi == -1:
                        # No complete frame start found, keep the last few bytes in case of partial SOI
                        buffer = buffer[-2:] if len(buffer) > 2 else buffer
                        break
                        
                    # Find end of frame
                    eoi = buffer.find(EOI, soi + 2)
                    if eoi == -1:
                        # No complete frame end found, keep the buffer for next read
                        buffer = buffer[soi:]
                        break
                        
                    # Extract the complete frame (including SOI and EOI)
                    frame_data = buffer[soi:eoi + 2]
                    
                    # Remove processed data from buffer
                    buffer = buffer[eoi + 2:]
                    
                    # Yield the frame with MJPEG boundary
                    frame_count += 1
                    current_time = time.time()
                    if frame_count % 30 == 0 or current_time - last_log_time >= 5:
                        # app.logger.info(f"[MJPEG] Streaming frame {frame_count}")
                        last_log_time = current_time
                    
                    yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + 
                           frame_data + 
                           b'\r\n')
                    
                    # Break if we've processed all complete frames
                    if len(buffer) < 2:
                        break

        except Exception as e:
            app.logger.error(f"[MJPEG] Error starting FFmpeg: {str(e)}")
            yield f"Error: {str(e)}"
            
        finally:
            # Cleanup FFmpeg process
            if process:
                try:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                except Exception as e:
                    app.logger.error(f"[MJPEG] Error during process cleanup: {str(e)}")
                    
            # Check if FFmpeg process had an error
            if process and process.poll() is not None and process.returncode != 0:
                try:
                    error_output = process.stderr.read().decode('utf-8', 'ignore')
                    app.logger.error(f"[MJPEG] FFmpeg process exited with code {process.returncode}: {error_output}")
                except Exception as e:
                    app.logger.error(f"[MJPEG] Error reading FFmpeg stderr: {e}")
    
    # Return the streaming response
    return Response(
        stream_with_context(generate()),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

@app.route('/api/camera/<camera_id>/info')
def camera_info(camera_id):
    """Get camera information"""
    try:
        camera = config_manager.get_camera(camera_id)
        if not camera:
            return jsonify({'success': False, 'error': 'Camera not found'}), 404
        
        # Get resolution, FPS, and bitrate from config
        resolution = camera.get('resolution', '')
        fps = camera.get('fps')
        bitrate_kbps = camera.get('bitrate_kbps')
        
        # If resolution is in WxH format, split into width/height
        width, height = None, None
        if resolution and 'x' in resolution:
            try:
                width, height = map(int, resolution.lower().split('x', 1))
            except (ValueError, AttributeError):
                pass
        
        return jsonify({
            'success': True,
            'camera': {
                'id': camera_id,
                'name': camera.get('name', ''),
                'rtsp_url': camera.get('rtsp_url', ''),
                'onvif_ip': camera.get('onvif_ip', ''),
                'onvif_port': camera.get('onvif_port', 80),
                'enabled': camera.get('enabled', False),
                'onvif_mac': camera.get('onvif_mac', ''),
                'use_dhcp': camera.get('use_dhcp', False),
                'last_ping_status': camera.get('last_ping_status', 'unknown'),
                'resolution': resolution,
                'width': width,
                'height': height,
                'fps': fps,
                'bitrate_kbps': bitrate_kbps
            }
        })
    
    except Exception as e:
        status_code = 500
        error_msg = str(e)
        app.logger.error(f"[ERROR] {request.path} - {status_code} - {error_msg}")
        return jsonify({'success': False, 'error': error_msg}), status_code

@app.route('/api/camera/<camera_id>/refresh-ip', methods=['POST'])
def refresh_camera_ip(camera_id):
    """Refresh IP address for DHCP-enabled camera"""
    try:
        camera = config_manager.get_camera(camera_id)
        if not camera:
            return jsonify({'success': False, 'error': 'Camera not found'}), 404
        
        if not camera.get('use_dhcp', False):
            return jsonify({'success': False, 'error': 'Camera is not using DHCP'}), 400
        
        # Get the interface name for this camera
        interface_name = f"onvif-{camera_id}"
        
        # Try to get the current IP from the interface
        import subprocess
        try:
            result = subprocess.run(['ip', 'addr', 'show', interface_name], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse IP from output
                import re
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if ip_match:
                    new_ip = ip_match.group(1)
                    
                    # Update camera config with new IP
                    camera_config = dict(camera)
                    camera_config['onvif_ip'] = new_ip
                    
                    if config_manager.update_camera(camera_id, camera_config):
                        return jsonify({
                            'success': True, 
                            'message': f'IP refreshed successfully',
                            'new_ip': new_ip
                        })
                    else:
                        return jsonify({'success': False, 'error': 'Failed to update camera config'})
                else:
                    return jsonify({'success': False, 'error': 'No IP address found on interface'})
            else:
                return jsonify({'success': False, 'error': f'Interface {interface_name} not found'})
                
        except subprocess.TimeoutExpired:
            return jsonify({'success': False, 'error': 'Timeout getting interface info'})
        except Exception as e:
            return jsonify({'success': False, 'error': f'Error getting interface info: {str(e)}'})
    
    except Exception as e:
        status_code = 500
        error_msg = str(e)
        app.logger.error(f"[ERROR] {request.path} - {status_code} - {error_msg}")
        return jsonify({'success': False, 'error': error_msg}), status_code

@app.route('/api/camera/<camera_id>/toggle', methods=['POST'])
def toggle_camera(camera_id):
    """Toggle camera enabled/disabled status"""
    try:
        camera = config_manager.get_camera(camera_id)
        if not camera:
            return jsonify({'success': False, 'error': 'Camera not found'}), 404
        
        data = request.get_json()
        if not data or 'enabled' not in data:
            return jsonify({'success': False, 'error': 'Missing enabled parameter'}), 400
        
        # Update camera config
        camera_config = dict(camera)
        camera_config['enabled'] = data['enabled']
        
        if config_manager.update_camera(camera_id, camera_config):
            # Send SIGHUP to reload configuration in the main service
            try:
                subprocess.run(['sudo', 'systemctl', 'reload', 'onvif-proxy'], 
                             capture_output=True, text=True, timeout=10)
            except:
                pass  # Service reload is best effort
            
            # Reload config so front-end immediately reflects toggle state
            try:
                config_manager.reload_config()
            except Exception as e:
                app.logger.warning(f"[CONFIG] Reload after toggle failed: {e}")

            # Update network interface based on enabled status
            try:
                if data['enabled']:
                    network_manager.ensure_camera_interface(camera_id, camera_config)
                else:
                    network_manager.remove_camera_interface(camera_id)
            except Exception as e:
                app.logger.warning(f"[NETWORK] Interface update failed on toggle: {e}")

            status = 'enabled' if data['enabled'] else 'disabled'
            
            # Log and notify camera enable/disable
            message = f"Camera '{camera['name']}' (ID: {camera_id}) {status}"
            app.logger.info(f"[SYSTEM] {message}")
            
            # Send notification if configured
            try:
                system_config = config_manager.get_system_config()
                if system_config.get('pushover_token') and system_config.get('pushover_user'):
                    notification_manager.send_notification(
                        title=f"ONVIF Proxy - Camera {status.title()}",
                        message=message,
                        priority=0
                    )
            except Exception as e:
                app.logger.warning(f"[NOTIFICATION] Failed to send camera {status} notification: {e}")
            
            return jsonify({
                'success': True, 
                'message': f'Camera {status} successfully',
                'enabled': data['enabled']
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to update camera config'})
    
    except Exception as e:
        status_code = 500
        error_msg = str(e)
        app.logger.error(f"[ERROR] {request.path} - {status_code} - {error_msg}")
        return jsonify({'success': False, 'error': error_msg}), status_code


@app.route('/config-editor', methods=['GET', 'POST'])
def config_editor():
    """Raw config file editor"""
    if request.method == 'POST':
        try:
            raw_config = request.form.get('config_content', '')
            
            # Atomic write to disk with fsync
            config_path = config_manager.config_path
            dirpath = os.path.dirname(config_path) or "."
            import tempfile, os
            fd, tmppath = tempfile.mkstemp(prefix=".config.xml.", dir=dirpath)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as tmp:
                    tmp.write(raw_config)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                os.replace(tmppath, config_path)
                # fsync directory
                try:
                    dir_fd = os.open(dirpath, os.O_DIRECTORY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except Exception:
                    pass
            except Exception:
                try:
                    if os.path.exists(tmppath):
                        os.unlink(tmppath)
                except Exception:
                    pass
                raise
            
            # Reload in-process configuration immediately
            try:
                config_manager.reload_config()
            except Exception as e:
                app.logger.warning(f"[CONFIG] Reload after raw save failed: {e}")
            
            flash('Configuration saved successfully!', 'success')
            
            # Reload service configuration
            try:
                subprocess.run(['sudo', 'systemctl', 'reload-or-restart', 'onvif-proxy'], 
                             capture_output=True, text=True, timeout=10)
            except:
                pass  # Service reload is best effort
            
            # Post/Redirect/Get to avoid stale content and resubmissions
            return redirect(url_for('config_editor'))
                
        except Exception as e:
            flash(f'Error saving configuration: {str(e)}', 'error')
            # Emergency alert on failure
            try:
                notification_manager.notify_fatal_error(f"Config write failure while saving raw config: {e}")
            except Exception:
                pass
    
    # Read current config file
    try:
        config_path = config_manager.config_path
        with open(config_path, 'r', encoding='utf-8') as f:
            config_content = f.read()
    except Exception as e:
        config_content = f"<!-- Error reading config file: {str(e)} -->"
        flash(f'Error reading configuration: {str(e)}', 'error')
    
    # No-cache headers to always fetch latest from disk
    resp = make_response(render_template('config_editor.html', config_content=config_content))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """System settings page"""
    # Initialize configs with default values
    system_config = {}
    notification_config = {}
    
    if request.method == 'POST':
        try:
            # Debug: Log all form data
            app.logger.debug(f"Form data: {dict(request.form)}")
            
            # System configuration
            system_config = {
                'enabled': request.form.get('enabled') == 'on',
                'base_interface': request.form.get('base_interface', 'eth0'),
                'base_ip_range': request.form.get('base_ip_range', '192.168.1.100'),
                'ping_interval': int(request.form.get('ping_interval', 30)),
                'web_port': int(request.form.get('web_port', 8080)),
                'notify_camera_offline': request.form.get('notify_camera_offline') == 'on',
                'notify_camera_offline_priority': int(request.form.get('notify_camera_offline_priority', 0)),
                'notify_camera_online': request.form.get('notify_camera_online') == 'on',
                'notify_camera_online_priority': int(request.form.get('notify_camera_online_priority', 0)),
                'notify_system_error': request.form.get('notify_system_error') == 'on',
                'notify_system_error_priority': int(request.form.get('notify_system_error_priority', 0)),
                'notify_service_restart': request.form.get('notify_service_restart') == 'on',
                'notify_service_restart_priority': int(request.form.get('notify_service_restart_priority', 0)),
                'no_traffic_alerts': request.form.get('no_traffic_alerts') == 'on',
                'no_traffic_minutes': int(request.form.get('no_traffic_minutes', 5)),
                'no_traffic_priority': int(request.form.get('no_traffic_priority', 1))
            }
            
            app.logger.debug(f"Parsed system config: {system_config}")
            
            # Notification configuration
            notification_config = {
                'pushover_token': request.form.get('pushover_token', '').strip(),
                'pushover_user': request.form.get('pushover_user', '').strip(),
                'notify_camera_up': 'notify_camera_up' in request.form,
                'notify_camera_down': 'notify_camera_down' in request.form,
                'notify_camera_added': 'notify_camera_added' in request.form,
                'notify_camera_removed': 'notify_camera_removed' in request.form,
                'notify_system_error': 'notify_system_error' in request.form,
                'notify_priority': int(request.form.get('notify_priority', 0)),
                'notify_retry': int(request.form.get('notify_retry', 300)),
                'notify_expire': int(request.form.get('notify_expire', 3600))
            }
            app.logger.debug(f"Parsed notification config: {notification_config}")
            
            # Save configurations
            try:
                # First save the system config
                config_manager.update_system_config(system_config)
                
                # Then save the notification config
                method = getattr(config_manager, 'update_notification_config', None)
                if callable(method):
                    try:
                        method(notification_config)
                    except Exception as ue:
                        app.logger.warning(f"update_notification_config failed, falling back to inline XML update: {ue}")
                        system = config_manager.root.find('system')
                        if system is not None:
                            for key, value in notification_config.items():
                                elem = system.find(key)
                                if elem is None:
                                    elem = ET.SubElement(system, key)
                                elem.text = str(value).lower() if isinstance(value, bool) else str(value)
                            config_manager.save_config()
                else:
                    # Fallback: Update notification settings directly in system config
                    system = config_manager.root.find('system')
                    if system is not None:
                        for key, value in notification_config.items():
                            elem = system.find(key)
                            if elem is None:
                                elem = ET.SubElement(system, key)
                            elem.text = str(value).lower() if isinstance(value, bool) else str(value)
                        config_manager.save_config()
                    
                    # Update notification manager with new credentials and settings
                    try:
                        if notification_manager:
                            if hasattr(notification_manager, 'update_credentials'):
                                notification_manager.update_credentials(
                                    notification_config.get('pushover_token', ''),
                                    notification_config.get('pushover_user', '')
                                )
                            
                            # Update notification manager settings if method exists
                            if hasattr(notification_manager, 'update_notification_settings'):
                                notification_manager.update_notification_settings(notification_config)
                        
                    except Exception as ne:
                        app.logger.error(f"Failed to update notification manager: {ne}", exc_info=True)
                        # Don't fail the entire save if just notification update fails
                    
                    # Reload service configuration via systemd
                    try:
                        subprocess.run(['sudo', 'systemctl', 'reload-or-restart', 'onvif-proxy'], 
                                     capture_output=True, text=True, timeout=10)
                    except Exception as se:
                        app.logger.warning(f"Failed to restart service: {se}")
                    
                    flash('Settings updated successfully!', 'success')
                    return redirect(url_for('settings'))
                    
            except Exception as e:
                app.logger.error(f"Error saving configuration: {e}", exc_info=True)
                flash(f'Failed to save configuration: {str(e)}', 'error')
                try:
                    if notification_manager and hasattr(notification_manager, 'notify_fatal_error'):
                        notification_manager.notify_fatal_error(f"Config write failure while updating settings: {e}")
                except Exception as ne:
                    app.logger.error(f"Failed to send notification: {ne}")
                
        except (ValueError, TypeError) as e:
            app.logger.error(f"Error parsing form data: {e}", exc_info=True)
            flash(f'Invalid form data: {str(e)}', 'error')
            return redirect(url_for('settings'))
        
        # For GET requests or if there was an error in POST
        try:
            system_config = config_manager.get_system_config()
            interfaces = network_manager.get_available_interfaces()
            
            return render_template('settings.html', 
                                 system_config=system_config, 
                                 interfaces=interfaces)
                                 
        except Exception as e:
            app.logger.error(f"Error loading settings: {e}", exc_info=True)
            flash(f'Error loading settings: {str(e)}', 'error')
            return render_template('settings.html', 
                                 system_config={},
                                 interfaces=[])
    
    system_config = config_manager.get_system_config()
    interfaces = network_manager.get_available_interfaces()
    
    return render_template('settings.html', 
                         system_config=system_config, 
                         interfaces=interfaces)

@app.route('/api/interface/<interface_name>/addresses')
def api_interface_addresses(interface_name):
    """API endpoint to get IP addresses for a specific interface"""
    try:
        addresses = network_manager.get_interface_addresses(interface_name)
        
        # Extract IPv4 addresses
        ipv4_addresses = []
        if 2 in addresses:  # AF_INET (IPv4)
            for addr_info in addresses[2]:
                ip = addr_info.get('addr', '')
                if ip and ip != '127.0.0.1':  # Skip localhost
                    ipv4_addresses.append(ip)
        
        # Generate suggested base IP range
        suggested_base = ""
        if ipv4_addresses:
            # Take first IP and suggest next range
            first_ip = ipv4_addresses[0]
            parts = first_ip.split('.')
            if len(parts) == 4:
                # Suggest .100 in the same subnet
                suggested_base = f"{parts[0]}.{parts[1]}.{parts[2]}.100"
        
        return jsonify({
            'success': True,
            'addresses': ipv4_addresses,
            'suggested_base': suggested_base
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/test_notification', methods=['POST'])
def test_notification():
    """Test Pushover notification"""
    system_config = config_manager.get_system_config()
    
    if not system_config.get('pushover_token') or not system_config.get('pushover_user'):
        return jsonify({'success': False, 'error': 'Pushover credentials not configured'})
    
    notification_manager.update_credentials(
        system_config['pushover_token'],
        system_config['pushover_user']
    )
    
    success = notification_manager.test_notification()
    
    return jsonify({
        'success': success,
        'message': 'Test notification sent!' if success else 'Failed to send test notification'
    })

@app.route('/api/system/status')
def api_system_status():
    """API endpoint for system status"""
    system_config = config_manager.get_system_config()
    cameras = config_manager.get_cameras()
    
    # Check status of all 3 services
    services = ['onvif-proxy', 'onvif-proxy-web', 'onvif-proxy-watchdog']
    service_status = {}
    
    for service in services:
        try:
            result = subprocess.run(['systemctl', 'is-active', '--quiet', service])
            service_status[service] = (result.returncode == 0)
        except Exception:
            service_status[service] = False
    
    status = {
        'system_enabled': system_config.get('enabled', True),
        'total_cameras': len(cameras),
        'active_cameras': len([c for c in cameras if c.get('enabled', True)]),
        'service_running': service_status.get('onvif-proxy', False),  # Keep for backward compatibility
        'services': service_status
    }
    
    return jsonify(status)

@app.route('/api/cameras/status')
def api_cameras_status():
    """API endpoint for cameras status"""
    try:
        ensure_fresh_config()
        cameras = config_manager.get_cameras()
        status_data = []
        
        for camera in cameras:
            status_data.append({
                'id': camera.get('id'),
                'name': camera.get('name'),
                'enabled': camera.get('enabled', True),
                'rtsp_url': camera.get('rtsp_url', ''),
                'onvif_ip': camera.get('onvif_ip', ''),
                'onvif_port': camera.get('onvif_port', 80),
                'onvif_mac': camera.get('onvif_mac', '')
            })
        
        return jsonify({'success': True, 'cameras': status_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/camera/<camera_id>/traffic')
def camera_traffic(camera_id):
    """Display traffic monitoring page for a camera"""
    cameras = config_manager.get_cameras()
    camera = next((c for c in cameras if c['id'] == camera_id), None)
    
    if not camera:
        flash(f'Camera {camera_id} not found', 'error')
        return redirect(url_for('cameras'))
    
    return render_template('traffic.html', camera=camera)

@app.route('/api/camera/<camera_id>/traffic/current')
def api_camera_traffic_current(camera_id):
    """Get current traffic statistics for a camera"""
    try:
        ensure_fresh_config()
        camera = config_manager.get_camera(camera_id)
        if not camera:
            return jsonify({'error': 'Camera not found'}), 404

        virtual_ip = camera.get('onvif_ip')
        camera_ip = _extract_camera_ip(camera.get('rtsp_url', ''))
        if not virtual_ip or not camera_ip:
            return jsonify({'error': 'Missing camera IPs for traffic lookup'}), 400

        counters = _get_iptables_counters(virtual_ip, camera_ip)
        if counters is None:
            return jsonify({'error': 'Unable to read iptables counters'}), 500

        rx_bytes, tx_bytes, rx_packets, tx_packets = counters
        now = time.time()

        # Compute rates from local cache
        last = traffic_last_stats.get(camera_id)
        rates = {}
        if last and now > last['timestamp']:
            dt = now - last['timestamp']
            rates = {
                'rx_bytes_per_sec': max(0.0, (rx_bytes - last['rx_bytes']) / dt),
                'tx_bytes_per_sec': max(0.0, (tx_bytes - last['tx_bytes']) / dt),
                'rx_packets_per_sec': max(0.0, (rx_packets - last['rx_packets']) / dt),
                'tx_packets_per_sec': max(0.0, (tx_packets - last['tx_packets']) / dt),
            }

        # Update cache
        traffic_last_stats[camera_id] = {
            'timestamp': now,
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'rx_packets': rx_packets,
            'tx_packets': tx_packets,
        }

        return jsonify({
            'success': True,
            'stats': {
                'timestamp': now,
                'rx_bytes': rx_bytes,
                'tx_bytes': tx_bytes,
                'rx_packets': rx_packets,
                'tx_packets': tx_packets,
                'virtual_ip': virtual_ip
            },
            'rates': rates
        })
        
    except Exception as e:
        status_code = 500
        error_msg = str(e)
        app.logger.error(f"[ERROR] {request.path} - {status_code} - {error_msg}")
        return jsonify({'success': False, 'error': error_msg}), status_code

@app.route('/api/camera/<camera_id>/traffic/graph')
def api_camera_traffic_graph(camera_id):
    """Generate traffic graph for a camera"""
    try:
        ensure_fresh_config()
        time_range = request.args.get('range', '-1h')  # Default to last hour
        width = int(request.args.get('width', 800))
        height = int(request.args.get('height', 400))
        
        # Generate graph file in the same directory as the active config.xml
        config_dir = os.path.dirname(config_manager.config_path)
        graph_file = os.path.join(config_dir, f"camera_{camera_id}_traffic_{time_range.replace('-', '')}.png")
        
        # Ensure RRD mapping exists for this camera in the monitor instance
        if camera_id not in getattr(traffic_monitor, 'cameras', {}):
            camera = config_manager.get_camera(camera_id)
            if camera:
                virtual_ip = camera.get('onvif_ip')
                camera_ip = _extract_camera_ip(camera.get('rtsp_url', ''))
                if virtual_ip and camera_ip:
                    # Mirror TrafficMonitor.add_camera structure without starting threads
                    rrd_path = os.path.join(traffic_monitor.rrd_base_path, f"camera_{camera_id}_traffic.rrd")
                    traffic_monitor.cameras[camera_id] = {
                        'virtual_ip': virtual_ip,
                        'camera_ip': camera_ip,
                        'rrd_file': rrd_path
                    }
        
        success = traffic_monitor.create_graph(
            camera_id, graph_file, time_range, width, height
        )
        
        if success and os.path.exists(graph_file):
            return send_from_directory(config_dir, os.path.basename(graph_file))
        else:
            return jsonify({'error': 'Failed to generate graph'}), 500
            
    except Exception as e:
        status_code = 500
        error_msg = str(e)
        app.logger.error(f"[ERROR] {request.path} - {status_code} - {error_msg}")
        return jsonify({'error': error_msg}), status_code

@app.route('/api/camera/<camera_id>/traffic/data')
def api_camera_traffic_data(camera_id):
    """Get RRD traffic data for a camera"""
    try:
        ensure_fresh_config()
        start_time = request.args.get('start', '-1h')
        end_time = request.args.get('end', 'now')
        
        # Ensure RRD mapping exists similar to graph endpoint
        if camera_id not in getattr(traffic_monitor, 'cameras', {}):
            camera = config_manager.get_camera(camera_id)
            if camera:
                virtual_ip = camera.get('onvif_ip')
                camera_ip = _extract_camera_ip(camera.get('rtsp_url', ''))
                if virtual_ip and camera_ip:
                    rrd_path = os.path.join(traffic_monitor.rrd_base_path, f"camera_{camera_id}_traffic.rrd")
                    traffic_monitor.cameras[camera_id] = {
                        'virtual_ip': virtual_ip,
                        'camera_ip': camera_ip,
                        'rrd_file': rrd_path
                    }
        
        data = traffic_monitor.get_rrd_data(camera_id, start_time, end_time)
        
        if data:
            return jsonify({'success': True, 'data': data})
        else:
            return jsonify({'error': 'No data available'}), 404
            
    except Exception as e:
        status_code = 500
        error_msg = str(e)
        app.logger.error(f"[ERROR] {request.path} - {status_code} - {error_msg}")
        return jsonify({'error': error_msg}), status_code

@app.route('/validate_rtsp', methods=['POST'])
def validate_rtsp():
    """Validate RTSP URL and probe stream parameters"""
    try:
        data = request.get_json()
        rtsp_url = data.get('rtsp_url', '').strip()
        
        if not rtsp_url:
            return jsonify({'success': False, 'error': 'RTSP URL is required'})
        
        if not rtsp_url.startswith('rtsp://'):
            return jsonify({'success': False, 'error': 'URL must start with rtsp://'})
        
        # Probe the stream using ffprobe
        probe_result = probe_rtsp_stream(rtsp_url)
        
        if probe_result['success']:
            return jsonify({
                'success': True,
                'resolution': probe_result.get('resolution'),
                'fps': probe_result.get('fps'),
                'bitrate_kbps': probe_result.get('bitrate_kbps'),
                'codec': probe_result.get('codec'),
                'duration_tested': probe_result.get('duration_tested')
            })
        else:
            return jsonify({
                'success': False,
                'error': probe_result.get('error', 'Failed to probe stream')
            })
            
    except Exception as e:
        app.logger.error(f"[RTSP_VALIDATE] Error validating RTSP URL: {str(e)}")
        return jsonify({'success': False, 'error': f'Validation error: {str(e)}'})

# Compatibility alias for front-end endpoint
@app.route('/api/rtsp/validate', methods=['POST'])
def api_validate_rtsp():
    return validate_rtsp()

def probe_rtsp_stream(rtsp_url, timeout=10):
    """
    Probe RTSP stream to get video parameters using ffprobe
    Returns dict with success, resolution, fps, bitrate_kbps, codec, error
    """
    try:
        # Mask credentials in logs
        log_url = rtsp_url
        if '@' in rtsp_url:
            parts = rtsp_url.split('@')
            if len(parts) == 2:
                protocol_and_creds = parts[0]
                if '://' in protocol_and_creds:
                    protocol = protocol_and_creds.split('://')[0]
                    log_url = f"{protocol}://***:***@{parts[1]}"
        
        app.logger.info(f"[RTSP_PROBE] Probing stream: {log_url}")
        
        # ffprobe command to get stream information
        ffprobe_cmd = [
            'ffprobe',
            '-v', 'error',
            '-select_streams', 'v:0',  # Select first video stream
            '-show_entries', 'stream=width,height,r_frame_rate,bit_rate,codec_name:format=bit_rate',
            '-of', 'json',
            '-timeout', str(timeout * 1000000),  # timeout in microseconds
            '-rtsp_transport', 'tcp',
            '-analyzeduration', '5000000',  # 5 seconds
            '-probesize', '5000000',  # 5MB
            rtsp_url
        ]
        
        # Run ffprobe with timeout
        result = subprocess.run(
            ffprobe_cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5  # Add buffer to subprocess timeout
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else 'Unknown ffprobe error'
            app.logger.warning(f"[RTSP_PROBE] ffprobe failed: {error_msg}")
            return {
                'success': False,
                'error': f'Stream probe failed: {error_msg}'
            }
        
        # Parse JSON output
        try:
            probe_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            app.logger.error(f"[RTSP_PROBE] Failed to parse ffprobe output: {e}")
            return {
                'success': False,
                'error': 'Failed to parse stream information'
            }
        
        # Extract stream information
        if 'streams' not in probe_data or len(probe_data['streams']) == 0:
            return {
                'success': False,
                'error': 'No video streams found'
            }
        
        stream = probe_data['streams'][0]
        
        # Extract resolution
        width = stream.get('width')
        height = stream.get('height')
        resolution = f"{width}x{height}" if width and height else None
        
        # Extract and calculate FPS (round down to integer)
        fps = None
        if 'r_frame_rate' in stream:
            try:
                rate_parts = stream['r_frame_rate'].split('/')
                if len(rate_parts) == 2:
                    num = float(rate_parts[0])
                    denom = float(rate_parts[1])
                    if denom > 0:
                        fps = int(num / denom)  # Round down to integer
            except (ValueError, ZeroDivisionError):
                pass
        
        # Extract bitrate (convert to kbps) - try stream first, then format
        bitrate_kbps = None
        if 'bit_rate' in stream and stream['bit_rate']:
            try:
                bitrate_bps = int(stream['bit_rate'])
                bitrate_kbps = round(bitrate_bps / 1000)
            except (ValueError, TypeError):
                pass
        
        # If stream bitrate not available, try format bitrate
        if bitrate_kbps is None and 'format' in probe_data and 'bit_rate' in probe_data['format']:
            try:
                bitrate_bps = int(probe_data['format']['bit_rate'])
                bitrate_kbps = round(bitrate_bps / 1000)
            except (ValueError, TypeError):
                pass
        
        # Extract codec
        codec = stream.get('codec_name')
        
        app.logger.info(f"[RTSP_PROBE] Successfully probed stream: {resolution}, {fps}fps, {bitrate_kbps}kbps, {codec}")
        
        return {
            'success': True,
            'resolution': resolution,
            'fps': fps,
            'bitrate_kbps': bitrate_kbps,
            'codec': codec,
            'duration_tested': timeout
        }
        
    except subprocess.TimeoutExpired:
        app.logger.warning(f"[RTSP_PROBE] Timeout probing stream: {log_url}")
        return {
            'success': False,
            'error': f'Stream probe timed out after {timeout} seconds'
        }
    except Exception as e:
        app.logger.error(f"[RTSP_PROBE] Error probing stream: {str(e)}")
        return {
            'success': False,
            'error': f'Probe error: {str(e)}'
        }

@app.route('/service/<service_name>/start', methods=['POST'])
def start_service(service_name):
    """Start a specific service via systemd"""
    if service_name not in ['onvif-proxy', 'onvif-proxy-web', 'onvif-proxy-watchdog']:
        return jsonify({'success': False, 'error': 'Invalid service name'})
    
    try:
        import subprocess
        result = subprocess.run(['sudo', 'systemctl', 'start', service_name], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Log and notify service start
            message = f"Service '{service_name}' started successfully"
            app.logger.info(f"[SYSTEM] {message}")
            
            # Send notification if configured
            try:
                system_config = config_manager.get_system_config()
                if system_config.get('pushover_token') and system_config.get('pushover_user'):
                    notification_manager.send_notification(
                        title="ONVIF Proxy - Service Started",
                        message=message,
                        priority=0
                    )
            except Exception as e:
                app.logger.warning(f"[NOTIFICATION] Failed to send service start notification: {e}")
            
            return jsonify({'success': True, 'message': f'{service_name} started successfully'})
        else:
            # Log and notify service start failure
            error_msg = f"Failed to start service '{service_name}': {result.stderr}"
            app.logger.error(f"[SYSTEM] {error_msg}")
            
            # Send error notification
            try:
                system_config = config_manager.get_system_config()
                if system_config.get('pushover_token') and system_config.get('pushover_user'):
                    notification_manager.send_notification(
                        title="ONVIF Proxy - Service Start Failed",
                        message=error_msg,
                        priority=1
                    )
            except Exception as e:
                app.logger.warning(f"[NOTIFICATION] Failed to send service start error notification: {e}")
            
            return jsonify({'success': False, 'error': result.stderr})
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': f'{service_name} start timed out'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/service/<service_name>/stop', methods=['POST'])
def stop_service(service_name):
    """Stop a specific service via systemd"""
    if service_name not in ['onvif-proxy', 'onvif-proxy-web', 'onvif-proxy-watchdog']:
        return jsonify({'success': False, 'error': 'Invalid service name'})
    
    try:
        import subprocess
        result = subprocess.run(['sudo', 'systemctl', 'stop', service_name], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Log and notify service stop
            message = f"Service '{service_name}' stopped successfully"
            app.logger.info(f"[SYSTEM] {message}")
            
            # Send notification if configured
            try:
                system_config = config_manager.get_system_config()
                if system_config.get('pushover_token') and system_config.get('pushover_user'):
                    notification_manager.send_notification(
                        title="ONVIF Proxy - Service Stopped",
                        message=message,
                        priority=0
                    )
            except Exception as e:
                app.logger.warning(f"[NOTIFICATION] Failed to send service stop notification: {e}")
            
            return jsonify({'success': True, 'message': f'{service_name} stopped successfully'})
        else:
            # Log and notify service stop failure
            error_msg = f"Failed to stop service '{service_name}': {result.stderr}"
            app.logger.error(f"[SYSTEM] {error_msg}")
            
            # Send error notification
            try:
                system_config = config_manager.get_system_config()
                if system_config.get('pushover_token') and system_config.get('pushover_user'):
                    notification_manager.send_notification(
                        title="ONVIF Proxy - Service Stop Failed",
                        message=error_msg,
                        priority=1
                    )
            except Exception as e:
                app.logger.warning(f"[NOTIFICATION] Failed to send service stop error notification: {e}")
            
            return jsonify({'success': False, 'error': result.stderr})
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': f'{service_name} stop timed out'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/service/<service_name>/restart', methods=['POST'])
def restart_service(service_name):
    """Restart a specific service via systemd"""
    if service_name not in ['onvif-proxy', 'onvif-proxy-web', 'onvif-proxy-watchdog']:
        return jsonify({'success': False, 'error': 'Invalid service name'})
    
    try:
        import subprocess
        result = subprocess.run(['sudo', 'systemctl', 'restart', service_name], 
                              capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            # Log and notify service restart
            message = f"Service '{service_name}' restarted successfully"
            app.logger.info(f"[SYSTEM] {message}")
            
            # Send notification if configured
            try:
                system_config = config_manager.get_system_config()
                if system_config.get('pushover_token') and system_config.get('pushover_user'):
                    notification_manager.send_notification(
                        title="ONVIF Proxy - Service Restarted",
                        message=message,
                        priority=0
                    )
            except Exception as e:
                app.logger.warning(f"[NOTIFICATION] Failed to send service restart notification: {e}")
            
            return jsonify({'success': True, 'message': f'{service_name} restarted successfully'})
        else:
            # Log and notify service restart failure
            error_msg = f"Failed to restart service '{service_name}': {result.stderr}"
            app.logger.error(f"[SYSTEM] {error_msg}")
            
            # Send error notification
            try:
                system_config = config_manager.get_system_config()
                if system_config.get('pushover_token') and system_config.get('pushover_user'):
                    notification_manager.send_notification(
                        title="ONVIF Proxy - Service Restart Failed",
                        message=error_msg,
                        priority=1
                    )
            except Exception as e:
                app.logger.warning(f"[NOTIFICATION] Failed to send service restart error notification: {e}")
            
            return jsonify({'success': False, 'error': result.stderr})
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': f'{service_name} restart timed out'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Legacy endpoints for backward compatibility
@app.route('/service/start', methods=['POST'])
def start_main_service():
    """Start the main ONVIF proxy service (legacy endpoint)"""
    return start_service('onvif-proxy')

@app.route('/service/stop', methods=['POST'])
def stop_main_service():
    """Stop the main ONVIF proxy service (legacy endpoint)"""
    return stop_service('onvif-proxy')

@app.route('/service/restart', methods=['POST'])
def restart_main_service():
    """Restart the main ONVIF proxy service (legacy endpoint)"""
    return restart_service('onvif-proxy')

def create_app():
    """Application factory"""
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Log application startup
    app.logger.info("[SYSTEM] ONVIF Proxy Web Interface starting up")
    
    # Update notification manager with current config
    system_config = config_manager.get_system_config()
    notification_manager.update_credentials(
        system_config.get('pushover_token', ''),
        system_config.get('pushover_user', '')
    )
    
    # Send startup notification if configured
    try:
        if system_config.get('pushover_token') and system_config.get('pushover_user'):
            notification_manager.send_notification(
                title="ONVIF Proxy - System Started",
                message="ONVIF Proxy Web Interface has started successfully",
                priority=0
            )
    except Exception as e:
        app.logger.warning(f"[NOTIFICATION] Failed to send startup notification: {e}")
    
    return app

@app.route('/api/camera/<camera_id>/screenshot')
def api_camera_screenshot(camera_id):
    """Serve camera screenshot"""
    try:
        config_dir = os.path.dirname(config_manager.config_path)
        screenshots_dir = os.path.join(config_dir, "screenshots")
        screenshot_file = f"camera_{camera_id}_latest.jpg"
        screenshot_path = os.path.join(screenshots_dir, screenshot_file)
        
        if os.path.exists(screenshot_path):
            return send_from_directory(screenshots_dir, screenshot_file)
        else:
            # Return a placeholder or 404
            return jsonify({'error': 'Screenshot not available'}), 404
            
    except Exception as e:
        status_code = 500
        error_msg = str(e)
        app.logger.error(f"[ERROR] {request.path} - {status_code} - {error_msg}")
        return jsonify({'error': error_msg}), status_code

@app.route('/api/camera/<camera_id>/traffic/summary')
def api_camera_traffic_summary(camera_id):
    """Get traffic summary with 5-min averages and 24h totals"""
    try:
        ensure_fresh_config()
        camera = config_manager.get_camera(camera_id)
        if not camera:
            return jsonify({'error': 'Camera not found'}), 404
        
        # Ensure RRD mapping exists for this camera in the monitor instance
        if camera_id not in getattr(traffic_monitor, 'cameras', {}):
            virtual_ip = camera.get('onvif_ip')
            camera_ip = _extract_camera_ip(camera.get('rtsp_url', ''))
            if virtual_ip and camera_ip:
                rrd_path = os.path.join(traffic_monitor.rrd_base_path, f"camera_{camera_id}_traffic.rrd")
                traffic_monitor.cameras[camera_id] = {
                    'virtual_ip': virtual_ip,
                    'camera_ip': camera_ip,
                    'rrd_file': rrd_path
                }
        
        summary = traffic_monitor.get_traffic_summary(camera_id)
        if summary:
            return jsonify(summary)
        else:
            return jsonify({'error': 'No traffic data available'}), 404
            
    except Exception as e:
        status_code = 500
        error_msg = str(e)
        app.logger.error(f"[ERROR] {request.path} - {status_code} - {error_msg}")
        return jsonify({'error': error_msg}), status_code

if __name__ == '__main__':
    app = create_app()
    system_config = config_manager.get_system_config()
    port = system_config.get('web_port', 8080)
    
    # Only run development server if not using Gunicorn
    import os
    if os.environ.get('SERVER_SOFTWARE', '').startswith('gunicorn'):
        # Running under Gunicorn, don't start development server
        pass
    else:
        # Development mode
        app.run(host='0.0.0.0', port=port, debug=False)
