#!/usr/bin/env python3
"""
Core ONVIF Proxy service
Handles RTSP stream translation to ONVIF protocol
"""

import logging
import threading
import time
import cv2
import socket
import uuid
import time
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Tuple
import xml.etree.ElementTree as ET
import logging

# Configure logging to use system's default logging (systemd-journald) when available
logger = logging.getLogger('ONVIFProxy')
root_logger = logging.getLogger()
# Root at DEBUG so file handler can capture full bodies; journald handler will be set to INFO
root_logger.setLevel(logging.DEBUG)

# Avoid duplicate handlers on reload
for h in list(root_logger.handlers):
    root_logger.removeHandler(h)

handler = None
try:
    from systemd.journal import JournalHandler  # type: ignore
    handler = JournalHandler(SYSLOG_IDENTIFIER='onvif-proxy')
except Exception:
    # Fallback to stdout so systemd can capture it
    handler = logging.StreamHandler()

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
root_logger.addHandler(handler)

# File logging to /tmp/onvif-proxy.log removed; rely on journald/stream handlers only

# Proxy version used in ONVIF responses
PROXY_VERSION = "1.0.1"

class ONVIFHandler(BaseHTTPRequestHandler):
    """HTTP handler for ONVIF requests"""
    
    def __init__(self, *args, camera_config=None, **kwargs):
        self.camera_config = camera_config or {}
        super().__init__(*args, **kwargs)
    
    def _log_request(self, method, path, headers, body=''):
        """Log incoming request details"""
        request_id = str(uuid.uuid4())[:8]
        client_ip = self.client_address[0]
        # Save on instance so other methods can correlate
        self.request_id = request_id
        # Local address (the interface/IP this server is bound to)
        try:
            local_ip, local_port = self.request.getsockname()[:2]
            local_addr_info = f" on {local_ip}:{local_port}"
        except Exception:
            local_addr_info = ""
        
        # Log basic request info
        logger.info(f"[REQ {request_id}] {method} {path} from {client_ip}{local_addr_info}")
        
        # Log headers (excluding sensitive ones)
        safe_headers = {k: v for k, v in headers.items() 
                      if k.lower() not in ['authorization', 'x-api-key']}
        logger.debug(f"[REQ {request_id}] Headers: {safe_headers}")
        
        # Log full request body at DEBUG (captured by file handler)
        if body:
            logger.debug(f"[REQ {request_id}] Body: {body}")
        
        return request_id

    def _get_local_base_url(self) -> str:
        """Build base URL from local socket address rather than config to ensure correct interface/IP."""
        try:
            local_ip, local_port = self.request.getsockname()[:2]
        except Exception:
            # Fallback to configured values
            local_ip = self.camera_config.get('onvif_ip', '127.0.0.1')
            local_port = self.camera_config.get('onvif_port', 80)
        return f"http://{local_ip}:{local_port}"
    
    def _video_params(self):
        """Return video parameters from camera_config with sensible defaults."""
        return {
            'encoding': self.camera_config.get('encoding', 'H264'),
            'width': int(self.camera_config.get('video_width', 1920)),
            'height': int(self.camera_config.get('video_height', 1080)),
            'framerate': int(self.camera_config.get('framerate', 30)),
            'bitrate': int(self.camera_config.get('bitrate', 4096)),
            'profile_token': self.camera_config.get('profile_token', 'Profile_1'),
            'video_source_token': self.camera_config.get('video_source_token', 'VideoSource_1'),
            'video_encoder_token': self.camera_config.get('video_encoder_token', 'VideoEncoder_1'),
        }
    
    def _log_response(self, request_id, status_code, headers, body='', error=''):
        """Log response details"""
        # Log basic response info
        log_msg = f"[RES {request_id}] Status: {status_code}"
        if error:
            log_msg += f" Error: {error}"
        logger.info(log_msg)
        
        # Log full response body at DEBUG (captured by file handler)
        if body:
            logger.debug(f"[RES {request_id}] Response: {body}")
    
    def do_GET(self):
        """Handle GET requests with logging"""
        start_time = time.time()
        request_id = self._log_request('GET', self.path, dict(self.headers))
        
        try:
            parsed_path = urlparse(self.path)
            
            if parsed_path.path == "/onvif/device_service":
                response = self.handle_device_service()
                self._log_response(request_id, 200, {}, response)
            elif parsed_path.path == "/onvif/media_service":
                response = self.handle_media_service()
                self._log_response(request_id, 200, {}, response)
            elif parsed_path.path.startswith("/stream"):
                self.handle_stream_request()
                self._log_response(request_id, 200, {}, "[Stream data]")
            else:
                self.send_error(404, "Not Found")
                self._log_response(request_id, 404, {}, error="Not Found")
        except Exception as e:
            logger.error(f"[REQ {request_id}] Error handling GET request: {str(e)}", exc_info=True)
            self.send_error(500, f"Internal Server Error: {str(e)}")
            self._log_response(request_id, 500, {}, error=str(e))
        finally:
            duration = (time.time() - start_time) * 1000  # in ms
            logger.info(f"[REQ {request_id}] Completed in {duration:.2f}ms")
    
    def _extract_soap_action(self, post_data: str) -> str:
        """Extract the SOAP action (operation) from the SOAP body"""
        try:
            root = ET.fromstring(post_data)
            # Support SOAP 1.2 and 1.1 namespaces
            soap_namespaces = [
                'http://www.w3.org/2003/05/soap-envelope',
                'http://schemas.xmlsoap.org/soap/envelope/'
            ]
            body = None
            for ns in soap_namespaces:
                body = root.find(f'.//{{{ns}}}Body')
                if body is not None:
                    break
            # If Body found, the action is the first direct child element of Body
            if body is not None:
                for child in list(body):
                    # Only consider element nodes
                    tag = getattr(child, 'tag', None)
                    if not isinstance(tag, str):
                        continue
                    local = tag.split('}')[-1] if '}' in tag else tag
                    if local:
                        return local
            # Fallback: previous heuristic, but skip wsse:Security headers explicitly
            for elem in root.iter():
                tag = getattr(elem, 'tag', None)
                if not isinstance(tag, str):
                    continue
                local = tag.split('}')[-1] if '}' in tag else tag
                if local in ("Envelope", "Header", "Body", "Security"):
                    continue
                if local:
                    return local
        except Exception as e:
            logger.debug(f"Could not parse SOAP action: {str(e)}")
        return "Unknown"
    
    def do_POST(self):
        """Handle POST requests (SOAP) with logging"""
        start_time = time.time()
        
        # Read request data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='replace')
        
        # Log request
        request_id = self._log_request('POST', self.path, dict(self.headers), post_data)
        
        try:
            # Log SOAP action if present
            soap_action = None
            if 'SOAPAction' in self.headers:
                soap_action = self.headers['SOAPAction']
                logger.info(f"[REQ {request_id}] SOAPAction: {soap_action}")
            
            # Parse SOAP action from the body
            action = self._extract_soap_action(post_data)
            if action and action != 'Envelope':  # Skip the root Envelope element
                logger.info(f"[REQ {request_id}] Detected ONVIF action: {action}")
            
            # Handle the request
            response = None
            if action == "GetDeviceInformation":
                response = self.handle_get_device_information()
            elif action == "GetCapabilities":
                response = self.handle_get_capabilities()
            elif action == "GetSystemDateAndTime":
                response = self.handle_get_system_date_and_time()
            elif action == "GetServices":
                response = self.handle_get_services()
            elif action == "GetServiceCapabilities":
                response = self.handle_get_service_capabilities()
            elif action == "GetProfiles":
                response = self.handle_get_profiles()
            elif action == "GetVideoSources":
                response = self.handle_get_video_sources()
            elif action == "GetVideoSourceConfigurations":
                response = self.handle_get_video_source_configurations()
            elif action == "GetVideoEncoderConfigurations":
                response = self.handle_get_video_encoder_configurations()
            elif action == "GetStreamUri":
                response = self.handle_get_stream_uri()
            elif action == "GetSnapshotUri":
                response = self.handle_get_snapshot_uri()
            elif action == "GetAudioOutputConfigurationOptions":
                response = self.handle_get_audio_output_config_options()
            else:
                error_msg = f"Action not supported: {action}"
                logger.warning(f"[REQ {request_id}] {error_msg}")
                if soap_action:
                    error_msg += f" (SOAPAction: {soap_action})"
                self.send_soap_fault(error_msg)
                self._log_response(request_id, 500, {}, error=error_msg)
                return
                
            if response:
                self._log_response(request_id, 200, {}, response)
                
        except Exception as e:
            logger.error(f"[REQ {request_id}] Error handling POST request: {str(e)}", exc_info=True)
            self.send_error(500, f"Internal Server Error: {str(e)}")
            self._log_response(request_id, 500, {}, error=str(e))
        finally:
            duration = (time.time() - start_time) * 1000  # in ms
            logger.info(f"[REQ {request_id}] Completed in {duration:.2f}ms")
    
    def handle_device_service(self):
        """Handle device service requests"""
        wsdl_content = """<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             targetNamespace="http://www.onvif.org/ver10/device/wsdl">
    <service name="DeviceService">
        <port name="DevicePort" binding="tns:DeviceBinding">
            <soap:address location="{}/onvif/device_service"/>
        </port>
    </service>
</definitions>""".format(self._get_local_base_url())
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/xml')
        self.end_headers()
        self.wfile.write(wsdl_content.encode())
        return wsdl_content
    
    def handle_media_service(self):
        """Handle media service requests"""
        wsdl_content = """<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             targetNamespace="http://www.onvif.org/ver10/media/wsdl">
    <service name="MediaService">
        <port name="MediaPort" binding="tns:MediaBinding">
            <soap:address location="{}/onvif/media_service"/>
        </port>
    </service>
</definitions>""".format(self._get_local_base_url())
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/xml')
        self.end_headers()
        self.wfile.write(wsdl_content.encode())
        return wsdl_content
    
    def handle_get_device_information(self):
        """Handle GetDeviceInformation SOAP request"""
        try:
            response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
            <tds:Manufacturer>ONVIF-Proxy</tds:Manufacturer>
            <tds:Model>{}</tds:Model>
            <tds:FirmwareVersion>{}</tds:FirmwareVersion>
            <tds:SerialNumber>{}</tds:SerialNumber>
            <tds:HardwareId>1.0</tds:HardwareId>
        </tds:GetDeviceInformationResponse>
    </soap:Body>
</soap:Envelope>""".format(
                self.camera_config.get('name', self.camera_config.get('model', 'ONVIF-Proxy-Camera')),
                PROXY_VERSION,
                self.camera_config.get('serial_number', '1234567890')
            )
            
            return self.send_soap_response(response)
            
        except Exception as e:
            logger.error(f"Error in handle_get_device_information: {str(e)}", exc_info=True)
            return self.send_soap_fault("Internal server error")
    
    def handle_get_capabilities(self):
        """Handle GetCapabilities SOAP request"""
        base_url = self._get_local_base_url()
        
        response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
            <tds:Capabilities>
                <tt:Device xmlns:tt="http://www.onvif.org/ver10/schema">
                    <tt:XAddr>{base_url}/onvif/device_service</tt:XAddr>
                </tt:Device>
                <tt:Media xmlns:tt="http://www.onvif.org/ver10/schema">
                    <tt:XAddr>{base_url}/onvif/media_service</tt:XAddr>
                </tt:Media>
            </tds:Capabilities>
        </tds:GetCapabilitiesResponse>
    </soap:Body>
</soap:Envelope>"""
        
        return self.send_soap_response(response)
    
    def handle_get_profiles(self):
        """Handle GetProfiles SOAP request"""
        try:
            vp = self._video_params()
            response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Body>
        <trt:GetProfilesResponse>
            <trt:Profiles token="{profile_token}" fixed="true">
                <tt:Name>{profile_token}</tt:Name>
                <tt:VideoSourceConfiguration token="{video_source_token}">
                    <tt:Name>{video_source_token}</tt:Name>
                    <tt:UseCount>1</tt:UseCount>
                </tt:VideoSourceConfiguration>
                <tt:VideoEncoderConfiguration token="{video_encoder_token}">
                    <tt:Name>{video_encoder_token}</tt:Name>
                    <tt:UseCount>1</tt:UseCount>
                    <tt:Encoding>{encoding}</tt:Encoding>
                    <tt:Resolution>
                        <tt:Width>{width}</tt:Width>
                        <tt:Height>{height}</tt:Height>
                    </tt:Resolution>
                    <tt:Quality>5</tt:Quality>
                    <tt:RateControl>
                        <tt:FrameRateLimit>{framerate}</tt:FrameRateLimit>
                        <tt:EncodingInterval>1</tt:EncodingInterval>
                        <tt:BitrateLimit>{bitrate}</tt:BitrateLimit>
                    </tt:RateControl>
                </tt:VideoEncoderConfiguration>
            </trt:Profiles>
        </trt:GetProfilesResponse>
    </soap:Body>
</soap:Envelope>""".format(**vp)
            
            return self.send_soap_response(response)
            
        except Exception as e:
            logger.error(f"Error in handle_get_profiles: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get profiles")
    
    def handle_get_stream_uri(self):
        """Handle GetStreamUri SOAP request"""
        try:
            rtsp_url = self.camera_config.get('rtsp_url', '')
            if not rtsp_url:
                logger.error("No RTSP URL configured for camera")
                return self.send_soap_fault("Stream URL not configured")
                
            response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Body>
        <trt:GetStreamUriResponse>
            <trt:MediaUri>
                <tt:Uri>{}</tt:Uri>
                <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
                <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
                <tt:Timeout>PT0H0M0.000S</tt:Timeout>
            </trt:MediaUri>
        </trt:GetStreamUriResponse>
    </soap:Body>
</soap:Envelope>""".format(rtsp_url)
            
            logger.info(f"Stream URI requested, returning: {rtsp_url}")
            return self.send_soap_response(response)
            
        except Exception as e:
            logger.error(f"Error in handle_get_stream_uri: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get stream URI")
    
    def handle_get_snapshot_uri(self):
        """Handle GetSnapshotUri SOAP request"""
        try:
            # Provide a placeholder snapshot URI (could be implemented to generate JPEG snapshots)
            base_url = self._get_local_base_url()
            snapshot_uri = f"{base_url}/stream/snapshot.jpg"
            response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Body>
        <trt:GetSnapshotUriResponse>
            <trt:MediaUri>
                <tt:Uri>{snapshot_uri}</tt:Uri>
                <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
                <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
                <tt:Timeout>PT0H0M0.000S</tt:Timeout>
            </trt:MediaUri>
        </trt:GetSnapshotUriResponse>
    </soap:Body>
</soap:Envelope>"""
            return self.send_soap_response(response)
        except Exception as e:
            logger.error(f"Error in handle_get_snapshot_uri: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get snapshot URI")
    
    def handle_stream_request(self):
        """Handle direct stream requests"""
        # Redirect to original RTSP stream
        rtsp_url = self.camera_config.get('rtsp_url', '')
        if rtsp_url:
            self.send_response(302)
            self.send_header('Location', rtsp_url)
            self.end_headers()
        else:
            self.send_error(404, "Stream not available")
    
    def handle_get_system_date_and_time(self):
        """Handle GetSystemDateAndTime SOAP request"""
        try:
            now = time.gmtime()
            response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Body>
        <tds:GetSystemDateAndTimeResponse>
            <tds:SystemDateAndTime>
                <tt:DateTimeType>NTP</tt:DateTimeType>
                <tt:DaylightSavings>false</tt:DaylightSavings>
                <tt:TimeZone><tt:TZ>UTC</tt:TZ></tt:TimeZone>
                <tt:UTCDateTime>
                    <tt:Time>
                        <tt:Hour>{now.tm_hour}</tt:Hour>
                        <tt:Minute>{now.tm_min}</tt:Minute>
                        <tt:Second>{now.tm_sec}</tt:Second>
                    </tt:Time>
                    <tt:Date>
                        <tt:Year>{now.tm_year}</tt:Year>
                        <tt:Month>{now.tm_mon}</tt:Month>
                        <tt:Day>{now.tm_mday}</tt:Day>
                    </tt:Date>
                </tt:UTCDateTime>
            </tds:SystemDateAndTime>
        </tds:GetSystemDateAndTimeResponse>
    </soap:Body>
</soap:Envelope>"""
            return self.send_soap_response(response)
        except Exception as e:
            logger.error(f"Error in handle_get_system_date_and_time: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get system date and time")
    
    def handle_get_services(self):
        """Handle GetServices SOAP request"""
        try:
            base_url = f"http://{self.camera_config.get('onvif_ip', '127.0.0.1')}:{self.camera_config.get('onvif_port', 80)}"
            response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Body>
        <tds:GetServicesResponse>
            <tds:Service>
                <tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>
                <tds:XAddr>{base_url}/onvif/device_service</tds:XAddr>
                <tds:Version>
                    <tds:Major>2</tds:Major>
                    <tds:Minor>42</tds:Minor>
                </tds:Version>
            </tds:Service>
            <tds:Service>
                <tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>
                <tds:XAddr>{base_url}/onvif/media_service</tds:XAddr>
                <tds:Version>
                    <tds:Major>2</tds:Major>
                    <tds:Minor>42</tds:Minor>
                </tds:Version>
            </tds:Service>
        </tds:GetServicesResponse>
    </soap:Body>
</soap:Envelope>"""
            return self.send_soap_response(response)
        except Exception as e:
            logger.error(f"Error in handle_get_services: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get services")
    
    def handle_get_service_capabilities(self):
        """Handle GetServiceCapabilities (Device service) SOAP request"""
        try:
            response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Body>
        <tds:GetServiceCapabilitiesResponse>
            <tds:Capabilities>
                <tt:Network>
                    <tt:IPFilter>false</tt:IPFilter>
                    <tt:ZeroConfiguration>false</tt:ZeroConfiguration>
                    <tt:IPVersion6>false</tt:IPVersion6>
                </tt:Network>
                <tt:System>
                    <tt:DiscoveryResolve>false</tt:DiscoveryResolve>
                    <tt:DiscoveryBye>false</tt:DiscoveryBye>
                    <tt:RemoteDiscovery>false</tt:RemoteDiscovery>
                    <tt:SystemBackup>false</tt:SystemBackup>
                    <tt:SystemLogging>false</tt:SystemLogging>
                    <tt:FirmwareUpgrade>false</tt:FirmwareUpgrade>
                </tt:System>
            </tds:Capabilities>
        </tds:GetServiceCapabilitiesResponse>
    </soap:Body>
</soap:Envelope>"""
            return self.send_soap_response(response)
        except Exception as e:
            logger.error(f"Error in handle_get_service_capabilities: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get service capabilities")
    
    def handle_get_video_sources(self):
        """Handle GetVideoSources SOAP request"""
        try:
            vp = self._video_params()
            response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Body>
        <trt:GetVideoSourcesResponse>
            <trt:VideoSources>
                <tt:VideoSource token="{video_source_token}">
                    <tt:Framerate>{framerate}</tt:Framerate>
                    <tt:Resolution>
                        <tt:Width>{width}</tt:Width>
                        <tt:Height>{height}</tt:Height>
                    </tt:Resolution>
                </tt:VideoSource>
            </trt:VideoSources>
        </trt:GetVideoSourcesResponse>
    </soap:Body>
</soap:Envelope>""".format(**vp)
            return self.send_soap_response(response)
        except Exception as e:
            logger.error(f"Error in handle_get_video_sources: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get video sources")
    
    def handle_get_video_source_configurations(self):
        """Handle GetVideoSourceConfigurations SOAP request"""
        try:
            vp = self._video_params()
            response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Body>
        <trt:GetVideoSourceConfigurationsResponse>
            <trt:Configurations token="{video_source_token}">
                <tt:Name>{video_source_token}</tt:Name>
                <tt:UseCount>1</tt:UseCount>
            </trt:Configurations>
        </trt:GetVideoSourceConfigurationsResponse>
    </soap:Body>
</soap:Envelope>""".format(**vp)
            return self.send_soap_response(response)
        except Exception as e:
            logger.error(f"Error in handle_get_video_source_configurations: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get video source configurations")
    
    def handle_get_video_encoder_configurations(self):
        """Handle GetVideoEncoderConfigurations SOAP request"""
        try:
            vp = self._video_params()
            response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
    <soap:Body>
        <trt:GetVideoEncoderConfigurationsResponse>
            <trt:Configurations token="{video_encoder_token}">
                <tt:Name>{video_encoder_token}</tt:Name>
                <tt:UseCount>1</tt:UseCount>
                <tt:Encoding>{encoding}</tt:Encoding>
                <tt:Resolution>
                    <tt:Width>{width}</tt:Width>
                    <tt:Height>{height}</tt:Height>
                </tt:Resolution>
                <tt:Quality>5</tt:Quality>
                <tt:RateControl>
                    <tt:FrameRateLimit>{framerate}</tt:FrameRateLimit>
                    <tt:EncodingInterval>1</tt:EncodingInterval>
                    <tt:BitrateLimit>{bitrate}</tt:BitrateLimit>
                </tt:RateControl>
            </trt:Configurations>
        </trt:GetVideoEncoderConfigurationsResponse>
    </soap:Body>
</soap:Envelope>""".format(**vp)
            return self.send_soap_response(response)
        except Exception as e:
            logger.error(f"Error in handle_get_video_encoder_configurations: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get video encoder configurations")
    
    def send_soap_response(self, response_xml: str):
        """Send SOAP response with logging"""
        try:
            # Get request ID if available
            request_id = getattr(self, 'request_id', 'unknown')
            
            # Log response summary
            logger.info(f"[RES {request_id}] Sending SOAP response (length: {len(response_xml)} bytes)")
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/soap+xml; charset=utf-8')
            self.send_header('Content-Length', str(len(response_xml)))
            self.end_headers()
            self.wfile.write(response_xml.encode())
            
            # Log first 200 chars of response for debugging
            preview = response_xml[:200] + ('...' if len(response_xml) > 200 else '')
            logger.debug(f"[RES {request_id}] Response preview: {preview}")
            
            return response_xml
            
        except Exception as e:
            logger.error(f"[RES {request_id}] Error sending SOAP response: {str(e)}", exc_info=True)
            raise
    
    def handle_get_audio_output_config_options(self):
        """Handle GetAudioOutputConfigurationOptions SOAP request"""
        try:
            response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tt="http://www.onvif.org/ver10/schema"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
    <soap:Body>
        <trt:GetAudioOutputConfigurationOptionsResponse>
            <trt:Options>
                <tt:OutputTokens>AudioOutput_1</tt:OutputTokens>
                <tt:SendPrimacy>http://www.onvif.org/ver10/stream/flow/FullDuplex</tt:SendPrimacy>
                <tt:OutputLevelRange>
                    <tt:Min>-100</tt:Min>
                    <tt:Max>6</tt:Max>
                </tt:OutputLevelRange>
            </trt:Options>
        </trt:GetAudioOutputConfigurationOptionsResponse>
    </soap:Body>
</soap:Envelope>"""
            return self.send_soap_response(response)
            
        except Exception as e:
            logger.error(f"Error in handle_get_audio_output_config_options: {str(e)}", exc_info=True)
            return self.send_soap_fault("Failed to get audio output configuration options")

    def send_soap_fault(self, fault_string: str):
        """Send SOAP fault response with logging"""
        try:
            # Get request ID if available
            request_id = getattr(self, 'request_id', 'unknown')
            
            # Log the fault
            logger.warning(f"[REQ {request_id}] Sending SOAP fault: {fault_string}")
            
            # Create fault response
            response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <soap:Fault>
            <soap:Code>
                <soap:Value>soap:Sender</soap:Value>
                <soap:Subcode>
                    <soap:Value>ter:NotAuthorized</soap:Value>
                </soap:Subcode>
            </soap:Code>
            <soap:Reason>
                <soap:Text xml:lang="en">{fault_string}</soap:Text>
            </soap:Reason>
        </soap:Fault>
    </soap:Body>
</soap:Envelope>"""
            
            # Send response
            self.send_response(500)
            self.send_header('Content-Type', 'application/soap+xml')
            self.end_headers()
            self.wfile.write(response.encode())
            
            return response
            
        except Exception as e:
            logger.error(f"[REQ {request_id}] Error sending SOAP fault: {str(e)}", exc_info=True)
            raise


class ONVIFProxyServer:
    """ONVIF Proxy Server for individual cameras"""
    
    def __init__(self, camera_config: Dict):
        self.camera_config = camera_config
        self.server = None
        self.server_thread = None
        self.running = False
        self.logger = logging.getLogger(__name__)
    
    def start(self) -> bool:
        """Start the ONVIF proxy server"""
        try:
            ip = self.camera_config.get('onvif_ip') or '127.0.0.1'
            port = self.camera_config.get('onvif_port', 80)
            
            # Create handler with camera config
            def handler(*args, **kwargs):
                return ONVIFHandler(*args, camera_config=self.camera_config, **kwargs)
            
            self.server = HTTPServer((ip, port), handler)
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.running = True
            self.logger.info(f"ONVIF proxy started for camera {self.camera_config.get('name')} on {ip}:{port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start ONVIF proxy: {e}")
            return False
    
    def stop(self):
        """Stop the ONVIF proxy server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            self.logger.info(f"ONVIF proxy stopped for camera {self.camera_config.get('name')}")
    
    def is_running(self) -> bool:
        """Check if server is running"""
        return self.running and self.server_thread and self.server_thread.is_alive()


class StreamMonitor:
    """Monitor RTSP streams for availability"""
    
    def __init__(self, camera_config: Dict, callback=None):
        self.camera_config = camera_config
        self.callback = callback
        self.monitoring = False
        self.monitor_thread = None
        self.logger = logging.getLogger(__name__)
        self.last_status = None
    
    def start_monitoring(self):
        """Start monitoring the RTSP stream"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.logger.info(f"Started monitoring camera {self.camera_config.get('name')}")
    
    def stop_monitoring(self):
        """Stop monitoring the RTSP stream"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info(f"Stopped monitoring camera {self.camera_config.get('name')}")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                is_available = self._check_stream_availability()
                
                # Check for status change
                if self.last_status is not None and self.last_status != is_available:
                    if self.callback:
                        self.callback(self.camera_config, is_available)
                
                self.last_status = is_available
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _check_stream_availability(self) -> bool:
        """Check if RTSP stream is available"""
        rtsp_url = self.camera_config.get('rtsp_url', '')
        if not rtsp_url:
            return False
        
        try:
            # Try to open the stream with OpenCV
            cap = cv2.VideoCapture(rtsp_url)
            if cap.isOpened():
                ret, frame = cap.read()
                cap.release()
                return ret and frame is not None
            else:
                cap.release()
                return False
                
        except Exception as e:
            self.logger.debug(f"Stream check failed for {rtsp_url}: {e}")
            return False
