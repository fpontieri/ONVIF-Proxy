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
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional
import xml.etree.ElementTree as ET

class ONVIFHandler(BaseHTTPRequestHandler):
    """HTTP handler for ONVIF requests"""
    
    def __init__(self, *args, camera_config=None, **kwargs):
        self.camera_config = camera_config or {}
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/onvif/device_service":
            self.handle_device_service()
        elif parsed_path.path == "/onvif/media_service":
            self.handle_media_service()
        elif parsed_path.path.startswith("/stream"):
            self.handle_stream_request()
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        """Handle POST requests (SOAP)"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        if "GetDeviceInformation" in post_data:
            self.handle_get_device_information()
        elif "GetCapabilities" in post_data:
            self.handle_get_capabilities()
        elif "GetProfiles" in post_data:
            self.handle_get_profiles()
        elif "GetStreamUri" in post_data:
            self.handle_get_stream_uri()
        else:
            self.send_soap_fault("Action not supported")
    
    def handle_device_service(self):
        """Handle device service requests"""
        wsdl_content = """<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             targetNamespace="http://www.onvif.org/ver10/device/wsdl">
    <service name="DeviceService">
        <port name="DevicePort" binding="tns:DeviceBinding">
            <soap:address location="http://{}:{}/onvif/device_service"/>
        </port>
    </service>
</definitions>""".format(self.camera_config.get('onvif_ip', '127.0.0.1'), 
                         self.camera_config.get('onvif_port', 80))
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/xml')
        self.end_headers()
        self.wfile.write(wsdl_content.encode())
    
    def handle_media_service(self):
        """Handle media service requests"""
        wsdl_content = """<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             targetNamespace="http://www.onvif.org/ver10/media/wsdl">
    <service name="MediaService">
        <port name="MediaPort" binding="tns:MediaBinding">
            <soap:address location="http://{}:{}/onvif/media_service"/>
        </port>
    </service>
</definitions>""".format(self.camera_config.get('onvif_ip', '127.0.0.1'), 
                         self.camera_config.get('onvif_port', 80))
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/xml')
        self.end_headers()
        self.wfile.write(wsdl_content.encode())
    
    def handle_get_device_information(self):
        """Handle GetDeviceInformation SOAP request"""
        response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
            <tds:Manufacturer>ONVIF-Proxy</tds:Manufacturer>
            <tds:Model>{}</tds:Model>
            <tds:FirmwareVersion>1.0.0</tds:FirmwareVersion>
            <tds:SerialNumber>{}</tds:SerialNumber>
            <tds:HardwareId>ONVIF-Proxy-{}</tds:HardwareId>
        </tds:GetDeviceInformationResponse>
    </soap:Body>
</soap:Envelope>""".format(
            self.camera_config.get('name', 'Unknown Camera'),
            self.camera_config.get('id', '000000'),
            self.camera_config.get('id', '000000')
        )
        
        self.send_soap_response(response)
    
    def handle_get_capabilities(self):
        """Handle GetCapabilities SOAP request"""
        base_url = f"http://{self.camera_config.get('onvif_ip', '127.0.0.1')}:{self.camera_config.get('onvif_port', 80)}"
        
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
        
        self.send_soap_response(response)
    
    def handle_get_profiles(self):
        """Handle GetProfiles SOAP request"""
        response = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
            <trt:Profiles token="MainProfile">
                <tt:Name xmlns:tt="http://www.onvif.org/ver10/schema">Main Profile</tt:Name>
                <tt:VideoSourceConfiguration xmlns:tt="http://www.onvif.org/ver10/schema" token="VideoSource">
                    <tt:Name>Video Source</tt:Name>
                    <tt:UseCount>1</tt:UseCount>
                    <tt:SourceToken>VideoSourceToken</tt:SourceToken>
                    <tt:Bounds x="0" y="0" width="1920" height="1080"/>
                </tt:VideoSourceConfiguration>
                <tt:VideoEncoderConfiguration xmlns:tt="http://www.onvif.org/ver10/schema" token="VideoEncoder">
                    <tt:Name>Video Encoder</tt:Name>
                    <tt:UseCount>1</tt:UseCount>
                    <tt:Encoding>H264</tt:Encoding>
                    <tt:Resolution>
                        <tt:Width>1920</tt:Width>
                        <tt:Height>1080</tt:Height>
                    </tt:Resolution>
                    <tt:Quality>5</tt:Quality>
                    <tt:RateControl>
                        <tt:FrameRateLimit>30</tt:FrameRateLimit>
                        <tt:EncodingInterval>1</tt:EncodingInterval>
                        <tt:BitrateLimit>8000</tt:BitrateLimit>
                    </tt:RateControl>
                </tt:VideoEncoderConfiguration>
            </trt:Profiles>
        </trt:GetProfilesResponse>
    </soap:Body>
</soap:Envelope>"""
        
        self.send_soap_response(response)
    
    def handle_get_stream_uri(self):
        """Handle GetStreamUri SOAP request"""
        stream_uri = f"rtsp://{self.camera_config.get('onvif_ip', '127.0.0.1')}:{self.camera_config.get('onvif_port', 554)}/stream"
        
        response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
            <trt:MediaUri>
                <tt:Uri xmlns:tt="http://www.onvif.org/ver10/schema">{stream_uri}</tt:Uri>
                <tt:InvalidAfterConnect xmlns:tt="http://www.onvif.org/ver10/schema">false</tt:InvalidAfterConnect>
                <tt:InvalidAfterReboot xmlns:tt="http://www.onvif.org/ver10/schema">false</tt:InvalidAfterReboot>
                <tt:Timeout xmlns:tt="http://www.onvif.org/ver10/schema">PT60S</tt:Timeout>
            </trt:MediaUri>
        </trt:GetStreamUriResponse>
    </soap:Body>
</soap:Envelope>"""
        
        self.send_soap_response(response)
    
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
    
    def send_soap_response(self, response_xml: str):
        """Send SOAP response"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/soap+xml; charset=utf-8')
        self.send_header('Content-Length', str(len(response_xml)))
        self.end_headers()
        self.wfile.write(response_xml.encode())
    
    def send_soap_fault(self, fault_string: str):
        """Send SOAP fault response"""
        fault_response = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <soap:Fault>
            <soap:Code>
                <soap:Value>soap:Receiver</soap:Value>
            </soap:Code>
            <soap:Reason>
                <soap:Text>{fault_string}</soap:Text>
            </soap:Reason>
        </soap:Fault>
    </soap:Body>
</soap:Envelope>"""
        
        self.send_response(500)
        self.send_header('Content-Type', 'application/soap+xml; charset=utf-8')
        self.send_header('Content-Length', str(len(fault_response)))
        self.end_headers()
        self.wfile.write(fault_response.encode())


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
            ip = self.camera_config.get('onvif_ip', '127.0.0.1')
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
