#!/usr/bin/env python3
"""
Gunicorn configuration for ONVIF Proxy Web Interface
Production WSGI server configuration
"""

import os
import sys
import multiprocessing

# Add the application directory to Python path
sys.path.insert(0, '/opt/onvif-proxy')

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests, to prevent memory leaks
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "/var/log/onvif-proxy/gunicorn-access.log"
errorlog = "/var/log/onvif-proxy/gunicorn-error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "onvif-proxy-web"

# Server mechanics
daemon = False
pidfile = "/run/onvif-proxy/gunicorn.pid"
user = "onvif-proxy"
group = "onvif-proxy"
tmp_upload_dir = None

# SSL (if needed in future)
# keyfile = None
# certfile = None

# Worker tmp directory
worker_tmp_dir = "/dev/shm"

# Preload application for better performance
preload_app = True

# Application callable
# This should match the Flask app instance in web_interface.py
wsgi_module = "src.web_interface:app"

# Environment variables
raw_env = [
    "FLASK_ENV=production",
    "PYTHONPATH=/opt/onvif-proxy"
]

# Hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting ONVIF Proxy Web Interface")

def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP."""
    server.log.info("Reloading ONVIF Proxy Web Interface")

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info("Worker received INT or QUIT signal")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def worker_abort(worker):
    """Called when a worker received the SIGABRT signal."""
    worker.log.info("Worker received SIGABRT signal")
