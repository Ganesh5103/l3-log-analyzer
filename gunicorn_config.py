# ====================================================================
# GUNICORN CONFIGURATION FOR PRODUCTION
# ====================================================================
# Usage: gunicorn app_optimized:app -c gunicorn_config.py

import multiprocessing
import os

# ====================================================================
# WORKER CONFIGURATION
# ====================================================================

# Number of worker processes
# Formula: (2 * CPU_COUNT) + 1
# For 8-core CPU: (2 * 8) + 1 = 17 workers
workers = int(os.getenv('WORKERS', multiprocessing.cpu_count() * 2 + 1))

# Worker class - use Uvicorn for async support
worker_class = "uvicorn.workers.UvicornWorker"

# Max simultaneous connections per worker
worker_connections = 1000

# Restart workers after handling this many requests (prevents memory leaks)
max_requests = 10000
max_requests_jitter = 1000  # Randomize restarts

# Workers silent for more than this many seconds are killed and restarted
timeout = 120  # 2 minutes for long-running requests

# Graceful shutdown timeout
graceful_timeout = 30

# ====================================================================
# SERVER BINDING
# ====================================================================

# Bind to all interfaces on port 8000
bind = "0.0.0.0:8000"

# Backlog queue size
backlog = 2048

# ====================================================================
# LOGGING
# ====================================================================

# Access log file
accesslog = "/var/log/log-analyzer/access.log"

# Error log file
errorlog = "/var/log/log-analyzer/error.log"

# Log level
loglevel = "info"

# Access log format
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# ====================================================================
# PROCESS NAMING
# ====================================================================

proc_name = "log_analyzer"

# ====================================================================
# SERVER MECHANICS
# ====================================================================

# Daemonize the process (run in background)
daemon = False  # Set to True for production daemon mode

# PID file location
pidfile = "/var/run/log_analyzer.pid"

# User to run workers as (after binding to port)
# user = "www-data"
# group = "www-data"

# Directory to use for temporary files
tmp_upload_dir = "/tmp"

# ====================================================================
# PERFORMANCE TUNING
# ====================================================================

# Keep-alive timeout
keepalive = 5

# Pre-load application code before forking workers
# Saves memory but can cause issues with some code
preload_app = False  # Set to True if no shared state issues

# ====================================================================
# WORKER LIFECYCLE HOOKS
# ====================================================================

def on_starting(server):
    """Called just before the master process is initialized"""
    print("=" * 60)
    print("🚀 Starting Log Analyzer Server")
    print("=" * 60)
    print(f"   Workers: {workers}")
    print(f"   Worker Class: {worker_class}")
    print(f"   Bind: {bind}")
    print(f"   Timeout: {timeout}s")
    print("=" * 60)


def on_reload(server):
    """Called on config reload"""
    print("🔄 Configuration reloaded")


def when_ready(server):
    """Called just after the server is started"""
    print("✅ Server ready to accept connections")


def worker_int(worker):
    """Called when worker receives INT or QUIT signal"""
    print(f"⚠️  Worker {worker.pid} interrupted")


def pre_fork(server, worker):
    """Called before forking a worker"""
    pass


def post_fork(server, worker):
    """Called after forking a worker"""
    print(f"👷 Worker {worker.pid} spawned")


def post_worker_init(worker):
    """Called after worker initialized"""
    pass


def worker_exit(server, worker):
    """Called when worker exits"""
    print(f"👋 Worker {worker.pid} exited")


def on_exit(server):
    """Called just before shutting down"""
    print("=" * 60)
    print("👋 Shutting down Log Analyzer Server")
    print("=" * 60)

# ====================================================================
# DEVELOPMENT MODE
# ====================================================================

# For development, override with fewer workers
if os.getenv('ENV') == 'development':
    workers = 1
    reload = True
    loglevel = 'debug'
    accesslog = '-'  # stdout
    errorlog = '-'   # stderr
