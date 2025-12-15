import multiprocessing
import os

# Explicitly low concurrency - override with WEB_CONCURRENCY env var when scaling up
# Default to 1 worker for minimal memory usage (perfect when no users)
workers = int(os.getenv("WEB_CONCURRENCY", "1"))

# If someone accidentally sets 0 or negative, force to 1
if workers < 1:
    workers = 1

worker_class = "uvicorn.workers.UvicornWorker"

# 1 thread is enough for async FastAPI apps
threads = 1

# No automatic worker restarting → prevents memory fragmentation from frequent restarts
max_requests = 0
max_requests_jitter = 0

# Basic connection settings
worker_connections = 1000
keepalive = 5

# Timeouts
timeout = 60
graceful_timeout = 30

# Binding
bind = "0.0.0.0:8000"

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()

# Performance & safety
preload_app = False        # Critical: prevents DB pool leaks
reuse_port = True

# Use /dev/shm for temp files if available (faster, less disk I/O)
worker_tmp_dir = "/dev/shm" if os.path.exists("/dev/shm") else None

# Helpful startup log
def on_starting(server):
    server.log.info(
        f"Starting Gunicorn with {workers} worker(s) "
        f"({multiprocessing.cpu_count()} CPU cores detected) - "
        f"WEB_CONCURRENCY={os.getenv('WEB_CONCURRENCY', '1')}"
    )
