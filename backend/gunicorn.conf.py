"""Gunicorn config for the API (production)."""
import multiprocessing
import os
import shutil

bind = "0.0.0.0:8000"
worker_class = "uvicorn.workers.UvicornWorker"
workers = int(os.getenv("WEB_CONCURRENCY", min(multiprocessing.cpu_count() * 2, 4)))
timeout = 60
graceful_timeout = 30
keepalive = 5
max_requests = 5000          # recycle workers to bound memory growth
max_requests_jitter = 500
accesslog = "-"
errorlog = "-"

# Trust X-Forwarded-For from the reverse proxy. The API is only reachable on the
# internal Docker network, so the only client that can set it is the proxy.
forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "*")

# Prometheus multi-process mode: aggregate metrics across workers
PROM_DIR = os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", "/tmp/prometheus")


def on_starting(server):
    shutil.rmtree(PROM_DIR, ignore_errors=True)
    os.makedirs(PROM_DIR, exist_ok=True)


def child_exit(server, worker):
    from prometheus_client import multiprocess

    multiprocess.mark_process_dead(worker.pid)
