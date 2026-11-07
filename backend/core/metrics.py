"""
Prometheus metrics. Exposed at /metrics — the reverse proxy blocks this path
from the internet; scrape it from the internal Docker network.

With multiple gunicorn workers, set PROMETHEUS_MULTIPROC_DIR (the Dockerfile does)
so all workers' metrics are aggregated.
"""
from fastapi import FastAPI
from prometheus_client import Counter, Histogram
from prometheus_fastapi_instrumentator import Instrumentator

REQUESTS_ANALYZED = Counter(
    "aiwaf_requests_analyzed_total",
    "HTTP requests analyzed by the detection pipeline",
    ["threat_level"],
)
DETECTION_LATENCY = Histogram(
    "aiwaf_detection_seconds",
    "Time spent in the detection pipeline (features + rules + ML)",
    buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)


def setup_metrics(app: FastAPI):
    Instrumentator(
        excluded_handlers=["/health", "/ready", "/metrics"],
    ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
