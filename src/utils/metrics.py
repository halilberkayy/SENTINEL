"""
Prometheus metrics for monitoring scanner performance.
"""

import time
from collections.abc import Callable
from functools import wraps

from prometheus_client import Counter, Gauge, Histogram, Info

# Scan metrics
scan_requests_total = Counter("scanner_requests_total", "Total number of scan requests", ["module", "status"])

scan_duration_seconds = Histogram(
    "scanner_duration_seconds", "Scan duration in seconds", ["module"], buckets=[1, 5, 10, 30, 60, 120, 300, 600, 1800]
)

active_scans = Gauge("scanner_active_scans", "Number of currently active scans")

vulnerabilities_found = Counter("scanner_vulnerabilities_found", "Total vulnerabilities found", ["severity", "type"])

# HTTP metrics
http_requests_total = Counter("scanner_http_requests_total", "Total HTTP requests made", ["method", "status_code"])

http_request_duration_seconds = Histogram(
    "scanner_http_request_duration_seconds", "HTTP request duration", buckets=[0.1, 0.5, 1, 2, 5, 10]
)

# System metrics
scanner_info = Info("scanner", "Scanner version and metadata")
database_connections = Gauge("scanner_database_connections", "Active database connections")
cache_hit_rate = Gauge("scanner_cache_hit_rate", "Cache hit rate percentage")

# Plugin metrics
plugins_loaded = Gauge("scanner_plugins_loaded", "Number of loaded plugins")
plugin_execution_duration = Histogram("scanner_plugin_execution_seconds", "Plugin execution duration", ["plugin_name"])


def track_scan_duration(module_name: str):
    """Decorator to track scan duration."""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            active_scans.inc()

            try:
                result = await func(*args, **kwargs)
                scan_requests_total.labels(module=module_name, status="success").inc()
                return result
            except Exception:
                scan_requests_total.labels(module=module_name, status="error").inc()
                raise
            finally:
                duration = time.time() - start_time
                scan_duration_seconds.labels(module=module_name).observe(duration)
                active_scans.dec()

        return wrapper

    return decorator


def track_http_request(method: str):
    """Decorator to track HTTP requests."""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                response = await func(*args, **kwargs)
                status_code = response.status if hasattr(response, "status") else 200
                http_requests_total.labels(method=method, status_code=status_code).inc()
                return response
            except Exception:
                http_requests_total.labels(method=method, status_code=0).inc()
                raise
            finally:
                duration = time.time() - start_time
                http_request_duration_seconds.observe(duration)

        return wrapper

    return decorator
