# core.py
# System information and metrics gathering functions for ZOCK

import psutil
import platform

def get_system_info():
    return {
        'platform': platform.system(),
        'platform-release': platform.release(),
        'platform-version': platform.version(),
        'architecture': platform.machine(),
        'cpu': psutil.cpu_percent(interval=1),
        'memory': psutil.virtual_memory().percent,
        'disk': psutil.disk_usage('/').percent,
    }

def get_system_metrics():
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent,
    }
