# security_monitor.py
from sigma_engine import SigmaRuleEngine
from yara_scanner import YARALikeScanner
from core import get_system_info, get_system_metrics

class RealSecurityMonitor:
    def __init__(self):
        self.sigma_engine = SigmaRuleEngine()
        self.yara_scanner = YARALikeScanner()
        self.attack_log = []

    def get_system_info(self):
        return get_system_info()

    def get_system_metrics(self):
        return get_system_metrics()

    def run_security_scan(self):
        import psutil
        alerts = []
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                info = proc.info
                processes.append(info)
                # Basic suspicious process detection
                suspicious_names = ['xmrig', 'minerd', 'cpuminer', 'powershell', 'cmd', 'nc', 'ncat', 'netcat']
                if any(name in (info.get('name') or '').lower() for name in suspicious_names):
                    alerts.append({
                        "type": "Process",
                        "message": f"Suspicious process detected: {info.get('name')} (PID {info.get('pid')})",
                        "severity": "warning"
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # YARA-like scan (simple string match in process names and command lines)
        yara_alerts = self.yara_scanner.scan_processes(processes)
        alerts.extend(yara_alerts)

        return {
            "alerts": alerts,
            "process_count": len(processes)
        }

    def detect_system_anomalies(self):
        alerts = []
        # ...implementation...
        return alerts

    def test_web_attack(self, attack_data):
        # attack_data: {'payload': ..., 'url': ...}
        payload = attack_data.get('payload', '') if isinstance(attack_data, dict) else str(attack_data)
        # Analyze payload for attack patterns
        return self.sigma_engine.analyze_http_requests({'payload': payload})
