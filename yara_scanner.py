# yara_scanner.py
import os

class YARALikeScanner:
    def __init__(self, rule_dir="rules/yara"):
        self.malware_patterns = self.load_yara_patterns(rule_dir)

    def load_yara_patterns(self, rule_dir):
        patterns = {}
        for filename in os.listdir(rule_dir):
            if filename.endswith(".yar"):
                filepath = os.path.join(rule_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        patterns[filename] = f.read()
                except Exception as e:
                    print(f"Error loading YARA rule {filename}: {e}")
        return patterns

    def scan_processes(self, processes):
        alerts = []
        # Simple YARA-like scan: look for rule keywords in process name/cmdline
        for proc in processes:
            name = (proc.get('name') or '').lower()
            cmdline = ' '.join(proc.get('cmdline') or []).lower()
            for rule_name, rule_text in self.malware_patterns.items():
                for line in rule_text.splitlines():
                    if line.strip().startswith('$'):
                        # Extract keyword from rule
                        parts = line.split('=', 1)
                        if len(parts) == 2:
                            keyword = parts[1].strip().strip('"')
                            if keyword and (keyword in name or keyword in cmdline):
                                alerts.append({
                                    "type": "YARA",
                                    "rule": rule_name,
                                    "message": f"Matched keyword '{keyword}' in process: {name}",
                                    "severity": "critical"
                                })
        return alerts
