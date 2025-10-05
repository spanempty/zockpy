# sigma_engine.py
import yaml
import os
from threading import Lock

class SigmaRuleEngine:
    def __init__(self, rule_dir="rules/sigma"):
        self.sigma_rules = self.load_sigma_rules(rule_dir)
        self.detection_log = []
        self.lock = Lock()

    def load_sigma_rules(self, rule_dir):
        rules = {}
        for filename in os.listdir(rule_dir):
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                filepath = os.path.join(rule_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        rule = yaml.safe_load(f)
                        rule_id = filename.split('.')[0]
                        rules[rule_id] = rule
                except Exception as e:
                    print(f"Error loading rule {filename}: {e}")
        return rules

    def analyze_http_requests(self, request_data):
        alerts = []
        payload = ''
        if isinstance(request_data, dict):
            payload = request_data.get('payload', '')
        else:
            payload = str(request_data)
        payload_lower = payload.lower()
        for rule_id, rule in self.sigma_rules.items():
            detection = rule.get('detection', {})
            keywords = detection.get('keywords', [])
            for keyword in keywords:
                if keyword.lower() in payload_lower:
                    alerts.append({
                        'rule': rule_id,
                        'title': rule.get('title', 'Unknown'),
                        'matched_keyword': keyword,
                        'severity': detection.get('severity', 'info'),
                        'message': f"Matched Sigma rule '{rule.get('title', rule_id)}' with keyword '{keyword}'"
                    })
        return alerts
