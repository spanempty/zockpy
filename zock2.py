# app.py - ZOCK ADVANCED SECURITY MONITOR
from flask import Flask, render_template, request, jsonify
import socket
import platform
import os
import psutil
import datetime
import re
import time
import json
from threading import Thread, Lock
import subprocess
import requests

app = Flask(__name__)

class SigmaRuleEngine:
    """Sigma rule implementation for real attack detection"""
    
    def __init__(self):
        self.sigma_rules = self.load_sigma_rules()
        self.detection_log = []
        self.lock = Lock()
    
    def load_sigma_rules(self):
        """Load Sigma-style detection rules"""
        return {
            'sql_injection': {
                'title': 'SQL Injection Attack',
                'logsource': {'category': 'web', 'product': 'web_server'},
                'detection': {
                    'keywords': ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "1=1--", "xp_cmdshell"],
                    'severity': 'high',
                    'owasp': 'A03'
                }
            },
            'xss_attack': {
                'title': 'Cross-Site Scripting Attack', 
                'logsource': {'category': 'web', 'product': 'web_server'},
                'detection': {
                    'keywords': ["<script>", "javascript:", "onload=", "alert("],
                    'severity': 'medium',
                    'owasp': 'A03'
                }
            },
            'brute_force': {
                'title': 'Brute Force Attack',
                'logsource': {'category': 'auth', 'product': 'web_server'},
                'detection': {
                    'threshold': 10,  # Failed attempts per minute
                    'keywords': ["failed login", "authentication failure"],
                    'severity': 'high', 
                    'owasp': 'A07'
                }
            },
            'command_injection': {
                'title': 'Command Injection Attack',
                'logsource': {'category': 'web', 'product': 'web_server'},
                'detection': {
                    'keywords': ["; rm -rf", "| sh", "& cat", "`", "$("],
                    'severity': 'critical',
                    'owasp': 'A03'
                }
            },
            'path_traversal': {
                'title': 'Path Traversal Attack',
                'logsource': {'category': 'web', 'product': 'web_server'},
                'detection': {
                    'keywords': ["../", "..\\", "/etc/passwd", "c:\\windows"],
                    'severity': 'high',
                    'owasp': 'A01'
                }
            }
        }
    
    def analyze_network_traffic(self, connections):
        """Analyze network traffic for attacks"""
        alerts = []
        
        for conn in connections:
            # Check for connections to suspicious ports
            if conn.get('remote_port') in [4444, 1337, 31337, 9999]:
                alerts.append({
                    'rule': 'suspicious_port_connection',
                    'title': 'Connection to Suspicious Port',
                    'severity': 'high',
                    'message': f"Connection to suspicious port {conn['remote_port']} from {conn['remote_ip']}",
                    'sigma_rule': 'custom.suspicious_ports',
                    'timestamp': datetime.datetime.now().isoformat()
                })
            
            # Check for multiple connections from same IP (DDoS pattern)
            if self.count_connections_from_ip(conn['remote_ip']) > 50:
                alerts.append({
                    'rule': 'potential_ddos',
                    'title': 'Potential DDoS Attack',
                    'severity': 'critical', 
                    'message': f"Multiple connections from {conn['remote_ip']} (possible DDoS)",
                    'sigma_rule': 'custom.ddos_detection',
                    'timestamp': datetime.datetime.now().isoformat()
                })
        
        return alerts
    
    def count_connections_from_ip(self, ip):
        """Count connections from specific IP"""
        count = 0
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.raddr.ip == ip:
                    count += 1
        except:
            pass
        return count
    
    def analyze_http_requests(self, request_data):
        """Analyze HTTP requests for web attacks"""
        alerts = []
        
        if not request_data:
            return alerts
        
        # Check for SQL Injection patterns
        for rule_name, rule in self.sigma_rules.items():
            if 'keywords' in rule['detection']:
                for keyword in rule['detection']['keywords']:
                    if keyword.lower() in request_data.lower():
                        alerts.append({
                            'rule': rule_name,
                            'title': rule['title'],
                            'severity': rule['detection']['severity'],
                            'message': f"Detected {rule_name} pattern: {keyword}",
                            'sigma_rule': f"sigma.{rule_name}",
                            'owasp': rule['detection']['owasp'],
                            'timestamp': datetime.datetime.now().isoformat()
                        })
                        break  # Only alert once per rule
        
        return alerts

class YARALikeScanner:
    """YARA-like pattern matching for malware detection"""
    
    def __init__(self):
        self.malware_patterns = {
            'crypto_miner': {
                'patterns': ['xmrig', 'cryptonight', 'minerd', 'cpuminer'],
                'severity': 'high'
            },
            'ransomware': {
                'patterns': ['encrypt', 'decrypt', 'bitcoin', 'wallet', '.locked', '.encrypted'],
                'severity': 'critical'
            },
            'trojan': {
                'patterns': ['backdoor', 'keylogger', 'rat', 'remote access'],
                'severity': 'high'
            },
            'suspicious_scripts': {
                'patterns': ['powershell -enc', 'base64', 'iex', 'invoke-expression'],
                'severity': 'medium'
            }
        }
    
    def scan_processes(self, processes):
        """Scan running processes for malware patterns"""
        alerts = []
        
        for proc in processes:
            proc_name = proc.get('name', '').lower()
            proc_cmdline = self.get_process_command_line(proc.get('pid'))
            
            for malware_type, patterns in self.malware_patterns.items():
                for pattern in patterns['patterns']:
                    if (pattern in proc_name or 
                        (proc_cmdline and pattern in proc_cmdline.lower())):
                        alerts.append({
                            'type': 'malware_detection',
                            'malware_family': malware_type,
                            'severity': patterns['severity'],
                            'process': proc_name,
                            'pid': proc.get('pid'),
                            'pattern': pattern,
                            'timestamp': datetime.datetime.now().isoformat()
                        })
                        break
        
        return alerts
    
    def get_process_command_line(self, pid):
        """Get command line for process (if accessible)"""
        try:
            if pid:
                process = psutil.Process(pid)
                return ' '.join(process.cmdline())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return None

class RealSecurityMonitor:
    def __init__(self):
        self.sigma_engine = SigmaRuleEngine()
        self.yara_scanner = YARALikeScanner()
        self.attack_log = []
    
    def get_system_info(self):
        """Get REAL system information"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Get external IP
            try:
                external_ip = requests.get('https://api.ipify.org', timeout=2).text
            except:
                external_ip = "Cannot determine"
            
            return {
                'hostname': hostname,
                'local_ip': local_ip,
                'external_ip': external_ip,
                'platform': platform.system(),
                'platform_version': platform.version(),
                'processor': platform.processor() or "Unknown",
                'cpu_cores': psutil.cpu_count(),
                'ram_gb': round(psutil.virtual_memory().total / (1024**3), 1),
                'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            return {'error': f'Cannot access system info: {str(e)}'}
    
    def get_network_connections(self):
        """Get REAL network connections with enhanced info"""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            return connections[:25]
        except Exception as e:
            return [{'error': f'Cannot access network info: {str(e)}'}]
    
    def get_running_processes(self):
        """Get REAL running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu': round(proc.info['cpu_percent'] or 0, 1),
                        'memory': round(proc.info['memory_percent'] or 0, 1)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return sorted(processes, key=lambda x: x['cpu'], reverse=True)[:20]
        except Exception as e:
            return [{'error': f'Cannot access processes: {str(e)}'}]
    
    def get_system_metrics(self):
        """Get REAL system metrics"""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_io': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
                'boot_time_seconds': int(time.time() - psutil.boot_time()),
                'current_time': datetime.datetime.now().strftime("%H:%M:%S")
            }
        except Exception as e:
            return {'error': f'Cannot access metrics: {str(e)}'}
    
    def run_security_scan(self):
        """Run comprehensive security scan"""
        alerts = []
        
        try:
            # Get current system state
            processes = self.get_running_processes()
            network_connections = self.get_network_connections()
            
            # Run Sigma rule analysis on network traffic
            sigma_alerts = self.sigma_engine.analyze_network_traffic(network_connections)
            alerts.extend(sigma_alerts)
            
            # Run YARA-like malware scanning
            malware_alerts = self.yara_scanner.scan_processes(processes)
            alerts.extend(malware_alerts)
            
            # System-based anomaly detection
            system_alerts = self.detect_system_anomalies()
            alerts.extend(system_alerts)
            
            # Log the attacks
            for alert in alerts:
                self.attack_log.append(alert)
            
            # Keep only last 100 alerts
            self.attack_log = self.attack_log[-100:]
            
        except Exception as e:
            alerts.append({
                'type': 'scan_error',
                'severity': 'low',
                'message': f'Security scan error: {str(e)}',
                'timestamp': datetime.datetime.now().isoformat()
            })
        
        return alerts
    
    def detect_system_anomalies(self):
        """Detect system-level anomalies"""
        alerts = []
        
        try:
            # High CPU usage
            if psutil.cpu_percent() > 90:
                alerts.append({
                    'type': 'system_anomaly',
                    'severity': 'high',
                    'message': 'Critical CPU usage detected (>90%)',
                    'timestamp': datetime.datetime.now().isoformat()
                })
            
            # High memory usage
            if psutil.virtual_memory().percent > 90:
                alerts.append({
                    'type': 'system_anomaly', 
                    'severity': 'high',
                    'message': 'Critical memory usage detected (>90%)',
                    'timestamp': datetime.datetime.now().isoformat()
                })
            
            # Unusual number of network connections
            connections = len(self.get_network_connections())
            if connections > 1000:
                alerts.append({
                    'type': 'network_anomaly',
                    'severity': 'medium',
                    'message': f'Unusually high number of network connections: {connections}',
                    'timestamp': datetime.datetime.now().isoformat()
                })
                
        except Exception as e:
            pass
        
        return alerts
    
    def test_web_attack(self, attack_payload):
        """Test web attack detection with Sigma rules"""
        return self.sigma_engine.analyze_http_requests(attack_payload)

# Initialize the monitor
monitor = RealSecurityMonitor()

@app.route('/')
def dashboard():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZOCK ADVANCED SECURITY MONITOR</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { background: #0a0f1c; color: #e6fbff; font-family: Arial; margin: 0; padding: 20px; }
            .header { background: linear-gradient(135deg, #001f3f, #003366); padding: 25px; border-radius: 12px; margin-bottom: 25px; }
            .panel { background: #0b1220; padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #1e3a5c; }
            .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
            .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; }
            .metric { background: #15202b; padding: 15px; border-radius: 8px; text-align: center; }
            .metric-value { font-size: 24px; color: #00ffea; font-weight: bold; }
            .alert-critical { background: #3a1a1a; border-left: 4px solid #ff4444; padding: 15px; margin: 10px 0; }
            .alert-high { background: #3a2a1a; border-left: 4px solid #ffaa00; padding: 15px; margin: 10px 0; }
            .alert-medium { background: #2a2a2a; border-left: 4px solid #ffcc00; padding: 15px; margin: 10px 0; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #1e3a5c; }
            th { background: #15202b; color: #9ef0ff; }
            .btn { background: #0088cc; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; margin: 5px; }
            .btn-sigma { background: #ff6b6b; }
            .btn-yara { background: #44ff44; color: black; }
            .attack-test { background: #2a2a4a; padding: 15px; border-radius: 8px; margin: 10px 0; }
            .sigma-rule { background: #1a2a2a; padding: 10px; border-radius: 4px; margin: 5px 0; font-family: monospace; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ ZOCK ADVANCED SECURITY MONITOR</h1>
            <p>Sigma Rules + YARA Scanning + Real Attack Detection</p>
            <button class="btn" onclick="location.reload()">🔄 Refresh</button>
            <button class="btn btn-sigma" onclick="runSecurityScan()">🚨 Run Security Scan</button>
        </div>

        <div class="grid-2">
            <div class="panel">
                <h3>🖥️ SYSTEM INFORMATION</h3>
                <div id="systemInfo">Loading...</div>
            </div>
            
            <div class="panel">
                <h3>📊 LIVE METRICS</h3>
                <div id="systemMetrics">Loading...</div>
            </div>
        </div>

        <div class="grid-2">
            <div class="panel">
                <h3>🌐 NETWORK CONNECTIONS</h3>
                <div id="networkInfo">Loading...</div>
            </div>

            <div class="panel">
                <h3>⚡ RUNNING PROCESSES</h3>
                <div id="processInfo">Loading...</div>
            </div>
        </div>

        <div class="panel">
            <h3>🎯 ATTACK DETECTION TEST</h3>
            <div class="attack-test">
                <input type="text" id="attackInput" style="width: 70%; padding: 10px; background: #15202b; border: 1px solid #1e3a5c; color: white; border-radius: 4px;" 
                       value="admin&#39; OR &#39;1&#39;=&#39;1&#39;--">
                <button class="btn btn-sigma" onclick="testAttack()">🔍 Test with Sigma Rules</button>
                <div id="attackResult" style="margin-top: 10px;"></div>
            </div>
            
            <h4>Quick Tests:</h4>
            <button class="btn" onclick="quickTest('sql')">💉 SQL Injection</button>
            <button class="btn" onclick="quickTest('xss')">🕷️ XSS Attack</button>
            <button class="btn" onclick="quickTest('cmd')">⚡ Command Injection</button>
            <button class="btn" onclick="quickTest('path')">📁 Path Traversal</button>
        </div>

        <div class="grid-2">
            <div class="panel">
                <h3>📋 SIGMA RULES LOADED</h3>
                <div id="sigmaRules">
                    <div class="sigma-rule">SQL Injection: OR '1'='1, UNION SELECT, DROP TABLE</div>
                    <div class="sigma-rule">XSS Attack: &lt;script&gt;, javascript:, alert(</div>
                    <div class="sigma-rule">Command Injection: ; rm -rf, | sh, & cat</div>
                    <div class="sigma-rule">Path Traversal: ../, ..\\, /etc/passwd</div>
                    <div class="sigma-rule">Brute Force: failed login, authentication failure</div>
                </div>
            </div>
            
            <div class="panel">
                <h3>🔍 YARA PATTERNS LOADED</h3>
                <div id="yaraPatterns">
                    <div class="sigma-rule">Crypto Miner: xmrig, cryptonight, minerd</div>
                    <div class="sigma-rule">Ransomware: encrypt, decrypt, bitcoin, .locked</div>
                    <div class="sigma-rule">Trojan: backdoor, keylogger, remote access</div>
                    <div class="sigma-rule">Suspicious: powershell -enc, base64, invoke-expression</div>
                </div>
            </div>
        </div>

        <div class="panel">
            <h3>🚨 SECURITY ALERTS</h3>
            <div id="securityAlerts">
                <div style="color: #88ccff; text-align: center; padding: 20px;">Run security scan to detect threats...</div>
            </div>
        </div>

        <script>
        async function loadAllData() {
            await loadSystemInfo();
            await loadMetrics();
            await loadNetworkInfo();
            await loadProcessInfo();
        }

        async function runSecurityScan() {
            const response = await fetch('/api/security-scan');
            const alerts = await response.json();
            displaySecurityAlerts(alerts);
        }

        async function testAttack() {
            const attackInput = document.getElementById('attackInput').value;
            const response = await fetch('/api/test-attack', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({payload: attackInput})
            });
            const result = await response.json();
            
            let html = '<div style="background: #2a2a2a; padding: 15px; border-radius: 6px; margin-top: 10px;">';
            if (result.length > 0) {
                html += '<h4 style="color: #ff4444;">🚨 ATTACK DETECTED!</h4>';
                result.forEach(alert => {
                    html += `<div style="color: #ffaa00; margin: 5px 0;">
                        <strong>${alert.title}</strong> (${alert.severity})<br>
                        <small>Sigma Rule: ${alert.sigma_rule} | OWASP: ${alert.owasp}</small>
                    </div>`;
                });
            } else {
                html += '<div style="color: #44ff44;">✅ No threats detected in input</div>';
            }
            html += '</div>';
            document.getElementById('attackResult').innerHTML = html;
        }

        function quickTest(type) {
            const tests = {
                sql: "admin' OR '1'='1'--",
                xss: "<script>alert('XSS')</script>",
                cmd: "; cat /etc/passwd",
                path: "../../../etc/passwd"
            };
            document.getElementById('attackInput').value = tests[type];
            testAttack();
        }

        function displaySecurityAlerts(alerts) {
            const container = document.getElementById('securityAlerts');
            
            if (alerts.length === 0) {
                container.innerHTML = '<div style="color: #44ff44; text-align: center; padding: 20px;">✅ No security threats detected</div>';
                return;
            }
            
            let html = '';
            alerts.forEach(alert => {
                const alertClass = `alert-${alert.severity || 'medium'}`;
                html += `<div class="${alertClass}">
                    <strong>${alert.title || alert.type || 'Alert'}</strong><br>
                    ${alert.message}<br>
                    <small>Rule: ${alert.sigma_rule || alert.malware_family || 'custom'} | Time: ${new Date().toLocaleTimeString()}</small>
                </div>`;
            });
            container.innerHTML = html;
        }

        // Existing load functions (same as before)
        async function loadSystemInfo() {
            const response = await fetch('/api/system-info');
            const data = await response.json();
            let html = '<div class="grid-3">';
            for (const [key, value] of Object.entries(data)) {
                html += `<div class="metric">
                    <div style="font-size: 12px; color: #88ccff;">${key.replace('_', ' ').toUpperCase()}</div>
                    <div class="metric-value">${value}</div>
                </div>`;
            }
            html += '</div>';
            document.getElementById('systemInfo').innerHTML = html;
        }

        async function loadMetrics() {
            const response = await fetch('/api/metrics');
            const data = await response.json();
            let html = '<div class="grid-3">';
            html += `<div class="metric"><div style="font-size: 12px; color: #88ccff;">CPU USAGE</div><div class="metric-value">${data.cpu_percent}%</div></div>`;
            html += `<div class="metric"><div style="font-size: 12px; color: #88ccff;">MEMORY USAGE</div><div class="metric-value">${data.memory_percent}%</div></div>`;
            html += `<div class="metric"><div style="font-size: 12px; color: #88ccff;">DISK USAGE</div><div class="metric-value">${data.disk_usage}%</div></div>`;
            html += '</div>';
            document.getElementById('systemMetrics').innerHTML = html;
        }

        async function loadNetworkInfo() {
            const response = await fetch('/api/network');
            const connections = await response.json();
            let html = '<table><tr><th>Local Address</th><th>Remote Address</th><th>Status</th><th>PID</th></tr>';
            connections.forEach(conn => {
                html += `<tr><td>${conn.local_address}</td><td>${conn.remote_address}</td><td>${conn.status}</td><td>${conn.pid || 'N/A'}</td></tr>`;
            });
            html += '</table>';
            document.getElementById('networkInfo').innerHTML = html;
        }

        async function loadProcessInfo() {
            const response = await fetch('/api/processes');
            const processes = await response.json();
            let html = '<table><tr><th>PID</th><th>Name</th><th>CPU %</th><th>Memory %</th></tr>';
            processes.forEach(proc => {
                html += `<tr><td>${proc.pid}</td><td>${proc.name}</td><td>${proc.cpu}</td><td>${proc.memory}</td></tr>`;
            });
            html += '</table>';
            document.getElementById('processInfo').innerHTML = html;
        }

        // Initial load
        loadAllData();
        setInterval(loadAllData, 10000);
        </script>
    </body>
    </html>
    '''

@app.route('/api/system-info')
def system_info():
    return jsonify(monitor.get_system_info())

@app.route('/api/metrics')
def metrics():
    return jsonify(monitor.get_system_metrics())

@app.route('/api/network')
def network():
    return jsonify(monitor.get_network_connections())

@app.route('/api/processes')
def processes():
    return jsonify(monitor.get_running_processes())

@app.route('/api/security-scan')
def security_scan():
    alerts = monitor.run_security_scan()
    return jsonify(alerts)

@app.route('/api/test-attack', methods=['POST'])
def test_attack():
    data = request.json
    payload = data.get('payload', '')
    alerts = monitor.test_web_attack(payload)
    return jsonify(alerts)

if __name__ == '__main__':
    print("🛡️ ZOCK ADVANCED SECURITY MONITOR STARTING...")
    print("🔍 Features:")
    print("   • Sigma Rules for attack detection")
    print("   • YARA-like malware scanning") 
    print("   • Real system monitoring")
    print("   • Network traffic analysis")
    print("   • Web attack testing")
    print("🌐 Open: http://localhost:5000")
    
    # Install required package
    try:
        import psutil
        print("✅ psutil: INSTALLED")
    except ImportError:
        print("❌ psutil: NOT INSTALLED - Run: pip install psutil")
    
    app.run(debug=True, host='0.0.0.0', port=5000)