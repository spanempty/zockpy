import psutil
# routes.py
from flask import Flask, render_template, request, jsonify
from security_monitor import RealSecurityMonitor

app = Flask(__name__)
monitor = RealSecurityMonitor()

# Show top processes by CPU and memory usage
@app.route('/api/top-processes')
def top_processes():
    import time
    # First call to cpu_percent initializes the measurement
    procs_list = list(psutil.process_iter())
    for proc in procs_list:
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    time.sleep(1)  # Wait longer for accurate measurement
    procs = []
    for proc in procs_list:
        try:
            info = proc.as_dict(attrs=['pid', 'name', 'memory_percent'])
            cpu = proc.cpu_percent(interval=None)
            procs.append({
                'pid': info['pid'],
                'name': info['name'],
                'cpu_percent': cpu,
                'memory_percent': info['memory_percent']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Sort by CPU and memory usage
    top_cpu = sorted(procs, key=lambda x: x['cpu_percent'], reverse=True)[:10]
    top_mem = sorted(procs, key=lambda x: x['memory_percent'], reverse=True)[:10]
    return jsonify({'top_cpu': top_cpu, 'top_mem': top_mem})


@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/real-time')
def real_time():
    return render_template('real_time.html')

@app.route('/api/system-info')
def system_info():
    return jsonify(monitor.get_system_info())

@app.route('/api/metrics')
def metrics():
    return jsonify(monitor.get_system_metrics())

@app.route('/api/security-scan')
def security_scan():
    return jsonify(monitor.run_security_scan())


@app.route('/api/test-attack', methods=['POST'])
def test_attack():
    data = request.json
    url = data.get('url')
    payload = data.get('payload')


    # ...existing code...
    # ...existing code...
    if not url or not payload:
        return jsonify({'error': 'Missing url or payload'}), 400
    
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
