
# ZOCK ADVANCED SECURITY MONITOR

ZOCK is a Flask-based security monitoring tool featuring Sigma rule detection, YARA-like malware scanning, real-time system monitoring, and attack simulation.

## Features
- Sigma Rules for attack detection
- YARA-like malware scanning
- Real system monitoring (CPU, memory, disk, processes)
- Network traffic analysis
- Web attack testing
- Real-time dashboard and static dashboard

## Installation & Usage

### 1. Clone the repository
```
git clone <your-repo-url>
cd zockpy
```

### 2. Create a virtual environment (recommended)
```
python -m venv venv
```

### 3. Activate the virtual environment
On Windows:
```
.\venv\Scripts\activate
```
On Linux/macOS:
```
source venv/bin/activate
```

### 4. Install dependencies
```
pip install -r requirements.txt
```

### 5. Run the application
```
python routes.py
```

### 6. Open the dashboard in your browser
- Static dashboard: [http://localhost:5000/](http://localhost:5000/)
- Real-time dashboard: [http://localhost:5000/real-time](http://localhost:5000/real-time)

## Folder Structure
- `routes.py` - Main Flask application (entry point)
- `core.py` - System info and metrics
- `sigma_engine.py` - Sigma rule engine
- `yara_scanner.py` - YARA-like scanner
- `security_monitor.py` - Security monitor orchestration
- `rules/sigma/` - Sigma rules (YAML)
- `rules/yara/` - YARA rules
- `templates/` - HTML templates (`dashboard.html`, `real_time.html`)
- `static/` - CSS, JS, images (`style.css`, `script.js`, `real_time.js`)

## Notes
- You can switch between the static and real-time dashboards using the navigation links at the top of each page.
- The real-time dashboard updates all data every 2 seconds.
- Test attack feature allows you to simulate web attacks and see detection results.
