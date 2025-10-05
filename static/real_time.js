// real_time.js
// Same as script.js but updates data every 2 seconds
function renderSystemInfo(data) {
    const ul = document.getElementById('systemInfoList');
    ul.innerHTML = '';
    Object.entries(data).forEach(([key, value]) => {
        const li = document.createElement('li');
        li.textContent = `${key.replace(/_/g, ' ')}: ${value}`;
        ul.appendChild(li);
    });
}
function renderMetrics(data) {
    function setBar(barId, percentId, value) {
        const bar = document.getElementById(barId);
        bar.style.width = value + '%';
        bar.style.background = value > 80 ? '#e74c3c' : value > 60 ? '#f1c40f' : '#2ecc71';
        document.getElementById(percentId).textContent = value + '%';
    }
    setBar('cpuBar', 'cpuPercent', data.cpu_percent);
    setBar('memBar', 'memPercent', data.memory_percent);
    setBar('diskBar', 'diskPercent', data.disk_percent);
}
function renderSecurityScan(data) {
    const ul = document.getElementById('securityScanList');
    ul.innerHTML = '';
    if (data.alerts && data.alerts.length) {
        data.alerts.forEach(alert => {
            const li = document.createElement('li');
            li.className = 'alert-' + (alert.severity || 'info');
            li.innerHTML = `<strong>${alert.type || alert.rule || 'Alert'}:</strong> ${alert.message || alert.title || ''}`;
            ul.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = 'No alerts detected.';
        ul.appendChild(li);
    }
    document.getElementById('processCount').textContent = `Processes scanned: ${data.process_count || 0}`;
}
function renderProcTable(tableId, data, valueKey) {
    const tbody = document.getElementById(tableId).querySelector('tbody');
    tbody.innerHTML = '';
    data.forEach(proc => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${proc.pid}</td><td>${proc.name}</td><td>${proc[valueKey].toFixed(1)}%</td>`;
        tbody.appendChild(tr);
    });
}
function updateAll() {
    fetch('/api/system-info').then(r => r.json()).then(renderSystemInfo);
    fetch('/api/metrics').then(r => r.json()).then(renderMetrics);
    fetch('/api/security-scan').then(r => r.json()).then(renderSecurityScan);
    fetch('/api/top-processes').then(r => r.json()).then(data => {
        renderProcTable('cpuProcTable', data.top_cpu, 'cpu_percent');
        renderProcTable('memProcTable', data.top_mem, 'memory_percent');
    });
}
setInterval(updateAll, 2000);
updateAll();
// Test Attack form (same as script.js)
document.getElementById('attackForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const url = document.getElementById('attackUrl').value;
    const payload = document.getElementById('attackPayload').value;
    fetch('/api/test-attack', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({url: url, payload: payload})
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('attackResult').innerText = JSON.stringify(data, null, 2);
    })
    .catch(() => {
        document.getElementById('attackResult').innerText = 'Error testing attack.';
    });
});
