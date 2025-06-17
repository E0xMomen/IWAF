function showMessage(elementId, message, type = 'success') {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show" role="alert">${message}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>`;
        setTimeout(() => element.innerHTML = '', 5000);
    } else {
        console.error(`Element with ID ${elementId} not found`);
    }
}

function fetchStats() {
    fetch('/stats')
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error ${response.status}`);
            return response.json();
        })
        .then(data => {
            const blacklistSize = document.getElementById('blacklist-size');
            const trustedIPsCount = document.getElementById('trusted-ips-count');
            const activeIPs = document.getElementById('active-ips');
            const highRateIPs = document.getElementById('high-rate-ips');
            const slowOffenders = document.getElementById('slow-request-offenders');

            if (blacklistSize) blacklistSize.textContent = data.blacklist_size || 0;
            if (trustedIPsCount) trustedIPsCount.textContent = data.trusted_ips_count || 0;
            if (activeIPs) activeIPs.textContent = data.active_ips || 0;

            if (highRateIPs) {
                highRateIPs.innerHTML = Object.keys(data.high_rate_ips).length === 0
                    ? '<li class="list-group-item">No high rate IPs</li>'
                    : Object.entries(data.high_rate_ips).map(([ip, count]) => `
                        <li class="list-group-item">${ip}: ${count} requests</li>
                    `).join('');
            }

            if (slowOffenders) {
                slowOffenders.innerHTML = Object.keys(data.slow_request_offenders).length === 0
                    ? '<li class="list-group-item">No slow request offenders</li>'
                    : Object.entries(data.slow_request_offenders).map(([ip, count]) => `
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            ${ip}: ${count} slow requests
                            ${currentUserRole === 'admin' ? `<button class="btn btn-sm btn-warning" onclick="resetSlowCounter('${ip}')">Reset</button>` : ''}
                        </li>
                    `).join('');
            }
        })
        .catch(error => {
            console.error('Error fetching stats:', error);
            showMessage('stats', 'Failed to load stats', 'danger');
        });
}

function resetSlowCounter(ip) {
    fetch(`/reset-slow-counter/${ip}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        showMessage('slow-request-offenders', data.message, data.status === 'success' ? 'success' : 'danger');
        if (data.status === 'success') {
            fetchStats();
        }
    })
    .catch(error => {
        console.error('Error resetting slow counter:', error);
        showMessage('slow-request-offenders', 'Failed to reset slow counter', 'danger');
    });
}

function handleCheckIP(event) {
    event.preventDefault();
    const ip = document.getElementById('check-ip').value.trim();
    if (!ip) {
        showMessage('check-ip-result', 'Please enter an IP address', 'danger');
        return;
    }
    fetch(`/check-ip/${ip}`)
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('check-ip-result');
            if (!resultDiv) return;
            let alertType = data.status === 'MALICIOUS' ? 'danger' : data.status === 'SUSPICIOUS' ? 'warning' : data.status === 'ERROR' ? 'danger' : 'success';
            resultDiv.innerHTML = `
                <div class="alert alert-${alertType} alert-dismissible fade show" role="alert">
                    <strong>IP:</strong> ${data.ip}<br>
                    <strong>Status:</strong> ${data.status}<br>
                    <strong>Details:</strong> ${data.details.reason || 'No additional details'}<br>
                    <strong>Malicious Count:</strong> ${data.details.malicious_count || 0}<br>
                    <strong>Suspicious Count:</strong> ${data.details.suspicious_count || 0}<br>
                    <strong>Country:</strong> ${data.details.country || 'Unknown'}
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            `;
        })
        .catch(error => {
            console.error('Error checking IP:', error);
            showMessage('check-ip-result', 'Failed to check IP', 'danger');
        });
}

function handleClearVTCache() {
    fetch('/clear-vt-cache', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        showMessage('check-ip-result', data.message, data.status === 'success' ? 'success' : 'danger');
    })
    .catch(error => {
        console.error('Error clearing VT cache:', error);
        showMessage('check-ip-result', 'Failed to clear VT cache', 'danger');
    });
}

function fetchAttackLog() {
    fetch('/attack-log')
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error ${response.status}`);
            return response.json();
        })
        .then(data => {
            const logContent = document.getElementById('attack-log-content');
            if (!logContent) return;
            logContent.textContent = data.logs.length === 0 ? 'No attack logs available.' : JSON.stringify(data.logs, null, 2);
        })
        .catch(error => {
            console.error('Error fetching attack log:', error);
            showMessage('attack-log-content', 'Failed to load attack log', 'danger');
        });
}

function fetchAttackerLog() {
    fetch('/attacker-log')
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error ${response.status}`);
            return response.json();
        })
        .then(data => {
            const tableBody = document.getElementById('attacker-log-table');
            if (!tableBody) return;
            tableBody.innerHTML = data.logs.length === 0 ? '<tr><td colspan="5">No attacker logs available.</td></tr>'
                : data.logs.map(log => `
                    <tr>
                        <td>${log['IP Address'] || 'N/A'}</td>
                        <td>${log['MAC Address'] || 'N/A'}</td>
                        <td>${log['Request Count'] || 'N/A'}</td>
                        <td>${log['Timestamp'] || 'N/A'}</td>
                        <td>${log['Reason'] || 'N/A'}</td>
                    </tr>
                `).join('');
        })
        .catch(error => {
            console.error('Error fetching attacker log:', error);
            showMessage('attacker-log-table', 'Failed to load attacker log', 'danger');
        });
}

function fetchSecurityLog() {
    fetch('/security-log')
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error ${response.status}`);
            return response.json();
        })
        .then(data => {
            const logContent = document.getElementById('security-log-content');
            if (!logContent) return;
            logContent.textContent = data.logs.length === 0 ? 'No security logs available.' : data.logs.join('');
        })
        .catch(error => {
            console.error('Error fetching security log:', error);
            showMessage('security-log-content', 'Failed to load security log', 'danger');
        });
}

function deleteLog(logType) {
    if (!confirm(`Are you sure you want to delete the ${logType} log?`)) return;
    fetch(`/delete-log/${logType}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        showMessage(`${logType}-log-content`, data.message, data.status === 'success' ? 'success' : 'danger');
        if (data.status === 'success') {
            if (logType === 'attack') fetchAttackLog();
            else if (logType === 'attacker') fetchAttackerLog();
            else if (logType === 'security') fetchSecurityLog();
        }
    })
    .catch(error => {
        console.error(`Error deleting ${logType} log:`, error);
        showMessage(`${logType}-log-content`, `Failed to delete ${logType} log`, 'danger');
    });
}

function updateAttackChart() {
    fetch('/attack-log')
        .then(response => response.json())
        .then(data => {
            const attackTypes = {};
            data.logs.forEach(log => {
                const type = log.violation_type || 'Unknown';
                attackTypes[type] = (attackTypes[type] || 0) + 1;
            });

            const ctx = document.getElementById('attack-chart')?.getContext('2d');
            if (ctx) {
                new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: Object.keys(attackTypes),
                        datasets: [{
                            data: Object.values(attackTypes),
                            backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40'],
                        }],
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'top' },
                            title: { display: true, text: 'Attack Type Distribution' }
                        }
                    }
                });
            }
        })
        .catch(error => {
            console.error('Error updating attack chart:', error);
        });
}

const currentUserRole = document.querySelector('.navbar-nav .nav-link span')?.textContent?.match(/\((\w+)\)/)?.[1]?.toLowerCase() || 'user';

document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('attack-chart')) {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/chart.js';
        script.onload = updateAttackChart;
        document.head.appendChild(script);
    }

    if (document.getElementById('stats')) fetchStats();
    if (document.getElementById('attack-log-content')) fetchAttackLog();
    if (document.getElementById('attacker-log-table')) fetchAttackerLog();
    if (document.getElementById('security-log-content')) fetchSecurityLog();

    const checkIPForm = document.getElementById('check-ip-form');
    if (checkIPForm) checkIPForm.addEventListener('submit', handleCheckIP);

    const clearVTCacheBtn = document.getElementById('clear-vt-cache');
    if (clearVTCacheBtn && currentUserRole === 'admin') clearVTCacheBtn.addEventListener('click', handleClearVTCache);

    const deleteAttackLogBtn = document.getElementById('delete-attack-log');
    if (deleteAttackLogBtn && currentUserRole === 'admin') deleteAttackLogBtn.addEventListener('click', () => deleteLog('attack'));

    const deleteAttackerLogBtn = document.getElementById('delete-attacker-log');
    if (deleteAttackerLogBtn && currentUserRole === 'admin') deleteAttackerLogBtn.addEventListener('click', () => deleteLog('attacker'));

    const deleteSecurityLogBtn = document.getElementById('delete-security-log');
    if (deleteSecurityLogBtn && currentUserRole === 'admin') deleteSecurityLogBtn.addEventListener('click', () => deleteLog('security'));

    setInterval(() => {
        if (document.getElementById('stats')) fetchStats();
        if (document.getElementById('attack-log-content')) fetchAttackLog();
        if (document.getElementById('attacker-log-table')) fetchAttackerLog();
        if (document.getElementById('security-log-content')) fetchSecurityLog();
    }, 30000);
});