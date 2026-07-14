document.addEventListener('DOMContentLoaded', () => {
    
    // Initialize Chart
    const ctx = document.getElementById('statsChart').getContext('2d');
    const statsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    'rgba(239, 68, 68, 0.8)',   // Red
                    'rgba(245, 158, 11, 0.8)',  // Yellow
                    'rgba(59, 130, 246, 0.8)'   // Blue
                ],
                borderColor: '#1e293b',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#f8fafc' }
                }
            },
            cutout: '70%'
        }
    });

    function fetchStats() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                statsChart.data.labels = Object.keys(data);
                statsChart.data.datasets[0].data = Object.values(data);
                statsChart.update();
            })
            .catch(err => console.error("Error fetching stats:", err));
    }

    function fetchEvents() {
        fetch('/api/events?limit=15')
            .then(response => response.json())
            .then(data => {
                const tbody = document.querySelector('#eventsTable tbody');
                tbody.innerHTML = '';
                
                data.forEach(event => {
                    const tr = document.createElement('tr');
                    
                    // Format timestamp
                    const date = new Date(event.timestamp);
                    const timeString = date.toLocaleTimeString([], { hour12: false }) + '.' + date.getMilliseconds();
                    
                    let severityClass = event.severity.toLowerCase() === 'high' ? 'badge-danger' : 'badge-warning';

                    tr.innerHTML = `
                        <td class="mono-text" style="color: #94a3b8; font-size: 0.8rem;">${timeString}</td>
                        <td class="mono-text">${event.src_ip}</td>
                        <td style="font-weight: 500;">${event.attack_type}</td>
                        <td><span style="color: ${event.action_taken === 'Blocked' ? '#ef4444' : '#94a3b8'}">${event.action_taken}</span></td>
                        <td><span class="badge ${severityClass}">${event.severity}</span></td>
                    `;
                    tbody.appendChild(tr);
                });
            })
            .catch(err => console.error("Error fetching events:", err));
    }

    function fetchBlocklist() {
        fetch('/api/blocklist')
            .then(response => response.json())
            .then(data => {
                const tbody = document.querySelector('#blocklistTable tbody');
                tbody.innerHTML = '';
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #94a3b8; padding: 2rem;">No active blocks</td></tr>';
                    return;
                }

                data.forEach(item => {
                    const tr = document.createElement('tr');
                    
                    const expires = new Date(item.expires_at * 1000);
                    
                    tr.innerHTML = `
                        <td class="mono-text">${item.ip}</td>
                        <td class="mono-text" style="color: #94a3b8; font-size: 0.8rem;">${expires.toLocaleTimeString()}</td>
                        <td><button class="btn btn-unblock" onclick="unblockIp('${item.ip}')">Unblock</button></td>
                    `;
                    tbody.appendChild(tr);
                });
            })
            .catch(err => console.error("Error fetching blocklist:", err));
    }

    // Expose to window for the onclick handler
    window.unblockIp = function(ip) {
        if(confirm(`Are you sure you want to unblock ${ip}?`)) {
            fetch(`/api/blocklist/unblock/${ip}`, { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        fetchBlocklist(); // refresh immediately
                    } else {
                        alert("Failed to unblock: " + data.message);
                    }
                })
                .catch(err => console.error("Error unblocking IP:", err));
        }
    };

    // Initial fetch
    fetchStats();
    fetchEvents();
    fetchBlocklist();

    // Poll every 5 seconds
    setInterval(() => {
        fetchStats();
        fetchEvents();
        fetchBlocklist();
    }, 5000);
});
