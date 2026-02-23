let ws = null;
let reconnect_attempts = 0;
const max_reconnect_attempts = 10;

function format_bytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function format_number(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function format_uptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

function update_dashboard(data) {
    document.getElementById('totalRequests').textContent = format_number(data.requests.total);
    document.getElementById('requestsPerSecond').textContent = data.requests.per_second.toFixed(1);
    document.getElementById('activeConnections').textContent = data.connections.active;
    document.getElementById('bytesSent').textContent = format_bytes(data.traffic.bytes_sent);
    document.getElementById('bytesReceived').textContent = format_bytes(data.traffic.bytes_received);
    document.getElementById('sendRate').textContent = format_bytes(data.traffic.send_rate_bps);
    document.getElementById('receiveRate').textContent = format_bytes(data.traffic.receive_rate_bps);

    document.getElementById('uptime').textContent = format_uptime(data.uptime_seconds);

    const total_status = data.requests.by_status.status_2xx +
        data.requests.by_status.status_3xx +
        data.requests.by_status.status_4xx +
        data.requests.by_status.status_5xx;

    if (total_status > 0) {
        document.getElementById('status2xx').textContent = format_number(data.requests.by_status.status_2xx);
        document.getElementById('status2xxPercent').textContent =
            ((data.requests.by_status.status_2xx / total_status) * 100).toFixed(1) + '%';

        document.getElementById('status3xx').textContent = format_number(data.requests.by_status.status_3xx);
        document.getElementById('status3xxPercent').textContent =
            ((data.requests.by_status.status_3xx / total_status) * 100).toFixed(1) + '%';

        document.getElementById('status4xx').textContent = format_number(data.requests.by_status.status_4xx);
        document.getElementById('status4xxPercent').textContent =
            ((data.requests.by_status.status_4xx / total_status) * 100).toFixed(1) + '%';

        document.getElementById('status5xx').textContent = format_number(data.requests.by_status.status_5xx);
        document.getElementById('status5xxPercent').textContent =
            ((data.requests.by_status.status_5xx / total_status) * 100).toFixed(1) + '%';
    }

    const total_methods = data.requests.by_method.get +
        data.requests.by_method.post +
        data.requests.by_method.put +
        data.requests.by_method.del;

    if (total_methods > 0) {
        document.getElementById('getRequests').textContent = format_number(data.requests.by_method.get);
        document.getElementById('getPercent').textContent =
            ((data.requests.by_method.get / total_methods) * 100).toFixed(1) + '%';

        document.getElementById('postRequests').textContent = format_number(data.requests.by_method.post);
        document.getElementById('postPercent').textContent =
            ((data.requests.by_method.post / total_methods) * 100).toFixed(1) + '%';

        document.getElementById('putRequests').textContent = format_number(data.requests.by_method.put);
        document.getElementById('putPercent').textContent =
            ((data.requests.by_method.put / total_methods) * 100).toFixed(1) + '%';

        document.getElementById('deleteRequests').textContent = format_number(data.requests.by_method.del);
        document.getElementById('deletePercent').textContent =
            ((data.requests.by_method.del / total_methods) * 100).toFixed(1) + '%';
    }

    document.getElementById('avgLatency').textContent = data.latency.avg_ms.toFixed(2) + ' ms';
    document.getElementById('minLatency').textContent = data.latency.min_ms.toFixed(2) + ' ms';
    document.getElementById('maxLatency').textContent = data.latency.max_ms.toFixed(2) + ' ms';
}

function update_connections(connections) {
    const tbody = document.getElementById('connectionsTable');
    if (!tbody || !connections) return;

    document.getElementById('connectionCount').textContent = connections.length;

    tbody.innerHTML = connections.slice(0, 50).map(conn => `
        <tr>
            <td><code>${conn.client_ip}</code></td>
            <td>${conn.client_port}</td>
            <td>${conn.request_path || '-'}</td>
            <td>${format_bytes(conn.bytes_sent)}</td>
            <td>${format_bytes(conn.bytes_received)}</td>
            <td>${conn.request_count}</td>
            <td>${conn.is_ssl ? '🔒' : '-'}</td>
        </tr>
    `).join('');
}

function connect_websocket() {
    const ws_protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws_url = `${ws_protocol}//${window.location.host}/ws/stats`;

    ws = new WebSocket(ws_url);

    ws.onopen = function () {
        console.log('WebSocket已连接');
        reconnect_attempts = 0;
        document.getElementById('serverStatus').classList.add('online');
        document.getElementById('serverStatusText').textContent = '服务器运行中';
    };

    ws.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);
            update_dashboard(data);
            if (window.onWSMessage) {
                window.onWSMessage(data);
            }
        } catch (e) {
            console.error('解析数据失败:', e);
        }
    };

    ws.onerror = function (error) {
        console.error('WebSocket错误:', error);
    };

    ws.onclose = function () {
        console.log('WebSocket已断开');
        document.getElementById('serverStatus').classList.remove('online');
        document.getElementById('serverStatusText').textContent = '连接断开';

        if (reconnect_attempts < max_reconnect_attempts) {
            reconnect_attempts++;
            setTimeout(connect_websocket, 2000 * reconnect_attempts);
        }
    };
}

function update_current_time() {
    const now = new Date();
    const time_element = document.getElementById('currentTime');
    if (time_element) {
        time_element.textContent = now.toLocaleTimeString('zh-CN', { hour12: false });
    }
}

async function fetch_connections() {
    try {
        const response = await fetch('/api/connections/active');
        const data = await response.json();
        update_connections(data.connections);
    } catch (e) {
        console.error('获取连接列表失败:', e);
    }
}

document.addEventListener('DOMContentLoaded', function () {
    connect_websocket();
    update_current_time();
    setInterval(update_current_time, 1000);

    setInterval(fetch_connections, 2000);

    window.addEventListener('beforeunload', function () {
        if (ws) {
            ws.close();
        }
    });
});
