/**
 * NIDS Dashboard - Main Application JavaScript
 * Uses SocketIO for real-time updates and HTTP polling as fallback
 */

// SocketIO connection
let socket = null;

// Configuration
const CONFIG = {
    pollInterval: 2000,  // Poll every 2 seconds
    maxAlerts: 100,
    maxPayloadLength: 500
};

// Application State
const state = {
    capturing: false,
    demoMode: false,
    interfaces: [],
    selectedInterface: null,
    alerts: [],
    packets: [],
    selectedPacket: null,
    protocolStats: {},
    // Closed-Loop State
    closedLoopEnabled: true,
    anomalies: [],
    autoRules: []
};

// Sorting state
const sortState = {
    alerts: 'newest',
    traffic: 'newest',
    anomalies: 'score'
};

// Sorting functions
function sortAlerts(alerts, sortBy) {
    return [...alerts].sort((a, b) => {
        switch(sortBy) {
            case 'newest':
                return new Date(b.timestamp) - new Date(a.timestamp);
            case 'oldest':
                return new Date(a.timestamp) - new Date(b.timestamp);
            case 'severity':
                const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
                const aSev = severityOrder[a.severity] || 2;
                const bSev = severityOrder[b.severity] || 2;
                return bSev - aSev;
            case 'source':
                return (a.src || '').localeCompare(b.src || '');
            default:
                return 0;
        }
    });
}

function sortTraffic(packets, sortBy) {
    return [...packets].sort((a, b) => {
        switch(sortBy) {
            case 'newest':
                return 1; // Keep original order for newest
            case 'oldest':
                return -1;
            case 'src-ip':
                return (a.src || '').localeCompare(b.src || '');
            case 'dst-ip':
                return (a.dst || '').localeCompare(b.dst || '');
            case 'protocol':
                return (a.proto || '').localeCompare(b.proto || '');
            case 'port':
                return (a.dport || 0) - (b.dport || 0);
            default:
                return 0;
        }
    });
}

function sortAnomalies(anomalies, sortBy) {
    return [...anomalies].sort((a, b) => {
        switch(sortBy) {
            case 'score':
                return (b.score || 0) - (a.score || 0);
            case 'score-low':
                return (a.score || 0) - (b.score || 0);
            case 'type':
                return (a.type || '').localeCompare(b.type || '');
            case 'source':
                return (a.src_ip || '').localeCompare(b.src_ip || '');
            default:
                return 0;
        }
    });
}

// Poll timer
let pollTimer = null;

// DOM Elements
const elements = {};

/**
 * Initialize application
 */
document.addEventListener('DOMContentLoaded', () => {
    initElements();
    initSocketIO();  // Initialize SocketIO connection
    loadInterfaces();
    loadRules();
    initEventListeners();
    initClosedLoop();  // Initialize closed-loop UI
    initSorting();  // Initialize sorting
    initDemoMode();  // Initialize demo mode
    updateTime();
    
    // Update time every second
    setInterval(updateTime, 1000);
    
    // Update connection status
    updateConnectionStatus(true);
});

/**
 * Initialize SocketIO connection for real-time updates
 */
function initSocketIO() {
    // Check if SocketIO is available
    if (typeof io === 'undefined') {
        console.warn('SocketIO not available, using HTTP polling only');
        return;
    }
    
    try {
        socket = io();
        
        socket.on('connect', function() {
            console.log('SocketIO connected');
            updateConnectionStatus(true);
        });
        
        socket.on('disconnect', function() {
            console.log('SocketIO disconnected');
            updateConnectionStatus(false);
        });
        
        // Handle real-time packet updates
        socket.on('packet_update', function(data) {
            state.protocolStats = data.protocol_stats || {};
            elements.packetCount.textContent = formatNumber(data.packet_count || 0);
            elements.alertCount.textContent = formatNumber(data.alert_count || 0);
            renderProtocolStats();
            renderProtocolChart();
        });
        
        // Handle new alerts in real-time
        socket.on('new_alert', function(alert) {
            console.log('New alert received:', alert);
            state.alerts.unshift(alert);
            addAlert(alert);
        });
        
        // Handle new anomalies in real-time
        socket.on('new_anomaly', function(anomaly) {
            console.log('New anomaly detected:', anomaly);
            state.anomalies.unshift(anomaly);
            renderAnomalies();
            
            // Update closed-loop stats
            if (elements.clAnomalies) {
                elements.clAnomalies.textContent = (parseInt(elements.clAnomalies.textContent) || 0) + 1;
            }
        });
        
        // Handle capture events
        socket.on('capture_started', function(data) {
            console.log('Capture started:', data);
            state.capturing = true;
            updateCaptureUI(true);
        });
        
        socket.on('capture_stopped', function(data) {
            console.log('Capture stopped:', data);
            state.capturing = false;
            updateCaptureUI(false);
        });
        
        // Handle rules loaded
        socket.on('rules_loaded', function(data) {
            console.log('Rules loaded:', data);
            renderRules(data.rules || []);
        });
        
        console.log('SocketIO initialized');
    } catch (error) {
        console.error('SocketIO init error:', error);
    }
}

/**
 * Update capture UI state
 */
function updateCaptureUI(capturing) {
    if (capturing) {
        elements.captureStatus.textContent = 'RUNNING';
        elements.captureStatus.style.color = '#00ff33';
        elements.startBtn.disabled = true;
        elements.stopBtn.disabled = false;
        elements.interfaceSelect.disabled = true;
    } else {
        elements.captureStatus.textContent = 'IDLE';
        elements.captureStatus.style.color = '#00cc29';
        elements.startBtn.disabled = false;
        elements.stopBtn.disabled = true;
        elements.interfaceSelect.disabled = false;
    }
}

/**
 * Initialize DOM element references
 */
function initElements() {
    elements.interfaceSelect = document.getElementById('interface-select');
    elements.startBtn = document.getElementById('start-btn');
    elements.stopBtn = document.getElementById('stop-btn');
    elements.refreshRulesBtn = document.getElementById('refresh-rules-btn');
    elements.loadPcapBtn = document.getElementById('load-pcap-btn');
    elements.savePcapBtn = document.getElementById('save-pcap-btn');
    elements.saveJsonBtn = document.getElementById('save-json-btn');
    elements.pcapUpload = document.getElementById('pcap-upload');
    elements.rulesList = document.getElementById('rules-list');
    elements.yaraResults = document.getElementById('yara-results');
    elements.alertsContainer = document.getElementById('alerts-container');
    elements.packetCount = document.getElementById('packet-count');
    elements.alertCount = document.getElementById('alert-count');
    elements.captureStatus = document.getElementById('capture-status');
    elements.currentTime = document.getElementById('current-time');
    elements.connectionStatus = document.getElementById('connection-status');
    elements.packetAnalysis = document.getElementById('packet-analysis');
    elements.protocolStats = document.getElementById('protocol-stats');
    elements.infoBtn = document.getElementById('info-btn');
    elements.infoModal = document.getElementById('info-modal');
    elements.infoModalClose = document.getElementById('info-modal-close');
}

/**
 * Update connection status display
 */
function updateConnectionStatus(connected) {
    if (connected) {
        elements.connectionStatus.innerHTML = '● CONNECTED';
        elements.connectionStatus.classList.add('connected');
        elements.connectionStatus.classList.remove('disconnected');
    } else {
        elements.connectionStatus.innerHTML = '● DISCONNECTED';
        elements.connectionStatus.classList.add('disconnected');
        elements.connectionStatus.classList.remove('connected');
    }
}

/**
 * Update status from server
 */
async function pollStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        elements.packetCount.textContent = formatNumber(data.packet_count || 0);
        elements.alertCount.textContent = formatNumber(data.alert_count || 0);
        
        // Update capture status
        if (data.running) {
            elements.captureStatus.textContent = 'RUNNING';
            elements.captureStatus.style.color = '#00ff33';
            elements.startBtn.disabled = true;
            elements.stopBtn.disabled = false;
            elements.interfaceSelect.disabled = true;
            state.capturing = true;
        } else {
            elements.captureStatus.textContent = 'IDLE';
            elements.captureStatus.style.color = '#00cc29';
            elements.startBtn.disabled = false;
            elements.stopBtn.disabled = true;
            elements.interfaceSelect.disabled = false;
            state.capturing = false;
        }
    } catch (error) {
        console.error('Status poll error:', error);
    }
}

/**
 * Render protocol distribution stats
 */
// Chart instance for protocol pie chart
let protocolChart = null;

function renderProtocolChart() {
    const ctx = document.getElementById('protocol-chart');
    if (!ctx) return;
    
    const stats = state.protocolStats;
    const labels = Object.keys(stats).map(k => k.toUpperCase());
    const data = Object.values(stats);
    
    // Dynamic colors
    const colors = [
        '#00ff33', // TCP - green
        '#3399ff', // UDP - blue  
        '#ff9933', // ICMP - orange
        '#ff3333', // Other - red
        '#9933ff', // Purple
        '#ffcc00', // Yellow
    ];
    
    if (protocolChart) {
        protocolChart.destroy();
    }
    
    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: '#0a0a0f',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#00ff33',
                        font: { family: 'JetBrains Mono', size: 10 },
                        padding: 8
                    }
                }
            }
        }
    });
}

function renderProtocolStats() {
    const container = document.getElementById('protocol-stats-content');
    if (!container) return;
    
    const statsHtml = Object.entries(state.protocolStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([proto, count]) => `
            <div class="proto-stat">
                <span class="proto-name">${proto.toUpperCase()}</span>
                <span class="proto-count">${formatNumber(count)}</span>
            </div>
        `).join('');
    
    container.innerHTML = statsHtml;
}

/**
 * Load protocol stats
 */
async function loadProtocolStats() {
    try {
        const response = await fetch('/api/protocols');
        const data = await response.json();
        state.protocolStats = data.protocols || {};
        // Render both chart and stats after getting data
        renderProtocolStats();
        renderProtocolChart();
    } catch (error) {
        console.error('Protocol stats error:', error);
    }
}

/**
 * Load packets from server
 */
async function loadPackets() {
    try {
        const response = await fetch('/api/packets');
        const data = await response.json();
        state.packets = sortTraffic(data.packets || [], sortState.traffic);
        renderPackets();
    } catch (error) {
        console.error('Load packets error:', error);
    }
}

/**
 * Render packets in traffic table
 */
function renderPackets() {
    const tableBody = document.getElementById('traffic-table-body');
    if (!tableBody) return;
    
    console.log('Rendering packets, count:', state.packets.length);
    
    if (state.packets.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" class="empty-text">No packets captured yet - Start capture to see traffic</td></tr>';
        return;
    }
    
    // Get the last 50 packets and reverse for display (newest first)
    const packetsToShow = state.packets.slice(-50).reverse();
    
    const rows = packetsToShow.map((pkt, idx) => {
        const actualIndex = state.packets.length - 1 - idx;
        return `
            <tr onclick="selectPacketFromTable(${actualIndex})">
                <td>${actualIndex + 1}</td>
                <td>${new Date().toLocaleTimeString()}</td>
                <td>${escapeHtml(pkt.src || 'N/A')}:${pkt.sport || 0}</td>
                <td>${escapeHtml(pkt.dst || 'N/A')}:${pkt.dport || 0}</td>
                <td>${(pkt.proto || 'N/A').toUpperCase()}</td>
                <td>${escapeHtml(pkt.summary || pkt.proto || 'N/A')}</td>
            </tr>
        `;
    }).join('');
    
    tableBody.innerHTML = rows;
}

/**
 * Select packet from traffic table
 */
function selectPacketFromTable(index) {
    if (state.packets[index]) {
        state.selectedPacket = state.packets[index];
        // Show in alerts tab for now
    }
}

/**
 * Load network interfaces
 */
async function loadInterfaces() {
    try {
        const response = await fetch('/api/interfaces');
        const data = await response.json();
        state.interfaces = data.interfaces || [];
        renderInterfaces();
    } catch (error) {
        console.error('Failed to load interfaces:', error);
        elements.interfaceSelect.innerHTML = '<option value="">Error loading interfaces</option>';
    }
}

/**
 * Render interface list
 */
function renderInterfaces() {
    elements.interfaceSelect.innerHTML = '<option value="">Select Interface...</option>';
    
    state.interfaces.forEach((iface, index) => {
        const option = document.createElement('option');
        option.value = iface.name;
        const ip = iface.ip !== 'N/A' ? iface.ip : 'Auto-detect';
        option.textContent = `${iface.name} (${ip})`;
        
        // Auto-select first valid interface
        if (index === 0 && iface.ip !== 'N/A') {
            option.selected = true;
            state.selectedInterface = iface.name;
        }
        
        elements.interfaceSelect.appendChild(option);
    });
    
    if (state.interfaces.length === 0) {
        elements.interfaceSelect.innerHTML = '<option value="">No interfaces found</option>';
    }
}

/**
 * Load detection rules
 */
async function loadRules() {
    try {
        const response = await fetch('/api/rules');
        const data = await response.json();
        renderRules(data.rules || []);
    } catch (error) {
        console.error('Failed to load rules:', error);
    }
}

/**
 * Render rules list
 */
function renderRules(rules) {
    if (!rules || rules.length === 0) {
        elements.rulesList.innerHTML = '<p class="empty-text">No rules loaded</p>';
        return;
    }

    elements.rulesList.innerHTML = rules.map(rule =>
        `<div class="rule-item">${escapeHtml(rule)}</div>`
    ).join('');
}

/**
 * Initialize event listeners
 */
function initEventListeners() {
    // Interface selection
    elements.interfaceSelect.addEventListener('change', (e) => {
        state.selectedInterface = e.target.value;
    });

    // Capture controls
    elements.startBtn.addEventListener('click', startCapture);
    elements.stopBtn.addEventListener('click', stopCapture);

    // Info button - Open help modal
    if (elements.infoBtn) {
        elements.infoBtn.addEventListener('click', () => {
            elements.infoModal.classList.add('active');
        });
    }

    // Info modal close
    if (elements.infoModalClose) {
        elements.infoModalClose.addEventListener('click', () => {
            elements.infoModal.classList.remove('active');
        });
    }

    // Close info modal on backdrop click
    if (elements.infoModal) {
        elements.infoModal.addEventListener('click', (e) => {
            if (e.target === elements.infoModal) {
                elements.infoModal.classList.remove('active');
            }
        });
    }

    // Action buttons
    if (elements.refreshRulesBtn) {
        elements.refreshRulesBtn.addEventListener('click', () => {
            loadRules();
            showNotification('Rules refreshed', 'success');
        });
    }

    if (elements.loadPcapBtn) {
        elements.loadPcapBtn.addEventListener('click', () => {
            elements.pcapUpload.click();
        });
    }

    if (elements.pcapUpload) {
        elements.pcapUpload.addEventListener('change', handlePcapUpload);
    }

    if (elements.savePcapBtn) {
        elements.savePcapBtn.addEventListener('click', saveCapture);
    }
    
    if (elements.saveJsonBtn) {
        elements.saveJsonBtn.addEventListener('click', exportJson);
    }

    // Tab navigation
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const tabName = e.target.dataset.tab;
            switchTab(tabName);
        });
    });

    // Modal close
    const modalClose = document.querySelector('.modal-close');
    if (modalClose) {
        modalClose.addEventListener('click', closeModal);
    }
    
    const modal = document.getElementById('stream-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
    }

// Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
            if (elements.infoModal) {
                elements.infoModal.classList.remove('active');
            }
        }
        if (e.key === 's' && !e.ctrlKey && !state.capturing) startCapture();
        if (e.key === 'x' && state.capturing) stopCapture();
    });
}

/**
 * Start packet capture
 */
async function startCapture() {
    if (!state.selectedInterface) {
        showNotification('Please select an interface first', 'error');
        return;
    }

    try {
        const response = await fetch('/api/capture', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'start',
                interface: state.selectedInterface
            })
        });
        const data = await response.json();
        
        if (data.status === 'started') {
            showNotification('Capture started (simulation mode)', 'success');
            
            // Start polling
            pollStatus();
            loadProtocolStats();
            loadPackets();
            loadAlerts();
            pollTimer = setInterval(async () => {
                await pollStatus();
                await loadProtocolStats();
                await loadPackets();
                await loadAlerts();
            }, CONFIG.pollInterval);
        } else {
            showNotification('Failed to start capture', 'error');
        }
    } catch (error) {
        console.error('Start capture error:', error);
        showNotification('Error starting capture', 'error');
    }
}

/**
 * Stop packet capture
 */
async function stopCapture() {
    try {
        // First try to stop demo mode if running
        if (state.demoMode) {
            await fetch('/api/demo/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            state.demoMode = false;
        }
        
        // Also try regular capture stop
        const response = await fetch('/api/capture', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'stop' })
        });
        const data = await response.json();
        
        if (data.status === 'stopped' || data.status === 'ok') {
            showNotification('Capture stopped', 'info');
            
            // Stop polling
            if (pollTimer) {
                clearInterval(pollTimer);
                pollTimer = null;
            }
            
            // Still load data - don't lose captured packets/alerts!
            await pollStatus();
            await loadProtocolStats();
            await loadPackets();
            await loadAlerts();
            
            // Render the data
            renderProtocolStats();
            renderProtocolChart();
            renderPackets();
            renderAlerts();
        }
    } catch (error) {
        console.error('Stop capture error:', error);
    }
}

/**
 * Load alerts from server
 */
async function loadAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const data = await response.json();
        const alerts = data.alerts || [];
        
        // Check for new alerts
        if (alerts.length > state.alerts.length) {
            const newAlerts = alerts.slice(0, alerts.length - state.alerts.length);
            newAlerts.reverse().forEach(alert => {
                state.alerts.unshift(alert);
                addAlert(alert);
            });
        } else {
            state.alerts = sortAlerts(alerts, sortState.alerts);
        }
    } catch (error) {
        console.error('Load alerts error:', error);
    }
}

/**
 * Render alerts from state
 */
function renderAlerts() {
    if (!elements.alertsContainer) return;
    
    // Clear container but keep structure
    elements.alertsContainer.innerHTML = '';
    
    if (state.alerts.length === 0) {
        elements.alertsContainer.innerHTML = '<p class="empty-text">No security alerts detected</p>';
        return;
    }
    
    state.alerts.forEach(alert => {
        elements.alertsContainer.insertAdjacentHTML('beforeend', createAlertCard(alert));
    });
    
    // Add click handlers
    elements.alertsContainer.querySelectorAll('.alert-card').forEach((card, index) => {
        card.addEventListener('click', () => {
            selectPacket(state.alerts[index]);
        });
    });
}

/**
 * Handle PCAP file upload
 */
async function handlePcapUpload(e) {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    showNotification('Loading PCAP file...', 'info');

    try {
        const response = await fetch('/api/upload_pcap', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            showNotification(`Loaded ${data.packets} packets, ${data.alerts} alerts`, 'success');
            await pollStatus();
            await loadAlerts();
        } else {
            showNotification(data.message || 'Failed to load PCAP', 'error');
        }
    } catch (error) {
        console.error('Upload error:', error);
        showNotification('Error uploading PCAP', 'error');
    }

    e.target.value = '';
}

/**
 * Save captured packets
 */
async function exportJson() {
    try {
        const response = await fetch('/api/export/json', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            // Create downloadable JSON file
            const jsonStr = JSON.stringify(data.data, null, 2);
            const blob = new Blob([jsonStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `nids_capture_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showNotification(`Exported ${data.data.packet_count} packets to JSON`, 'success');
        } else {
            showNotification('Failed to export data', 'error');
        }
    } catch (error) {
        console.error('Export error:', error);
        showNotification('Error exporting data', 'error');
    }
}

async function saveCapture() {
    const filename = `nids_capture_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.pcap`;
    
    try {
        const response = await fetch('/api/save_pcap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            showNotification(`Saved to ${data.filename}`, 'success');
        } else {
            showNotification(data.message || 'Failed to save PCAP', data.status === 'success' ? 'success' : 'error');
        }
    } catch (error) {
        console.error('Save error:', error);
    }
}

/**
 * Add new alert to UI
 */
function addAlert(alert) {
    if (!elements.alertsContainer) return;
    
    // Remove empty text if present
    const emptyText = elements.alertsContainer.querySelector('.empty-text');
    if (emptyText) {
        emptyText.remove();
    }
    
    const alertCard = createAlertCard(alert);
    elements.alertsContainer.insertAdjacentHTML('afterbegin', alertCard);

    // Update alert count
    elements.alertCount.textContent = formatNumber(state.alerts.length);

    // Add click handler
    const newAlertCard = elements.alertsContainer.firstElementChild;
    if (newAlertCard) {
        newAlertCard.addEventListener('click', () => {
            selectPacket(alert);
        });
    }
}

/**
 * Create alert card element
 */
function createAlertCard(alert) {
    const time = new Date(alert.timestamp).toLocaleTimeString();
    return `
        <div class="alert-card" data-id="${alert.id}">
            <div class="alert-header">
                <span class="alert-id">#${alert.id}</span>
                <span class="alert-time">${time}</span>
            </div>
            <div class="alert-message">${escapeHtml(alert.message)}</div>
            <div class="alert-details">
                <span>${escapeHtml(alert.src)}:${alert.sport}</span>
                <span>→</span>
                <span>${escapeHtml(alert.dst)}:${alert.dport}</span>
                <span>${alert.proto.toUpperCase()}</span>
            </div>
        </div>
    `;
}

/**
 * Select packet for analysis
 */
function selectPacket(packet) {
    state.selectedPacket = packet;
    
    if (!elements.packetAnalysis) return;
    
    elements.packetAnalysis.innerHTML = `
        <div class="packet-detail">
            <div class="detail-section">
                <strong>Alert ID:</strong> #${packet.id}
            </div>
            <div class="detail-section">
                <strong>Message:</strong> ${escapeHtml(packet.message)}
            </div>
            <div class="detail-section">
                <strong>Source:</strong> ${escapeHtml(packet.src)}:${packet.sport}
            </div>
            <div class="detail-section">
                <strong>Destination:</strong> ${escapeHtml(packet.dst)}:${packet.dport}
            </div>
            <div class="detail-section">
                <strong>Protocol:</strong> ${packet.proto.toUpperCase()}
            </div>
            <div class="detail-section">
                <strong>Payload Preview:</strong>
                <pre class="payload-preview">${escapeHtml(packet.payload)}</pre>
            </div>
        </div>
    `;
}

/**
 * Switch tab
 */
function switchTab(tabName) {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `${tabName}-tab`);
    });
}

/**
 * Update current time
 */
function updateTime() {
    if (elements.currentTime) {
        elements.currentTime.textContent = new Date().toLocaleTimeString();
    }
}

/**
 * Close modal
 */
function closeModal() {
    const modal = document.getElementById('stream-modal');
    if (modal) {
        modal.classList.remove('active');
    }
}

/**
 * Format number with commas
 */
function formatNumber(num) {
    return num.toLocaleString();
}

/**
 * Escape HTML
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Notification styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        background: ${type === 'error' ? '#ff3333' : type === 'warning' ? '#ff9933' : '#00ff33'};
        color: ${type === 'info' ? '#000' : '#fff'};
        border-radius: 4px;
        z-index: 10000;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Export for potential module usage
window.NIDSDashboard = {
    state,
    startCapture,
    stopCapture,
    showNotification,
    // Closed-Loop functions
    pollClosedLoopStatus,
    loadAnomalies,
    renderAnomalies,
    toggleLearning,
    initClosedLoop
};

/**
 * Initialize closed-loop UI elements and event listeners
 */
function initSorting() {
    // Alerts sorting
    const alertsSort = document.getElementById('alerts-sort');
    if (alertsSort) {
        alertsSort.addEventListener('change', (e) => {
            sortState.alerts = e.target.value;
            renderAlerts();
        });
    }
    
    // Traffic sorting
    const trafficSort = document.getElementById('traffic-sort');
    if (trafficSort) {
        trafficSort.addEventListener('change', (e) => {
            sortState.traffic = e.target.value;
            renderPackets();
        });
    }
    
    // Anomalies sorting
    const anomaliesSort = document.getElementById('anomalies-sort');
    if (anomaliesSort) {
        anomaliesSort.addEventListener('change', (e) => {
            sortState.anomalies = e.target.value;
            renderAnomalies();
        });
    }
}

function initClosedLoop() {
    // Get closed-loop elements
    elements.clAnomalies = document.getElementById('cl-anomalies');
    elements.clRulesGenerated = document.getElementById('cl-rules-generated');
    elements.clTrackedIps = document.getElementById('cl-tracked-ips');
    elements.learningStatus = document.getElementById('learning-status');
    elements.toggleLearningBtn = document.getElementById('toggle-learning-btn');
    elements.viewAnomaliesBtn = document.getElementById('view-anomalies-btn');
    elements.anomaliesContainer = document.getElementById('anomalies-container');
    
    // Add event listeners for closed-loop buttons
    if (elements.toggleLearningBtn) {
        elements.toggleLearningBtn.addEventListener('click', toggleLearning);
    }
    
    if (elements.viewAnomaliesBtn) {
        elements.viewAnomaliesBtn.addEventListener('click', () => {
            switchTab('anomalies');
        });
    }
    
    // Start polling closed-loop status
    pollClosedLoopStatus();
    setInterval(pollClosedLoopStatus, CONFIG.pollInterval);
    
    // Initialize YARA scanner polling
    initYaraScanner();
}

/**
 * Initialize Demo Mode - Add demo button and functionality
 */
function initDemoMode() {
    // Create demo button if it doesn't exist
    let demoBtn = document.getElementById('demo-btn');
    if (!demoBtn) {
        // Find the capture control section to add demo button
        const captureSection = document.querySelector('.panel-section');
        if (captureSection) {
            const demoBtnHtml = `
                <button id="demo-btn" class="cyber-btn demo">
                    <span class="btn-icon">🎮</span> DEMO MODE
                </button>
            `;
            const buttonGroup = captureSection.querySelector('.button-group');
            if (buttonGroup) {
                buttonGroup.insertAdjacentHTML('afterend', demoBtnHtml);
            }
        }
    }
    
    demoBtn = document.getElementById('demo-btn');
    if (demoBtn) {
        demoBtn.addEventListener('click', toggleDemoMode);
    }
    
    // Poll demo status
    pollDemoStatus();
    setInterval(pollDemoStatus, 3000);
}

/**
 * Toggle demo mode on/off
 */
async function toggleDemoMode() {
    const demoBtn = document.getElementById('demo-btn');
    
    try {
        if (state.demoMode) {
            // Stop demo mode
            const response = await fetch('/api/demo/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();
            
            state.demoMode = false;
            if (demoBtn) {
                demoBtn.classList.remove('active');
                demoBtn.innerHTML = '<span class="btn-icon">🎮</span> DEMO MODE';
            }
            showNotification(`Demo stopped - ${data.packets_generated} packets generated`, 'info');
            
        } else {
            // Start demo mode
            const response = await fetch('/api/demo/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: 'mixed' })
            });
            const data = await response.json();
            
            if (data.status === 'started') {
                state.demoMode = true;
                if (demoBtn) {
                    demoBtn.classList.add('active');
                    demoBtn.innerHTML = '<span class="btn-icon">⏹</span> STOP DEMO';
                }
                showNotification('Demo mode started - Generating synthetic traffic', 'success');
                
                // Start polling for updates
                startDemoPolling();
            }
        }
    } catch (error) {
        console.error('Demo toggle error:', error);
        showNotification('Error toggling demo mode', 'error');
    }
}

/**
 * Poll demo mode status
 */
async function pollDemoStatus() {
    try {
        const response = await fetch('/api/demo/status');
        const data = await response.json();
        
        const demoBtn = document.getElementById('demo-btn');
        if (demoBtn) {
            if (data.running && !state.demoMode) {
                state.demoMode = true;
                demoBtn.classList.add('active');
                demoBtn.innerHTML = '<span class="btn-icon">⏹</span> STOP DEMO';
            } else if (!data.running && state.demoMode) {
                state.demoMode = false;
                demoBtn.classList.remove('active');
                demoBtn.innerHTML = '<span class="btn-icon">🎮</span> DEMO MODE';
            }
        }
    } catch (error) {
        // Silently fail - demo status is optional
    }
}

/**
 * Start polling for demo updates
 */
let demoPollInterval = null;

function startDemoPolling() {
    if (demoPollInterval) {
        clearInterval(demoPollInterval);
    }
    
    demoPollInterval = setInterval(async () => {
        try {
            // Poll status
            const response = await fetch('/api/status');
            const data = await response.json();
            
            elements.packetCount.textContent = formatNumber(data.packet_count || 0);
            elements.alertCount.textContent = formatNumber(data.alert_count || 0);
            
            // Load packets
            await loadPackets();
            
            // Load alerts
            await loadAlerts();
            
            // Load protocol stats
            await loadProtocolStats();
            
            // Check if demo still running
            const demoStatus = await fetch('/api/demo/status');
            const demoData = await demoStatus.json();
            
            if (!demoData.running && state.demoMode) {
                state.demoMode = false;
                clearInterval(demoPollInterval);
                demoPollInterval = null;
                
                const demoBtn = document.getElementById('demo-btn');
                if (demoBtn) {
                    demoBtn.classList.remove('active');
                    demoBtn.innerHTML = '<span class="btn-icon">🎮</span> DEMO MODE';
                }
            }
            
        } catch (error) {
            console.error('Demo polling error:', error);
        }
    }, 800);  // Poll faster during demo mode
}

/**
 * Initialize YARA scanner UI
 */
function initYaraScanner() {
    elements.yaraMatches = document.getElementById('yara-matches');
    elements.yaraStatus = document.querySelector('.yara-status');
    
    // Poll YARA status
    pollYaraStatus();
    setInterval(pollYaraStatus, CONFIG.pollInterval);
}

/**
 * Poll YARA status and update UI
 */
async function pollYaraStatus() {
    try {
        const response = await fetch('/api/yara/status');
        const data = await response.json();
        
        renderYaraMatches(data.matches || []);
    } catch (error) {
        console.error('YARA status error:', error);
    }
}

/**
 * Render YARA matches in UI
 */
function renderYaraMatches(matches) {
    if (!elements.yaraMatches) return;
    
    if (matches.length === 0) {
        elements.yaraMatches.innerHTML = '<p class="yara-no-matches">No malware detected yet</p>';
        return;
    }
    
    // Show latest matches
    const recentMatches = matches.slice(-5).reverse();
    
    elements.yaraMatches.innerHTML = recentMatches.map(match => `
        <div class="yara-match">
            <div class="rule-name">🛡️ ${escapeHtml(match.rule)}</div>
            <div class="match-details">
                <span>${escapeHtml(match.src_ip)}</span>
                <span>→</span>
                <span>${escapeHtml(match.dst_ip)}</span>
                <span>${escapeHtml(match.proto)}</span>
            </div>
            <div class="match-details" style="margin-top: 4px;">
                <span style="color: var(--matrix-orange);">${escapeHtml(match.meta?.description || 'Malware detected')}</span>
            </div>
        </div>
    `).join('');
}

/**
 * Poll closed-loop system status
 */
async function pollClosedLoopStatus() {
    if (!state.closedLoopEnabled) return;
    
    try {
        const response = await fetch('/api/closed-loop/status');
        const data = await response.json();
        
        // Fix: API returns data.stats, not data.detector
        const stats = data.stats || {};
        
        // Update UI stats
        if (elements.clAnomalies) {
            elements.clAnomalies.textContent = stats.total_anomalies || 0;
        }
        if (elements.clRulesGenerated) {
            elements.clRulesGenerated.textContent = stats.rules_generated || 0;
        }
        if (elements.clTrackedIps) {
            elements.clTrackedIps.textContent = stats.tracked_ips || 0;
        }
        
        // Update learning status indicator
        if (elements.learningStatus && data.enabled) {
            elements.learningStatus.textContent = '● ACTIVE';
            elements.learningStatus.style.color = '#00ff33';
        } else if (elements.learningStatus) {
            elements.learningStatus.textContent = '● PAUSED';
            elements.learningStatus.style.color = '#ff9933';
        }
        
        // Also load anomalies when polling status
        await loadAnomalies();
        
    } catch (error) {
        console.error('Closed-loop status error:', error);
    }
}

/**
 * Load and display anomalies
 */
async function loadAnomalies() {
    if (!state.closedLoopEnabled) return;
    
    try {
        const response = await fetch('/api/closed-loop/anomalies');
        const data = await response.json();
        state.anomalies = sortAnomalies(data.anomalies || [], sortState.anomalies);
        renderAnomalies();
    } catch (error) {
        console.error('Load anomalies error:', error);
    }
}

/**
 * Render anomalies in the anomalies tab
 */
function renderAnomalies() {
    if (!elements.anomaliesContainer) return;
    
    if (state.anomalies.length === 0) {
        elements.anomaliesContainer.innerHTML = '<p class="empty-text">No anomalies detected - Auto-learning is active</p>';
        return;
    }
    
    elements.anomaliesContainer.innerHTML = state.anomalies.map(anomaly => `
        <div class="anomaly-card">
            <div class="anomaly-header">
                <span class="anomaly-type">${escapeHtml(anomaly.type)}</span>
                <span class="anomaly-score">Score: ${(anomaly.score * 100).toFixed(1)}%</span>
            </div>
            <div class="anomaly-details">
                <span>Source: ${escapeHtml(anomaly.src_ip)}</span>
                <span>Detected: ${new Date(anomaly.timestamp).toLocaleString()}</span>
            </div>
            <div class="anomaly-features">
                ${Object.entries(anomaly.features || {}).map(([key, value]) => `
                    <span class="feature-tag">${key}: ${typeof value === 'number' ? value.toFixed(2) : value}</span>
                `).join('')}
            </div>
        </div>
    `).join('');
}

/**
 * Toggle learning on/off
 */
async function toggleLearning() {
    try {
        const response = await fetch('/api/closed-loop/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                auto_generate_rules: !state.closedLoopEnabled 
            })
        });
        const data = await response.json();
        
        state.closedLoopEnabled = data.auto_generate_rules;
        
        if (elements.toggleLearningBtn) {
            if (state.closedLoopEnabled) {
                elements.toggleLearningBtn.innerHTML = '<span class="btn-icon">⏸</span> PAUSE LEARNING';
            } else {
                elements.toggleLearningBtn.innerHTML = '<span class="btn-icon">▶</span> RESUME LEARNING';
            }
        }
        
        showNotification(
            state.closedLoopEnabled ? 'Auto-learning enabled' : 'Auto-learning paused',
            state.closedLoopEnabled ? 'success' : 'warning'
        );
    } catch (error) {
        console.error('Toggle learning error:', error);
    }
}

/* ============== FEDERATION FUNCTIONS ============== */

// Federation state
const federationState = {
    isRunning: false,
    currentRound: 0,
    totalRounds: 0,
    clients: {},
    globalRules: [],
    results: {},
    status: 'IDLE'
};

// Federation DOM elements
const fedElements = {};

/**
 * Initialize federation elements
 */
function initFederationElements() {
    fedElements.scenario = document.getElementById('fed-scenario');
    fedElements.startBtn = document.getElementById('fed-start-btn');
    fedElements.refreshBtn = document.getElementById('fed-refresh-btn');
    fedElements.scenarioName = document.getElementById('fed-scenario-name');
    fedElements.currentRound = document.getElementById('fed-current-round');
    fedElements.globalRules = document.getElementById('fed-global-rules');
    fedElements.status = document.getElementById('fed-status');
    fedElements.progress = document.getElementById('fed-progress');
    fedElements.progressFill = document.getElementById('fed-progress-fill');
    fedElements.progressText = document.getElementById('fed-progress-text');
    fedElements.globalRulesList = document.getElementById('fed-global-rules-list');
    
    // Client elements
    ['A', 'B', 'C'].forEach(client => {
        fedElements[`client${client}Packets`] = document.getElementById(`fed-client-${client}-packets`);
        fedElements[`client${client}Anomalies`] = document.getElementById(`fed-client-${client}-anomalies`);
        fedElements[`client${client}Rules`] = document.getElementById(`fed-client-${client}-rules`);
    });
}

/**
 * Load federation status from API
 */
async function loadFederationStatus() {
    try {
        const response = await fetch('/api/federation/status');
        const data = await response.json();
        
        federationState.isRunning = data.is_running || false;
        federationState.currentRound = data.current_round || 0;
        federationState.totalRounds = data.total_rounds || 0;
        federationState.clients = data.clients || {};
        federationState.globalRules = data.global_rules || [];
        federationState.results = data.results || {};
        
        updateFederationUI();
    } catch (error) {
        console.error('Load federation status error:', error);
    }
}

/**
 * Update federation UI elements
 */
function updateFederationUI() {
    if (!fedElements.status) return;
    
    // Update status
    if (federationState.isRunning) {
        federationState.status = 'RUNNING';
        fedElements.status.textContent = 'RUNNING';
        fedElements.status.style.color = '#00ff33';
        fedElements.progress.style.display = 'block';
        
        // Update progress bar
        const progress = (federationState.currentRound / federationState.totalRounds) * 100;
        fedElements.progressFill.style.width = `${progress}%`;
        fedElements.progressText.textContent = `Round ${federationState.currentRound}/${federationState.totalRounds}`;
        
        if (fedElements.startBtn) {
            fedElements.startBtn.disabled = true;
            fedElements.startBtn.textContent = 'RUNNING...';
        }
    } else {
        federationState.status = 'IDLE';
        fedElements.status.textContent = 'IDLE';
        fedElements.status.style.color = '#888';
        fedElements.progress.style.display = 'none';
        
        if (fedElements.startBtn) {
            fedElements.startBtn.disabled = false;
            fedElements.startBtn.textContent = 'START FEDERATION';
        }
    }
    
    // Update scenario name
    if (fedElements.scenarioName && fedElements.scenario) {
        const scenario = fedElements.scenario.value;
        const scenarioNames = {
            'iid': 'IID - Same Patterns',
            'non_iid': 'Non-IID - Different Patterns',
            'zero_day': 'Zero-Day Attack'
        };
        fedElements.scenarioName.textContent = scenarioNames[scenario] || scenario;
    }
    
    // Update round
    if (fedElements.currentRound) {
        fedElements.currentRound.textContent = `${federationState.currentRound}/${federationState.totalRounds}`;
    }
    
    // Update global rules count
    if (fedElements.globalRules) {
        fedElements.globalRules.textContent = federationState.globalRules.length || 0;
    }
    
    // Update client cards - use lowercase keys
    ['A', 'B', 'C'].forEach(client => {
        const lowercaseClient = client.toLowerCase();
        const clientData = federationState.clients[`client_${lowercaseClient}`] || federationState.clients[lowercaseClient] || {};
        const packetsEl = fedElements[`client${client}Packets`];
        const anomaliesEl = fedElements[`client${client}Anomalies`];
        const rulesEl = fedElements[`client${client}Rules`];
        
        if (packetsEl) packetsEl.textContent = clientData.packets || 0;
        if (anomaliesEl) anomaliesEl.textContent = clientData.anomalies || 0;
        if (rulesEl) rulesEl.textContent = clientData.rules || 0;
    });
    
    // Update global rules list
    if (fedElements.globalRulesList) {
        if (federationState.globalRules.length > 0) {
            fedElements.globalRulesList.innerHTML = federationState.globalRules.map(rule => 
                `<div class="fed-rule-item">${escapeHtml(rule)}</div>`
            ).join('');
        } else {
            fedElements.globalRulesList.innerHTML = '<p class="empty-text">No global rules yet - Run federation to generate rules</p>';
        }
    }
}

/**
 * Start federation
 */
async function startFederation() {
    if (!fedElements.scenario) return;
    
    const scenario = fedElements.scenario.value;
    const numRounds = 3; // Default rounds
    
    try {
        const response = await fetch('/api/federation/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                num_rounds: numRounds,
                scenario: scenario
            })
        });
        
        const data = await response.json();
        
        if (data.status === 'started') {
            federationState.isRunning = true;
            federationState.totalRounds = data.num_rounds;
            federationState.currentRound = 0;
            
            updateFederationUI();
            showNotification(`Federation started: ${scenario}`, 'success');
            
            // Start polling for status updates
            pollFederationStatus();
        }
    } catch (error) {
        console.error('Start federation error:', error);
        showNotification('Failed to start federation', 'error');
    }
}

/**
 * Poll federation status periodically
 */
let federationPollInterval = null;

function pollFederationStatus() {
    if (federationPollInterval) {
        clearInterval(federationPollInterval);
    }
    
    federationPollInterval = setInterval(async () => {
        await loadFederationStatus();
        
        if (!federationState.isRunning) {
            clearInterval(federationPollInterval);
            federationPollInterval = null;
            
            // Load results when done
            await loadFederationResults();
        }
    }, 2000);
}

/**
 * Load federation results
 */
async function loadFederationResults() {
    try {
        const response = await fetch('/api/federation/results');
        const data = await response.json();
        
        federationState.results = data.results || {};
        
        // Update global rules
        const globalRulesResponse = await fetch('/api/federation/global-rules');
        const globalRulesData = await globalRulesResponse.json();
        federationState.globalRules = globalRulesData.global_rules || [];
        
        updateFederationUI();
        
        if (!federationState.isRunning) {
            showNotification('Federation completed!', 'success');
        }
    } catch (error) {
        console.error('Load federation results error:', error);
    }
}

/**
 * Initialize federation event listeners
 */
function initFederationEvents() {
    initFederationElements();
    
    if (fedElements.startBtn) {
        fedElements.startBtn.addEventListener('click', startFederation);
    }
    
    if (fedElements.refreshBtn) {
        fedElements.refreshBtn.addEventListener('click', async () => {
            await loadFederationStatus();
            await loadFederationResults();
            showNotification('Federation data refreshed', 'info');
        });
    }
    
    // Load initial status
    loadFederationStatus();
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initFederationEvents();
});

