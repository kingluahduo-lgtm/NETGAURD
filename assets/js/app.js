// NetGuard Client Side Application Logic

document.addEventListener("DOMContentLoaded", () => {
    // --- State Variables ---
    let socket = null;
    let interfaces = [];
    let currentSessionId = "";
    let isCapturing = false;
    let isPaused = false;
    let selectedPacketId = null;
    let packetSequenceNumber = 0;
    
    // Stats accumulators
    let totalPackets = 0;
    let threatAlerts = 0;
    let activeDevices = new Set();
    let protocolCounts = {};
    let trafficRatesHistory = Array(15).fill(0);
    let trafficTimeLabels = Array(15).fill("");
    let bandwidthHistory = Array(15).fill(0);
    
    // --- UI Elements ---
    const sidebarItems = document.querySelectorAll(".sidebar-item");
    const viewPanels = document.querySelectorAll(".view-panel");
    const panelTitle = document.getElementById("current-panel-title");
    const snifferIndicator = document.getElementById("sniffer-status-indicator");
    const snifferStatusText = document.getElementById("sniffer-status-text");
    const themeToggleBtn = document.getElementById("theme-toggle-btn");
    
    // Metrics
    const cardPackets = document.getElementById("card-total-packets");
    const cardRate = document.getElementById("card-packet-rate");
    const cardAlerts = document.getElementById("card-threat-alerts");
    const cardDevices = document.getElementById("card-active-devices");
    
    // Controls
    const ifaceSelect = document.getElementById("capture-interface-select");
    const ifaceRefreshBtn = document.getElementById("interface-refresh-btn");
    const startBtn = document.getElementById("capture-start-btn");
    const pauseBtn = document.getElementById("capture-pause-btn");
    const stopBtn = document.getElementById("capture-stop-btn");
    const clearTableBtn = document.getElementById("capture-clear-btn");
    
    // Tables
    const packetTableBody = document.getElementById("capture-packets-tbody");
    const analyzerTableBody = document.getElementById("analyzer-packets-tbody");
    const threatsTableBody = document.getElementById("threats-table-tbody");
    const dashboardRecentAlerts = document.getElementById("dashboard-recent-alerts");
    const dashboardTopSources = document.getElementById("dashboard-top-sources");
    const reportsSessionsTable = document.getElementById("reports-sessions-tbody");
    
    // Analyzer Details
    const detailsGrid = document.getElementById("analyzer-details-grid");
    const hexCodeBlock = document.getElementById("analyzer-hexdump-code");
    
    // Reports Selects / File uploads
    const reportSessionSelect = document.getElementById("report-session-select");
    const exportPdfBtn = document.getElementById("export-pdf-btn");
    const exportCsvBtn = document.getElementById("export-csv-btn");
    const exportJsonBtn = document.getElementById("export-json-btn");
    const pcapInput = document.getElementById("pcap-file-input");
    const pcapUploadBtn = document.getElementById("pcap-upload-btn");
    
    // Settings
    const portscanThreshold = document.getElementById("settings-portscan-threshold");
    const synfloodThreshold = document.getElementById("settings-synflood-threshold");
    const soundToggle = document.getElementById("settings-sound-alert");
    const autoSaveToggle = document.getElementById("settings-autosave");
    const settingsSaveBtn = document.getElementById("settings-save-btn");

    // Audio Context for alarm sound synthesis
    let audioCtx = null;

    // --- CHART INITIALIZATION ---
    
    // 1. Live Traffic throughput Line Chart
    const ctxTraffic = document.getElementById("liveTrafficChart").getContext("2d");
    const liveTrafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: trafficTimeLabels,
            datasets: [{
                label: 'Packets / Sec',
                data: trafficRatesHistory,
                borderColor: '#00f0ff',
                backgroundColor: 'rgba(0, 240, 255, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' }, beginAtZero: true }
            }
        }
    });

    // 2. Protocol Pie Chart
    const ctxProtocol = document.getElementById("protocolPieChart").getContext("2d");
    const protocolPieChart = new Chart(ctxProtocol, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#14b8a6', '#f43f5e']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } } }
        }
    });

    // 3. Top Destination IPs bar chart
    const ctxDest = document.getElementById("topDestIPsChart").getContext("2d");
    const topDestIPsChart = new Chart(ctxDest, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packet Density',
                data: [],
                backgroundColor: 'rgba(57, 255, 20, 0.65)',
                borderColor: '#39ff14',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
            }
        }
    });

    // 4. Bandwidth consumption area chart
    const ctxBandwidth = document.getElementById("bandwidthChart").getContext("2d");
    const bandwidthChart = new Chart(ctxBandwidth, {
        type: 'line',
        data: {
            labels: trafficTimeLabels,
            datasets: [{
                label: 'Data Rate (KB/s)',
                data: bandwidthHistory,
                borderColor: '#eab308',
                backgroundColor: 'rgba(234, 179, 8, 0.1)',
                borderWidth: 2,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' }, beginAtZero: true }
            }
        }
    });

    // --- TAB SWITCHING (ROUTING) ---
    sidebarItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const targetPanel = item.getAttribute("data-target");
            
            // Switch Sidebar active state
            sidebarItems.forEach(i => i.classList.remove("active"));
            item.classList.add("active");
            
            // Switch Panel view
            viewPanels.forEach(p => p.classList.remove("active"));
            const activePanel = document.getElementById(targetPanel);
            activePanel.classList.add("active");
            
            // Header Title change
            const linkText = item.querySelector("a").textContent;
            panelTitle.textContent = linkText;
            
            // Trigger specific actions when switching to panels
            if (targetPanel === "panel-reports") {
                fetchSessions();
            } else if (targetPanel === "panel-stats") {
                updateDeeperStatsCharts();
            } else if (targetPanel === "panel-analyzer") {
                refreshAnalyzerTable();
            }
        });
    });

    // --- THEME SWITCHER ---
    themeToggleBtn.addEventListener("click", () => {
        document.body.classList.toggle("light-theme");
        const isLight = document.body.classList.contains("light-theme");
        themeToggleBtn.innerHTML = isLight ? '<i class="fa-solid fa-sun"></i>' : '<i class="fa-solid fa-moon"></i>';
        
        // Update Chart font colors
        const fontColor = isLight ? '#0f172a' : '#94a3b8';
        [liveTrafficChart, protocolPieChart, topDestIPsChart, bandwidthChart].forEach(chart => {
            if (chart.options.scales) {
                if (chart.options.scales.x) chart.options.scales.x.ticks.color = fontColor;
                if (chart.options.scales.y) chart.options.scales.y.ticks.color = fontColor;
            }
            if (chart.options.plugins && chart.options.plugins.legend) {
                chart.options.plugins.legend.labels.color = fontColor;
            }
            chart.update();
        });
    });

    // --- ALARM SOUND SYNTHESIZER ---
    function playAlarmTone(severity) {
        if (!soundToggle.checked) return;
        
        try {
            if (!audioCtx) {
                audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            }
            
            // Synthesize different tones depending on severity
            let frequency = 523.25; // C5 default
            let duration = 0.2;
            let count = 1;
            
            if (severity === "critical") {
                frequency = 880.00; // A5
                duration = 0.35;
                count = 2; // Double warning beep
            } else if (severity === "high") {
                frequency = 783.99; // G5
                duration = 0.25;
            } else if (severity === "medium") {
                frequency = 587.33; // D5
                duration = 0.2;
            } else {
                frequency = 440.00; // A4 (lower notification)
                duration = 0.15;
            }

            function emitBeep(delay = 0) {
                setTimeout(() => {
                    const osc = audioCtx.createOscillator();
                    const gainNode = audioCtx.createGain();
                    
                    osc.type = severity === "critical" ? "sawtooth" : "sine";
                    osc.frequency.value = frequency;
                    
                    gainNode.gain.setValueAtTime(0.08, audioCtx.currentTime);
                    // Smooth volume decay
                    gainNode.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
                    
                    osc.connect(gainNode);
                    gainNode.connect(audioCtx.destination);
                    
                    osc.start();
                    osc.stop(audioCtx.currentTime + duration);
                }, delay);
            }
            
            for (let i = 0; i < count; i++) {
                emitBeep(i * 450); // space double warning beeps
            }
        } catch (e) {
            console.warn("Could not play synthesized audio alarm: ", e);
        }
    }

    // --- SYSTEM NOTIFICATION TOASTS ---
    function triggerToastNotification(title, message, severity = "low") {
        const toast = document.createElement("div");
        toast.className = `toast ${severity}`;
        
        let iconClass = "fa-info-circle";
        if (severity === "critical" || severity === "high") iconClass = "fa-triangle-exclamation";
        else if (severity === "medium") iconClass = "fa-bell";
        
        toast.innerHTML = `
            <i class="fa-solid ${iconClass} toast-icon"></i>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>
        `;
        
        document.getElementById("toast-container").appendChild(toast);
        
        // Audio
        playAlarmTone(severity);
        
        // Manual click to dismiss toast instantly
        toast.style.cursor = "pointer";
        toast.addEventListener("click", () => {
            toast.style.transition = "all 0.3s ease-out";
            toast.style.opacity = "0";
            toast.style.transform = "translateX(100%)";
            setTimeout(() => toast.remove(), 300);
        });

        // Auto remove toast after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.style.transition = "all 0.5s ease-out";
                toast.style.opacity = "0";
                toast.style.transform = "translateX(100%)";
                setTimeout(() => {
                    if (toast.parentNode) toast.remove();
                }, 500);
            }
        }, 5000);
    }

    // --- CAPTURE CONTROLS & API ACTIONS ---
    
    // Fetch available interfaces
    async function fetchInterfaces() {
        try {
            const res = await fetch("/api/interfaces");
            interfaces = await res.json();
            
            // Reset options but keep simulation
            ifaceSelect.innerHTML = '<option value="Simulation Mode">Simulation Mode (Fallback)</option>';
            interfaces.forEach(iface => {
                if (iface.name !== "Simulation Mode") {
                    const opt = document.createElement("option");
                    opt.value = iface.name;
                    opt.textContent = `${iface.description} [${iface.ip}]`;
                    ifaceSelect.appendChild(opt);
                }
            });
        } catch (e) {
            console.error("Could not fetch interfaces: ", e);
        }
    }
    
    ifaceRefreshBtn.addEventListener("click", fetchInterfaces);
    
    // Start capturing
    startBtn.addEventListener("click", async () => {
        const iface = ifaceSelect.value;
        startBtn.disabled = true;
        
        try {
            const res = await fetch("/api/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ interface: iface })
            });
            const data = await res.json();
            
            if (data.status === "success") {
                currentSessionId = data.session_id;
                isCapturing = true;
                isPaused = false;
                
                // Clear active stats counters
                resetSessionStats();
                packetTableBody.innerHTML = "";
                
                // Toggle status
                snifferIndicator.className = "status-indicator active";
                snifferStatusText.textContent = `Sniffing: ${iface}`;
                
                // Toggle Buttons
                pauseBtn.disabled = false;
                stopBtn.disabled = false;
                ifaceSelect.disabled = true;
                ifaceRefreshBtn.disabled = true;
                
                // Start WebSocket Stream
                connectWebSocket(data.session_id);
                
                if (data.is_simulated && iface !== "Simulation Mode") {
                    triggerToastNotification("Simulation Fallback", `Could not start live capture on ${iface} (WinPcap/Npcap missing or need Admin rights). Running in simulation mode.`, "high");
                    snifferStatusText.textContent = `Simulated: ${iface}`;
                } else {
                    triggerToastNotification("Sniffer Started", `Capturing packets on ${iface}`, "low");
                }
            } else {
                triggerToastNotification("Start Capture Error", data.message, "high");
                startBtn.disabled = false;
            }
        } catch (e) {
            console.error("Error starting sniffer: ", e);
            startBtn.disabled = false;
        }
    });

    // Pause capturing
    pauseBtn.addEventListener("click", async () => {
        if (!isCapturing) return;
        
        try {
            const url = isPaused ? "/api/resume" : "/api/pause";
            const res = await fetch(url, { method: "POST" });
            const data = await res.json();
            
            if (data.status === "success") {
                isPaused = !isPaused;
                if (isPaused) {
                    snifferIndicator.className = "status-indicator paused";
                    snifferStatusText.textContent = "Sniffer Paused";
                    pauseBtn.innerHTML = '<i class="fa-solid fa-play"></i> Resume';
                    triggerToastNotification("Sniffer Paused", "Packet processing suspended.", "low");
                } else {
                    snifferIndicator.className = "status-indicator active";
                    snifferStatusText.textContent = "Sniffing active...";
                    pauseBtn.innerHTML = '<i class="fa-solid fa-pause"></i> Pause';
                    triggerToastNotification("Sniffer Resumed", "Resuming packet parsing.", "low");
                }
            }
        } catch (e) {
            console.error("Error toggling pause state: ", e);
        }
    });

    // Stop capturing
    stopBtn.addEventListener("click", async () => {
        if (!isCapturing) return;
        
        try {
            const res = await fetch("/api/stop", { method: "POST" });
            const data = await res.json();
            
            if (data.status === "success") {
                cleanupCaptureState();
                triggerToastNotification("Sniffer Stopped", "Packet capturing closed. Session saved.", "low");
            }
        } catch (e) {
            console.error("Error stopping sniffer: ", e);
        }
    });

    clearTableBtn.addEventListener("click", () => {
        packetTableBody.innerHTML = '<tr><td colspan="7" style="text-align: center;">Table cleared. Packets are still recorded in DB.</td></tr>';
        packetSequenceNumber = 0;
    });

    function cleanupCaptureState() {
        isCapturing = false;
        isPaused = false;
        
        snifferIndicator.className = "status-indicator";
        snifferStatusText.textContent = "Sniffer Idle";
        
        startBtn.disabled = false;
        pauseBtn.disabled = true;
        pauseBtn.innerHTML = '<i class="fa-solid fa-pause"></i> Pause';
        stopBtn.disabled = true;
        
        ifaceSelect.disabled = false;
        ifaceRefreshBtn.disabled = false;
        
        if (socket) {
            socket.close();
            socket = null;
        }
    }

    function resetSessionStats() {
        totalPackets = 0;
        threatAlerts = 0;
        activeDevices.clear();
        protocolCounts = {};
        packetSequenceNumber = 0;
        
        cardPackets.textContent = "0";
        cardRate.textContent = "0.0/s";
        cardAlerts.textContent = "0";
        cardDevices.textContent = "0";
        
        trafficRatesHistory.fill(0);
        bandwidthHistory.fill(0);
        trafficTimeLabels.fill("");
        
        threatsTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No malicious vectors detected by NetGuard IDS.</td></tr>';
        dashboardRecentAlerts.innerHTML = '<tr><td colspan="4" style="text-align: center;">No threats detected</td></tr>';
        dashboardTopSources.innerHTML = '<tr><td colspan="2" style="text-align: center;">No active traffic data</td></tr>';
    }

    // --- WEBSOCKET EVENT HANDLER ---
    function connectWebSocket(sessionId) {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws/${sessionId}`;
        
        socket = new WebSocket(wsUrl);
        
        socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === "packet") {
                handleIncomingPacket(data.data);
            } else if (data.type === "alert") {
                handleIncomingAlert(data.data);
            } else if (data.type === "stats") {
                handleIncomingStats(data.data);
            }
        };
        
        socket.onerror = (err) => {
            console.error("WebSocket error: ", err);
        };
        
        socket.onclose = () => {
            console.log("WebSocket connection closed.");
        };
    }

    function handleIncomingPacket(p) {
        if (isPaused) return;
        
        packetSequenceNumber++;
        totalPackets++;
        cardPackets.textContent = totalPackets;
        
        // Add active devices
        if (p.src_ip) activeDevices.add(p.src_ip);
        if (p.dst_ip) activeDevices.add(p.dst_ip);
        cardDevices.textContent = activeDevices.size;
        
        // Append to Grid in Live Capture Panel
        const newRow = document.createElement("tr");
        newRow.style.cursor = "pointer";
        newRow.dataset.id = p.id || "";
        newRow.innerHTML = `
            <td>${packetSequenceNumber}</td>
            <td>${new Date(p.timestamp * 1000).toLocaleTimeString()}</td>
            <td>${p.src_ip || "N/A"}</td>
            <td>${p.dst_ip || "N/A"}</td>
            <td><span class="badge badge-proto">${p.protocol}</span></td>
            <td>${p.length}</td>
            <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${p.summary}</td>
        `;
        
        // Open selected row details in Analyzer
        newRow.addEventListener("click", () => {
            // Highlight
            const rows = packetTableBody.querySelectorAll("tr");
            rows.forEach(r => r.classList.remove("selected-row"));
            newRow.classList.add("selected-row");
            
            selectedPacketId = p.id;
            // Instantly go to analyzer panel
            openPacketInAnalyzer(p);
        });
        
        if (packetTableBody.firstChild) {
            packetTableBody.insertBefore(newRow, packetTableBody.firstChild);
        } else {
            packetTableBody.appendChild(newRow);
        }
        
        // Limit table rows for DOM efficiency
        if (packetTableBody.childNodes.length > 300) {
            packetTableBody.removeChild(packetTableBody.lastChild);
        }
        
        // Update protocol count
        protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + 1;
        updateProtocolPieChart();
    }

    function handleIncomingAlert(a) {
        threatAlerts++;
        cardAlerts.textContent = threatAlerts;
        
        // Create Alarm Toaster
        const severity = a.severity.toLowerCase();
        triggerToastNotification(a.threat_type, `${a.details} (Source: ${a.src_ip || "Unknown"})`, severity);
        
        // Add row to Threats panel
        const timeStr = new Date(a.timestamp * 1000).toLocaleTimeString();
        const tbody = threatsTableBody;
        
        // Clear placeholder
        if (tbody.innerHTML.includes("No malicious vectors")) {
            tbody.innerHTML = "";
        }
        
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${threatAlerts}</td>
            <td>${timeStr}</td>
            <td style="font-weight: 600;">${a.threat_type}</td>
            <td><span class="badge badge-${severity}">${a.severity}</span></td>
            <td>${a.src_ip || "N/A"}</td>
            <td>${a.details}</td>
        `;
        tbody.insertBefore(tr, tbody.firstChild);
        
        // Add to Dashboard recent alerts list
        const dAlertsTbody = dashboardRecentAlerts;
        if (dAlertsTbody.innerHTML.includes("No threats detected")) {
            dAlertsTbody.innerHTML = "";
        }
        const dtr = document.createElement("tr");
        dtr.innerHTML = `
            <td>${timeStr}</td>
            <td style="font-weight: 600;">${a.threat_type}</td>
            <td><span class="badge badge-${severity}">${a.severity}</span></td>
            <td>${a.src_ip || "N/A"}</td>
        `;
        dAlertsTbody.insertBefore(dtr, dAlertsTbody.firstChild);
        if (dAlertsTbody.childNodes.length > 5) {
            dAlertsTbody.removeChild(dAlertsTbody.lastChild);
        }
    }

    function handleIncomingStats(s) {
        // Update Live chart scroll rate datasets
        const timeStr = new Date().toLocaleTimeString().split(" ")[0];
        
        trafficRatesHistory.push(s.packet_rate);
        trafficRatesHistory.shift();
        
        bandwidthHistory.push(s.bytes_rate / 1024); // KB/s
        bandwidthHistory.shift();
        
        trafficTimeLabels.push(timeStr);
        trafficTimeLabels.shift();
        
        liveTrafficChart.update();
        bandwidthChart.update();
        
        cardRate.textContent = `${s.packet_rate.toFixed(1)}/s`;
        
        // Update top sources table
        if (s.top_sources && s.top_sources.length > 0) {
            dashboardTopSources.innerHTML = "";
            s.top_sources.forEach(src => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono);">${src.ip}</td>
                    <td><b>${src.count}</b> pkts</td>
                `;
                dashboardTopSources.appendChild(tr);
            });
        }
    }

    // --- CHART UPDATES ---
    function updateProtocolPieChart() {
        const labels = Object.keys(protocolCounts);
        const data = Object.values(protocolCounts);
        
        protocolPieChart.data.labels = labels;
        protocolPieChart.data.datasets[0].data = data;
        protocolPieChart.update();
    }

    async function updateDeeperStatsCharts() {
        if (!currentSessionId) return;
        try {
            const res = await fetch(`/api/session/${currentSessionId}/stats`);
            const stats = await res.json();
            
            // Update Destination IPs Chart
            if (stats.top_destinations && stats.top_destinations.length > 0) {
                topDestIPsChart.data.labels = stats.top_destinations.map(d => d.ip);
                topDestIPsChart.data.datasets[0].data = stats.top_destinations.map(d => d.count);
                topDestIPsChart.update();
            }
            
            // Average Size & totals
            const totalsRes = await fetch(`/api/session/${currentSessionId}/totals`);
            const totals = await totalsRes.json();
            
            document.getElementById("stats-avg-size").textContent = `${Math.round(totals.avg_size || 0)} B`;
            document.getElementById("stats-duration").textContent = `${Math.round(totals.duration_sec || 0)}s`;
            
            const totalKb = (totals.total_bytes || 0) / 1024;
            document.getElementById("stats-total-bytes").textContent = totalKb > 1024 
                ? `${(totalKb / 1024).toFixed(1)} MB` 
                : `${totalKb.toFixed(1)} KB`;
                
        } catch (e) {
            console.error("Error updating stats charts: ", e);
        }
    }

    // --- PACKET ANALYZER ACTIONS ---
    function openPacketInAnalyzer(p) {
        // Go to analyzer tab
        document.querySelector('[data-target="panel-analyzer"]').click();
        
        // Fill Header mapping details panel
        detailsGrid.innerHTML = `
            <div class="kv-key">Packet ID:</div><div class="kv-value">#${p.id || packetSequenceNumber}</div>
            <div class="kv-key">Timestamp:</div><div class="kv-value">${new Date(p.timestamp * 1000).toLocaleString()}</div>
            <div class="kv-key">Source MAC:</div><div class="kv-value" style="font-family: var(--font-mono);">${p.src_mac || "N/A"}</div>
            <div class="kv-key">Dest MAC:</div><div class="kv-value" style="font-family: var(--font-mono);">${p.dst_mac || "N/A"}</div>
            <div class="kv-key">Source IP:</div><div class="kv-value" style="font-weight:600;">${p.src_ip || "N/A"}</div>
            <div class="kv-key">Dest IP:</div><div class="kv-value" style="font-weight:600;">${p.dst_ip || "N/A"}</div>
            <div class="kv-key">Ports (Src/Dst):</div><div class="kv-value">${p.src_port || "-"}:${p.dst_port || "-"}</div>
            <div class="kv-key">TTL / Flags:</div><div class="kv-value">TTL: ${p.ttl || "-"} / Flags: [${p.flags || "-"}]</div>
        `;
        
        // Fill hex code block
        if (p.payload_hex) {
            hexCodeBlock.textContent = p.payload_hex;
        } else {
            hexCodeBlock.textContent = `[Frame length: ${p.length} Bytes]\nNo transport-layer raw payload payload payload block detected.`;
        }
    }

    // Search and apply filter query on Analyzer left side list
    async function refreshAnalyzerTable() {
        if (!currentSessionId) return;
        
        const proto = document.getElementById("filter-proto").value;
        const ip = document.getElementById("filter-ip").value;
        const port = document.getElementById("filter-port").value;
        const kw = document.getElementById("filter-search").value;
        
        let queryParams = new URLSearchParams();
        if (proto) queryParams.append("protocol", proto);
        if (ip) queryParams.append("ip", ip);
        if (port) queryParams.append("port", port);
        if (kw) queryParams.append("keyword", kw);
        
        try {
            const res = await fetch(`/api/session/${currentSessionId}/packets?${queryParams.toString()}`);
            const packets = await res.json();
            
            analyzerTableBody.innerHTML = "";
            if (packets.length === 0) {
                analyzerTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No matching packets match filters.</td></tr>';
                return;
            }
            
            packets.forEach((p, idx) => {
                const tr = document.createElement("tr");
                tr.style.cursor = "pointer";
                tr.innerHTML = `
                    <td>${packets.length - idx}</td>
                    <td>${new Date(p.timestamp * 1000).toLocaleTimeString()}</td>
                    <td>${p.src_ip || "N/A"}</td>
                    <td>${p.dst_ip || "N/A"}</td>
                    <td><span class="badge badge-proto">${p.protocol}</span></td>
                    <td>${p.length}</td>
                `;
                
                tr.addEventListener("click", () => {
                    const rows = analyzerTableBody.querySelectorAll("tr");
                    rows.forEach(r => r.classList.remove("selected-row"));
                    tr.classList.add("selected-row");
                    
                    openPacketInAnalyzer(p);
                });
                
                analyzerTableBody.appendChild(tr);
            });
        } catch (e) {
            console.error("Error filtering packets: ", e);
        }
    }

    document.getElementById("analyzer-filter-btn").addEventListener("click", refreshAnalyzerTable);
    document.getElementById("analyzer-reset-btn").addEventListener("click", () => {
        document.getElementById("filter-proto").value = "";
        document.getElementById("filter-ip").value = "";
        document.getElementById("filter-port").value = "";
        document.getElementById("filter-search").value = "";
        refreshAnalyzerTable();
    });

    // --- REPORTS MANAGEMENT PANEL ---
    async function fetchSessions() {
        try {
            const res = await fetch("/api/sessions");
            const sessions = await res.json();
            
            reportsSessionsTable.innerHTML = "";
            reportSessionSelect.innerHTML = '<option value="">-- Select Capture Session --</option>';
            
            if (sessions.length === 0) {
                reportsSessionsTable.innerHTML = '<tr><td colspan="5" style="text-align: center;">No stored database capture records found.</td></tr>';
                return;
            }
            
            sessions.forEach(s => {
                const dateStr = new Date(s.created_at * 1000).toLocaleString();
                
                // Add option to reports selector dropdown
                const opt = document.createElement("option");
                opt.value = s.session_id;
                opt.textContent = `${s.name} (${dateStr})`;
                reportSessionSelect.appendChild(opt);
                
                // Add row to table
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td style="max-width: 100px; overflow:hidden; text-overflow:ellipsis;">${s.session_id}</td>
                    <td><b>${s.name}</b></td>
                    <td>${dateStr}</td>
                    <td>${s.packet_count} / <span style="color:var(--sev-critical);">${s.alert_count} alerts</span></td>
                    <td>
                        <button class="btn btn-secondary btn-sm select-session-btn" data-id="${s.session_id}" style="padding: 4px 8px; font-size:11px;">
                            <i class="fa-solid fa-folder-open"></i> Load
                        </button>
                        <button class="btn btn-danger btn-sm delete-session-btn" data-id="${s.session_id}" style="padding: 4px 8px; font-size:11px;">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </td>
                `;
                
                // Load Session listener
                tr.querySelector(".select-session-btn").addEventListener("click", () => {
                    currentSessionId = s.session_id;
                    totalPackets = s.packet_count;
                    cardPackets.textContent = totalPackets;
                    cardAlerts.textContent = s.alert_count;
                    
                    triggerToastNotification("Session Loaded", `Loaded capture session '${s.name}' into context.`, "low");
                    // Sync selector
                    reportSessionSelect.value = s.session_id;
                    
                    // Force refresh panels if we switch
                    refreshAnalyzerTable();
                });
                
                // Delete Session listener
                tr.querySelector(".delete-session-btn").addEventListener("click", async () => {
                    if (confirm(`Are you sure you want to delete session '${s.name}'?`)) {
                        try {
                            const delRes = await fetch(`/api/session/${s.session_id}`, { method: "DELETE" });
                            const delData = await delRes.json();
                            if (delData.status === "success") {
                                triggerToastNotification("Session Deleted", "Record deleted from DB.", "low");
                                fetchSessions();
                                if (currentSessionId === s.session_id) {
                                    resetSessionStats();
                                    currentSessionId = "";
                                }
                            }
                        } catch (err) {
                            console.error(err);
                        }
                    }
                });
                
                reportsSessionsTable.appendChild(tr);
            });
            
            // Sync report selector value
            if (currentSessionId) {
                reportSessionSelect.value = currentSessionId;
            }
        } catch (e) {
            console.error("Error loading sessions: ", e);
        }
    }

    // Download/export functions
    exportPdfBtn.addEventListener("click", () => triggerReportDownload("pdf"));
    exportCsvBtn.addEventListener("click", () => triggerReportDownload("csv"));
    exportJsonBtn.addEventListener("click", () => triggerReportDownload("json"));
    
    function triggerReportDownload(format) {
        const sessId = reportSessionSelect.value;
        if (!sessId) {
            triggerToastNotification("Export Denied", "Please select a capture session to export.", "high");
            return;
        }
        
        window.open(`/api/reports/${format}?session_id=${sessId}`, '_blank');
        triggerToastNotification("Report Triggered", `Downloading forensic ${format.toUpperCase()} report...`, "low");
    }

    // --- PCAP UPLOAD / IMPORT ---
    pcapInput.addEventListener("change", () => {
        if (pcapInput.files.length > 0) {
            pcapUploadBtn.disabled = false;
            pcapUploadBtn.innerHTML = `<i class="fa-solid fa-file-export"></i> Process ${pcapInput.files[0].name}`;
        }
    });
    
    pcapUploadBtn.addEventListener("click", async () => {
        if (pcapInput.files.length === 0) return;
        
        const file = pcapInput.files[0];
        const formData = new FormData();
        formData.append("file", file);
        
        pcapUploadBtn.disabled = true;
        pcapUploadBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Parsing headers...';
        
        try {
            const res = await fetch("/api/pcap/import", {
                method: "POST",
                body: formData
            });
            const data = await res.json();
            
            if (data.status === "success") {
                currentSessionId = data.session_id;
                totalPackets = data.packet_count;
                threatAlerts = data.alert_count;
                
                cardPackets.textContent = totalPackets;
                cardAlerts.textContent = threatAlerts;
                
                triggerToastNotification("PCAP Imported", `Successfully analyzed PCAP file. Found ${data.packet_count} packets and flagged ${data.alert_count} anomalies.`, "medium");
                
                pcapInput.value = "";
                pcapUploadBtn.innerHTML = '<i class="fa-solid fa-upload"></i> Process File';
                
                // Refresh sessions and load
                fetchSessions();
            } else {
                triggerToastNotification("Import Failed", data.message, "high");
                pcapUploadBtn.disabled = false;
                pcapUploadBtn.innerHTML = '<i class="fa-solid fa-upload"></i> Process File';
            }
        } catch (e) {
            console.error("Error uploading PCAP: ", e);
            triggerToastNotification("Upload Error", "Could not submit file to backend.", "high");
            pcapUploadBtn.disabled = false;
            pcapUploadBtn.innerHTML = '<i class="fa-solid fa-upload"></i> Process File';
        }
    });

    // --- SETTINGS PRESERVES ---
    settingsSaveBtn.addEventListener("click", async () => {
        const payload = {
            portscan_threshold: parseInt(portscanThreshold.value),
            synflood_threshold: parseInt(synfloodThreshold.value),
            sound_alert: soundToggle.checked,
            autosave: autoSaveToggle.checked
        };
        
        try {
            const res = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.status === "success") {
                triggerToastNotification("Settings Saved", "Intrusion thresholds updated successfully.", "low");
            }
        } catch (e) {
            console.error("Error saving settings: ", e);
        }
    });

    // Initialize Page
    fetchInterfaces();
});
