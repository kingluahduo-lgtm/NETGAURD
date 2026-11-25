# NetGuard – Intelligent Packet Sniffer & Network Threat Analyzer

NetGuard is a production-quality network analysis and security platform. It captures live network packets, decodes standard transport and application layer headers in real time, runs traffic through a stateful Intrusion Detection System (IDS) engine, visualizes traffic trends, and compiles forensic security audit reports. 

Built with a modular Python backend (FastAPI, Scapy, PyShark, SQLite, Pandas, ReportLab) and a responsive glassmorphic security dashboard (HTML5, CSS, Chart.js, WebSockets), NetGuard is designed for security engineers, analysts, and administrators.

---

## Architecture Diagram

```text
                     +---------------------------------------+
                     |        Target Network Interface       |
                     +-------------------+-------------------+
                                         |
                                         v (Live Sniffing / Mock Fallback)
                     +-------------------+-------------------+
                     |         capture/sniffer.py            |
                     +-------------------+-------------------+
                                         |
                                         v (Raw Scapy Packet)
                     +-------------------+-------------------+
                     |      analyzer/packet_parser.py        |
                     +---------+-------------------+---------+
                               |                   |
        (Extracts Metadata)    v                   v    (Evaluate Signatures)
                     +---------+---------+   +-----+-----------------+
                     |analyzer/protocols |   |detector/ids_engine.py |
                     +---------+---------+   +-----+--------+--------+
                               |                            |
                               | (Parsed Packet)            | (Security Alert)
                               v                            v
                     +---------+----------------------------+--------+
                     |               database/db_manager.py          |
                     +-----------------------+-----------------------+
                                             |
                   +-------------------------+-------------------------+
                   |                                                   |
                   v (WebSocket Stream)                                v (Forensic Queries)
     +-------------+-------------+                       +-------------+-------------+
     |     main.py (FastAPI)     |                       |reports/report_generator.py|
     +-------------+-------------+                       +-------------+-------------+
                   |                                                   |
                   v (Real-Time Visuals)                               v (Audit Document)
     +-------------+-------------+                       +-------------+-------------+
     |   Web Dashboard (HTML/JS) |                       |     PDF / CSV / JSON      |
     +---------------------------+                       +---------------------------+
```

---

## Key Features

1. **Dual Capture Modes**: Supports live promiscuous-mode packet sniffing on any active network interface. If ran without administrative privileges or on machines missing packet capture drivers, it automatically launches in **Simulation Mode** (mocking realistic network traffic and security attack simulations).
2. **Stateful Intrusion Detection System (IDS)**: Inspects packets against rules to identify and flag threats:
   - Port Scanning, SYN Flood, ICMP Flood (Ping of Death), ARP Spoofing/Poisoning, DNS Floods, Broadcast Storms, MAC Table Floods, Large Packet MTU Abuse, and Excessive Failed SSH Login Sequences.
3. **Deep Packet Decoder**: decodes Ethernet, IP/IPv6, TCP, UDP, ARP, and ICMP headers. Provides direct payload extraction formatted in standard Hex Dump columns and ASCII characters.
4. **Rich Operations Dashboard**: Live interactive counters, packet rate sparklines, dynamic protocol doughnut charts, bandwidth history trackers, recent alerts panel, and a live top-talkers source IP leaderboard.
5. **Report Center**: Generates ReportLab-powered PDF Security Audits including Executive Summary tables, threat logs, protocol stats, top IP grids, and contextual security recommendations, as well as raw JSON and CSV captures.
6. **PCAP Imports**: Allows importing existing Wireshark `.pcap` / `.pcapng` logs to execute the IDS rules offline and save data to SQLite.
7. **Zero-Dependency Alerts**: Generates Toast notifications and synthesizes alarm sounds directly in the browser via the Web Audio API (no local sound files required).

---

## Directory Structure

```text
NetGuard/
│
├── main.py                    # Server runner (FastAPI, WebSockets, Browser launcher)
├── requirements.txt           # Python application dependencies
├── README.md                  # Detailed platform guide
│
├── capture/
│   ├── interface.py           # Network interface listing
│   └── sniffer.py             # Live Scapy sniffing & Simulated generator threads
│
├── analyzer/
│   ├── packet_parser.py       # Packet field parser, hex dump & ASCII formatters
│   └── protocols.py           # Layer 4/7 Protocol port identifiers
│
├── detector/
│   └── ids_engine.py          # Sliding window threat analyzer & alert rules
│
├── database/
│   └── db_manager.py          # SQLite database connection & query manager
│
├── reports/
│   └── report_generator.py    # PDF (ReportLab), CSV, JSON report engines
│
├── utils/
│   ├── geoip.py               # GeoIP client (Mocked database & Online API fallback)
│   └── logger.py              # File rotating logger (app.log & threat.log)
│
├── assets/                    # Static Web Dashboard assets
│   ├── css/style.css          # Cyberpunk/Dark themed stylesheet
│   ├── js/app.js              # WebSockets client, Chart.js updates, synthesizers
│   └── templates/index.html   # Main dashboard layout
│
├── tests/
│   └── test_netguard.py       # Automated testing suite
│
├── logs/                      # Application activity logs
└── captures/                  # Stored SQLite databases & exported PCAP records
```

---

## Installation & Setup

### Prerequisites
- **Python 3.8+** must be installed.
- **Npcap** (Windows) or **libpcap** (Linux/macOS) is required for live network card sniffing.
  - Windows users: Install [Npcap](https://npcap.com/) (select "Install Npcap with WinPcap-compatibility" during setup).
  - Linux users: Install libpcap via `sudo apt install libpcap-dev`.

### Installing Dependencies
Clone or copy the workspace files and run:
```bash
pip install -r requirements.txt
```

### Running NetGuard
To start the FastAPI server and automatically launch the dashboard in your default browser:
- **Windows (Administrator Terminal required for live capture)**:
  ```powershell
  python main.py
  ```
- **Linux / macOS**:
  ```bash
  sudo python main.py
  ```

---

## Threat Detection Rule Details

- **Port Scan**: Triggered if a source IP targets more than 15 unique ports in a 5-second window (Severity: **High**).
- **SYN Flood**: Triggered if TCP SYN packet frequency exceeds 50 packets/sec from an individual IP (Severity: **High**).
- **ARP Spoofing**: Triggered if NetGuard spots multiple MAC addresses claiming the same IP (IP collision) or rogue ARP reply updates (Severity: **Critical**).
- **DNS Query Flood**: Triggered if query velocity exceeds 30/sec, or lookups target suspicious blacklisted words like "botnet" or "malware" (Severity: **Medium**).
- **MAC Flood**: Triggered if more than 50 unique MAC addresses transmit on the link within 5 seconds (Severity: **High**).
- **Broadcast Storm**: Triggered if broadcast frames represent more than 40% of captured packets (Severity: **Medium**).
- **Failed SSH Connections**: Triggered if TCP handshakes on Port 22 close or fail more than 5 times in 10 seconds (Severity: **High**).

---

## Troubleshooting

1. **Scapy socket permission error**: If you get a warning saying `L2socket creation failed` on launch, the application will default to **Simulation Mode**. To capture real network cards, run the terminal as Administrator (Windows) or with `sudo` (Linux).
2. **WebSocket connection drops**: Ensure your browser supports WebSockets. If hosting behind a reverse proxy (like Nginx), make sure to configure WebSocket forwarding rules.
3. **No Network interfaces listed**: Click the **Scan** button next to the dropdown in the Live Capture panel to trigger a reload of local adapter devices.
