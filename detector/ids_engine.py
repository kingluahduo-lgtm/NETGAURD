import time
from collections import defaultdict
from utils.logger import get_threat_logger

threat_logger = get_threat_logger()

class IDSEngine:
    def __init__(self):
        # Sliding window tracker storage: maps src_ip -> list of timestamps/details
        self.port_scan_tracker = defaultdict(list)  # src_ip -> [(timestamp, port)]
        self.syn_flood_tracker = defaultdict(list)  # src_ip -> [timestamps]
        self.icmp_flood_tracker = defaultdict(list)  # src_ip -> [timestamps]
        self.dns_flood_tracker = defaultdict(list)  # src_ip -> [timestamps]
        self.ssh_fail_tracker = defaultdict(list)   # src_ip -> [timestamps]
        self.large_packet_tracker = defaultdict(list) # src_ip -> [timestamps]
        
        # ARP Spoofing tracker: maps IP -> MAC
        self.arp_cache = {}
        
        # MAC Flood tracker: list of (timestamp, src_mac)
        self.macs_seen = []
        
        # Broadcast Storm tracker: list of (timestamp, is_broadcast)
        self.broadcast_history = []
        
        # Cooldown trackers to prevent spamming duplicate alerts (maps threat_type_ip -> last_alert_time)
        self.cooldowns = {}
        self.COOLDOWN_PERIOD = 10.0  # 10 seconds suppression per threat/IP pair

    def _clean_trackers(self, now: float):
        """Purge records older than 5-10 seconds to maintain sliding window constraints."""
        window_5s = now - 5.0
        window_10s = now - 10.0
        
        # Clean Port Scan
        for ip in list(self.port_scan_tracker.keys()):
            self.port_scan_tracker[ip] = [x for x in self.port_scan_tracker[ip] if x[0] > window_5s]
            if not self.port_scan_tracker[ip]:
                del self.port_scan_tracker[ip]
                
        # Clean SYN Flood
        for ip in list(self.syn_flood_tracker.keys()):
            self.syn_flood_tracker[ip] = [t for t in self.syn_flood_tracker[ip] if t > window_5s]
            if not self.syn_flood_tracker[ip]:
                del self.syn_flood_tracker[ip]

        # Clean ICMP Flood
        for ip in list(self.icmp_flood_tracker.keys()):
            self.icmp_flood_tracker[ip] = [t for t in self.icmp_flood_tracker[ip] if t > window_5s]
            if not self.icmp_flood_tracker[ip]:
                del self.icmp_flood_tracker[ip]

        # Clean DNS Flood
        for ip in list(self.dns_flood_tracker.keys()):
            self.dns_flood_tracker[ip] = [t for t in self.dns_flood_tracker[ip] if t > window_5s]
            if not self.dns_flood_tracker[ip]:
                del self.dns_flood_tracker[ip]

        # Clean SSH failed attempts
        for ip in list(self.ssh_fail_tracker.keys()):
            self.ssh_fail_tracker[ip] = [t for t in self.ssh_fail_tracker[ip] if t > window_10s]
            if not self.ssh_fail_tracker[ip]:
                del self.ssh_fail_tracker[ip]

        # Clean Large Packets
        for ip in list(self.large_packet_tracker.keys()):
            self.large_packet_tracker[ip] = [t for t in self.large_packet_tracker[ip] if t > window_5s]
            if not self.large_packet_tracker[ip]:
                del self.large_packet_tracker[ip]
                
        # Clean MAC Flood history
        self.macs_seen = [x for x in self.macs_seen if x[0] > window_5s]
        
        # Clean Broadcast Storm history
        self.broadcast_history = [x for x in self.broadcast_history if x[0] > window_10s]

    def _is_cooling_down(self, threat_type: str, ip: str, now: float) -> bool:
        """Determines if a duplicate alert should be suppressed."""
        key = f"{threat_type}_{ip}"
        last_alert = self.cooldowns.get(key, 0)
        if now - last_alert < self.COOLDOWN_PERIOD:
            return True
        self.cooldowns[key] = now
        return False

    def analyze(self, p: dict) -> list:
        """
        Analyzes a single parsed packet for threat vectors.
        Returns a list of alert dictionaries if threats are matched.
        """
        now = p["timestamp"]
        src_ip = p["src_ip"]
        dst_ip = p["dst_ip"]
        protocol = p["protocol"]
        length = p["length"]
        flags = p["flags"]
        dst_port = p["dst_port"]
        src_mac = p["src_mac"]
        dst_mac = p["dst_mac"]
        
        alerts = []
        
        # Clean sliding windows
        self._clean_trackers(now)
        
        # Skip analysis if packet has no source IP (unless MAC Flood or ARP spoof checks apply)
        if not src_ip and protocol != "ARP" and not src_mac:
            return []

        # ----------------------------------------------------
        # 1. ARP Spoofing Detection
        # ----------------------------------------------------
        if protocol == "ARP" and p["summary"].lower().find("reply") != -1:
            # Format: 'ARP reply 192.168.1.1 is at aa:bb:cc:dd:ee:ff'
            # We track IP-to-MAC associations.
            if src_ip and src_mac:
                # Exclude local broadcast MACs or empty mapping
                if src_mac != "00:00:00:00:00:00" and src_mac != "ff:ff:ff:ff:ff:ff":
                    if src_ip in self.arp_cache:
                        old_mac = self.arp_cache[src_ip]
                        if old_mac != src_mac:
                            if not self._is_cooling_down("ARP_SPOOF", src_ip, now):
                                alerts.append({
                                    "timestamp": now,
                                    "threat_type": "ARP Spoofing Detected",
                                    "severity": "Critical",
                                    "src_ip": src_ip,
                                    "details": f"IP address {src_ip} claimed by multiple MACs: {old_mac} and rogue {src_mac}."
                                })
                    else:
                        self.arp_cache[src_ip] = src_mac

        # ----------------------------------------------------
        # 2. Port Scanning Detection
        # ----------------------------------------------------
        if src_ip and dst_port and protocol in ("TCP", "UDP"):
            # Register port access
            self.port_scan_tracker[src_ip].append((now, dst_port))
            # Check number of unique ports hit in sliding window
            unique_ports = set(port for t, port in self.port_scan_tracker[src_ip])
            if len(unique_ports) > 15:
                if not self._is_cooling_down("PORT_SCAN", src_ip, now):
                    alerts.append({
                        "timestamp": now,
                        "threat_type": "Port Scanning Activity",
                        "severity": "High",
                        "src_ip": src_ip,
                        "details": f"Source IP scanned {len(unique_ports)} unique ports in 5 seconds."
                    })

        # ----------------------------------------------------
        # 3. SYN Flood Detection
        # ----------------------------------------------------
        if src_ip and protocol == "TCP" and "S" in flags and "A" not in flags:
            self.syn_flood_tracker[src_ip].append(now)
            if len(self.syn_flood_tracker[src_ip]) > 50:
                if not self._is_cooling_down("SYN_FLOOD", src_ip, now):
                    alerts.append({
                        "timestamp": now,
                        "threat_type": "SYN Flood Attack",
                        "severity": "High",
                        "src_ip": src_ip,
                        "details": f"TCP SYN flood detected. Packet rate exceeds 50 SYN packets/sec."
                    })

        # ----------------------------------------------------
        # 4. ICMP Flood Detection
        # ----------------------------------------------------
        if src_ip and protocol == "ICMP" and "request" in p["summary"].lower():
            self.icmp_flood_tracker[src_ip].append(now)
            if len(self.icmp_flood_tracker[src_ip]) > 30:
                if not self._is_cooling_down("ICMP_FLOOD", src_ip, now):
                    alerts.append({
                        "timestamp": now,
                        "threat_type": "ICMP Flood (Ping of Death)",
                        "severity": "Medium",
                        "src_ip": src_ip,
                        "details": f"ICMP Echo Request rate exceeds 30 pings/sec."
                    })

        # ----------------------------------------------------
        # 5. DNS Flood Detection
        # ----------------------------------------------------
        if src_ip and protocol == "DNS":
            self.dns_flood_tracker[src_ip].append(now)
            if len(self.dns_flood_tracker[src_ip]) > 30:
                if not self._is_cooling_down("DNS_FLOOD", src_ip, now):
                    alerts.append({
                        "timestamp": now,
                        "threat_type": "DNS Query Flood",
                        "severity": "Medium",
                        "src_ip": src_ip,
                        "details": f"DNS query burst detected. Request rate exceeds 30 queries/sec."
                    })

        # ----------------------------------------------------
        # 6. Suspicious DNS Requests
        # ----------------------------------------------------
        if protocol == "DNS" and p["payload_ascii"]:
            payload_lower = p["payload_ascii"].lower()
            malicious_keywords = ["botnet", "malware", "phishing", "c2-server", "suspicious-botnet"]
            matched_kw = [kw for kw in malicious_keywords if kw in payload_lower]
            if matched_kw:
                if not self._is_cooling_down("SUSPICIOUS_DNS", src_ip, now):
                    alerts.append({
                        "timestamp": now,
                        "threat_type": "Suspicious DNS Request",
                        "severity": "Medium",
                        "src_ip": src_ip,
                        "details": f"DNS request resolved a domain containing suspicious keyword: '{matched_kw[0]}'."
                    })

        # ----------------------------------------------------
        # 7. MAC Flood Detection
        # ----------------------------------------------------
        if src_mac and src_mac != "00:00:00:00:00:00" and src_mac != "ff:ff:ff:ff:ff:ff":
            self.macs_seen.append((now, src_mac))
            unique_macs = set(mac for t, mac in self.macs_seen)
            if len(unique_macs) > 50:
                if not self._is_cooling_down("MAC_FLOOD", "network", now):
                    alerts.append({
                        "timestamp": now,
                        "threat_type": "MAC Table Flooding",
                        "severity": "High",
                        "src_ip": src_ip or "0.0.0.0",
                        "details": f"MAC Address Flooding detected. {len(unique_macs)} unique MAC addresses seen on the network in 5 seconds."
                    })

        # ----------------------------------------------------
        # 8. Broadcast Storm Detection
        # ----------------------------------------------------
        is_broadcast = (dst_mac == "ff:ff:ff:ff:ff:ff" or dst_ip == "255.255.255.255")
        self.broadcast_history.append((now, is_broadcast))
        # Evaluate broadcast ratio in the last 100 packets (if we have at least 30 packets)
        if len(self.broadcast_history) >= 30:
            broadcast_count = sum(1 for t, b in self.broadcast_history if b)
            ratio = broadcast_count / len(self.broadcast_history)
            if ratio > 0.40: # Exceeds 40% of captured traffic
                if not self._is_cooling_down("BROADCAST_STORM", "network", now):
                    alerts.append({
                        "timestamp": now,
                        "threat_type": "Broadcast Storm Warning",
                        "severity": "Medium",
                        "src_ip": src_ip or "0.0.0.0",
                        "details": f"Broadcast traffic constitutes {int(ratio*100)}% of network transmissions in the last 10 seconds."
                    })

        # ----------------------------------------------------
        # 9. Large Packet Attack Detection
        # ----------------------------------------------------
        if length > 1500:
            self.large_packet_tracker[src_ip].append(now)
            if len(self.large_packet_tracker[src_ip]) > 20:
                if not self._is_cooling_down("LARGE_PACKET", src_ip, now):
                    alerts.append({
                        "timestamp": now,
                        "threat_type": "Large Packet Attack / MTU Abuse",
                        "severity": "Low",
                        "src_ip": src_ip,
                        "details": f"Sender transmitting unusually high density of oversized MTU packets (>1500 bytes)."
                    })

        # ----------------------------------------------------
        # 10. Excessive Failed SSH Connections
        # ----------------------------------------------------
        # Failed attempts can be recognized by client termination right after opening (SYN followed immediately by FIN/RST)
        if dst_port == 22 and protocol == "SSH":
            # For simulation or live, we flag SSH attempts
            if "F" in flags or "R" in flags or "failure" in p["summary"].lower():
                self.ssh_fail_tracker[src_ip].append(now)
                if len(self.ssh_fail_tracker[src_ip]) >= 5:
                    if not self._is_cooling_down("SSH_BRUTE_FORCE", src_ip, now):
                        alerts.append({
                            "timestamp": now,
                            "threat_type": "Excessive Failed SSH Connections",
                            "severity": "High",
                            "src_ip": src_ip,
                            "details": f"Possible SSH Brute Force attempt. {len(self.ssh_fail_tracker[src_ip])} connection failures detected in 10 seconds."
                        })

        # Log alerts in threat logger
        for alert in alerts:
            threat_logger.warning(
                f"{alert['threat_type']} | Severity: {alert['severity']} | Source IP: {alert['src_ip']} | Details: {alert['details']}"
            )
            
        return alerts
