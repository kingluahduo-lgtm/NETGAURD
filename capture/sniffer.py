import time
import threading
import random
import os
from analyzer.packet_parser import parse_scapy_packet
from utils.logger import get_app_logger

logger = get_app_logger()

class NetGuardSniffer:
    def __init__(self, interface: str, session_id: str, db_manager, ids_engine, packet_callback=None, alert_callback=None):
        self.interface = interface
        self.session_id = session_id
        self.db = db_manager
        self.ids = ids_engine
        self.packet_callback = packet_callback
        self.alert_callback = alert_callback
        
        self.active = False
        self.paused = False
        self.thread = None
        self.raw_packets_buffer = []  # Keep in-memory raw Scapy packets for PCAP export (capped at 5000)
        self.buffer_lock = threading.Lock()
        
        # Capture metrics
        self.start_time = 0
        self.packet_count = 0
        self.bytes_transferred = 0
        
        # Check if we should use simulation mode
        self.is_simulated = (interface == "Simulation Mode")
        if not self.is_simulated:
            # Check permissions
            try:
                import scapy.all as scapy
                # Attempt to open a socket briefly to check for root/admin permissions
                scapy.conf.L2socket()
            except Exception as e:
                logger.warning(f"Raw socket creation failed ({e}). Forcing Simulation Mode.")
                self.is_simulated = True

    def start(self):
        """Start packet capture in a background thread."""
        if self.active:
            return
        
        self.active = True
        self.paused = False
        self.start_time = time.time()
        
        if self.is_simulated:
            self.thread = threading.Thread(target=self._run_simulation, daemon=True)
            logger.info("Starting NetGuard Sniffer in SIMULATION mode.")
        else:
            self.thread = threading.Thread(target=self._run_live_capture, daemon=True)
            logger.info(f"Starting NetGuard Sniffer on interface: {self.interface}")
            
        self.thread.start()

    def pause(self):
        """Pause processing of captured packets."""
        self.paused = True
        logger.info("Packet capture paused.")

    def resume(self):
        """Resume processing of captured packets."""
        self.paused = False
        logger.info("Packet capture resumed.")

    def stop(self):
        """Stop packet capture thread."""
        self.active = False
        if self.thread:
            self.thread.join(timeout=1.5)
        logger.info("Packet capture stopped.")

    def get_stats(self) -> dict:
        """Get live metrics of the current capture session."""
        duration = time.time() - self.start_time if self.start_time else 0
        rate = round(self.packet_count / duration, 2) if duration > 0 else 0
        return {
            "packet_count": self.packet_count,
            "bytes_transferred": self.bytes_transferred,
            "duration_sec": int(duration),
            "packet_rate": rate,
            "is_simulated": self.is_simulated
        }

    def _add_raw_packet(self, packet):
        """Buffers raw packets in memory for PCAP export."""
        with self.buffer_lock:
            self.raw_packets_buffer.append(packet)
            if len(self.raw_packets_buffer) > 5000:
                self.raw_packets_buffer.pop(0)  # Sliding window to avoid memory leaks

    def get_raw_packets(self):
        """Retrieve copy of raw packets buffer."""
        with self.buffer_lock:
            return list(self.raw_packets_buffer)

    def _process_packet(self, parsed_pkt, raw_pkt=None):
        """Common logic to register packet, check IDS threats, and push to database and callbacks."""
        if self.paused:
            return
            
        self.packet_count += 1
        self.bytes_transferred += parsed_pkt["length"]
        
        # Buffer raw packet for PCAP export (if live scapy packet is present)
        if raw_pkt:
            self._add_raw_packet(raw_pkt)
            
        # 1. Feed to Threat Detection Engine
        alerts = self.ids.analyze(parsed_pkt)
        for alert in alerts:
            self.db.insert_alert(self.session_id, alert)
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
                    
        # 2. Save Packet metadata to DB
        self.db.insert_packet(self.session_id, parsed_pkt)
        
        # 3. Call packet websocket callback
        if self.packet_callback:
            try:
                self.packet_callback(parsed_pkt)
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")

    def _run_live_capture(self):
        """Live Scapy sniffing loop running in a background thread."""
        def handle_pkt(pkt):
            if not self.active:
                return
            try:
                parsed = parse_scapy_packet(pkt)
                self._process_packet(parsed, pkt)
            except Exception as e:
                logger.error(f"Error parsing packet: {e}")

        def stop_check(pkt):
            return not self.active

        try:
            import scapy.all as scapy
            # We use store=0 so scapy does not consume memory internally
            scapy.sniff(iface=self.interface, prn=handle_pkt, stop_filter=stop_check, store=0)
        except Exception as e:
            logger.error(f"Fatal error in live capture thread: {e}", exc_info=True)
            self.is_simulated = True
            logger.info("Live capture failed. Falling back to simulation.")
            self._run_simulation()

    def _run_simulation(self):
        """Generates mock network packets and schedules threat scenarios."""
        # Realistic device/attacker IPs
        local_ips = ["192.168.1.15", "192.168.1.42", "192.168.1.108", "192.168.1.20"]
        external_ips = ["8.8.8.8", "142.250.190.46", "34.117.186.192", "204.79.197.200", "185.190.140.22", "45.33.32.156"]
        mac_addresses = ["b4:2e:99:a4:23:cc", "00:0c:29:68:21:55", "3c:a8:2a:11:c3:90", "00:15:5d:01:ca:08"]
        gateway_mac = "00:11:22:33:44:55"
        rogue_mac = "aa:bb:cc:dd:ee:ff"
        
        protocols = ["HTTP", "HTTPS", "DNS", "SSH", "FTP", "TCP", "UDP", "ARP", "ICMP", "DHCP"]
        
        attack_timer = time.time()
        attack_types = ["PORT_SCAN", "SYN_FLOOD", "ICMP_FLOOD", "ARP_SPOOF", "DNS_FLOOD", "SSH_FAIL", "MAC_FLOOD", "LARGE_PACKET"]
        current_attack = None
        attack_packets_left = 0
        attack_src_ip = None
        
        while self.active:
            if self.paused:
                time.sleep(0.5)
                continue
                
            now = time.time()
            
            # Check if it's time to trigger a simulated attack scenario
            if not current_attack and (now - attack_timer > random.randint(20, 30)):
                current_attack = random.choice(attack_types)
                attack_src_ip = random.choice(external_ips) if current_attack != "ARP_SPOOF" else "192.168.1.99"
                attack_packets_left = random.randint(40, 80)
                logger.info(f"SIMULATOR: Starting mock threat event: {current_attack} from {attack_src_ip}")
                
            # Create a mock packet dictionary
            parsed = {
                "timestamp": now,
                "src_mac": random.choice(mac_addresses),
                "dst_mac": random.choice(mac_addresses),
                "src_ip": random.choice(local_ips),
                "dst_ip": random.choice(external_ips),
                "src_port": random.randint(49152, 65535),
                "dst_port": random.choice([80, 443, 53, 22, 21]),
                "protocol": "TCP",
                "ttl": random.choice([64, 128]),
                "length": random.randint(64, 1500),
                "flags": "PA",
                "summary": "",
                "payload_hex": "",
                "payload_ascii": ""
            }
            
            # Adjust parsed packet structure if inside an attack scenario
            if current_attack and attack_packets_left > 0:
                attack_packets_left -= 1
                
                if current_attack == "PORT_SCAN":
                    parsed["src_ip"] = attack_src_ip
                    parsed["dst_ip"] = "192.168.1.15"
                    parsed["dst_port"] = random.randint(20, 1024)
                    parsed["protocol"] = "TCP"
                    parsed["flags"] = "S"
                    parsed["length"] = 64
                    parsed["summary"] = f"TCP {parsed['src_ip']}:{parsed['src_port']} > {parsed['dst_ip']}:{parsed['dst_port']} S"
                    
                elif current_attack == "SYN_FLOOD":
                    parsed["src_ip"] = attack_src_ip
                    parsed["dst_ip"] = "192.168.1.15"
                    parsed["dst_port"] = 80
                    parsed["protocol"] = "TCP"
                    parsed["flags"] = "S"
                    parsed["length"] = 64
                    parsed["summary"] = f"TCP {parsed['src_ip']}:{parsed['src_port']} > {parsed['dst_ip']}:80 S"
                    
                elif current_attack == "ICMP_FLOOD":
                    parsed["src_ip"] = attack_src_ip
                    parsed["dst_ip"] = "192.168.1.15"
                    parsed["protocol"] = "ICMP"
                    parsed["length"] = 64
                    parsed["summary"] = f"ICMP Echo Request {parsed['src_ip']} > {parsed['dst_ip']}"
                    
                elif current_attack == "ARP_SPOOF":
                    parsed["protocol"] = "ARP"
                    parsed["src_mac"] = rogue_mac
                    parsed["dst_mac"] = gateway_mac
                    parsed["src_ip"] = "192.168.1.1"
                    parsed["dst_ip"] = "192.168.1.15"
                    parsed["summary"] = f"ARP reply 192.168.1.1 is at {rogue_mac}"
                    
                elif current_attack == "DNS_FLOOD":
                    parsed["src_ip"] = attack_src_ip
                    parsed["dst_ip"] = "192.168.1.15"
                    parsed["dst_port"] = 53
                    parsed["protocol"] = "DNS"
                    parsed["length"] = 72
                    parsed["summary"] = f"DNS Query from {parsed['src_ip']} for suspicious-botnet.cc"
                    parsed["payload_ascii"] = ".....suspicious-botnet.cc....."
                    
                elif current_attack == "SSH_FAIL":
                    parsed["src_ip"] = attack_src_ip
                    parsed["dst_ip"] = "192.168.1.15"
                    parsed["dst_port"] = 22
                    parsed["protocol"] = "SSH"
                    parsed["flags"] = "FA"
                    parsed["summary"] = f"SSH login failure sequence from {parsed['src_ip']}"
                    
                elif current_attack == "MAC_FLOOD":
                    parsed["src_mac"] = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
                    parsed["dst_mac"] = "ff:ff:ff:ff:ff:ff"
                    parsed["src_ip"] = "0.0.0.0"
                    parsed["dst_ip"] = "255.255.255.255"
                    parsed["protocol"] = "UDP"
                    parsed["summary"] = f"DHCP Discover from {parsed['src_mac']}"
                    
                elif current_attack == "LARGE_PACKET":
                    parsed["src_ip"] = attack_src_ip
                    parsed["dst_ip"] = "192.168.1.15"
                    parsed["length"] = 65000
                    parsed["protocol"] = "ICMP"
                    parsed["summary"] = f"Oversized Ping from {parsed['src_ip']} (65000 bytes)"
                
                time.sleep(0.01 if current_attack in ["SYN_FLOOD", "ICMP_FLOOD", "MAC_FLOOD"] else 0.05)
                
                if attack_packets_left == 0:
                    current_attack = None
                    attack_timer = time.time()
                    logger.info("SIMULATOR: Threat event finished. Returning to normal traffic.")
            
            else:
                # Generate Normal Traffic
                proto = random.choice(protocols)
                parsed["protocol"] = proto
                
                if proto == "DNS":
                    parsed["dst_port"] = 53
                    parsed["src_port"] = random.randint(49152, 65535)
                    parsed["summary"] = f"DNS Query: standard lookup for google.com"
                    parsed["payload_ascii"] = ".....www.google.com....."
                    parsed["payload_hex"] = "00 01 00 00 00 01 00 00 00 00 00 00 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d"
                elif proto == "HTTP":
                    parsed["dst_port"] = 80
                    parsed["flags"] = "PA"
                    parsed["summary"] = f"HTTP GET /index.html HTTP/1.1"
                    parsed["payload_ascii"] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                    parsed["payload_hex"] = "47 45 54 20 2f 69 6e 64 65 78 2e 68 74 6d 6c 20 48 54 54 50 2f 31 2e 31 0d 0a"
                elif proto == "HTTPS":
                    parsed["dst_port"] = 443
                    parsed["flags"] = "PA"
                    parsed["summary"] = f"TLSv1.3 Encrypted Application Data"
                    parsed["payload_ascii"] = "................................."
                    parsed["payload_hex"] = "17 03 03 00 20 a1 b2 c3 d4 e5 f6 a1 b2 c3 d4 e5 f6"
                elif proto == "SSH":
                    parsed["dst_port"] = 22
                    parsed["flags"] = "PA"
                    parsed["summary"] = f"SSH-2.0-OpenSSH_8.2p1 Key Exchange Packet"
                elif proto == "ARP":
                    parsed["src_mac"] = random.choice(mac_addresses)
                    parsed["dst_mac"] = "ff:ff:ff:ff:ff:ff"
                    parsed["src_ip"] = random.choice(local_ips)
                    parsed["dst_ip"] = "0.0.0.0"
                    parsed["summary"] = f"ARP Who has 192.168.1.1? Tell {parsed['src_ip']}"
                elif proto == "ICMP":
                    parsed["src_ip"] = "192.168.1.15"
                    parsed["dst_ip"] = "8.8.8.8"
                    parsed["summary"] = f"ICMP Echo Request (ping)"
                elif proto == "DHCP":
                    parsed["src_port"] = 68
                    parsed["dst_port"] = 67
                    parsed["src_ip"] = "0.0.0.0"
                    parsed["dst_ip"] = "255.255.255.255"
                    parsed["summary"] = f"DHCP Request Transaction ID 0x3d4a2f"
                else:
                    parsed["summary"] = f"{proto} Packet: {parsed['src_ip']}:{parsed['src_port']} > {parsed['dst_ip']}:{parsed['dst_port']}"
                    
                time.sleep(random.uniform(0.1, 0.4))
                
            self._process_packet(parsed)
            
        logger.info("Simulation thread finished.")
        
    def write_pcap(self, file_path: str) -> bool:
        """Saves current buffered raw packets to a PCAP file using Scapy's wrpcap."""
        raw_list = self.get_raw_packets()
        if not raw_list:
            logger.warning("No live scapy packets in buffer to export to PCAP.")
            return False
        try:
            import scapy.all as scapy
            pcap_dir = os.path.dirname(file_path)
            if pcap_dir and not os.path.exists(pcap_dir):
                os.makedirs(pcap_dir)
            scapy.wrpcap(file_path, raw_list)
            logger.info(f"PCAP written to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving PCAP to {file_path}: {e}")
            return False
