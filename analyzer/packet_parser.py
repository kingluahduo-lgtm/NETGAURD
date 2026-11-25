import time
from analyzer.protocols import identify_protocol

def bytes_to_hexdump(data: bytes) -> str:
    """Formats bytes into a standard Wireshark-like hex dump."""
    if not data:
        return ""
    
    hex_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        
        # Hex values column
        hex_values = " ".join(f"{b:02x}" for b in chunk)
        # Pad columns for shorter final lines
        if len(chunk) < 16:
            hex_values += " " * (3 * (16 - len(chunk)))
            
        # ASCII representation column
        ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        
        hex_lines.append(f"{i:04x}   {hex_values}   |{ascii_values}|")
        
    return "\n".join(hex_lines)

def bytes_to_ascii(data: bytes) -> str:
    """Converts bytes to a printable ASCII string, replacing non-printables with dots."""
    if not data:
        return ""
    return "".join(chr(b) if (32 <= b <= 126 or b == 10 or b == 13) else "." for b in data)

def parse_scapy_packet(packet) -> dict:
    """
    Parses a Scapy packet and extracts metadata, protocols, and payloads.
    Uses dynamic Scapy imports to prevent server initialization blocks.
    """
    import scapy.all as scapy
    
    parsed = {
        "timestamp": float(packet.time) if packet.time else time.time(),
        "src_mac": "",
        "dst_mac": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": None,
        "dst_port": None,
        "protocol": "UNKNOWN",
        "ttl": None,
        "length": len(packet),
        "flags": "",
        "summary": packet.summary(),
        "payload_hex": "",
        "payload_ascii": ""
    }
    
    # Parse Ethernet Link Layer
    if packet.haslayer(scapy.Ether):
        parsed["src_mac"] = packet[scapy.Ether].src
        parsed["dst_mac"] = packet[scapy.Ether].dst
        
    # Parse IP Network Layer
    proto_num = None
    has_arp = False
    
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        parsed["src_ip"] = ip_layer.src
        parsed["dst_ip"] = ip_layer.dst
        parsed["ttl"] = ip_layer.ttl
        proto_num = ip_layer.proto
    elif packet.haslayer(scapy.IPv6):
        ipv6_layer = packet[scapy.IPv6]
        parsed["src_ip"] = ipv6_layer.src
        parsed["dst_ip"] = ipv6_layer.dst
        parsed["ttl"] = ipv6_layer.hlim  # Hop Limit in IPv6 acts like TTL
        proto_num = ipv6_layer.nh
    elif packet.haslayer(scapy.ARP):
        arp_layer = packet[scapy.ARP]
        parsed["src_ip"] = arp_layer.psrc
        parsed["dst_ip"] = arp_layer.pdst
        parsed["src_mac"] = arp_layer.hwsrc
        parsed["dst_mac"] = arp_layer.hwdst
        has_arp = True
        proto_num = None
        parsed["protocol"] = "ARP"

    # Parse Transport Layer
    if packet.haslayer(scapy.TCP):
        tcp_layer = packet[scapy.TCP]
        parsed["src_port"] = tcp_layer.sport
        parsed["dst_port"] = tcp_layer.dport
        parsed["flags"] = str(tcp_layer.flags)
        proto_num = 6
    elif packet.haslayer(scapy.UDP):
        udp_layer = packet[scapy.UDP]
        parsed["src_port"] = udp_layer.sport
        parsed["dst_port"] = udp_layer.dport
        proto_num = 17
    elif packet.haslayer(scapy.ICMP):
        proto_num = 1

    # Classify high-level application protocol
    if not has_arp:
        parsed["protocol"] = identify_protocol(
            proto_num or 0,
            parsed["src_port"] or 0,
            parsed["dst_port"] or 0
        )

    # Extract Payload
    payload = None
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
    elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].payload:
        payload = bytes(packet[scapy.TCP].payload)
    elif packet.haslayer(scapy.UDP) and packet[scapy.UDP].payload:
        payload = bytes(packet[scapy.UDP].payload)

    # Format payload
    if payload:
        parsed["payload_hex"] = bytes_to_hexdump(payload)
        parsed["payload_ascii"] = bytes_to_ascii(payload)
        
    return parsed
