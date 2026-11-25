PORT_MAP = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    20: "FTP-DATA",
    67: "DHCP",
    68: "DHCP",
    8080: "HTTP-ALT",
    123: "NTP",
    161: "SNMP",
    162: "SNMP",
    389: "LDAP",
    445: "SMB",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    1883: "MQTT",
    5060: "SIP"
}

def identify_protocol(proto_num: int, sport: int, dport: int, has_arp: bool = False) -> str:
    """
    Classify transport or application protocol based on ports, layers, and protocol numbers.
    - proto_num = 1: ICMP
    - proto_num = 6: TCP
    - proto_num = 17: UDP
    """
    if has_arp:
        return "ARP"
    
    if proto_num == 1:
        return "ICMP"
    
    # Check Source & Destination Ports in MAP
    if sport in PORT_MAP:
        return PORT_MAP[sport]
    if dport in PORT_MAP:
        return PORT_MAP[dport]
    
    # Generic fallback
    if proto_num == 6:
        return "TCP"
    elif proto_num == 17:
        return "UDP"
    
    return f"PROTO-{proto_num}"
