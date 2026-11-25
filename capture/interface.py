import threading
from utils.logger import get_app_logger

logger = get_app_logger()

_cached_interfaces = [
    {"name": "Simulation Mode", "description": "Simulation Mode (Fallback)", "ip": "127.0.0.1", "mac": "00:00:00:00:00:00", "status": "active"}
]

def _scan_interfaces_worker(result_list):
    try:
        import scapy.all as scapy
        scapy_ifaces = scapy.get_working_ifaces()
        ifaces = []
        for iface in scapy_ifaces:
            ip_addr = iface.ip if iface.ip else "No IP Address"
            mac_addr = iface.mac if iface.mac else "No MAC"
            name = iface.name
            desc = iface.description or name
            
            ifaces.append({
                "name": name,
                "description": f"{desc} ({mac_addr})",
                "ip": ip_addr,
                "mac": mac_addr,
                "status": "active" if ip_addr != "No IP Address" else "inactive"
            })
        result_list.extend(ifaces)
    except Exception as e:
        logger.warning(f"Error scanning inside interface worker: {e}")

def get_network_interfaces() -> list:
    """
    Retrieves list of network interfaces. Uses a thread join timeout
    to prevent blocking the server if Scapy hangs during adapter scan.
    """
    global _cached_interfaces
    
    result = []
    t = threading.Thread(target=_scan_interfaces_worker, args=(result,))
    t.daemon = True
    t.start()
    t.join(timeout=5.0)
    
    if t.is_alive():
        logger.warning("Scapy interface scanning took too long. Using cached/simulation interface.")
        return _cached_interfaces
        
    if result:
        # Ensure Simulation Mode is always the first option
        sim_present = any(i["name"] == "Simulation Mode" for i in result)
        if not sim_present:
            result.insert(0, _cached_interfaces[0])
        _cached_interfaces = result
        return result
        
    return _cached_interfaces
