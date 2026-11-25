import os
import uuid
import time
import webbrowser
import threading
import shutil
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Module Imports
from utils.logger import get_app_logger
from utils.geoip import lookup_ip
from database.db_manager import DBManager
from analyzer.packet_parser import parse_scapy_packet
from detector.ids_engine import IDSEngine
from capture.interface import get_network_interfaces
from capture.sniffer import NetGuardSniffer
from reports.report_generator import ReportGenerator

logger = get_app_logger()
app = FastAPI(title="NetGuard Web Engine", version="1.0.0")

# Setup folder targets
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, 'assets')
CAPTURES_DIR = os.path.join(BASE_DIR, 'captures')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports_export')

for folder in [CAPTURES_DIR, REPORTS_DIR]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Mount Static Assets (HTML, CSS, JS)
app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")

# Global instances
db = DBManager()
ids = IDSEngine()
report_gen = ReportGenerator(db)

# Capture Tracking State
active_sniffer = None
active_session_id = None
active_connections = []  # WebSocket connections list
websocket_loop = None

# Sniffer settings state
class SettingsSchema(BaseModel):
    portscan_threshold: int
    synflood_threshold: int
    sound_alert: bool
    autosave: bool

current_settings = {
    "portscan_threshold": 15,
    "synflood_threshold": 50,
    "sound_alert": True,
    "autosave": True
}

# --- HTML ROUTE ---
@app.get("/", response_class=HTMLResponse)
async def read_index():
    index_path = os.path.join(ASSETS_DIR, 'templates', 'index.html')
    with open(index_path, 'r', encoding='utf-8') as f:
        return f.read()

# --- API ENDPOINTS ---

@app.get("/api/interfaces")
async def get_interfaces():
    """Return scanned network interfaces."""
    return get_network_interfaces()

class StartCaptureRequest(BaseModel):
    interface: str

@app.post("/api/start")
async def start_capture(payload: StartCaptureRequest):
    global active_sniffer, active_session_id
    
    if active_sniffer and active_sniffer.active:
        return {"status": "error", "message": "Capture session is already running."}
        
    session_id = str(uuid.uuid4())[:8]
    session_name = f"Capture_{payload.interface}_{session_id}"
    
    # Create DB entry
    db.create_session(session_id, session_name)
    active_session_id = session_id

    # Callbacks to push packets to active WebSocket clients
    def on_packet(pkt):
        # Broadcast packet metadata to connected clients
        broadcast_msg({
            "type": "packet",
            "data": pkt
        })

    def on_alert(alt):
        # Broadcast threat alert to clients
        broadcast_msg({
            "type": "alert",
            "data": alt
        })

    try:
        active_sniffer = NetGuardSniffer(
            interface=payload.interface,
            session_id=session_id,
            db_manager=db,
            ids_engine=ids,
            packet_callback=on_packet,
            alert_callback=on_alert
        )
        active_sniffer.start()
        
        # Start background task to broadcast periodically aggregated stats (rate, top source IPs)
        threading.Thread(target=stats_broadcast_loop, args=(session_id,), daemon=True).start()
        
        return {"status": "success", "session_id": session_id, "name": session_name, "is_simulated": active_sniffer.is_simulated}
    except Exception as e:
        logger.error(f"Failed to start sniffer: {e}", exc_info=True)
        return {"status": "error", "message": str(e)}

@app.post("/api/pause")
async def pause_capture():
    global active_sniffer
    if active_sniffer and active_sniffer.active:
        active_sniffer.pause()
        return {"status": "success"}
    return {"status": "error", "message": "No active sniffer found."}

@app.post("/api/resume")
async def resume_capture():
    global active_sniffer
    if active_sniffer and active_sniffer.active:
        active_sniffer.resume()
        return {"status": "success"}
    return {"status": "error", "message": "No active sniffer found."}

@app.post("/api/stop")
async def stop_capture():
    global active_sniffer, active_session_id
    if active_sniffer:
        active_sniffer.stop()
        
        # PCAP Autosave Check if not simulation
        if current_settings["autosave"] and not active_sniffer.is_simulated:
            pcap_file = os.path.join(CAPTURES_DIR, f"{active_session_id}.pcap")
            active_sniffer.write_pcap(pcap_file)
            
        active_sniffer = None
        active_session_id = None
        return {"status": "success"}
    return {"status": "error", "message": "No active sniffer found."}

@app.get("/api/sessions")
async def get_sessions_list():
    return db.get_sessions()

@app.get("/api/session/{session_id}/packets")
async def get_session_packets(session_id: str, protocol: str = None, ip: str = None, port: str = None, keyword: str = None):
    filters = {}
    if protocol: filters["protocol"] = protocol
    if ip: filters["ip"] = ip
    if port: filters["port"] = port
    if keyword: filters["keyword"] = keyword
    
    return db.get_packets(session_id, filters=filters, limit=1000)

@app.delete("/api/session/{session_id}")
async def delete_session(session_id: str):
    success = db.delete_session(session_id)
    return {"status": "success" if success else "error"}

@app.get("/api/session/{session_id}/stats")
async def get_session_stats(session_id: str):
    """Collect session parameters, top sources, and top destinations."""
    top_destinations = db.get_top_ips(session_id, "dst_ip", 10)
    return {
        "top_destinations": top_destinations
    }

@app.get("/api/session/{session_id}/totals")
async def get_session_totals(session_id: str):
    return db.get_aggregate_stats(session_id)

@app.post("/api/settings")
async def update_settings(payload: SettingsSchema):
    global current_settings
    current_settings.update(payload.model_dump())
    
    # Propagate settings to IDS engine thresholds
    ids.port_scan_tracker.clear() # clear scanning history when config changes
    
    logger.info(f"System settings updated: {current_settings}")
    return {"status": "success"}

# --- PCAP IMPORT ---
@app.post("/api/pcap/import")
async def import_pcap_file(file: UploadFile = File(...)):
    """Upload and parse a PCAP file, feeding it to the parser and IDS engine."""
    import tempfile
    try:
        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name

        session_id = f"import_{str(uuid.uuid4())[:8]}"
        session_name = f"Imported_{file.filename}"
        
        db.create_session(session_id, session_name)
        
        # Scapy parse loop
        import scapy.all as scapy
        try:
            packets = scapy.rdpcap(tmp_path)
        except Exception as pcap_err:
            logger.error(f"Failed to read PCAP: {pcap_err}")
            return {"status": "error", "message": "Invalid PCAP format or corrupted file."}
            
        alert_count = 0
        
        for pkt in packets:
            try:
                parsed = parse_scapy_packet(pkt)
                
                # Check threats
                alerts = ids.analyze(parsed)
                for alt in alerts:
                    db.insert_alert(session_id, alt)
                    alert_count += 1
                    
                db.insert_packet(session_id, parsed)
            except Exception as e:
                pass
                
        # Remove temp file
        os.unlink(tmp_path)
        
        return {
            "status": "success",
            "session_id": session_id,
            "packet_count": len(packets),
            "alert_count": alert_count
        }
    except Exception as e:
        logger.error(f"Error processing PCAP upload: {e}")
        return {"status": "error", "message": str(e)}

# --- REPORT DOWNLOAD ENDPOINTS ---

@app.get("/api/reports/{format_type}")
async def download_report(format_type: str, session_id: str):
    """Generates and downloads report format types: pdf, csv, json."""
    timestamp = int(time.time())
    
    if format_type == "pdf":
        file_path = os.path.join(REPORTS_DIR, f"NetGuard_Report_{session_id}_{timestamp}.pdf")
        success = report_gen.generate_pdf_report(session_id, file_path)
        if success and os.path.exists(file_path):
            return FileResponse(file_path, filename=os.path.basename(file_path), media_type="application/pdf")
            
    elif format_type == "csv":
        file_path = os.path.join(REPORTS_DIR, f"NetGuard_Log_{session_id}_{timestamp}.csv")
        success = report_gen.export_csv(session_id, file_path)
        if success and os.path.exists(file_path):
            return FileResponse(file_path, filename=os.path.basename(file_path), media_type="text/csv")
            
    elif format_type == "json":
        file_path = os.path.join(REPORTS_DIR, f"NetGuard_Log_{session_id}_{timestamp}.json")
        success = report_gen.export_json(session_id, file_path)
        if success and os.path.exists(file_path):
            return FileResponse(file_path, filename=os.path.basename(file_path), media_type="application/json")

    return {"status": "error", "message": "Report generation failed or format invalid."}

# --- WEBSOCKET CHANNELS ---

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    global websocket_loop
    await websocket.accept()
    # Keep the loop that Uvicorn/FastAPI is actively running. Packet capture
    # happens in worker threads, so broadcasts must be scheduled on this loop.
    import asyncio
    websocket_loop = asyncio.get_running_loop()
    active_connections.append(websocket)
    logger.info(f"WebSocket client connected for session: {session_id}")
    try:
        while True:
            # We just wait for disconnect, message sending is initiated from callbacks
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)
        logger.info("WebSocket client disconnected.")

def broadcast_msg(message: dict):
    """Sends JSON logs to all connected WebSocket clients."""
    if websocket_loop is None or not websocket_loop.is_running():
        return

    for connection in active_connections:
        try:
            # Packet callbacks originate on capture worker threads.
            import asyncio
            asyncio.run_coroutine_threadsafe(
                connection.send_json(message),
                websocket_loop
            )
        except Exception:
            pass

def stats_broadcast_loop(session_id: str):
    """Periodically fetches aggregated counts and pushes to dashboard."""
    while True:
        time.sleep(1.0)
        
        # Check active status safely
        sniffer = active_sniffer
        if not sniffer or not sniffer.active:
            break
            
        try:
            # Calculate stats
            stats = sniffer.get_stats()
        except AttributeError:
            break
        
        # Fetch Top Sources
        top_sources = db.get_top_ips(session_id, "src_ip", 5)
        
        # Combine
        stats_payload = {
            "packet_rate": stats["packet_rate"],
            "bytes_rate": stats["bytes_transferred"] / max(1.0, stats["duration_sec"]), # Bytes/sec avg
            "top_sources": top_sources
        }
        
        broadcast_msg({
            "type": "stats",
            "data": stats_payload
        })

# --- AUTO OPEN BROWSER AND LAUNCH SERVER ---
HOST = os.environ.get("NETGUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("NETGUARD_PORT", "8001"))

def launch_browser():
    time.sleep(2.0)
    webbrowser.open(f"http://{HOST}:{PORT}")
    logger.info("Local browser launched targeting %s:%s", HOST, PORT)

if __name__ == "__main__":
    # Launch browser thread
    threading.Thread(target=launch_browser, daemon=True).start()
    
    # Run Uvicorn Server
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
  
