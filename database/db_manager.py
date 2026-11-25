import sqlite3
import os
import time
from utils.logger import get_app_logger

logger = get_app_logger()

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'captures')
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

DB_PATH = os.path.join(DB_DIR, 'netguard.db')

class DBManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.initialize_db()

    def _get_connection(self):
        """Open a new database connection with timeout for multi-threaded access."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize_db(self):
        """Creates tables if they do not exist."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Sessions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        packet_count INTEGER DEFAULT 0,
                        alert_count INTEGER DEFAULT 0
                    )
                """)
                
                # Packets table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        src_mac TEXT,
                        dst_mac TEXT,
                        protocol TEXT,
                        length INTEGER,
                        ttl INTEGER,
                        flags TEXT,
                        summary TEXT,
                        payload_hex TEXT,
                        payload_ascii TEXT,
                        FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                    )
                """)
                
                # Alerts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        threat_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        src_ip TEXT,
                        details TEXT,
                        resolved INTEGER DEFAULT 0,
                        FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                    )
                """)
                
                # Create indices for fast searching
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(protocol)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_ips ON packets(src_ip, dst_ip)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id)")
                
                conn.commit()
                logger.info(f"Database initialized successfully at {self.db_path}")
        except Exception as e:
            logger.error(f"Error initializing database: {e}", exc_info=True)

    def create_session(self, session_id: str, name: str) -> bool:
        """Create a new capture session."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO sessions (session_id, name, created_at) VALUES (?, ?, ?)",
                    (session_id, name, time.time())
                )
                conn.commit()
                logger.info(f"Session '{name}' ({session_id}) created in DB.")
                return True
        except sqlite3.IntegrityError:
            logger.warning(f"Session {session_id} already exists.")
            return False
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return False

    def insert_packet(self, session_id: str, p: dict):
        """Insert a packet record and update session packet count."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO packets (
                        session_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                        src_mac, dst_mac, protocol, length, ttl, flags, summary,
                        payload_hex, payload_ascii
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id, p.get("timestamp"), p.get("src_ip"), p.get("dst_ip"),
                    p.get("src_port"), p.get("dst_port"), p.get("src_mac"), p.get("dst_mac"),
                    p.get("protocol"), p.get("length"), p.get("ttl"), p.get("flags"),
                    p.get("summary"), p.get("payload_hex"), p.get("payload_ascii")
                ))
                cursor.execute(
                    "UPDATE sessions SET packet_count = packet_count + 1 WHERE session_id = ?",
                    (session_id,)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Error inserting packet: {e}")

    def insert_alert(self, session_id: str, alert: dict):
        """Insert a threat alert and update session alert count."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO alerts (
                        session_id, timestamp, threat_type, severity, src_ip, details
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    session_id, alert.get("timestamp", time.time()), alert.get("threat_type"),
                    alert.get("severity"), alert.get("src_ip"), alert.get("details")
                ))
                cursor.execute(
                    "UPDATE sessions SET alert_count = alert_count + 1 WHERE session_id = ?",
                    (session_id,)
                )
                conn.commit()
                logger.warning(f"IDS Alert inserted: {alert.get('threat_type')} - {alert.get('details')}")
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")

    def get_packets(self, session_id: str, filters: dict = None, limit: int = 100, offset: int = 0) -> list:
        """Retrieve packets from DB with optional filters."""
        query = "SELECT * FROM packets WHERE session_id = ?"
        params = [session_id]
        
        if filters:
            if filters.get("protocol"):
                query += " AND protocol = ?"
                params.append(filters["protocol"])
            if filters.get("ip"):
                query += " AND (src_ip = ? OR dst_ip = ?)"
                params.extend([filters["ip"], filters["ip"]])
            if filters.get("port"):
                query += " AND (src_port = ? OR dst_port = ?)"
                try:
                    port_val = int(filters["port"])
                    params.extend([port_val, port_val])
                except ValueError:
                    pass
            if filters.get("mac"):
                query += " AND (src_mac = ? OR dst_mac = ?)"
                params.extend([filters["mac"], filters["mac"]])
            if filters.get("size_min"):
                query += " AND length >= ?"
                params.append(int(filters["size_min"]))
            if filters.get("size_max"):
                query += " AND length <= ?"
                params.append(int(filters["size_max"]))
            if filters.get("keyword"):
                query += " AND (summary LIKE ? OR payload_ascii LIKE ?)"
                kw = f"%{filters['keyword']}%"
                params.extend([kw, kw])
        
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving packets: {e}")
            return []

    def get_packet_by_id(self, packet_id: int) -> dict:
        """Fetch a specific packet's full details."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM packets WHERE id = ?", (packet_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error fetching packet by id: {e}")
            return None

    def get_alerts(self, session_id: str, limit: int = 100, offset: int = 0) -> list:
        """Retrieve threat alerts from DB."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM alerts WHERE session_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (session_id, limit, offset)
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []

    def get_sessions(self) -> list:
        """List all historical captures."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM sessions ORDER BY created_at DESC")
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error listing sessions: {e}")
            return []

    def get_session(self, session_id: str) -> dict:
        """Get info of a single session."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error getting session details: {e}")
            return None

    def delete_session(self, session_id: str) -> bool:
        """Deletes a session and cascadingly removes its packet and alert records."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
                logger.info(f"Session {session_id} deleted successfully.")
                return True
        except Exception as e:
            logger.error(f"Error deleting session {session_id}: {e}")
            return False

    def get_protocol_stats(self, session_id: str) -> list:
        """Fetch protocol distribution count for the dashboard."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT protocol, COUNT(*) as count, SUM(length) as bytes FROM packets WHERE session_id = ? GROUP BY protocol",
                    (session_id,)
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error generating protocol stats: {e}")
            return []

    def get_top_ips(self, session_id: str, field: str = "src_ip", limit: int = 5) -> list:
        """Get top talkers (Source or Destination IP)."""
        if field not in ("src_ip", "dst_ip"):
            return []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT {field} as ip, COUNT(*) as count, SUM(length) as bytes FROM packets WHERE session_id = ? AND {field} IS NOT NULL AND {field} != '' GROUP BY {field} ORDER BY count DESC LIMIT ?",
                    (session_id, limit)
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error finding top IPs: {e}")
            return []

    def get_aggregate_stats(self, session_id: str) -> dict:
        """Obtain session global metrics (totals, averages, rates)."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_packets, 
                        SUM(length) as total_bytes,
                        AVG(length) as avg_size,
                        (SELECT COUNT(*) FROM alerts WHERE session_id = ?) as total_alerts
                    FROM packets WHERE session_id = ?
                """, (session_id, session_id))
                row = cursor.fetchone()
                
                stats = dict(row) if row else {}
                
                # Fetch start and end times to calculate durations
                cursor.execute("SELECT MIN(timestamp) as start_t, MAX(timestamp) as end_t FROM packets WHERE session_id = ?", (session_id,))
                time_row = cursor.fetchone()
                duration = 0
                packet_rate = 0
                if time_row and time_row["start_t"] and time_row["end_t"]:
                    duration = max(1.0, time_row["end_t"] - time_row["start_t"])
                    total_p = stats.get("total_packets") or 0
                    packet_rate = round(total_p / duration, 2)
                
                stats["duration_sec"] = round(duration, 1)
                stats["packet_rate"] = packet_rate
                return stats
        except Exception as e:
            logger.error(f"Error compiling session stats: {e}")
            return {}
