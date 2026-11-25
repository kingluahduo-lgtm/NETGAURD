import unittest
import os
import shutil
import time
from database.db_manager import DBManager
from analyzer.packet_parser import parse_scapy_packet, bytes_to_ascii, bytes_to_hexdump
from detector.ids_engine import IDSEngine
from utils.geoip import is_private_ip, lookup_ip

class TestNetGuardModules(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Create temp database path for isolated testing
        cls.test_db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_captures')
        if not os.path.exists(cls.test_db_dir):
            os.makedirs(cls.test_db_dir)
        cls.test_db_path = os.path.join(cls.test_db_dir, 'test_netguard.db')
        cls.db = DBManager(db_path=cls.test_db_path)
        cls.session_id = "test_sess_001"
        cls.db.create_session(cls.session_id, "Test Session Name")

    @classmethod
    def tearDownClass(cls):
        # Remove testing database folders
        if os.path.exists(cls.test_db_dir):
            shutil.rmtree(cls.test_db_dir)

    def test_database_manager_operations(self):
        """Test database initialization, packet creation, and aggregation fetches."""
        # Insert test packets
        test_pkt = {
            "timestamp": time.time(),
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "aa:bb:cc:dd:ee:ff",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 12345,
            "dst_port": 443,
            "protocol": "HTTPS",
            "length": 512,
            "ttl": 64,
            "flags": "PA",
            "summary": "TCP 192.168.1.10:12345 > 8.8.8.8:443 PA",
            "payload_hex": "ab cd ef",
            "payload_ascii": "..."
        }
        
        self.db.insert_packet(self.session_id, test_pkt)
        
        # Verify packet count increment
        session = self.db.get_session(self.session_id)
        self.assertEqual(session["packet_count"], 1)
        
        # Verify retrieving packets
        packets = self.db.get_packets(self.session_id, limit=5)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["src_ip"], "192.168.1.10")
        self.assertEqual(packets[0]["protocol"], "HTTPS")
        
        # Check aggregation statistics
        agg = self.db.get_aggregate_stats(self.session_id)
        self.assertEqual(agg["total_packets"], 1)
        self.assertEqual(agg["total_bytes"], 512)

    def test_geoip_lookups(self):
        """Test Local IP recognition and public mock GeoIP responses."""
        # Private IP validations
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.25"))
        self.assertTrue(is_private_ip("10.0.0.5"))
        self.assertTrue(is_private_ip("172.16.2.22"))
        
        # Public IP validation (should trigger fallback/mock mapping dynamically)
        public_res = lookup_ip("8.8.8.8")
        self.assertNotEqual(public_res["country"], "Local Network")
        self.assertIn("country_code", public_res)

    def test_ids_engine_threat_rules(self):
        """Test if IDS engine correctly signals alerts under flood and scanning conditions."""
        ids = IDSEngine()
        now = time.time()
        
        # 1. ARP Spoof warning verification
        arp_pkt_1 = {
            "timestamp": now,
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "aa:bb:cc:dd:ee:ff",
            "src_ip": "192.168.1.1",
            "protocol": "ARP",
            "summary": "ARP reply 192.168.1.1 is at 00:11:22:33:44:55",
            "flags": "", "dst_port": None, "length": 64
        }
        # First mapping registers
        alerts_1 = ids.analyze(arp_pkt_1)
        self.assertEqual(len(alerts_1), 0)
        
        # Second packet claims different MAC for same IP -> ARPSpoof!
        arp_pkt_2 = arp_pkt_1.copy()
        arp_pkt_2["src_mac"] = "ff:ee:dd:cc:bb:aa"
        arp_pkt_2["summary"] = "ARP reply 192.168.1.1 is at ff:ee:dd:cc:bb:aa"
        
        alerts_2 = ids.analyze(arp_pkt_2)
        self.assertEqual(len(alerts_2), 1)
        self.assertEqual(alerts_2[0]["threat_type"], "ARP Spoofing Detected")
        self.assertEqual(alerts_2[0]["severity"], "Critical")

        # 2. SYN Flood detection check
        ids_syn = IDSEngine()
        syn_pkt = {
            "timestamp": now, "src_ip": "185.190.140.2", "dst_ip": "192.168.1.15",
            "protocol": "TCP", "flags": "S", "dst_port": 80, "length": 64,
            "src_mac": "00:11:22:33:44:55", "dst_mac": "aa:bb:cc:dd:ee:ff",
            "summary": "TCP SYN"
        }
        
        # Feed 51 SYN packets quickly
        alerts = []
        for _ in range(55):
            alerts.extend(ids_syn.analyze(syn_pkt))
            
        self.assertTrue(any(a["threat_type"] == "SYN Flood Attack" for a in alerts))

    def test_payload_dump_formatters(self):
        """Test Hex dump and ASCII text decoder utility logic."""
        test_bytes = b"Hello NetGuard\n\x00\x01"
        
        # ASCII decoder removes control codes
        ascii_out = bytes_to_ascii(test_bytes)
        self.assertIn("Hello NetGuard", ascii_out)
        self.assertIn(".", ascii_out)
        
        # Hex dump formatter returns structured spacing lines
        hex_out = bytes_to_hexdump(test_bytes)
        self.assertTrue(len(hex_out) > 0)
        self.assertIn("|Hello NetGuard.|", hex_out)

if __name__ == "__main__":
    unittest.main()
