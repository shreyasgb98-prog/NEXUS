import unittest
import sys
import struct
import time
from pathlib import Path
from fastapi import HTTPException

# Configure path imports
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.incident_manager import (
    is_mac_randomized,
    identify_hardware_profile,
    generate_remediation_advisory,
    OFFENSIVE_OUI_MAP
)
from app.database import (
    get_connection,
    create_incident,
    fetch_incident_with_timeline
)
from app.main import (
    generate_incident_pcap,
    download_incident_pcap,
    reset_telemetry_state
)
from app.assistant import AskNexusAssistant


class TestBinaryPCAPGeneration(unittest.TestCase):
    """Verifies binary PCAP generation matching DLT_IEEE802_11 Wireshark specifications."""

    def setUp(self):
        self.sample_incident = {
            "incident_id": "INC-20261124-00101",
            "attacker_mac": "24:0A:C4:11:22:33",
            "target_mac": "00:11:22:33:44:55",
            "deauth_reason": 7,
            "start_epoch_ms": 1700000000000,
            "event_count": 5
        }

    def test_pcap_global_header_validation(self):
        """Validates that the PCAP global header matches DLT_IEEE802_11 (magic 0xA1B2C3D4, major 2, minor 4, link 105)."""
        pcap_data = generate_incident_pcap(self.sample_incident)
        self.assertGreaterEqual(len(pcap_data), 24)

        # Unpack the 24-byte PCAP global header
        magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            "<IHHIIII",
            pcap_data[:24]
        )

        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual(ver_major, 2)
        self.assertEqual(ver_minor, 4)
        self.assertEqual(thiszone, 0)
        self.assertEqual(sigfigs, 0)
        self.assertEqual(snaplen, 65535)
        self.assertEqual(network, 105)  # DLT_IEEE802_11

    def test_pcap_packet_header_and_deauth_frame(self):
        """Verifies synthesized 802.11 Deauth frame structure, addressing, and reason code."""
        pcap_data = generate_incident_pcap(self.sample_incident)

        # First packet header starts at offset 24 (16 bytes)
        pkt_hdr = pcap_data[24:40]
        self.assertEqual(len(pkt_hdr), 16)
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)

        self.assertEqual(incl_len, 26)
        self.assertEqual(orig_len, 26)

        # First packet frame body starts at offset 40 (26 bytes)
        frame_bytes = pcap_data[40:66]
        self.assertEqual(len(frame_bytes), 26)

        # Frame Control: 0x00C0 (little-endian unsigned short for Type 0 Management, Subtype 12 Deauth)
        fc = struct.unpack("<H", frame_bytes[:2])[0]
        self.assertEqual(fc, 0x00C0)

        # Addresses: Addr1=Target, Addr2=Attacker, Addr3=BSSID
        addr1 = frame_bytes[4:10]
        addr2 = frame_bytes[10:16]
        addr3 = frame_bytes[16:22]
        self.assertEqual(addr1, bytes.fromhex("001122334455"))
        self.assertEqual(addr2, bytes.fromhex("240AC4112233"))
        self.assertEqual(addr3, bytes.fromhex("001122334455"))

        # Reason Code at the end of the 26-byte deauth frame
        reason_code = struct.unpack("<H", frame_bytes[24:26])[0]
        self.assertEqual(reason_code, 7)

    def test_pcap_download_endpoint_success_and_404(self):
        """Verifies GET /api/incidents/{incident_id}/pcap endpoint output."""
        reset_telemetry_state()
        conn = get_connection()
        create_incident({
            "incident_id": "INC-20261124-77777",
            "title": "Adversary Deauth Surge",
            "attacker_mac": "B8:27:EB:12:34:56",
            "target_mac": "AA:BB:CC:DD:EE:FF",
            "deauth_reason": 7,
            "event_count": 3
        }, conn=conn)
        conn.close()

        # Success case
        resp = download_incident_pcap("INC-20261124-77777")
        self.assertEqual(resp.media_type, "application/vnd.tcpdump.pcap")
        self.assertIn("incident_INC-20261124-77777.pcap", resp.headers["Content-Disposition"])
        self.assertGreaterEqual(len(resp.body), 24)

        # Verify header on downloaded binary body
        magic, major, minor, _, _, _, network = struct.unpack("<IHHIIII", resp.body[:24])
        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual(network, 105)

        # 404 Not Found case
        with self.assertRaises(HTTPException) as ctx:
            download_incident_pcap("INC-NONEXISTENT-99999")
        self.assertEqual(ctx.exception.status_code, 404)


class TestMACAnalysisAndHardwareOUI(unittest.TestCase):
    """Verifies MAC randomization detection and offensive hardware OUI profiling."""

    def test_is_mac_randomized_laa(self):
        # 0xDA = 1101 1010 -> bit 1 is set (LAA randomized)
        self.assertTrue(is_mac_randomized("DA:A1:19:22:33:44"))
        # 0x02 = 0000 0010 -> bit 1 is set
        self.assertTrue(is_mac_randomized("02:00:00:00:00:01"))
        # 0x24 = 0010 0100 -> bit 1 is 0 (UAA assigned OUI)
        self.assertFalse(is_mac_randomized("24:0A:C4:11:22:33"))
        # 0x00 = 0000 0000 -> bit 1 is 0
        self.assertFalse(is_mac_randomized("00:C0:CA:99:88:77"))
        # Empty or short input
        self.assertFalse(is_mac_randomized(""))
        self.assertFalse(is_mac_randomized("X"))

    def test_identify_hardware_profile(self):
        # Known offensive hardware OUIs
        self.assertEqual(
            identify_hardware_profile("24:0A:C4:11:22:33"),
            "Espressif Deauther / Rogue Node (ESP8266/ESP32)"
        )
        self.assertEqual(
            identify_hardware_profile("30:AE:A4:00:11:22"),
            "Espressif Embedded Transceiver"
        )
        self.assertEqual(
            identify_hardware_profile("84:F3:EB:12:34:56"),
            "Espressif Wireless SoC"
        )
        self.assertEqual(
            identify_hardware_profile("B8:27:EB:AA:BB:CC"),
            "Raspberry Pi (Pwnagotchi / Kali Linux)"
        )
        self.assertEqual(
            identify_hardware_profile("DC:A6:32:00:22:44"),
            "Raspberry Pi 4 / Embedded Attack Rig"
        )
        self.assertEqual(
            identify_hardware_profile("E4:5F:01:77:88:99"),
            "Raspberry Pi Foundation Transceiver"
        )
        self.assertEqual(
            identify_hardware_profile("00:C0:CA:11:22:33"),
            "Alfa Network High-Power Injection Card"
        )

        # Spoofed LAA MAC
        self.assertEqual(
            identify_hardware_profile("DA:A1:19:22:33:44"),
            "Anti-Forensic MAC Randomization (Spoofed LAA)"
        )

        # Standard commercial NIC
        self.assertEqual(
            identify_hardware_profile("00:11:22:33:44:55"),
            "Standard Commercial NIC"
        )


class TestRemediationAdvisories(unittest.TestCase):
    """Verifies automated remediation advisory text generation."""

    def test_deauth_pmf_advisory(self):
        adv = generate_remediation_advisory("deauth_flood", reason_code=7)
        self.assertIn("MANDATE IEEE 802.11w (PMF / WPA3-SAE)", adv)
        self.assertIn("AES-128 CMAC (BIP)", adv)

    def test_rogue_ap_eap_tls_advisory(self):
        adv = generate_remediation_advisory("evil_twin")
        self.assertIn("ENFORCE IEEE 802.1X EAP-TLS", adv)
        self.assertIn("root certificate pinning", adv)

    def test_ble_secure_connections_advisory(self):
        adv = generate_remediation_advisory("ble_anomaly")
        self.assertIn("ENFORCE BLE SECURE CONNECTIONS (LE SC)", adv)
        self.assertIn("Identity Resolving Key (IRK)", adv)


class TestAssistantForensicInquiries(unittest.TestCase):
    """Verifies Ask NEXUS assistant answers regarding OUI hardware profiling, injection metrics, and 802.11w."""

    def setUp(self):
        self.assistant = AskNexusAssistant()
        reset_telemetry_state()

        now_ms = int(time.time() * 1000)
        conn = get_connection()
        create_incident({
            "incident_id": "INC-20261124-55555",
            "title": "Adversary Deauth Campaign",
            "primary_type": "DEAUTH",
            "event_type": "Deauth Flood",
            "severity": "CRITICAL",
            "attacker_mac": "24:0A:C4:DE:AD:01",
            "target_mac": "00:11:22:33:44:55",
            "deauth_reason": 7,
            "event_count": 12
        }, conn=conn)
        conn.close()

    def test_query_hardware_profile(self):
        query = "What hardware was the attacker using?"
        intent, data = self.assistant.route_query(query)
        self.assertEqual(intent, "hardware_profile")

        resp = self.assistant.generate_deterministic_response(intent, data)
        self.assertIn("24:0A:C4:DE:AD:01", resp)
        self.assertIn("Espressif Deauther / Rogue Node (ESP8266/ESP32)", resp)

    def test_query_80211w_mitigation(self):
        query = "What are the 802.11w mitigation recommendations?"
        intent, data = self.assistant.route_query(query)
        self.assertEqual(intent, "remediation_advisory")

        resp = self.assistant.generate_deterministic_response(intent, data)
        self.assertIn("IEEE 802.11w", resp)
        self.assertIn("PMF / WPA3-SAE", resp)

    def test_query_packet_injection_metrics(self):
        query = "Were there packet injection metrics?"
        intent, data = self.assistant.route_query(query)
        self.assertEqual(intent, "injection_metrics")

        resp = self.assistant.generate_deterministic_response(intent, data)
        self.assertIn("Reason Code", resp)
        self.assertIn("Injection", resp)
        self.assertIn("Adversary frame injection detected", resp)


if __name__ == "__main__":
    unittest.main()
