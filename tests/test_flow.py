"""NetFlow v5 parsing, persistence, and dashboard integration tests."""
import datetime
import ipaddress
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import config
import db
import flow_collector
import flow_service
import services


def packet(sequence=1, version=5, bytes_count=1000):
    header = flow_collector.HEADER.pack(version, 1, 1000, 1700000000, 0, sequence, 0, 0, 0)
    record = flow_collector.RECORD.pack(
        int(ipaddress.IPv4Address("192.168.88.10")),
        int(ipaddress.IPv4Address("8.8.8.8")), 0,
        1, 2, 10, bytes_count, 100, 900,
        53000, 443, 0, 0, 6, 0, 0, 0, 0, 0, 0,
    )
    return header + record


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.old_db = config.DB_PATH
        cls.old_dir = config.DATA_DIR
        config.DB_PATH = os.path.join(cls.temp.name, "test.db")
        config.DATA_DIR = cls.temp.name
        db.init_db()
        cls.router_id = services.create_router({
            "name": "Test router", "host": "127.0.0.1", "port": 8728,
            "username": "", "password": "", "flow_enabled": 1,
        })

    @classmethod
    def tearDownClass(cls):
        config.DB_PATH = cls.old_db
        config.DATA_DIR = cls.old_dir
        cls.temp.cleanup()

    def setUp(self):
        services._network_ips_cache.clear()
        conn = db.get_connection()
        try:
            conn.execute("DELETE FROM flow_datagrams")
            conn.commit()
        finally:
            conn.close()

    def test_parser_rejects_wrong_version_and_truncation(self):
        with self.assertRaises(ValueError):
            flow_collector.parse_v5(packet(version=9))
        with self.assertRaises(ValueError):
            flow_collector.parse_v5(packet()[:-1])
        header, records = flow_collector.parse_v5(packet())
        self.assertEqual(header["sequence"], 1)
        self.assertEqual(records[0]["src_ip"], "192.168.88.10")
        self.assertEqual(records[0]["bytes"], 1000)

    def test_dedup_and_traffic_queries(self):
        self.assertEqual(flow_collector.store_datagram(self.router_id, packet()), 1)
        self.assertEqual(flow_collector.store_datagram(self.router_id, packet()), 0)
        summary = flow_service.overview(self.router_id)
        self.assertEqual(summary["flows"], 1)
        self.assertEqual(summary["bytes"], 1000)
        self.assertEqual(summary["packets"], 10)
        self.assertTrue(summary["fresh"])
        self.assertEqual(summary["top_ips"][0]["ip"], "192.168.88.10")
        self.assertEqual(summary["protocols"][0]["name"], "TCP")
        ip = flow_service.ip_summary(self.router_id, "192.168.88.10")
        self.assertEqual(ip["upload_bytes"], 1000)
        self.assertEqual(ip["download_bytes"], 0)
        network_ips = services.get_network_ips(services.get_router(self.router_id))
        self.assertEqual(network_ips["records"][0]["ip"], "192.168.88.10")
        self.assertIn("Flow", network_ips["records"][0]["sources"])

    def test_v9_storage_and_summary(self):
        from test_netflow_v9 import export, template, data
        flow_collector.store_datagram(self.router_id, export(template()))
        self.assertEqual(flow_collector.store_datagram(self.router_id, export(data(), sequence=2)), 1)
        self.assertEqual(flow_collector.store_datagram(self.router_id, export(data(), sequence=2)), 0)
        summary = flow_service.overview(self.router_id)
        self.assertEqual(summary["bytes"], 5000000000)
        self.assertEqual(summary["flows"], 1)

    def test_stale_flow_and_exporter_allowlist(self):
        import app

        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        flow_collector.store_datagram(self.router_id, packet(), old)
        self.assertFalse(flow_service.snapshot(self.router_id)["fresh"])
        self.assertEqual(flow_collector.exporter_map()["127.0.0.1"], self.router_id)
        client = app.create_app().test_client()
        with client.session_transaction() as session:
            session["user_id"] = 1
            session["role"] = "admin"
            session["username"] = "admin"
        self.assertIn(b"Waiting for recent Flow packets", client.get("/").data)

    def test_authenticated_flow_page_and_api(self):
        import app

        flow_collector.store_datagram(self.router_id, packet())
        client = app.create_app().test_client()
        self.assertEqual(client.get(f"/api/flow/{self.router_id}").status_code, 401)
        with client.session_transaction() as session:
            session["user_id"] = 1
            session["role"] = "admin"
            session["username"] = "admin"
        self.assertEqual(client.get(f"/flow/{self.router_id}").status_code, 200)
        response = client.get(f"/api/flow/{self.router_id}?minutes=5")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"]["bytes"], 1000)
        self.assertEqual(client.get(f"/api/flow/{self.router_id}?minutes=2").status_code, 400)
        dashboard = client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Flow Receiving", dashboard.data)

    def test_flow_only_router_form(self):
        import app

        client = app.create_app().test_client()
        with client.session_transaction() as session:
            session["user_id"] = 1
            session["role"] = "admin"
            session["username"] = "admin"
        page = client.get("/add_router")
        self.assertEqual(page.status_code, 200)
        csrf = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        response = client.post("/add_router", data={
            "csrf_token": csrf, "name": "Flow only", "host": "192.0.2.10",
            "flow_enabled": "1", "flow_source_ip": "192.0.2.10",
        })
        self.assertEqual(response.status_code, 302)
        created = next(router for router in services.list_routers() if router["name"] == "Flow only")
        self.assertEqual(created["flow_source_ip"], "192.0.2.10")
        services.delete_router(created["id"])

    def test_udp_listener_receives_export(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        env = dict(os.environ, DB_PATH=config.DB_PATH, FLOW_LISTEN_HOST="127.0.0.1", FLOW_PORT=str(port))
        process = subprocess.Popen(
            [sys.executable, "flow_collector.py"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    sender.sendto(packet(sequence=55), ("127.0.0.1", port))
                    if flow_service.snapshot(self.router_id)["flows"] == 1:
                        break
                    time.sleep(0.1)
            self.assertEqual(flow_service.snapshot(self.router_id)["flows"], 1)
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_snmp_failure_is_visible_despite_recent_sample(self):
        import app

        router_id = services.create_router({
            "name": "SNMP failed", "host": "192.0.2.20", "port": 8728,
            "username": "", "password": "", "snmp_enabled": 1,
        })
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        conn = db.get_connection()
        try:
            conn.execute(
                "INSERT INTO snmp_system_metrics (router_id,timestamp,cpu_percent) VALUES (?,?,?)",
                (router_id, now, 12),
            )
            conn.execute(
                "INSERT INTO snmp_poll_state (router_id,status,checked_at) VALUES (?,?,?)",
                (router_id, "offline", now),
            )
            conn.commit()
        finally:
            conn.close()
        try:
            self.assertTrue(services.get_snmp_detailed_info(services.get_router(router_id))["_source"]["stale"])
            client = app.create_app().test_client()
            with client.session_transaction() as session:
                session["user_id"] = 1
                session["role"] = "admin"
                session["username"] = "admin"
            page = client.get("/")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"SNMP offline", page.data)
        finally:
            services.delete_router(router_id)


if __name__ == "__main__":
    unittest.main()
