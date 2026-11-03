"""Coverage for endpoint completeness, filtering and receive-time charts."""
import datetime
import os
import tempfile
import unittest
from unittest.mock import patch

import config
import db
import flow_service
import services
import security


class FlowQueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = patch.multiple(config, DB_PATH=os.path.join(self.temp.name, 'test.db'), DATA_DIR=self.temp.name, DEFAULT_PASSWORD=None)
        self.settings.start()
        self.addCleanup(self.settings.stop)
        db.init_db()
        self.rid = services.create_router({'name': 'test', 'host': '127.0.0.1', 'port': 8728, 'username': '', 'password': '', 'flow_enabled': 1})
        now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        conn = db.get_connection()
        try:
            did = conn.execute('INSERT INTO flow_datagrams (router_id, received_at,export_seconds,sequence,engine_type,engine_id,record_count) VALUES (?,?,1,1,0,0,75)', (self.rid, now)).lastrowid
            conn.executemany('INSERT INTO flow_records (router_id,datagram_id,received_at,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,input_if,output_if) VALUES (?,?,?,?,?,1234,443,6,?,1,1,2)',
                             [(self.rid, did, now, f'192.168.1.{n}', '8.8.8.8', n*100) for n in range(1,76)])
            conn.commit()
        finally:
            conn.close()

    def test_all_endpoints_paginated_and_ranked(self):
        first = flow_service.overview(self.rid)
        second = flow_service.overview(self.rid, page=2)
        self.assertEqual(first['total_ips'], 76)
        self.assertEqual(len(first['top_ips']), 50)
        ips = {r['ip'] for r in first['top_ips'] + second['top_ips']}
        self.assertEqual(len(ips), 76)
        self.assertEqual(flow_service.overview(self.rid, sort='upload')['top_ips'][0]['ip'], '192.168.1.75')
        self.assertEqual(flow_service.overview(self.rid, sort='download')['top_ips'][0]['ip'], '8.8.8.8')
        self.assertEqual(flow_service.overview(self.rid, page=999)['page'], 2)

    def test_filters_and_no_double_counted_totals(self):
        data = flow_service.overview(self.rid, src='192.168.1.2', dst='8.8.8.8')
        self.assertEqual(data['bytes'], 200)
        self.assertEqual(data['total_ips'], 2)
        self.assertEqual(flow_service.overview(self.rid, view='src')['total_ips'], 75)
        self.assertEqual(flow_service.overview(self.rid, view='dst')['total_ips'], 1)
        self.assertEqual(flow_service.overview(self.rid, search='192.168.1.75')['total_ips'], 1)
        self.assertEqual(flow_service.overview(self.rid, dst='1.1.1.1')['flows'], 0)
        for kwargs in ({'src': "' OR 1=1 --"}, {'sort': 'bytes; DROP TABLE routers'}, {'page': 0}, {'per_page': 201}, {'minutes': 2}):
            with self.assertRaises(ValueError):
                flow_service.overview(self.rid, **kwargs)

    def test_chart_window_direction_gaps_and_router_isolation(self):
        for minutes in (1, 5, 30, 60, 10080):
            data = flow_service.ip_history(self.rid, '192.168.1.2', minutes)
            self.assertLessEqual(len(data['points']), 122)
            populated = [p for p in data['points'] if p['upload_mbps'] is not None]
            self.assertEqual(len(populated), 1)
            self.assertGreater(populated[0]['upload_mbps'], 0)
            self.assertEqual(populated[0]['download_mbps'], 0)
            self.assertIsNone(data['points'][0]['upload_mbps'])
        self.assertEqual(flow_service.ip_history(self.rid+1, '192.168.1.2', 5)['points'], [])
        self.assertEqual(flow_service.ip_history(self.rid, '1.1.1.1', 5)['points'], [])
        conn = db.get_connection()
        try:
            conn.execute("UPDATE flow_records SET received_at=datetime('now','-10 minutes')")
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(flow_service.ip_history(self.rid, '192.168.1.2', 5)['points'], [])
        self.assertTrue(flow_service.ip_history(self.rid, '192.168.1.2', 30)['points'])

    def test_history_api_uses_flow_and_short_periods(self):
        import app
        client = app.create_app().test_client()
        with client.session_transaction() as session:
            session['user_id'] = 1
            session['role'] = 'admin'
        for period in ('1m', '5m', '30m'):
            response = client.get(f'/api/ip/{self.rid}/192.168.1.2/history?period={period}')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['data']['source'], 'flow')
            self.assertTrue(response.json['data']['points'])
        self.assertEqual(client.get(f'/api/ip/{self.rid}/192.168.1.2/history?period=bad').status_code, 400)
        for query in ('page=bad', 'src=bad', 'per_page=999', 'direction=bad'):
            self.assertEqual(client.get(f'/api/flow/{self.rid}?{query}').status_code, 400)
        self.assertEqual(client.get('/login').headers['X-Frame-Options'], 'DENY')

    def test_bootstrap_is_private_and_does_not_elevate_existing_user(self):
        path = os.path.join(self.temp.name, '.bootstrap_password')
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path) as handle:
            password = handle.read()
        conn = db.get_connection()
        try:
            user = conn.execute('SELECT * FROM users').fetchone()
            self.assertTrue(security.verify_password(password, user['password_hash']))
            self.assertFalse(security.verify_password('admin', user['password_hash']))
            conn.execute("UPDATE users SET role='viewer'")
            conn.commit()
        finally:
            conn.close()
        db.init_db()
        conn = db.get_connection()
        try:
            self.assertEqual(conn.execute('SELECT role FROM users').fetchone()[0], 'viewer')
        finally:
            conn.close()

    def test_recursive_audit_redaction(self):
        redacted = security._redact_dict([{'Password': 'secret123', 'nested': {'token': 'hidden', 'name': 'visible'}, 'action_config': '{"url":"sensitive"}'}])
        for value in ('secret123', 'hidden', 'sensitive'):
            self.assertNotIn(value, redacted)
        self.assertIn('visible', redacted)

class ApiBaselineTests(unittest.TestCase):
    def test_baseline_reset_and_direction(self):
        with tempfile.TemporaryDirectory() as directory, patch.multiple(config, DB_PATH=os.path.join(directory,'test.db'), DATA_DIR=directory):
            db.init_db()
            rid=services.create_router({'name':'api','host':'127.0.0.1','port':8728,'username':'','password':''})
            conn=db.get_connection()
            now=datetime.datetime.now()
            for age,rx,tx in ((90,1000,2000),(30,601000,302000),(10,1,1)):
                conn.execute('INSERT INTO ip_bandwidth_data(router_id,ip_address,rx_bytes,tx_bytes,timestamp) VALUES (?,?,?,?,?)',(rid,'192.168.1.10',rx,tx,(now-datetime.timedelta(seconds=age)).strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit();conn.close()
            rows=services.get_ip_bandwidth_history(rid,'192.168.1.10','1m')
            self.assertEqual(len(rows),2)
            self.assertAlmostEqual(rows[0]['download_mbps'],0.08)
            self.assertAlmostEqual(rows[0]['upload_mbps'],0.04)
            self.assertIsNone(rows[1]['total_mbps'])

class SnmpTrafficTests(unittest.TestCase):
    def test_snmp_rates_without_api(self):
        with tempfile.TemporaryDirectory() as directory, patch.multiple(config, DB_PATH=os.path.join(directory,'test.db'), DATA_DIR=directory):
            db.init_db()
            rid=services.create_router({'name':'snmp','host':'127.0.0.1','port':8728,'username':'','password':'','snmp_enabled':1})
            conn=db.get_connection()
            now=datetime.datetime.now(datetime.timezone.utc)
            for age,rx,tx in ((70,100,200),(10,60100,120200)):
                conn.execute('INSERT INTO snmp_interface_metrics(router_id,interface_name,ifindex,rx_bytes,tx_bytes,timestamp) VALUES (?,?,?,?,?,?)',(rid,'ether1',1,rx,tx,(now-datetime.timedelta(seconds=age)).strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit();conn.close()
            result=services.get_interface_traffic(rid)
            self.assertEqual(result['source'],'snmp')
            self.assertEqual(result['interfaces'][0]['rx_rate_bps'],8000)
            self.assertEqual(result['interfaces'][0]['tx_rate_bps'],16000)

class SourceIntegrationTests(FlowQueryTests):
    def test_snmp_inventory_and_flow_peers(self):
        import json
        conn=db.get_connection()
        payload={'interfaces':[{'name':'ether1','type':'SNMP','running':'false','mtu':'N/A'}], 'ip_addresses':[{'address':'192.168.50.1/24','network':'192.168.50.0','interface':'ether1'}]}
        try:
            conn.execute('UPDATE routers SET snmp_enabled=1 WHERE id=?',(self.rid,))
            conn.execute("INSERT INTO snmp_inventory VALUES (?,datetime('now'),?)",(self.rid,json.dumps(payload)))
            conn.commit()
        finally:conn.close()
        services._network_ips_cache.clear()
        router=services.get_router(self.rid)
        self.assertIn('192.168.50.1',[r['ip'] for r in services.get_network_ips(router)['records']])
        info=services.get_snmp_detailed_info(router)
        self.assertEqual(info['interfaces'][0]['running'],'false')
        self.assertEqual(info['ip_addresses'][0]['address'],'192.168.50.1/24')
        peers=services.get_ip_connections_details(self.rid,'192.168.1.75')
        self.assertEqual(peers['source'],'flow')
        self.assertEqual(peers['destinations'][0]['total_bytes'],7500)
        self.assertEqual(peers['connections'],[])

    def test_numeric_snmp_table_index(self):
        import snmp_collector
        from types import SimpleNamespace
        output='.1.3.6.1.2.1.4.20.1.2.192.168.1.1 = 2\n.1.3.6.1.2.1.4.20.1.2.192.168.2.1 = 3\n'
        with patch.object(snmp_collector.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=output)):
            rows=snmp_collector.snmp_walk('localhost','test','.1.3.6.1.2.1.4.20.1.2',full_suffix=True)
        self.assertEqual(rows,[('192.168.1.1','2'),('192.168.2.1','3')])
