import struct
import unittest

from netflow_v9 import V9Decoder


FIELDS = [(8, 4), (12, 4), (1, 8), (2, 4), (7, 2), (11, 2), (4, 1)]


def flowset(identity, body):
    body += bytes((-len(body)) % 4)
    return struct.pack("!HH", identity, len(body) + 4) + body


def template(identity=256, fields=FIELDS):
    return flowset(0, struct.pack("!HH", identity, len(fields)) + b"".join(struct.pack("!HH", *f) for f in fields))


def export(*sets, domain=1, uptime=10000, sequence=1):
    return struct.pack("!HHIIII", 9, 1, uptime, 1700000000, sequence, domain) + b"".join(sets)


def data():
    return flowset(256, bytes([192, 168, 88, 10, 8, 8, 8, 8]) + struct.pack("!QIHHB", 5000000000, 25, 12345, 443, 6))


class V9Tests(unittest.TestCase):
    def test_template_cache_and_padding(self):
        decoder = V9Decoder()
        decoder.parse(export(template()), "router")
        header, records = decoder.parse(export(data()), "router")
        self.assertEqual(header["missing_templates"], [])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["bytes"], 5000000000)
        self.assertEqual(records[0]["src_ip"], "192.168.88.10")
        self.assertEqual(records[0]["dst_port"], 443)

    def test_templates_later_in_same_packet(self):
        _, records = V9Decoder().parse(export(data(), template()), "router")
        self.assertEqual(len(records), 1)

    def test_missing_and_isolated_templates(self):
        decoder = V9Decoder()
        decoder.parse(export(template()), "router")
        for exporter, domain in [("other", 1), ("router", 2)]:
            header, records = decoder.parse(export(data(), domain=domain), exporter)
            self.assertEqual(records, [])
            self.assertEqual(header["missing_templates"], [256])

    def test_expiry_and_reboot(self):
        decoder = V9Decoder(ttl=-1)
        decoder.parse(export(template()), "router")
        self.assertEqual(decoder.parse(export(data()), "router")[1], [])
        decoder = V9Decoder()
        decoder.parse(export(template()), "router")
        self.assertEqual(decoder.parse(export(data(), uptime=1), "router")[1], [])

    def test_bad_lengths_do_not_install_templates(self):
        decoder = V9Decoder()
        with self.assertRaises(ValueError):
            decoder.parse(export(template(), data())[:-2], "router")
        self.assertEqual(len(decoder.templates), 0)
        with self.assertRaises(ValueError):
            decoder.parse(export(struct.pack("!HH", 256, 0)), "router")

    def test_options_are_not_counted_as_traffic(self):
        options = flowset(1, struct.pack("!HHHHHHH", 300, 4, 4, 1, 4, 34, 4))
        _, records = V9Decoder().parse(export(options, flowset(300, struct.pack("!II", 0, 100))), "router")
        self.assertEqual(records, [])

    def test_ipv6(self):
        fields = [(27, 16), (28, 16), (1, 4), (2, 4)]
        import ipaddress
        payload = ipaddress.ip_address("fd00::1").packed + ipaddress.ip_address("2001:db8::2").packed + struct.pack("!II", 1000, 2)
        _, records = V9Decoder().parse(export(template(fields=fields), flowset(256, payload)), "router")
        self.assertEqual(records[0]["src_ip"], "fd00::1")
