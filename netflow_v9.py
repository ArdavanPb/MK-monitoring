"""Bounded NetFlow v9 template decoder (RFC 3954)."""
import ipaddress
import struct
import time
from collections import OrderedDict


class V9Decoder:
    def __init__(self, ttl=3600, max_templates=4096):
        self.ttl = ttl
        self.max_templates = max_templates
        self.templates = OrderedDict()
        self.boots = OrderedDict()

    def parse(self, packet, exporter):
        if len(packet) < 20:
            raise ValueError("short NetFlow v9 header")
        version, _count, uptime, seconds, sequence, domain = struct.unpack_from("!HHIIII", packet)
        if version != 9:
            raise ValueError("not NetFlow v9")
        stream = (exporter, domain)
        now = time.monotonic()
        # Expire templates even if they have not been used recently.
        for key, entry in list(self.templates.items()):
            if now - entry[2] > self.ttl:
                del self.templates[key]
        previous = self.boots.get(stream)
        if previous and seconds >= previous[0] and uptime + 1000 < previous[1]:
            # Includes uptime wrap: wait for a refreshed template in either case.
            for key in list(self.templates):
                if key[:2] == stream:
                    del self.templates[key]

        sets = []
        offset = 20
        while offset < len(packet):
            if len(packet) - offset < 4:
                raise ValueError("truncated v9 FlowSet header")
            set_id, length = struct.unpack_from("!HH", packet, offset)
            if length < 4 or offset + length > len(packet):
                raise ValueError("invalid v9 FlowSet length")
            sets.append((set_id, packet[offset + 4:offset + length]))
            offset += length

        updates = {}
        for set_id, payload in sets:
            if set_id not in (0, 1):
                continue
            pos = 0
            while pos < len(payload):
                remaining = len(payload) - pos
                if remaining <= 3 and not any(payload[pos:]):
                    break
                header_size = 4 if set_id == 0 else 6
                if remaining < header_size:
                    raise ValueError("truncated v9 template")
                if set_id == 0:
                    template_id, count = struct.unpack_from("!HH", payload, pos)
                else:
                    template_id, scopes, options = struct.unpack_from("!HHH", payload, pos)
                    if scopes % 4 or options % 4:
                        raise ValueError("invalid v9 options lengths")
                    count = (scopes + options) // 4
                pos += header_size
                if template_id < 256 or not 1 <= count <= 256 or pos + count * 4 > len(payload):
                    raise ValueError("invalid v9 template fields")
                fields = [struct.unpack_from("!HH", payload, pos + i * 4) for i in range(count)]
                pos += count * 4
                if any(length == 0 for _, length in fields) or sum(length for _, length in fields) > 65531:
                    raise ValueError("invalid v9 field width")
                updates[stream + (template_id,)] = (fields, set_id == 1, now)

        records = []
        missing = set()
        for set_id, payload in sets:
            if set_id < 256:
                continue
            key = stream + (set_id,)
            template = updates.get(key) or self.templates.get(key)
            if template is None:
                missing.add(set_id)
                continue
            fields, options, _ = template
            width = sum(length for _, length in fields)
            count, padding = divmod(len(payload), width)
            if padding > 3 or (padding and any(payload[-padding:])):
                raise ValueError("truncated v9 data record")
            if options:
                continue  # Exporter metadata is not traffic volume.
            for index in range(count):
                values = {}
                pos = index * width
                for field, length in fields:
                    values[field] = payload[pos:pos + length]
                    pos += length
                src = values.get(8) or values.get(27)
                dst = values.get(12) or values.get(28)
                if not src or not dst or len(src) not in (4, 16) or len(dst) != len(src):
                    continue
                if 1 not in values or 2 not in values:
                    continue

                def number(field):
                    raw = values.get(field, b"\x00")
                    if len(raw) > 8:
                        raise ValueError("unsupported v9 integer width")
                    value = int.from_bytes(raw, "big")
                    if value > 9223372036854775807:
                        raise ValueError("v9 counter exceeds storage range")
                    return value

                records.append({
                    "src_ip": str(ipaddress.ip_address(src)), "dst_ip": str(ipaddress.ip_address(dst)),
                    "src_port": number(7), "dst_port": number(11), "protocol": number(4),
                    "bytes": number(1), "packets": number(2),
                    "input_if": number(10), "output_if": number(14),
                })
        # Commit template updates only after the entire packet validates.
        self.templates.update(updates)
        for key in updates:
            self.templates.move_to_end(key)
        while len(self.templates) > self.max_templates:
            self.templates.popitem(last=False)
        if not previous or seconds >= previous[0]:
            self.boots[stream] = (seconds, uptime)
            self.boots.move_to_end(stream)
        while len(self.boots) > self.max_templates:
            self.boots.popitem(last=False)
        return {
            "export_seconds": seconds, "sequence": sequence,
            # v5 engine_type is one byte; 256 reserves a distinct dedup namespace
            # for v9. engine_id holds the full 32-bit observation Source ID.
            "engine_type": 256, "engine_id": domain, "missing_templates": sorted(missing),
        }, records
