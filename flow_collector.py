#!/usr/bin/env python3
"""Receive RouterOS Traffic Flow NetFlow v5/v9 exports over UDP.

Only exporters explicitly enabled on a router are accepted. NetFlow v5 carries
IPv4 records; v9 templates support IPv4/IPv6. IPFIX is not supported.
"""
import datetime
import ipaddress
import logging
import signal
import socket
import struct
import time

import config
import db
from netflow_v9 import V9Decoder

logger = logging.getLogger("flow_collector")
HEADER = struct.Struct("!HHIIIIBBH")
RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")
_running = True
_v9_decoder = V9Decoder()
_last_warning = {}


def warn_limited(router_id, message):
    now = time.monotonic()
    if now - _last_warning.get(router_id, float("-inf")) >= 60:
        logger.warning("Router %s: %s", router_id, message)
        _last_warning[router_id] = now


def parse_v5(packet):
    """Return (header, records) or raise ValueError for a malformed export."""
    if len(packet) < HEADER.size:
        raise ValueError("short NetFlow header")
    version, count, uptime, export_seconds, _nsecs, sequence, engine_type, engine_id, sampling = HEADER.unpack_from(packet)
    if version != 5:
        raise ValueError(f"unsupported NetFlow version {version}; use version=5")
    if count > 1000 or len(packet) != HEADER.size + count * RECORD.size:
        raise ValueError("invalid NetFlow v5 record count or length")
    records = []
    for offset in range(HEADER.size, len(packet), RECORD.size):
        row = RECORD.unpack_from(packet, offset)
        records.append({
            "src_ip": str(ipaddress.IPv4Address(row[0])),
            "dst_ip": str(ipaddress.IPv4Address(row[1])),
            "input_if": row[3], "output_if": row[4],
            "packets": row[5], "bytes": row[6],
            "src_port": row[9], "dst_port": row[10], "protocol": row[13],
        })
    return {
        "export_seconds": export_seconds, "sequence": sequence,
        "engine_type": engine_type, "engine_id": engine_id,
        "uptime": uptime, "sampling": sampling,
    }, records


def exporter_map():
    """Map unique allowed IPv4 source addresses to router IDs."""
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT id, host, flow_source_ip FROM routers WHERE flow_enabled=1"
        ).fetchall()
    finally:
        conn.close()
    sources = {}
    for row in rows:
        address = (row["flow_source_ip"] or row["host"]).strip()
        try:
            ipaddress.IPv4Address(address)
            resolved = [address]
        except ipaddress.AddressValueError:
            try:
                resolved = list({item[4][0] for item in socket.getaddrinfo(address, None, socket.AF_INET)})
            except socket.gaierror:
                logger.warning("Cannot resolve Flow exporter %s for router %s", address, row["id"])
                continue
        for source in resolved:
            if source in sources and sources[source] != row["id"]:
                logger.warning("Ambiguous Flow exporter %s; ignoring it", source)
                sources[source] = None
            else:
                sources[source] = row["id"]
    return {source: router_id for source, router_id in sources.items() if router_id is not None}


def store_datagram(router_id, packet, received_at=None):
    """Persist one valid export atomically; return number of new flow records."""
    if len(packet) < 2:
        raise ValueError("short NetFlow packet")
    version = struct.unpack_from("!H", packet)[0]
    if version == 9:
        header, records = _v9_decoder.parse(packet, router_id)
        if header["missing_templates"]:
            warn_limited(router_id, f"Waiting for v9 templates {header['missing_templates']}; undecodable FlowSets skipped")
    elif version == 5:
        header, records = parse_v5(packet)
    else:
        raise ValueError(f"unsupported NetFlow version {version}; supported: 5, 9")
    received_at = received_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_connection()
    try:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO flow_datagrams
               (router_id, received_at, export_seconds, sequence, engine_type, engine_id, record_count)
               VALUES (?,?,?,?,?,?,?)""",
            (router_id, received_at, header["export_seconds"], header["sequence"],
             header["engine_type"], header["engine_id"], len(records)),
        )
        if not cursor.rowcount:
            return 0
        if records:
            conn.executemany(
                """INSERT INTO flow_records
                   (router_id, datagram_id, received_at, src_ip, dst_ip, src_port, dst_port,
                    protocol, bytes, packets, input_if, output_if)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                [(router_id, cursor.lastrowid, received_at, row["src_ip"], row["dst_ip"],
                  row["src_port"], row["dst_port"], row["protocol"], row["bytes"],
                  row["packets"], row["input_if"], row["output_if"]) for row in records],
            )
        conn.commit()
        return len(records)
    finally:
        conn.close()


def prune_old_data():
    threshold = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=config.FLOW_RETENTION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM flow_datagrams WHERE received_at < ?", (threshold,))
        conn.commit()
    finally:
        conn.close()


def _stop(_signal, _frame):
    global _running
    _running = False


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s FLOW %(levelname)s: %(message)s")
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    db.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((config.FLOW_LISTEN_HOST, config.FLOW_PORT))
    sock.settimeout(1)
    logger.info("Listening for NetFlow v5/v9 on %s:%s/udp", config.FLOW_LISTEN_HOST, config.FLOW_PORT)
    sources = {}
    refreshed_at = float("-inf")
    pruned_at = float("-inf")
    try:
        while _running:
            now = time.monotonic()
            if now - refreshed_at >= 30:
                sources = exporter_map()
                refreshed_at = now
            if now - pruned_at >= 3600:
                prune_old_data()
                pruned_at = now
            try:
                packet, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            router_id = sources.get(address[0])
            if router_id is None:
                continue
            try:
                store_datagram(router_id, packet)
            except ValueError as exc:
                warn_limited(router_id, f"Rejected Flow packet from {address[0]}: {exc}")
            except Exception:
                logger.exception("Failed to store Flow packet from %s", address[0])
    finally:
        sock.close()


if __name__ == "__main__":
    main()
