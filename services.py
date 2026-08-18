"""Business logic: routers, bandwidth, connections, logs, backups, alerts."""
import datetime
import difflib
import glob
import json
import logging
import os
import subprocess
import threading
import time
import traceback
from collections import OrderedDict

import config
import db
import security
import utils
import routeros_client

logger = logging.getLogger("app")


# ─── Router repository ────────────────────────────────────────────────────

_SECRET_FIELDS = ("password", "snmp_community", "snmp_auth_pass", "snmp_priv_pass")


def decrypt_router(data):
    for field in _SECRET_FIELDS:
        data[field] = security.decrypt_secret(data.get(field, ""))
    return data


def encrypt_router(data):
    for field in _SECRET_FIELDS:
        if field in data:
            data[field] = security.encrypt_secret(data.get(field, ""))
    return data


def get_router(router_id):
    """Return a router as a dict with decrypted secrets, or None."""
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM routers WHERE id=?", (router_id,)).fetchone()
        return decrypt_router(dict(row)) if row else None
    finally:
        conn.close()


def list_routers():
    conn = db.get_connection()
    try:
        rows = conn.execute("SELECT * FROM routers ORDER BY created_at DESC").fetchall()
        return [decrypt_router(dict(row)) for row in rows]
    finally:
        conn.close()


def create_router(data):
    conn = db.get_connection()
    try:
        data = encrypt_router(dict(data))
        cursor = conn.execute(
            """INSERT INTO routers
               (name, host, port, username, password, snmp_enabled, snmp_community,
                snmp_version, snmp_port, snmp_user, snmp_auth_protocol, snmp_auth_pass,
                snmp_priv_protocol, snmp_priv_pass)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["name"], data["host"], data["port"], data["username"], data["password"],
                data.get("snmp_enabled", 0), data.get("snmp_community", "public"),
                data.get("snmp_version", 2), data.get("snmp_port", 161), data.get("snmp_user", ""),
                data.get("snmp_auth_protocol", "MD5"), data.get("snmp_auth_pass", ""),
                data.get("snmp_priv_protocol", "DES"), data.get("snmp_priv_pass", ""),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def update_router(router_id, data):
    conn = db.get_connection()
    try:
        data = encrypt_router(dict(data))
        conn.execute(
            """UPDATE routers SET name=?, host=?, port=?, username=?, password=?,
               snmp_enabled=?, snmp_community=?, snmp_version=?, snmp_port=?,
               snmp_user=?, snmp_auth_protocol=?, snmp_auth_pass=?,
               snmp_priv_protocol=?, snmp_priv_pass=? WHERE id=?""",
            (
                data["name"], data["host"], data["port"], data["username"], data["password"],
                data.get("snmp_enabled", 0), data.get("snmp_community", "public"),
                data.get("snmp_version", 2), data.get("snmp_port", 161), data.get("snmp_user", ""),
                data.get("snmp_auth_protocol", "MD5"), data.get("snmp_auth_pass", ""),
                data.get("snmp_priv_protocol", "DES"), data.get("snmp_priv_pass", ""),
                router_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def delete_router(router_id):
    """Delete a router and all of its associated data."""
    conn = db.get_connection()
    try:
        tables = (
            "ip_bandwidth_data", "interface_bandwidth_data", "router_status_cache",
            "router_logs", "log_retention_settings", "snmp_system_metrics",
            "snmp_interface_metrics", "alert_rules",
        )
        for table in tables:
            conn.execute(f"DELETE FROM {table} WHERE router_id=?", (router_id,))
        conn.execute("DELETE FROM alert_events WHERE router_id=?", (router_id,))
        conn.execute("DELETE FROM routers WHERE id=?", (router_id,))
        conn.commit()
    finally:
        conn.close()


def migrate_plaintext_credentials():
    """Encrypt any legacy plaintext credentials found in the database."""
    conn = db.get_connection()
    try:
        rows = conn.execute("SELECT id, password, snmp_community, snmp_auth_pass, snmp_priv_pass FROM routers").fetchall()
        for row in rows:
            encrypted = {field: security.encrypt_secret(row[field]) for field in _SECRET_FIELDS}
            conn.execute(
                "UPDATE routers SET password=?, snmp_community=?, snmp_auth_pass=?, snmp_priv_pass=? WHERE id=?",
                (encrypted["password"], encrypted["snmp_community"], encrypted["snmp_auth_pass"], encrypted["snmp_priv_pass"], row["id"]),
            )
        conn.commit()
    finally:
        conn.close()


# ─── Status cache ─────────────────────────────────────────────────────────

def update_router_status_cache(router_id, name, host, port, username, password):
    api, connection, error = routeros_client.connect_to_router(host, port, username, password)
    if api:
        try:
            info = routeros_client.get_router_info(api)
            status = "online"
            router_info = json.dumps(info)
        finally:
            connection.disconnect()
    else:
        status = "offline"
        router_info = json.dumps({"error": error or "Connection failed"})

    conn = db.get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO router_status_cache
               (router_id, status, last_checked, router_info, source_type, api_port)
               VALUES (?,?,?,?,?,?)""",
            (router_id, status, datetime.datetime.now(), router_info, "API", port),
        )
        conn.commit()
    finally:
        conn.close()
    return status, router_info


def get_status_cache(router_id):
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT status, router_info, source_type, snmp_port, api_port "
            "FROM router_status_cache WHERE router_id=? ORDER BY last_checked DESC LIMIT 1",
            (router_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def set_status_cache(router_id, status, info, source_type, port=None, snmp_port=None):
    conn = db.get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO router_status_cache
               (router_id, status, last_checked, router_info, source_type, snmp_port, api_port)
               VALUES (?,?,?,?,?,?,?)""",
            (router_id, status, datetime.datetime.now(), json.dumps(info), source_type, snmp_port, port),
        )
        conn.commit()
    finally:
        conn.close()


# ─── Bandwidth ────────────────────────────────────────────────────────────

def _strip_port(address):
    """Strip a trailing :port from an IPv4 address (RouterOS 'ip:port' form)."""
    if not address:
        return ""
    address = str(address).strip()
    if ":" in address and "." in address:
        return address.split(":", 1)[0]
    return address


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_connection_bytes(value):
    """Return (sent, received) from a RouterOS byte-count field.

    ``/ip/accounting`` returns a single cumulative integer, while
    ``/ip/firewall/connection`` returns a "sent/received" string.
    """
    if value is None:
        return 0, 0
    if isinstance(value, (int, float)):
        return int(value), 0
    value = str(value)
    if "/" in value:
        sent, _, received = value.partition("/")
        return _as_int(sent), _as_int(received)
    return _as_int(value), 0


def _connection_upload_download(connection):
    """Return (upload_bytes, download_bytes) for a firewall connection.

    RouterOS 7 exposes ``orig-bytes`` (src->dst, i.e. upload) and
    ``repl-bytes`` (dst->src, i.e. download). RouterOS 6 used a single
    ``bytes`` field formatted as "sent/received".
    """
    orig = connection.get("orig-bytes")
    repl = connection.get("repl-bytes")
    if orig is not None or repl is not None:
        return _as_int(orig), _as_int(repl)
    return _parse_connection_bytes(connection.get("bytes", "0/0"))


# Routers where /ip/accounting is not available (e.g. the optional accounting
# package is not installed). We stop querying it for these to avoid repeated
# "no such command prefix" errors and fall back to firewall connections.
_accounting_unavailable = set()


def _is_unavailable_error(error):
    """Return True if a RouterOS error indicates an optional feature is absent."""
    return bool(error) and "no such command" in error


def collect_ip_bandwidth_data(router_id, api):
    """Collect per-IP traffic counters into ip_bandwidth_data."""
    try:
        accounting = []
        if router_id not in _accounting_unavailable:
            result = routeros_client.safe_api_call(api, "/ip/accounting")
            if result["data"] is not None:
                accounting = result["data"]
            elif _is_unavailable_error(result["error"]):
                _accounting_unavailable.add(router_id)
                logger.info("Router %s: /ip/accounting unavailable; using firewall connections", router_id)

        connections = []
        if not accounting:
            connections = routeros_client.safe_api_call(api, "/ip/firewall/connection")["data"] or []

        arp_table = {}
        for entry in routeros_client.safe_api_call(api, "/ip/arp")["data"] or []:
            if entry.get("address"):
                arp_table[entry["address"]] = {
                    "mac_address": entry.get("mac-address"),
                    "hostname": entry.get("host-name"),
                }

        internal_ips = set()
        for lease in routeros_client.safe_api_call(api, "/ip/dhcp-server/lease")["data"] or []:
            if lease.get("address"):
                internal_ips.add(lease["address"])
        for address in routeros_client.safe_api_call(api, "/ip/address")["data"] or []:
            if address.get("address"):
                internal_ips.add(address["address"].split("/")[0])

        ip_traffic = {}

        def add_traffic(ip, tx_bytes, rx_bytes):
            bucket = ip_traffic.setdefault(ip, {"rx_bytes": 0, "tx_bytes": 0})
            bucket["tx_bytes"] += tx_bytes
            bucket["rx_bytes"] += rx_bytes

        for item in accounting:
            src = _strip_port(item.get("src-address"))
            dst = _strip_port(item.get("dst-address"))
            total = _as_int(item.get("bytes"))
            if src in internal_ips:
                add_traffic(src, total, 0)
            if dst in internal_ips:
                add_traffic(dst, 0, total)

        for connection in connections:
            src = _strip_port(connection.get("src-address"))
            dst = _strip_port(connection.get("dst-address"))
            sent, received = _connection_upload_download(connection)
            if src in internal_ips:
                add_traffic(src, sent, received)
            if dst in internal_ips:
                add_traffic(dst, received, sent)

        batch = [
            (router_id, ip, arp_table.get(ip, {}).get("mac_address"),
             arp_table.get(ip, {}).get("hostname"), traffic["rx_bytes"], traffic["tx_bytes"])
            for ip, traffic in ip_traffic.items()
        ]

        if batch:
            conn = db.get_connection()
            try:
                conn.executemany(
                    "INSERT INTO ip_bandwidth_data (router_id, ip_address, mac_address, hostname, rx_bytes, tx_bytes, timestamp) VALUES (?,?,?,?,?,?,?)",
                    [(r, ip, mac, host, rx, tx, datetime.datetime.now()) for r, ip, mac, host, rx, tx in batch],
                )
                conn.commit()
            finally:
                conn.close()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("IP bandwidth error: %s", exc)
        return False


def collect_interface_bandwidth_data(router_id, api):
    """Collect per-interface traffic counters into interface_bandwidth_data.

    Interface byte counters are always available on RouterOS (unlike
    /ip/accounting), so this is the most reliable bandwidth source.
    """
    try:
        interfaces = routeros_client.safe_api_call(api, "/interface")["data"] or []
        batch = []
        for interface in interfaces:
            name = interface.get("name")
            if not name:
                continue
            rx = _as_int(interface.get("rx-byte", 0))
            tx = _as_int(interface.get("tx-byte", 0))
            batch.append((router_id, name, rx, tx))

        if batch:
            conn = db.get_connection()
            try:
                conn.executemany(
                    "INSERT INTO interface_bandwidth_data (router_id, interface_name, rx_bytes, tx_bytes, timestamp) VALUES (?,?,?,?,?)",
                    [(r, name, rx, tx, datetime.datetime.now()) for r, name, rx, tx in batch],
                )
                conn.commit()
            finally:
                conn.close()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Interface bandwidth error: %s", exc)
        return False


_PERIODS_MINUTES = {
    "1m": 1, "5m": 5, "15m": 15, "30m": 30, "1h": 60, "3h": 180,
    "6h": 360, "12h": 720, "24h": 1440, "3d": 4320, "1w": 10080,
}


def get_ip_bandwidth_stats(router_id, time_periods):
    """Return per-IP traffic totals (bytes transferred) for the requested periods.

    The collector stores cumulative byte counters, so we compute the delta
    between consecutive samples rather than summing them.
    """
    stats = {}
    conn = db.get_connection()
    try:
        for name in time_periods:
            minutes = _PERIODS_MINUTES.get(name)
            if minutes is None:
                continue
            threshold = datetime.datetime.now() - datetime.timedelta(minutes=minutes)
            rows = conn.execute(
                "SELECT ip_address, mac_address, hostname, rx_bytes, tx_bytes "
                "FROM ip_bandwidth_data WHERE router_id=? AND timestamp>=? "
                "ORDER BY ip_address, timestamp",
                (router_id, threshold),
            ).fetchall()

            per_ip = {}
            for row in rows:
                ip = row["ip_address"]
                entry = per_ip.setdefault(ip, {
                    "mac_address": row["mac_address"],
                    "hostname": row["hostname"],
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                    "last_rx": None,
                    "last_tx": None,
                })
                if entry["last_rx"] is not None and row["rx_bytes"] is not None:
                    entry["rx_bytes"] += max(0, row["rx_bytes"] - entry["last_rx"])
                if entry["last_tx"] is not None and row["tx_bytes"] is not None:
                    entry["tx_bytes"] += max(0, row["tx_bytes"] - entry["last_tx"])
                entry["last_rx"] = row["rx_bytes"]
                entry["last_tx"] = row["tx_bytes"]

            stats[name] = {
                ip: {
                    "mac_address": entry["mac_address"],
                    "hostname": entry["hostname"],
                    "rx_bytes": entry["rx_bytes"],
                    "tx_bytes": entry["tx_bytes"],
                    "rx_mb": entry["rx_bytes"] / 1048576,
                    "tx_mb": entry["tx_bytes"] / 1048576,
                }
                for ip, entry in sorted(
                    per_ip.items(),
                    key=lambda item: item[1]["rx_bytes"] + item[1]["tx_bytes"],
                    reverse=True,
                )
            }
    finally:
        conn.close()
    return stats


def get_interface_bandwidth_stats(router_id, time_periods):
    """Return per-interface traffic totals (bytes transferred) for the periods."""
    stats = {}
    conn = db.get_connection()
    try:
        for name in time_periods:
            minutes = _PERIODS_MINUTES.get(name)
            if minutes is None:
                continue
            threshold = datetime.datetime.now() - datetime.timedelta(minutes=minutes)
            rows = conn.execute(
                "SELECT interface_name, rx_bytes, tx_bytes FROM interface_bandwidth_data "
                "WHERE router_id=? AND timestamp>=? ORDER BY interface_name, timestamp",
                (router_id, threshold),
            ).fetchall()

            per_interface = {}
            for row in rows:
                interface = row["interface_name"]
                entry = per_interface.setdefault(interface, {
                    "rx_bytes": 0, "tx_bytes": 0, "last_rx": None, "last_tx": None,
                })
                if entry["last_rx"] is not None and row["rx_bytes"] is not None:
                    entry["rx_bytes"] += max(0, row["rx_bytes"] - entry["last_rx"])
                if entry["last_tx"] is not None and row["tx_bytes"] is not None:
                    entry["tx_bytes"] += max(0, row["tx_bytes"] - entry["last_tx"])
                entry["last_rx"] = row["rx_bytes"]
                entry["last_tx"] = row["tx_bytes"]

            stats[name] = {
                interface: {
                    "rx_bytes": entry["rx_bytes"],
                    "tx_bytes": entry["tx_bytes"],
                    "rx_mb": entry["rx_bytes"] / 1048576,
                    "tx_mb": entry["tx_bytes"] / 1048576,
                }
                for interface, entry in sorted(
                    per_interface.items(),
                    key=lambda item: item[1]["rx_bytes"] + item[1]["tx_bytes"],
                    reverse=True,
                )
            }
    finally:
        conn.close()
    return stats


_HISTORY_PERIODS = {
    "1h": 60, "3h": 180, "6h": 360, "12h": 720,
    "24h": 1440, "3d": 4320, "1w": 10080,
}


def get_ip_bandwidth_history(router_id, ip_address, time_period):
    if time_period not in _HISTORY_PERIODS:
        return {"error": "Invalid period"}
    threshold = (datetime.datetime.now() - datetime.timedelta(minutes=_HISTORY_PERIODS[time_period])).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT timestamp, rx_bytes, tx_bytes FROM ip_bandwidth_data "
            "WHERE router_id=? AND ip_address=? AND timestamp>=? ORDER BY timestamp",
            (router_id, ip_address, threshold),
        ).fetchall()
        data_points = []
        for index, row in enumerate(rows):
            if index == 0:
                download = upload = 0
            else:
                previous_row = rows[index - 1]
                previous = datetime.datetime.strptime(previous_row["timestamp"], "%Y-%m-%d %H:%M:%S")
                current = datetime.datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                diff = (current - previous).total_seconds()
                if diff > 0:
                    delta_rx = max(0, (row["rx_bytes"] or 0) - (previous_row["rx_bytes"] or 0))
                    delta_tx = max(0, (row["tx_bytes"] or 0) - (previous_row["tx_bytes"] or 0))
                    download = (delta_rx * 8) / diff / 1000000
                    upload = (delta_tx * 8) / diff / 1000000
                else:
                    download = upload = 0
            data_points.append({
                "timestamp": row["timestamp"],
                "download_mbps": download,
                "upload_mbps": upload,
                "total_mbps": download + upload,
            })
        return data_points
    finally:
        conn.close()


def get_interface_bandwidth_data(router_id, time_period):
    if time_period not in _HISTORY_PERIODS:
        return {"error": "Invalid period"}
    threshold = (datetime.datetime.now() - datetime.timedelta(minutes=_HISTORY_PERIODS[time_period])).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT interface_name, timestamp, rx_bytes, tx_bytes FROM interface_bandwidth_data "
            "WHERE router_id=? AND timestamp>=? ORDER BY interface_name, timestamp",
            (router_id, threshold),
        ).fetchall()
        groups = {}
        for row in rows:
            groups.setdefault(row["interface_name"], []).append((row["timestamp"], row["rx_bytes"], row["tx_bytes"]))

        result = {}
        for interface, points in groups.items():
            data = []
            for index, (ts, rx, tx) in enumerate(points):
                if index == 0:
                    download = upload = 0
                else:
                    previous = datetime.datetime.strptime(points[index - 1][0], "%Y-%m-%d %H:%M:%S")
                    current = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    diff = (current - previous).total_seconds()
                    if diff > 0:
                        delta_rx = max(0, (rx or 0) - (points[index - 1][1] or 0))
                        delta_tx = max(0, (tx or 0) - (points[index - 1][2] or 0))
                        download = (delta_rx * 8) / diff / 1000000
                        upload = (delta_tx * 8) / diff / 1000000
                    else:
                        download = upload = 0
                data.append({
                    "timestamp": ts,
                    "download_mbps": download,
                    "upload_mbps": upload,
                    "total_mbps": download + upload,
                })
            result[interface] = data
        return result
    finally:
        conn.close()


# ─── Live firewall connections ────────────────────────────────────────────

_connections_cache = OrderedDict()
_connections_lock = threading.Lock()


def _cache_get(router_id):
    with _connections_lock:
        entry = _connections_cache.get(router_id)
        if entry and time.time() - entry[1] < config.CONNECTIONS_CACHE_TTL:
            return entry[0]
        if entry:
            del _connections_cache[router_id]
    return None


def _cache_put(router_id, value):
    with _connections_lock:
        _connections_cache[router_id] = (value, time.time())
        _connections_cache.move_to_end(router_id)
        while len(_connections_cache) > config.CONNECTIONS_CACHE_MAX:
            _connections_cache.popitem(last=False)


def get_live_firewall_connections(router_id):
    cached = _cache_get(router_id)
    if cached is not None:
        return cached

    router = get_router(router_id)
    if not router:
        return {"error": "Not found"}

    api, connection, error = routeros_client.connect_to_router(
        router["host"], router["port"], router["username"], router["password"]
    )
    if not api:
        return {"error": error or "Failed to connect"}

    try:
        connections_data = routeros_client.safe_api_call(api, "/ip/firewall/connection")["data"] or []

        hostname_map = {}
        for lease in routeros_client.safe_api_call(api, "/ip/dhcp-server/lease")["data"] or []:
            if lease.get("address") and lease.get("host-name"):
                hostname_map[lease["address"]] = lease["host-name"]
        for arp in routeros_client.safe_api_call(api, "/ip/arp")["data"] or []:
            if arp.get("address") and arp.get("host-name") and arp["address"] not in hostname_map:
                hostname_map[arp["address"]] = arp["host-name"]

        processed = []
        total_count = 0
        total_up = 0
        total_down = 0
        for connection_item in connections_data:
            src = connection_item.get("src-address", "").split(":")[0]
            dst = connection_item.get("dst-address", "").split(":")[0]
            proto = connection_item.get("protocol", "")
            if not src or not dst:
                continue

            if not (utils.is_internal_ip(src) and utils.is_external_ip(dst)):
                continue

            total_count += 1
            sent, received = _connection_upload_download(connection_item)
            total_up += sent
            total_down += received

            destination_port = connection_item.get("dst-port", "0")
            duration = utils.parse_routeros_duration(connection_item.get("orig-time", "0s"))
            service = utils.get_service_name(destination_port, proto)
            sni = connection_item.get("sni", "")

            processed.append({
                "src_ip": src,
                "src_hostname": hostname_map.get(src, "-"),
                "dst_ip": dst,
                "dst_hostname": sni or dst,
                "service": service,
                "upload_bytes": sent,
                "download_bytes": received,
                "upload_human": utils.format_bytes(sent),
                "download_human": utils.format_bytes(received),
                "duration": duration,
                "duration_seconds": utils.duration_seconds(connection_item.get("orig-time", "0s")),
                "protocol": proto,
                "total_bytes": sent + received,
            })

        processed.sort(key=lambda item: item["total_bytes"], reverse=True)

        result = {
            "connections": processed,
            "total_count": total_count,
            "total_upload": total_up,
            "total_download": total_down,
            "total_upload_human": utils.format_bytes(total_up),
            "total_download_human": utils.format_bytes(total_down),
            "timestamp": time.time(),
        }
        _cache_put(router_id, result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("Firewall error: %s\n%s", exc, traceback.format_exc())
        return {
            "error": str(exc), "connections": [], "total_count": 0,
            "total_upload": 0, "total_download": 0,
            "total_upload_human": "0 B", "total_download_human": "0 B",
        }
    finally:
        connection.disconnect()


def get_router_connections(router_id):
    router = get_router(router_id)
    if not router:
        return {"error": "Not found"}

    api, connection, error = routeros_client.connect_to_router(
        router["host"], router["port"], router["username"], router["password"]
    )
    if not api:
        return {"error": error or "Failed to connect"}

    try:
        ip_data = routeros_client.safe_api_call(api, "/ip/address")["data"] or []
        leases_data = routeros_client.safe_api_call(api, "/ip/dhcp-server/lease")["data"] or []
        arp_data = routeros_client.safe_api_call(api, "/ip/arp")["data"] or []
        routes_data = routeros_client.safe_api_call(api, "/ip/route")["data"] or []
        interfaces_data = routeros_client.safe_api_call(api, "/interface")["data"] or []

        result = []
        for ip_address in ip_data:
            address = ip_address.get("address", "")
            interface = ip_address.get("interface", "")
            if not address or not interface:
                continue
            ip = address.split("/")[0]
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue

            clients = []
            for lease in leases_data:
                if lease.get("address") and lease.get("server") == ip:
                    arp_match = next((a for a in arp_data if a.get("address") == lease["address"]), None)
                    clients.append({
                        "ip": lease["address"],
                        "mac": lease.get("mac-address", ""),
                        "hostname": lease.get("host-name", ""),
                        "status": lease.get("status", "unknown"),
                        "interface": arp_match.get("interface", "") if arp_match else "",
                        "dynamic": arp_match.get("dynamic", False) if arp_match else False,
                    })

            upstream = None
            for route in routes_data:
                if route.get("dst-address") == "0.0.0.0/0" and route.get("interface") == interface:
                    upstream = {"gateway": route.get("gateway", ""), "interface": route.get("interface", ""), "type": "default_route"}
                    break
            if not upstream:
                for interface_item in interfaces_data:
                    if interface_item.get("name") == interface and interface_item.get("master-port"):
                        upstream = {"gateway": "N/A", "interface": interface_item["master-port"], "type": "bridge_parent"}
                        break
            if not upstream:
                upstream = {"gateway": "Direct to WAN", "interface": interface, "type": "direct"}

            result.append({
                "ip": ip, "interface": interface, "network": address,
                "clients": clients, "client_count": len(clients), "upstream": upstream,
            })
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("Connections error: %s", exc)
        return {"error": str(exc)}
    finally:
        connection.disconnect()


# ─── Logs ─────────────────────────────────────────────────────────────────

def get_log_statistics(logs):
    severities = {"critical": 0, "warning": 0, "info": 0, "error": 0, "debug": 0, "other": 0}
    categories = {}
    for log in logs:
        category = log.get("topics", "other")
        categories[category] = categories.get(category, 0) + 1
        message = log.get("message", "").lower()
        if "critical" in message:
            severities["critical"] += 1
        elif "warning" in message:
            severities["warning"] += 1
        elif "error" in message:
            severities["error"] += 1
        elif "info" in message:
            severities["info"] += 1
        elif "debug" in message:
            severities["debug"] += 1
        else:
            severities["other"] += 1
    return {
        "total": len(logs),
        "categories": dict(sorted(categories.items(), key=lambda item: item[1], reverse=True)),
        "severities": severities,
    }


def save_router_logs(router_id, logs):
    conn = db.get_connection()
    saved = 0
    try:
        for log in logs:
            timestamp = log.get("time", "")
            topics = log.get("topics", "")
            message = log.get("message", "")
            lowered = message.lower()
            severity = (
                "critical" if "critical" in lowered
                else "warning" if "warning" in lowered
                else "error" if "error" in lowered
                else "info" if "info" in lowered
                else "debug" if "debug" in lowered
                else "other"
            )
            exists = conn.execute(
                "SELECT id FROM router_logs WHERE router_id=? AND timestamp=? AND message=?",
                (router_id, timestamp, message),
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO router_logs (router_id, timestamp, topics, message, severity) VALUES (?,?,?,?,?)",
                    (router_id, timestamp, topics, message, severity),
                )
                saved += 1
        conn.commit()
        return saved
    finally:
        conn.close()


def get_log_retention_settings(router_id):
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT retention_days FROM log_retention_settings WHERE router_id=?", (router_id,)
        ).fetchone()
        return row["retention_days"] if row else 7
    finally:
        conn.close()


def update_log_retention_settings(router_id, days):
    conn = db.get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO log_retention_settings (router_id, retention_days) VALUES (?,?)",
            (router_id, days),
        )
        conn.commit()
    finally:
        conn.close()


def cleanup_old_logs(router_id):
    days = get_log_retention_settings(router_id)
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    conn = db.get_connection()
    try:
        cursor = conn.execute("DELETE FROM router_logs WHERE router_id=? AND stored_at<?", (router_id, cutoff))
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_paginated_logs(router_id, page=1, per_page=50, severity_filter=None, search_term=None):
    conn = db.get_connection()
    try:
        query = "SELECT * FROM router_logs WHERE router_id=?"
        params = [router_id]
        if severity_filter and severity_filter != "all":
            query += " AND severity=?"
            params.append(severity_filter)
        if search_term:
            query += " AND (message LIKE ? OR topics LIKE ?)"
            params.extend([f"%{search_term}%", f"%{search_term}%"])

        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        total = conn.execute(count_query, params).fetchone()[0]

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])
        logs = conn.execute(query, params).fetchall()

        total_pages = (total + per_page - 1) // per_page
        return {
            "logs": logs, "total_logs": total, "page": page, "per_page": per_page,
            "total_pages": total_pages, "has_prev": page > 1, "has_next": page < total_pages,
        }
    finally:
        conn.close()


# ─── Backups ──────────────────────────────────────────────────────────────

def ensure_backup_dir(router_id):
    path = os.path.join(config.BACKUP_DIR, str(router_id))
    os.makedirs(path, exist_ok=True)
    return path


def run_router_backup(router_id):
    router = get_router(router_id)
    if not router:
        return None
    api, connection, error = routeros_client.connect_to_router(
        router["host"], router["port"], router["username"], router["password"]
    )
    if not api:
        return None
    try:
        result = routeros_client.safe_api_call(api, "/export")
        if result["error"] or not result["data"]:
            return None
        connection.disconnect()
        backup_dir = ensure_backup_dir(router_id)
        filename = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + ".rsc"
        with open(os.path.join(backup_dir, filename), "w") as handle:
            if isinstance(result["data"], list):
                handle.write("\n".join(str(line) for line in result["data"]))
            else:
                handle.write(str(result["data"]))
        backups = sorted(glob.glob(os.path.join(backup_dir, "*.rsc")))
        while len(backups) > config.MAX_BACKUPS:
            os.remove(backups.pop(0))
        return filename
    except Exception:  # noqa: BLE001
        return None
    finally:
        if connection:
            connection.disconnect()


def get_backup_list(router_id):
    backup_dir = ensure_backup_dir(router_id)
    return [
        {
            "filename": os.path.basename(path),
            "size": os.path.getsize(path),
            "mtime": datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for path in sorted(glob.glob(os.path.join(backup_dir, "*.rsc")), reverse=True)
    ]


def get_backup_diff(router_id):
    backup_dir = ensure_backup_dir(router_id)
    backups = sorted(glob.glob(os.path.join(backup_dir, "*.rsc")), reverse=True)
    if len(backups) < 2:
        return None, None, "Need 2+ backups"
    newer, older = backups[0], backups[1]
    try:
        result = subprocess.run(["diff", "-u", older, newer], capture_output=True, text=True, timeout=10)
        return os.path.basename(newer), os.path.basename(older), result.stdout or "(identical)"
    except Exception:  # noqa: BLE001
        with open(older) as old_handle, open(newer) as new_handle:
            diff = difflib.unified_diff(old_handle.readlines(), new_handle.readlines(), n=3)
            return os.path.basename(newer), os.path.basename(older), "".join(diff)


# ─── SNMP detailed info ───────────────────────────────────────────────────

def get_snmp_detailed_info(router):
    """Build a monitor-page info dict from stored SNMP metrics."""
    router_id = router["id"]
    name = router["name"]
    api_port = router.get("port", 8728)
    snmp_port = router.get("snmp_port", 161)

    info = {
        "identity": {"name": name},
        "resources": {k: "N/A" for k in ["cpu_load", "cpu_count", "architecture_name", "board_name", "total_memory", "free_memory", "used_memory", "uptime", "version"]},
        "clock": {}, "ip_addresses": [], "interfaces": [], "dhcp_leases": [],
        "arp_table": [], "health": {}, "license": {}, "logs": [],
        "_source": {"type": "SNMP", "api_port": api_port, "snmp_port": snmp_port, "port": snmp_port},
    }

    conn = db.get_connection()
    try:
        row = conn.execute(
            """SELECT cpu_percent, memory_used, memory_total, uptime_seconds,
                      temperature_celsius, cpu_cores, board_name, architecture,
                      platform, firmware, router_name
               FROM snmp_system_metrics
               WHERE router_id=? AND cpu_percent IS NOT NULL
               ORDER BY timestamp DESC LIMIT 1""",
            (router_id,),
        ).fetchone()

        if row and row["cpu_percent"] is not None:
            cpu = row["cpu_percent"]
            memory_total = row["memory_total"]
            memory_used = row["memory_used"]
            uptime = row["uptime_seconds"]
            memory_percent = "N/A"
            if memory_total and memory_used and memory_total > 0:
                memory_percent = round(memory_used / memory_total * 100, 1)
            info["resources"] = {
                "cpu_load": str(int(cpu)),
                "total_memory": str(memory_total) if memory_total else "N/A",
                "free_memory": str(memory_total - memory_used) if memory_total and memory_used else "N/A",
                "used_memory": str(memory_used) if memory_used else "N/A",
                "uptime": f"{uptime // 3600}h {(uptime % 3600) // 60}m" if uptime else "N/A",
                "cpu_count": str(row["cpu_cores"]) if row["cpu_cores"] else "N/A",
                "version": row["firmware"] or "via SNMP",
                "board_name": row["board_name"] or "N/A",
                "architecture_name": row["architecture"] or "N/A",
                "memory_usage_percent": memory_percent,
                "platform": row["platform"] or "N/A",
            }
            if row["temperature_celsius"]:
                info["health"] = {"temperature": str(row["temperature_celsius"])}

        interfaces = conn.execute(
            "SELECT DISTINCT interface_name FROM snmp_interface_metrics WHERE router_id=?", (router_id,)
        ).fetchall()
        info["interfaces"] = [
            {"name": row["interface_name"], "type": "SNMP", "running": "true", "mtu": "N/A"}
            for row in interfaces
        ]
    except Exception as exc:  # noqa: BLE001
        logger.error("SNMP info error: %s", exc)
    finally:
        conn.close()
    return info


# ─── Alerts data access ───────────────────────────────────────────────────

def get_alerts(router_id, limit=50):
    conn = db.get_connection()
    try:
        rows = conn.execute(
            """SELECT ae.id, ae.status, ae.message, ae.triggered_at, ar.metric_type,
                      ar.condition, ar.threshold_value
               FROM alert_events ae JOIN alert_rules ar ON ae.rule_id=ar.id
               WHERE ae.router_id=? ORDER BY ae.triggered_at DESC LIMIT ?""",
            (router_id, limit),
        ).fetchall()
        return [
            {
                "id": row["id"], "status": row["status"], "message": row["message"],
                "triggered_at": row["triggered_at"], "metric_type": row["metric_type"],
                "condition": row["condition"], "threshold": row["threshold_value"],
            }
            for row in rows
        ]
    finally:
        conn.close()


def acknowledge_alert(alert_id):
    conn = db.get_connection()
    try:
        conn.execute("UPDATE alert_events SET status='acknowledged' WHERE id=?", (alert_id,))
        conn.commit()
    finally:
        conn.close()


def list_alert_rules(router_id):
    conn = db.get_connection()
    try:
        rows = conn.execute("SELECT * FROM alert_rules WHERE router_id=? ORDER BY created_at DESC", (router_id,)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def create_alert_rule(router_id, data):
    conn = db.get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO alert_rules (router_id, metric_type, condition, threshold_value,
               duration_seconds, action, action_config) VALUES (?,?,?,?,?,?,?)""",
            (
                router_id, data["metric_type"], data["condition"], data["threshold_value"],
                data.get("duration_seconds", 0), data["action"], json.dumps(data.get("action_config", {})),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def delete_alert_rule(rule_id):
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM alert_rules WHERE id=?", (rule_id,))
        conn.execute("DELETE FROM alert_events WHERE rule_id=?", (rule_id,))
        conn.commit()
    finally:
        conn.close()
