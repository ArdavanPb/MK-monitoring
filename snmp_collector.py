#!/usr/bin/env python3
"""SNMP collector for MikroTik routers.

Polls SNMP-enabled routers every 60 seconds for system and interface metrics.
Uses snmpget/snmpwalk CLI tools (no native library dependencies).
"""
import logging
import re
import signal
import subprocess
import time
from datetime import datetime

import db
import security

logging.basicConfig(level=logging.INFO, format="%(asctime)s SNMP %(levelname)s: %(message)s")
logger = logging.getLogger("snmp_collector")

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Received SIGTERM, shutting down gracefully...")
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def snmp_version_str(version):
    return "2c" if version == 2 else str(version)


def snmp_get(host, community, oid, version=2, port=161):
    version_string = snmp_version_str(version)
    command = ["snmpget", "-v", version_string, "-c", community, "-t", "5", "-r", "1", "-OQv", f"{host}:{port}", oid]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            value = result.stdout.strip()
            return value if value else None
        logger.warning("snmp_get rc=%s for %s on %s:%s: %s", result.returncode, oid, host, port, result.stderr.strip()[:200])
        return None
    except subprocess.TimeoutExpired:
        logger.warning("snmp_get timeout for %s", oid)
        return None
    except FileNotFoundError:
        logger.error("snmpget not found. Install: apt-get install snmp")
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("snmp_get exception for %s: %s", oid, exc)
        return None


def snmp_get_int(host, community, oid, version=2, port=161):
    raw = snmp_get(host, community, oid, version, port)
    if raw is None:
        return None
    match = re.search(r"(-?\d+)", raw)
    if match:
        return int(match.group(1))
    return None


def snmp_get_float(host, community, oid, version=2, port=161):
    raw = snmp_get(host, community, oid, version, port)
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        match = re.search(r"(-?\d+\.?\d*)", raw)
        return float(match.group(1)) if match else None


def snmp_walk(host, community, oid, version=2, port=161):
    version_string = snmp_version_str(version)
    command = ["snmpwalk", "-v", version_string, "-c", community, "-t", "5", "-r", "1", "-OQ", f"{host}:{port}", oid]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return []
        entries = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line or " = " not in line:
                continue
            oid_part, value = line.split(" = ", 1)
            suffix = oid_part.split(".")[-1]
            entries.append((suffix, value.strip()))
        return entries
    except Exception as exc:  # noqa: BLE001
        logger.warning("snmp_walk failed for %s: %s", oid, exc)
        return []


def poll_snmp_router(router_id, host, community, version, port):
    """Poll a router via SNMP CLI tools and store results."""
    try:
        now = datetime.now()

        uptime_raw = snmp_get(host, community, ".1.3.6.1.2.1.1.3.0", version, port)
        if uptime_raw is None:
            logger.warning("Router %s: SNMP connectivity test failed (no response from %s:%s)", router_id, host, port)
            return False

        uptime_seconds = None
        try:
            if uptime_raw.isdigit():
                uptime_seconds = int(uptime_raw) // 100
            else:
                parts = uptime_raw.split(":")
                if len(parts) == 4:
                    days, hours, minutes, seconds = parts
                    uptime_seconds = int(days) * 86400 + int(hours) * 3600 + int(minutes) * 60 + int(float(seconds))
                elif len(parts) == 3:
                    hours, minutes, seconds = parts
                    uptime_seconds = int(hours) * 3600 + int(minutes) * 60 + int(float(seconds))
        except (ValueError, IndexError):
            pass

        cpu_value = snmp_get_float(host, community, ".1.3.6.1.4.1.14988.1.1.3.1.0", version, port)

        memory_total = snmp_get_int(host, community, ".1.3.6.1.4.1.14988.1.1.4.1.0", version, port)
        free_memory = snmp_get_int(host, community, ".1.3.6.1.4.1.14988.1.1.4.2.0", version, port)
        memory_used = (memory_total - free_memory) if (memory_total and free_memory) else None

        temperature = None
        for temp_oid in (".1.3.6.1.4.1.14988.1.1.3.10.0", ".1.3.6.1.2.1.99.1.1.1.4.1"):
            temperature = snmp_get_float(host, community, temp_oid, version, port)
            if temperature is not None:
                break

        router_name = snmp_get(host, community, ".1.3.6.1.4.1.14988.1.1.1.1.0", version, port)
        board_name = snmp_get(host, community, ".1.3.6.1.4.1.14988.1.1.1.2.0", version, port)
        firmware = snmp_get(host, community, ".1.3.6.1.4.1.14988.1.1.1.3.0", version, port)
        platform = snmp_get(host, community, ".1.3.6.1.4.1.14988.1.1.1.4.0", version, port)
        architecture = snmp_get(host, community, ".1.3.6.1.4.1.14988.1.1.1.5.0", version, port)
        cpu_cores = snmp_get_int(host, community, ".1.3.6.1.4.1.14988.1.1.3.2.0", version, port)

        for value in (router_name, board_name, firmware, platform, architecture):
            if value:
                value = value.strip('"')

        conn = db.get_connection()
        try:
            conn.execute(
                """INSERT INTO snmp_system_metrics
                   (router_id, timestamp, cpu_percent, memory_used, memory_total,
                    uptime_seconds, temperature_celsius, cpu_cores, board_name,
                    architecture, platform, firmware, router_name, source_type)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (router_id, now, cpu_value, memory_used, memory_total, uptime_seconds,
                 temperature, cpu_cores, board_name, architecture, platform, firmware,
                 router_name, "SNMP"),
            )

            import json

            snmp_info = {
                "name": router_name or f"Router {router_id}",
                "uptime": f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m" if uptime_seconds else "N/A",
                "total_memory": str(memory_total) if memory_total else "N/A",
                "free_memory": str(free_memory) if free_memory else "N/A",
                "used_memory": str(memory_used) if memory_used else "N/A",
                "memory_usage_percent": round(float(memory_used) / float(memory_total) * 100, 1) if (memory_used and memory_total and memory_total > 0) else "N/A",
                "cpu_load": str(int(cpu_value)) if cpu_value is not None else "N/A",
                "cpu_count": str(cpu_cores) if cpu_cores else "N/A",
                "version": firmware or "via SNMP",
                "board_name": board_name or "N/A",
                "architecture_name": architecture or "N/A",
            }

            conn.execute(
                """INSERT OR REPLACE INTO router_status_cache
                   (router_id, status, last_checked, router_info, source_type, snmp_port)
                   VALUES (?,?,?,?,?,?)""",
                (router_id, "online", now, json.dumps(snmp_info), "SNMP", port),
            )

            if_names = snmp_walk(host, community, ".1.3.6.1.2.1.2.2.1.2", version, port)
            if_in = snmp_walk(host, community, ".1.3.6.1.2.1.2.2.1.10", version, port)
            if_out = snmp_walk(host, community, ".1.3.6.1.2.1.2.2.1.16", version, port)

            name_map = {}
            for suffix, value in if_names:
                name_map[suffix] = value.strip('"')
            in_map = {}
            for suffix, value in if_in:
                try:
                    in_map[suffix] = int(value)
                except ValueError:
                    pass
            out_map = {}
            for suffix, value in if_out:
                try:
                    out_map[suffix] = int(value)
                except ValueError:
                    pass

            batch = []
            for suffix in name_map:
                try:
                    if_index = int(suffix)
                    batch.append((router_id, name_map[suffix], if_index, in_map.get(suffix, 0), out_map.get(suffix, 0), now))
                except ValueError:
                    pass

            if batch:
                conn.executemany(
                    """INSERT INTO snmp_interface_metrics
                       (router_id, interface_name, ifindex, rx_bytes, tx_bytes, timestamp)
                       VALUES (?,?,?,?,?,?)""",
                    batch,
                )

                # Also feed the unified interface_bandwidth_data table used by
                # the Bandwidth page charts.
                interface_batch = [
                    (router_id, name_map[suffix], in_map.get(suffix, 0), out_map.get(suffix, 0))
                    for suffix in name_map
                    if suffix.isdigit()
                ]
                if interface_batch:
                    conn.executemany(
                        """INSERT INTO interface_bandwidth_data
                           (router_id, interface_name, rx_bytes, tx_bytes, timestamp)
                           VALUES (?,?,?,?,?)""",
                        [(r, n, rx, tx, now) for r, n, rx, tx in interface_batch],
                    )

            conn.commit()
        finally:
            conn.close()

        logger.info("Router %s: CPU=%s%%, Mem=%s/%s, Cores=%s, Board=%s", router_id, cpu_value, memory_used, memory_total, cpu_cores, board_name)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Router %s SNMP poll failed: %s", router_id, exc)
        return False


def collect_all():
    conn = db.get_connection()
    try:
        routers = conn.execute(
            "SELECT id, name, host, snmp_community, snmp_version, snmp_port FROM routers WHERE snmp_enabled = 1"
        ).fetchall()
    finally:
        conn.close()

    for row in routers:
        if not running:
            break
        community = security.decrypt_secret(row["snmp_community"])
        logger.info("Polling %s (%s) via SNMP v%s", row["name"], row["host"], row["snmp_version"])
        poll_snmp_router(row["id"], row["host"], community, row["snmp_version"], row["snmp_port"])


if __name__ == "__main__":
    logger.info("SNMP Collector started")
    db.init_db()

    while running:
        try:
            collect_all()
        except Exception as exc:  # noqa: BLE001
            logger.error("Collection cycle error: %s", exc)

        for _ in range(60):
            if not running:
                break
            time.sleep(1)

    logger.info("SNMP Collector stopped")
