#!/usr/bin/env python3
"""Bandwidth collector for MK-Monitoring.

Polls API-enabled routers every 60 seconds and stores per-IP traffic counters
into ip_bandwidth_data for the dashboard bandwidth charts.
"""
import logging
import signal
import time

import db
import routeros_client
import services

logging.basicConfig(level=logging.INFO, format="%(asctime)s BW %(levelname)s: %(message)s")
logger = logging.getLogger("bandwidth_collector")

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Received SIGTERM, shutting down gracefully...")
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def collect_all():
    for router in services.list_routers():
        if not running:
            break
        if not router.get("username") or not router.get("password"):
            continue

        api, connection, error = routeros_client.connect_to_router(
            router["host"], router["port"], router["username"], router["password"]
        )
        if not api:
            logger.warning("Skipping %s: %s", router["name"], error)
            continue

        try:
            logger.info("Collecting bandwidth for %s (%s)", router["name"], router["host"])
            services.collect_ip_bandwidth_data(router["id"], api)
            services.collect_interface_bandwidth_data(router["id"], api)
        finally:
            connection.disconnect()


if __name__ == "__main__":
    logger.info("Bandwidth Collector started")
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

    logger.info("Bandwidth Collector stopped")
