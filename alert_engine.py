#!/usr/bin/env python3
"""Alert Engine for MK-Monitoring.

Evaluates alert rules every 30 seconds and sends notifications.
Supports email (SMTP), webhook (HTTP POST), and syslog actions.
"""
import json
import logging
import os
import signal
import smtplib
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime
from email.message import EmailMessage
from logging.handlers import SysLogHandler

import db

logging.basicConfig(level=logging.INFO, format="%(asctime)s ALERT %(levelname)s: %(message)s")
logger = logging.getLogger("alert_engine")

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Received SIGTERM, shutting down gracefully...")
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Email config from environment
SMTP_HOST = os.environ.get("ALERT_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("ALERT_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("ALERT_SMTP_USER", "")
SMTP_PASS = os.environ.get("ALERT_SMTP_PASS", "")
SMTP_FROM = os.environ.get("ALERT_SMTP_FROM", "")
SMTP_TO = os.environ.get("ALERT_SMTP_TO", "")


def send_email(subject, body):
    if not SMTP_HOST:
        logger.warning("SMTP not configured, cannot send email alert")
        return False
    try:
        message = EmailMessage()
        message.set_content(body)
        message["Subject"] = subject
        message["From"] = SMTP_FROM
        message["To"] = SMTP_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(message)
        logger.info("Email alert sent: %s", subject)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Email send failed: %s", exc)
        return False


def send_webhook(url, payload):
    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(request, timeout=10)
        logger.info("Webhook posted to %s", url)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Webhook failed: %s", exc)
        return False


def send_syslog(message):
    for address in ("/dev/log", ("localhost", 514)):
        try:
            handler = SysLogHandler(address=address)
            handler.emit(logging.LogRecord("alert", logging.WARNING, "", 0, message, None, None))
            handler.close()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Syslog failed: %s", exc)
    return False


def fire_action(rule, message):
    """Execute the action configured in the rule."""
    action_config = rule["action_config"]
    if isinstance(action_config, str):
        try:
            action_config = json.loads(action_config)
        except ValueError:
            action_config = {}

    if rule["action"] == "email":
        send_email(f"Alert: {rule['metric_type']} on router {rule['router_id']}", message)
    elif rule["action"] == "webhook":
        url = action_config.get("url", "")
        if url:
            send_webhook(url, {
                "alert": rule["metric_type"], "router_id": rule["router_id"],
                "message": message, "time": str(datetime.now()),
            })
    elif rule["action"] == "syslog":
        send_syslog(message)


def evaluate_cpu(rule, conn):
    row = conn.execute(
        "SELECT cpu_percent FROM snmp_system_metrics WHERE router_id=? ORDER BY timestamp DESC LIMIT 1",
        (rule["router_id"],),
    ).fetchone()
    if row and row["cpu_percent"] is not None:
        value = row["cpu_percent"]
        threshold = float(rule["threshold_value"])
        if rule["condition"] == "gt" and value > threshold:
            return True, f"CPU at {value:.1f}% (threshold: >{threshold}%)"
        if rule["condition"] == "lt" and value < threshold:
            return True, f"CPU at {value:.1f}% (threshold: <{threshold}%)"
    return False, None


def evaluate_memory(rule, conn):
    row = conn.execute(
        "SELECT memory_used, memory_total FROM snmp_system_metrics "
        "WHERE router_id=? AND memory_total IS NOT NULL AND memory_total > 0 "
        "ORDER BY timestamp DESC LIMIT 1",
        (rule["router_id"],),
    ).fetchone()
    if row:
        percent = (row["memory_used"] / row["memory_total"]) * 100
        threshold = float(rule["threshold_value"])
        if rule["condition"] == "gt" and percent > threshold:
            return True, f"Memory at {percent:.1f}% (threshold: >{threshold}%)"
        if rule["condition"] == "lt" and percent < threshold:
            return True, f"Memory at {percent:.1f}% (threshold: <{threshold}%)"
    return False, None


def evaluate_interface_down(rule, conn):
    rows = conn.execute(
        "SELECT interface_name, rx_bytes, tx_bytes FROM snmp_interface_metrics "
        "WHERE router_id=? ORDER BY timestamp DESC LIMIT 50",
        (rule["router_id"],),
    ).fetchall()
    if len(rows) < 2:
        return False, None

    interface_data = defaultdict(list)
    for row in rows:
        interface_data[row["interface_name"]].append((row["rx_bytes"], row["tx_bytes"]))

    for interface, points in interface_data.items():
        if len(points) >= 2 and points[-1][0] == 0 and points[-1][1] == 0:
            return True, f"Interface {interface} appears down (0 traffic)"
    return False, None


def evaluate_connections(rule, conn):
    row = conn.execute(
        "SELECT COUNT(DISTINCT ip_address) AS cnt FROM ip_bandwidth_data "
        "WHERE router_id=? AND timestamp >= datetime('now', '-5 minutes')",
        (rule["router_id"],),
    ).fetchone()
    count = row["cnt"] or 0
    threshold = int(rule["threshold_value"])
    if rule["condition"] == "gt" and count > threshold:
        return True, f"Active connections: {count} (threshold: >{threshold})"
    if rule["condition"] == "lt" and count < threshold:
        return True, f"Active connections: {count} (threshold: <{threshold})"
    return False, None


def evaluate_log_match(rule, conn):
    rows = conn.execute(
        "SELECT message FROM router_logs WHERE router_id=? AND stored_at >= datetime('now', '-5 minutes') "
        "ORDER BY stored_at DESC LIMIT 50",
        (rule["router_id"],),
    ).fetchall()
    for row in rows:
        message = row["message"] or ""
        if rule["condition"] == "contains" and rule["threshold_value"].lower() in message.lower():
            return True, f"Log matched: {message[:200]}"
        if rule["condition"] == "eq" and message == rule["threshold_value"]:
            return True, f"Log matched: {message[:200]}"
    return False, None


EVALUATORS = {
    "cpu": evaluate_cpu,
    "memory": evaluate_memory,
    "interface_down": evaluate_interface_down,
    "connections": evaluate_connections,
    "log_match": evaluate_log_match,
}


def check_rules():
    """Evaluate all enabled alert rules."""
    conn = db.get_connection()
    try:
        rules = conn.execute("SELECT * FROM alert_rules WHERE enabled = 1").fetchall()
        now = datetime.now()

        for rule in rules:
            evaluator = EVALUATORS.get(rule["metric_type"])
            if evaluator is None:
                continue
            triggered, message = evaluator(rule, conn)

            if triggered:
                existing = conn.execute(
                    "SELECT id FROM alert_events WHERE rule_id=? AND status='active'",
                    (rule["id"],),
                ).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO alert_events (rule_id, router_id, status, message) VALUES (?,?, 'active', ?)",
                        (rule["id"], rule["router_id"], message),
                    )
                    conn.commit()
                    fire_action(rule, message)
            else:
                conn.execute(
                    "UPDATE alert_events SET status='resolved', resolved_at=? WHERE rule_id=? AND status='active'",
                    (now, rule["id"]),
                )
                conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    logger.info("Alert Engine started")
    db.init_db()

    while running:
        try:
            check_rules()
        except Exception as exc:  # noqa: BLE001
            logger.error("Alert check error: %s", exc)

        for _ in range(30):
            if not running:
                break
            time.sleep(1)

    logger.info("Alert Engine stopped")
