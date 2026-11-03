"""Read-side queries for stored NetFlow traffic."""
import datetime

import db
import utils


def _threshold(minutes):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


def timestamp_age_seconds(timestamp):
    if not timestamp:
        return None
    then = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    age = int((datetime.datetime.now(datetime.timezone.utc) - then).total_seconds())
    return max(0, age) if age >= -60 else None


def snapshot(router_id, minutes=5):
    """Recent flow volume and collector freshness, with a fixed average rate."""
    conn = db.get_connection()
    try:
        last = conn.execute(
            "SELECT MAX(received_at) FROM flow_datagrams WHERE router_id=?", (router_id,)
        ).fetchone()[0]
        row = conn.execute(
            "SELECT COUNT(*) AS flows, COALESCE(SUM(bytes),0) AS bytes, "
            "COALESCE(SUM(packets),0) AS packets FROM flow_records "
            "WHERE router_id=? AND received_at>=?",
            (router_id, _threshold(minutes)),
        ).fetchone()
    finally:
        conn.close()
    age = timestamp_age_seconds(last)
    return {
        "last_seen": last, "age_seconds": age, "fresh": age is not None and age <= 120,
        "minutes": minutes, "flows": row["flows"], "bytes": row["bytes"],
        "packets": row["packets"], "average_bps": round(row["bytes"] * 8 / (minutes * 60)),
    }


def overview(router_id, minutes=5, *, src="", dst="", search="", sort="total", direction="desc", view="all", page=1, per_page=50):
    """Paginated endpoint totals, filtered before aggregation."""
    import ipaddress
    if minutes not in (5, 60, 1440):
        raise ValueError("Invalid period")
    if sort not in ("total", "upload", "download", "ip") or direction not in ("asc", "desc") or view not in ("all", "src", "dst"):
        raise ValueError("Invalid sorting or view")
    if page < 1 or not 1 <= per_page <= 200 or len(search) > 64:
        raise ValueError("Invalid pagination or search")
    clauses = ["router_id=?", "received_at>=?"]
    params = [router_id, _threshold(minutes)]
    for field, address in (("src_ip", src), ("dst_ip", dst)):
        if address:
            try:
                address = str(ipaddress.ip_address(address.strip()))
            except ValueError:
                raise ValueError("Source and destination must be valid IP addresses") from None
            clauses.append(field + "=?")
            params.append(address)
    selected = "WITH selected AS (SELECT * FROM flow_records WHERE " + " AND ".join(clauses) + ")"
    sides = []
    if view in ("all", "src"):
        sides.append("SELECT src_ip AS ip, bytes AS upload_bytes, 0 AS download_bytes, packets FROM selected")
    if view in ("all", "dst"):
        sides.append("SELECT dst_ip AS ip, 0 AS upload_bytes, bytes AS download_bytes, packets FROM selected")
    grouped = selected + ", endpoints AS (" + " UNION ALL ".join(sides) + "), grouped AS (SELECT ip, SUM(upload_bytes) AS upload_bytes, SUM(download_bytes) AS download_bytes, SUM(packets) AS packets FROM endpoints WHERE instr(ip,?)>0 GROUP BY ip) "
    order = {"total": "(upload_bytes+download_bytes)", "upload": "upload_bytes", "download": "download_bytes", "ip": "ip"}[sort]
    summary = snapshot(router_id, minutes)
    conn = db.get_connection()
    try:
        count = conn.execute(grouped + "SELECT COUNT(*) FROM grouped", params + [search.strip()]).fetchone()[0]
        pages = max(1, (count + per_page - 1) // per_page)
        page = min(page, pages)
        ips = conn.execute(grouped + "SELECT * FROM grouped ORDER BY " + order + " " + direction + ", ip ASC LIMIT ? OFFSET ?", params + [search.strip(), per_page, (page-1)*per_page]).fetchall()
        totals = conn.execute(selected + " SELECT COUNT(*) AS flows, COALESCE(SUM(bytes),0) AS bytes, COALESCE(SUM(packets),0) AS packets FROM selected", params).fetchone()
        protocols = conn.execute(selected + " SELECT protocol, SUM(bytes) AS bytes, COUNT(*) AS flows FROM selected GROUP BY protocol ORDER BY bytes DESC", params).fetchall()
    finally:
        conn.close()
    summary.update(dict(totals))
    summary["average_bps"] = round(summary["bytes"] * 8 / (minutes * 60))
    summary["top_ips"] = [{**dict(row), "scope": "local" if utils.is_internal_ip(row["ip"]) else "external"} for row in ips]
    summary.update(page=page, pages=pages, total_ips=count, per_page=per_page)
    names = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
    summary["protocols"] = [{**dict(row), "name": names.get(row["protocol"], str(row["protocol"]))} for row in protocols]
    return summary


def ip_summary(router_id, ip_address, minutes=60):
    conn = db.get_connection()
    try:
        row = conn.execute(
            """SELECT COUNT(*) AS flows,
                      COALESCE(SUM(CASE WHEN src_ip=? THEN bytes ELSE 0 END),0) AS upload_bytes,
                      COALESCE(SUM(CASE WHEN dst_ip=? THEN bytes ELSE 0 END),0) AS download_bytes,
                      COALESCE(SUM(CASE WHEN src_ip=? THEN packets ELSE 0 END),0) AS upload_packets,
                      COALESCE(SUM(CASE WHEN dst_ip=? THEN packets ELSE 0 END),0) AS download_packets
               FROM flow_records WHERE router_id=? AND received_at>=?
                 AND (src_ip=? OR dst_ip=?)""",
            (ip_address, ip_address, ip_address, ip_address, router_id, _threshold(minutes), ip_address, ip_address),
        ).fetchone()
        return dict(row)
    finally:
        conn.close()


def recent_local_ips(router_id, minutes=5):
    """Local IP addresses observed in recent exports, newest first."""
    conn = db.get_connection()
    try:
        rows = conn.execute(
            """SELECT ip, MAX(received_at) AS seen FROM (
                   SELECT src_ip AS ip, received_at FROM flow_records WHERE router_id=? AND received_at>=?
                   UNION ALL
                   SELECT dst_ip AS ip, received_at FROM flow_records WHERE router_id=? AND received_at>=?
               ) GROUP BY ip ORDER BY seen DESC""",
            (router_id, _threshold(minutes), router_id, _threshold(minutes)),
        ).fetchall()
        return [row["ip"] for row in rows if utils.is_internal_ip(row["ip"])]
    finally:
        conn.close()


def ip_history(router_id, ip_address, minutes):
    """Receive-time bucket averages; missing exports are gaps, not zero traffic."""
    import math
    now = datetime.datetime.now(datetime.timezone.utc)
    end = now.timestamp()
    start = end - minutes * 60
    bucket_seconds = max(1, math.ceil(minutes * 60 / 120))
    threshold = datetime.datetime.fromtimestamp(start, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_connection()
    try:
        rows = conn.execute(
            """SELECT CAST(strftime('%s', received_at) AS INTEGER) / ? AS bucket,
                      SUM(CASE WHEN src_ip=? THEN bytes ELSE 0 END) AS upload,
                      SUM(CASE WHEN dst_ip=? THEN bytes ELSE 0 END) AS download
               FROM flow_records WHERE router_id=? AND received_at>=?
                 AND (src_ip=? OR dst_ip=?) GROUP BY bucket ORDER BY bucket""",
            (bucket_seconds, ip_address, ip_address, router_id, threshold, ip_address, ip_address),
        ).fetchall()
    finally:
        conn.close()
    points = []
    if rows:
        buckets = {row["bucket"]: row for row in rows}
        for bucket in range(int(start // bucket_seconds), int(end // bucket_seconds) + 1):
            row = buckets.get(bucket)
            duration = max(1, min(end, (bucket+1)*bucket_seconds) - max(start, bucket*bucket_seconds))
            upload = row["upload"] * 8 / duration / 1000000 if row else None
            download = row["download"] * 8 / duration / 1000000 if row else None
            points.append({
                "timestamp": datetime.datetime.fromtimestamp(bucket*bucket_seconds, datetime.timezone.utc).isoformat(),
                "upload_mbps": upload, "download_mbps": download,
                "total_mbps": upload + download if row else None,
            })
    return {"points": points, "source": "flow", "bucket_seconds": bucket_seconds,
            "upload_bytes": sum(row["upload"] for row in rows),
            "download_bytes": sum(row["download"] for row in rows),
            "window_seconds": minutes * 60,
            "note": "Traffic Flow: average rate by export receive time (UTC). Gaps mean no exports; delayed or sampled exports affect the rate."}


def ip_peers(router_id, ip):
    """Historical exported peers, explicitly distinct from live API connections."""
    conn = db.get_connection()
    try:
        rows = conn.execute('''SELECT CASE WHEN src_ip=? THEN dst_ip ELSE src_ip END AS ip,
            SUM(CASE WHEN src_ip=? THEN bytes ELSE 0 END) AS upload_bytes,
            SUM(CASE WHEN dst_ip=? THEN bytes ELSE 0 END) AS download_bytes,
            SUM(bytes) AS total_bytes, COUNT(*) AS count
            FROM flow_records WHERE router_id=? AND received_at>=? AND (src_ip=? OR dst_ip=?)
            GROUP BY 1 ORDER BY total_bytes DESC LIMIT 100''',
            (ip, ip, ip, router_id, _threshold(60), ip, ip)).fetchall()
    finally:
        conn.close()
    return {"destinations": [dict(row) for row in rows], "ports": [], "connections": [],
            "error": None, "estimated": False, "source": "flow",
            "note": "API live connections unavailable. Destinations show the top 100 Flow peers from the last hour; these are historical exports, not live connections."}
