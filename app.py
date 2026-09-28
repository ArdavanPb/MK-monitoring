"""MK-Monitoring Flask application.

Routes are kept thin; business logic lives in services.py, database access in
db.py, security helpers in security.py, and RouterOS connectivity in
routeros_client.py.
"""
import json
import logging
from datetime import datetime
from functools import wraps

from flask import (
    Flask, flash, jsonify, redirect, render_template, request, session, url_for,
)

import config
import db
import security
import services
import routeros_client
import utils

logging.basicConfig(level=logging.INFO, format="%(asctime)s APP %(levelname)s: %(message)s")
logger = logging.getLogger("app")


def create_app():
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY

    app.jinja_env.filters["format_bytes"] = utils.format_bytes
    app.jinja_env.filters["format_duration"] = utils.format_duration
    app.jinja_env.globals["csrf_token"] = security.generate_csrf_token

    _register_hooks(app)
    _register_routes(app)

    db.init_db()
    services.migrate_plaintext_credentials()
    return app


def _register_hooks(app):
    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if not security.validate_csrf_token():
                if request.path.startswith("/api/"):
                    return jsonify({"success": False, "error": "CSRF token missing or invalid"}), 400
                flash("Your session expired or the request was rejected. Please try again.", "error")
                return redirect(request.referrer or url_for("login"))

    @app.before_request
    def audit_middleware():
        if (
            request.method in ("POST", "PUT", "DELETE")
            and not request.path.startswith("/login")
            and "user_id" in session
        ):
            try:
                body = security.sanitize_audit_body(request)
                conn = db.get_connection()
                try:
                    conn.execute(
                        "INSERT INTO audit_log (user_id, username, method, path, request_body, ip_address) "
                        "VALUES (?,?,?,?,?,?)",
                        (session["user_id"], session.get("username", ""), request.method,
                         request.path, body, request.remote_addr),
                    )
                    conn.commit()
                finally:
                    conn.close()
            except Exception:  # noqa: BLE001 - auditing must never break requests
                pass


def _register_routes(app):
    login_limiter = security.RateLimiter(config.LOGIN_RATE_LIMIT, config.LOGIN_RATE_WINDOW)

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                if request.path.startswith("/api/"):
                    return jsonify({"success": False, "error": "Auth required"}), 401
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def role_required(min_role):
        hierarchy = {"admin": 3, "operator": 2, "viewer": 1}

        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if "user_id" not in session:
                    if request.path.startswith("/api/"):
                        return jsonify({"success": False, "error": "Auth required"}), 401
                    return redirect(url_for("login"))
                user_role = session.get("role") or "viewer"
                if hierarchy.get(user_role, 0) < hierarchy.get(min_role, 1):
                    if request.path.startswith("/api/"):
                        return jsonify({"success": False, "error": "Insufficient permissions"}), 403
                    flash("No permission", "error")
                    return redirect(url_for("index"))
                return view(*args, **kwargs)
            return wrapped
        return decorator

    def upgrade_user_hash(user_id, password):
        conn = db.get_connection()
        try:
            conn.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (security.hash_password(password), user_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ─── Authentication ───────────────────────────────────────────────────

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr or "unknown"
            if not login_limiter.allow(ip):
                flash("Too many login attempts. Please try again later.", "error")
                return render_template("login.html"), 429

            username = request.form.get("username", "")
            password = request.form.get("password", "")
            conn = db.get_connection()
            try:
                user = conn.execute(
                    "SELECT id, username, password_hash, role FROM users WHERE username=?",
                    (username,),
                ).fetchone()
            finally:
                conn.close()

            if user and security.verify_password(password, user["password_hash"]):
                if security.is_legacy_hash(user["password_hash"]):
                    upgrade_user_hash(user["id"], password)
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"] or "viewer"
                login_limiter.reset(ip)
                flash("Login successful!", "success")
                return redirect(url_for("index"))
            flash("Invalid credentials", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out", "info")
        return redirect(url_for("login"))

    @app.route("/change_password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not current or not new or not confirm:
                flash("All fields required", "error")
                return render_template("change_password.html")
            if new != confirm:
                flash("Passwords mismatch", "error")
                return render_template("change_password.html")
            if len(new) < 8:
                flash("Password must be at least 8 characters long", "error")
                return render_template("change_password.html")

            conn = db.get_connection()
            try:
                user = conn.execute(
                    "SELECT password_hash FROM users WHERE id=?", (session["user_id"],)
                ).fetchone()
                if not user or not security.verify_password(current, user["password_hash"]):
                    flash("Current password wrong", "error")
                    return render_template("change_password.html")
                conn.execute(
                    "UPDATE users SET password_hash=? WHERE id=?",
                    (security.hash_password(new), session["user_id"]),
                )
                conn.commit()
            finally:
                conn.close()
            flash("Password changed!", "success")
            return redirect(url_for("index"))
        return render_template("change_password.html")

    # ─── Dashboard / router management ────────────────────────────────────

    @app.route("/")
    @login_required
    def index():
        rdata = []
        for router in services.list_routers():
            router_id = router["id"]
            name = router["name"]
            host = router["host"]
            port = router["port"]
            snmp_enabled = router.get("snmp_enabled", 0)

            cache = services.get_status_cache(router_id)
            if cache and cache["status"] == "online" and cache["router_info"]:
                try:
                    info = json.loads(cache["router_info"])
                    source_type = cache["source_type"] or "API"
                    if source_type == "SNMP":
                        display_port = cache["snmp_port"] or cache["api_port"] or port
                    else:
                        display_port = cache["api_port"] or port
                    rdata.append({
                        "id": router_id, "name": name, "host": host, "port": port,
                        "display_port": display_port, "info": info, "status": "online",
                        "cached": True, "source_type": source_type,
                    })
                    continue
                except (ValueError, KeyError):
                    pass

            if snmp_enabled:
                si = services.get_snmp_detailed_info(router)
                res = si.get("resources", {})
                src_info = si.get("_source", {})
                display_port = src_info.get("port", 161)
                if res.get("cpu_load") and res["cpu_load"] != "N/A":
                    info = {
                        "name": name, "uptime": res.get("uptime", "via SNMP"),
                        "memory_usage_percent": res.get("memory_usage_percent", "N/A"),
                        "used_memory": res.get("used_memory", "N/A"),
                        "total_memory": res.get("total_memory", "N/A"),
                        "cpu_load": res.get("cpu_load", "N/A"),
                        "cpu_count": res.get("cpu_count", "N/A"),
                        "version": res.get("version", "via SNMP"),
                        "board_name": res.get("board_name", "N/A"),
                        "architecture_name": res.get("architecture_name", "N/A"),
                    }
                else:
                    info = {
                        "name": name, "uptime": "collecting...", "memory_usage_percent": "N/A",
                        "used_memory": "N/A", "total_memory": "N/A", "cpu_load": "N/A",
                        "cpu_count": "N/A", "cpu_frequency": "N/A", "version": "N/A",
                        "board_name": "N/A", "architecture_name": "N/A",
                    }
                rdata.append({
                    "id": router_id, "name": name, "host": host, "port": port,
                    "display_port": display_port, "info": info, "status": "online",
                    "source_type": "SNMP",
                })
            elif router.get("username") and router.get("password"):
                api, connection, error = routeros_client.connect_to_router(
                    host, port, router["username"], router["password"]
                )
                if api:
                    try:
                        info = routeros_client.get_router_info(api)
                        services.set_status_cache(router_id, "online", info, "API", port=port)
                        rdata.append({
                            "id": router_id, "name": name, "host": host, "port": port,
                            "display_port": port, "info": info, "status": "online",
                            "source_type": "API",
                        })
                    finally:
                        connection.disconnect()
                else:
                    rdata.append({
                        "id": router_id, "name": name, "host": host, "port": port,
                        "display_port": port, "info": {"error": error or "Connection failed"},
                        "status": "offline", "source_type": "API",
                    })
            else:
                rdata.append({
                    "id": router_id, "name": name, "host": host, "port": port,
                    "display_port": port, "info": {"error": "No connection method"},
                    "status": "offline", "source_type": "N/A",
                })
        return render_template("index.html", routers=rdata)

    @app.route("/add_router", methods=["GET", "POST"])
    @login_required
    @role_required("operator")
    def add_router():
        if request.method == "POST":
            form = request.form
            name = form.get("name", "")
            host = form.get("host", "")
            api_enabled = form.get("api_enabled", 0, type=int)
            snmp_enabled = form.get("snmp_enabled", 0, type=int)

            port = form.get("port", 8728, type=int)
            username = form.get("username", "")
            password = form.get("password", "")

            sc = form.get("snmp_community", "public")
            sv = form.get("snmp_version", 2, type=int)
            sp = form.get("snmp_port", 161, type=int)
            su = form.get("snmp_user", "")
            sap = form.get("snmp_auth_protocol", "MD5")
            sapw = form.get("snmp_auth_pass", "")
            spp = form.get("snmp_priv_protocol", "DES")
            sppw = form.get("snmp_priv_pass", "")

            errors = []
            api_connection = None

            if api_enabled:
                api, api_connection, error = routeros_client.connect_to_router(host, port, username, password)
                if not api:
                    errors.append(f"API: {error}")
            else:
                username = ""
                password = ""

            if snmp_enabled:
                if sv == 2:
                    if not routeros_client.test_snmp_connection(host, sc, 2, sp):
                        errors.append(f"SNMP: Connection failed to {host}:{sp}")
                else:
                    errors.append("SNMP v3 not supported")
            else:
                sc = "public"
                sv = 2
                sp = 161
                su = sap = sapw = spp = sppw = ""

            if errors:
                for error in errors:
                    flash(error, "error")
                return render_template("add_router.html", r={
                    "name": name, "host": host, "port": port, "username": username,
                    "api_enabled": api_enabled, "snmp_enabled": snmp_enabled,
                    "snmp_community": sc, "snmp_version": sv, "snmp_port": sp,
                    "snmp_user": su, "snmp_auth_protocol": sap, "snmp_auth_pass": sapw,
                    "snmp_priv_protocol": spp, "snmp_priv_pass": sppw,
                })

            services.create_router({
                "name": name, "host": host, "port": port, "username": username,
                "password": password, "snmp_enabled": snmp_enabled, "snmp_community": sc,
                "snmp_version": sv, "snmp_port": sp, "snmp_user": su,
                "snmp_auth_protocol": sap, "snmp_auth_pass": sapw,
                "snmp_priv_protocol": spp, "snmp_priv_pass": sppw,
            })
            if api_connection:
                api_connection.disconnect()
            flash("Router added!", "success")
            return redirect(url_for("index"))
        return render_template("add_router.html")

    @app.route("/edit_router/<int:router_id>", methods=["GET", "POST"])
    @login_required
    @role_required("operator")
    def edit_router(router_id):
        router = services.get_router(router_id)
        if not router:
            flash("Not found", "error")
            return redirect(url_for("index"))

        if request.method == "POST":
            form = request.form
            name = form.get("name", "")
            host = form.get("host", "")
            api_enabled = form.get("api_enabled", 0, type=int)
            snmp_enabled = form.get("snmp_enabled", 0, type=int)

            api_port = form.get("port", 8728, type=int)
            username = form.get("username", "")
            new_password = form.get("password", "")
            password = new_password if new_password else router["password"]

            sc = form.get("snmp_community", router.get("snmp_community", "public"))
            sv = form.get("snmp_version", router.get("snmp_version", 2), type=int)
            sp = form.get("snmp_port", router.get("snmp_port", 161), type=int)
            su = form.get("snmp_user", router.get("snmp_user", ""))
            sap = form.get("snmp_auth_protocol", router.get("snmp_auth_protocol", "MD5"))
            sapw = form.get("snmp_auth_pass", router.get("snmp_auth_pass", ""))
            spp = form.get("snmp_priv_protocol", router.get("snmp_priv_protocol", "DES"))
            sppw = form.get("snmp_priv_pass", router.get("snmp_priv_pass", ""))

            errors = []
            api_connection = None

            if api_enabled:
                api, api_connection, error = routeros_client.connect_to_router(host, api_port, username, password)
                if not api:
                    errors.append(f"API: {error}")
            else:
                username = router["username"]
                password = router["password"]
                api_port = router["port"]

            if snmp_enabled and sv != 2:
                errors.append("SNMP v3 unsupported")

            if errors:
                for error in errors:
                    flash(error, "error")
                return render_template("add_router.html", edit_mode=True, r={
                    "name": name, "host": host, "port": api_port, "username": username,
                    "api_enabled": api_enabled, "snmp_enabled": snmp_enabled,
                    "snmp_community": sc, "snmp_version": sv, "snmp_port": sp,
                    "snmp_user": su, "snmp_auth_protocol": sap, "snmp_auth_pass": sapw,
                    "snmp_priv_protocol": spp, "snmp_priv_pass": sppw,
                })

            services.update_router(router_id, {
                "name": name, "host": host, "port": api_port, "username": username,
                "password": password, "snmp_enabled": snmp_enabled, "snmp_community": sc,
                "snmp_version": sv, "snmp_port": sp, "snmp_user": su,
                "snmp_auth_protocol": sap, "snmp_auth_pass": sapw,
                "snmp_priv_protocol": spp, "snmp_priv_pass": sppw,
            })
            if api_connection:
                api_connection.disconnect()
            flash("Router updated!", "success")
            return redirect(url_for("index"))

        return render_template("add_router.html", edit_mode=True, r={
            "name": router["name"], "host": router["host"], "port": router["port"],
            "username": router["username"], "api_enabled": 1 if router["username"] else 0,
            "snmp_enabled": router.get("snmp_enabled", 0),
            "snmp_community": router.get("snmp_community", "public"),
            "snmp_version": router.get("snmp_version", 2),
            "snmp_port": router.get("snmp_port", 161),
            "snmp_user": router.get("snmp_user", ""),
            "snmp_auth_protocol": router.get("snmp_auth_protocol", "MD5"),
            "snmp_auth_pass": router.get("snmp_auth_pass", ""),
            "snmp_priv_protocol": router.get("snmp_priv_protocol", "DES"),
            "snmp_priv_pass": router.get("snmp_priv_pass", ""),
        })

    @app.route("/delete_router/<int:router_id>", methods=["POST"])
    @login_required
    @role_required("admin")
    def delete_router(router_id):
        services.delete_router(router_id)
        flash("Router deleted!", "success")
        return redirect(url_for("index"))

    @app.route("/refresh_router/<int:router_id>", methods=["POST"])
    @login_required
    @role_required("operator")
    def refresh_router(router_id):
        router = services.get_router(router_id)
        if router:
            status, _ = services.update_router_status_cache(
                router_id, router["name"], router["host"], router["port"],
                router["username"], router["password"],
            )
            flash("Refreshed!" if status == "online" else "Failed to connect",
                  "success" if status == "online" else "error")
        return redirect(url_for("index"))

    # ─── Monitoring ───────────────────────────────────────────────────────

    def render_monitor(router, rd, info, log_stats, alerts, backups, source_type, source_port, source_label, selected_tab="system", network_ips=None):
        return render_template(
            "monitor.html", router=rd, info=info,
            log_stats=log_stats,
            alerts=alerts, backups=backups, now=datetime.now(),
            source_type=source_type, source_port=source_port,
            source_label=source_label, selected_tab=selected_tab,
            network_ips=network_ips or {"records": [], "missing_sources": [], "error": None},
            source_colors=services.NETWORK_IP_SOURCE_COLORS,
        )

    @app.route("/monitor_router/<int:router_id>")
    @login_required
    def monitor_router(router_id):
        selected_tab = request.args.get("tab", "system")
        router = services.get_router(router_id)
        if not router:
            flash("Not found", "error")
            return redirect(url_for("index"))

        rd = {
            "id": router["id"], "name": router["name"], "host": router["host"],
            "port": router["port"], "snmp_enabled": router.get("snmp_enabled", 0),
        }
        alerts = services.get_alerts(router_id, 50)
        empty_stats = {"total": 0, "categories": {}, "severities": {}}

        if router.get("snmp_enabled"):
            si = services.get_snmp_detailed_info(router)
            src_info = si.get("_source", {})
            has_data = si["resources"].get("cpu_load") and si["resources"]["cpu_load"] != "N/A"
            if has_data:
                return render_monitor(router, rd, si, empty_stats, alerts, [], "SNMP", src_info.get("port", 161), "SNMP", selected_tab)
            if not router.get("username") or not router.get("password"):
                return render_monitor(router, rd, si, empty_stats, alerts, [], "SNMP", src_info.get("port", 161), "SNMP", selected_tab)

        if not router.get("username") or not router.get("password"):
            return render_template("error.html", error="No connection method configured"), 200

        api, connection, error = routeros_client.connect_to_router(
            router["host"], router["port"], router["username"], router["password"]
        )
        if not api:
            return render_template("error.html", error=error), 200

        try:
            detailed = routeros_client.get_detailed_router_info(api)
            log_stats = services.get_log_statistics(detailed.get("logs", []))
        finally:
            connection.disconnect()

        network_ips = services.get_network_ips(router)
        backups = services.get_backup_list(router_id)
        return render_monitor(router, rd, detailed, log_stats, alerts, backups, "API", router["port"], "API", selected_tab, network_ips)

    @app.route("/api/network-ips/<int:router_id>")
    @login_required
    def api_network_ips(router_id):
        router = services.get_router(router_id)
        if not router:
            return jsonify({"success": False, "error": "Router not found"}), 404
        data = services.get_network_ips(router)
        return jsonify({"success": True, "data": data})

    @app.route("/api/interface-traffic/<int:router_id>")
    @login_required
    def api_interface_traffic(router_id):
        router = services.get_router(router_id)
        if not router:
            return jsonify({"success": False, "error": "Router not found"}), 404
        data = services.get_interface_traffic(router_id)
        return jsonify({"success": True, "data": data})

    # ─── IP details (per-IP traffic & live connections) ──────────────────

    @app.route("/monitor_router/<int:router_id>/ip/<ip>")
    @login_required
    def ip_details(router_id, ip):
        if not utils.is_valid_ip(ip):
            return render_template("error.html", error="Invalid IP address"), 400
        router = services.get_router(router_id)
        if not router:
            flash("Router not found", "error")
            return redirect(url_for("index"))
        rd = {
            "id": router["id"], "name": router["name"], "host": router["host"],
            "port": router["port"], "snmp_enabled": router.get("snmp_enabled", 0),
        }
        header = services.get_ip_header(router, ip)
        totals = services.get_ip_traffic_totals(router_id, ip)
        return render_template(
            "ip_details.html", router=rd, ip=ip, header=header, totals=totals,
            history_periods=services._HISTORY_PERIODS,
        )

    @app.route("/api/ip/<int:router_id>/<ip>/history")
    @login_required
    def api_ip_history(router_id, ip):
        if not utils.is_valid_ip(ip):
            return jsonify({"success": False, "error": "Invalid IP address"}), 400
        router = services.get_router(router_id)
        if not router:
            return jsonify({"success": False, "error": "Router not found"}), 404
        period = request.args.get("period", "1h")
        result = services.get_ip_bandwidth_history(router_id, ip, period)
        if isinstance(result, dict) and result.get("error"):
            return jsonify({"success": False, "error": result["error"]}), 400
        return jsonify({"success": True, "data": {"points": result, "period": period}})

    @app.route("/api/ip/<int:router_id>/<ip>/connections")
    @login_required
    def api_ip_connections(router_id, ip):
        if not utils.is_valid_ip(ip):
            return jsonify({"success": False, "error": "Invalid IP address"}), 400
        router = services.get_router(router_id)
        if not router:
            return jsonify({"success": False, "error": "Router not found"}), 404
        data = services.get_ip_connections_details(router_id, ip)
        return jsonify({"success": True, "data": data})

    # ─── Backups ──────────────────────────────────────────────────────────

    @app.route("/backup/<int:router_id>", methods=["POST"])
    @login_required
    @role_required("operator")
    def trigger_backup(router_id):
        result = services.run_router_backup(router_id)
        flash(f"Backup saved: {result}" if result else "Backup failed",
              "success" if result else "error")
        return redirect(url_for("monitor_router", router_id=router_id))

    @app.route("/backup_diff/<int:router_id>")
    @login_required
    def backup_diff(router_id):
        newer, older, diff_text = services.get_backup_diff(router_id)
        if not newer or not older:
            flash(diff_text or "Need 2+ backups", "error")
            return redirect(url_for("monitor_router", router_id=router_id))
        router = services.get_router(router_id)
        return render_template(
            "backup_diff.html",
            router={"id": router_id, "name": router["name"] if router else "Unknown"},
            newer=newer, older=older, diff_text=diff_text,
        )

    # ─── Alerts ───────────────────────────────────────────────────────────

    @app.route("/api/alerts/acknowledge/<int:alert_id>", methods=["POST"])
    @login_required
    @role_required("operator")
    def api_acknowledge_alert(alert_id):
        services.acknowledge_alert(alert_id)
        return jsonify({"success": True})

    @app.route("/api/alert_rules/<int:router_id>", methods=["GET", "POST"])
    @login_required
    @role_required("operator")
    def api_alert_rules(router_id):
        if request.method == "POST":
            data = request.get_json(silent=True) or request.form.to_dict()
            rule_id = services.create_alert_rule(router_id, data)
            return jsonify({"success": True, "rule_id": rule_id})
        return jsonify({"success": True, "data": services.list_alert_rules(router_id)})

    @app.route("/api/alert_rules/<int:rule_id>/delete", methods=["POST"])
    @login_required
    @role_required("admin")
    def api_delete_alert_rule(rule_id):
        services.delete_alert_rule(rule_id)
        return jsonify({"success": True})

    # ─── Logs ─────────────────────────────────────────────────────────────

    @app.route("/update_log_retention/<int:router_id>", methods=["POST"])
    @login_required
    @role_required("admin")
    def update_log_retention(router_id):
        days = request.form.get("retention_days", 7, type=int)
        if days not in config.LOG_RETENTION_OPTIONS:
            flash("Invalid", "error")
            return redirect(url_for("router_logs", router_id=router_id))
        services.update_log_retention_settings(router_id, days)
        services.cleanup_old_logs(router_id)
        flash(f"Retention set to {days} days", "success")
        return redirect(url_for("router_logs", router_id=router_id))

    @app.route("/export_logs_csv/<int:router_id>")
    @login_required
    def export_logs_csv(router_id):
        import csv
        import io

        severity = request.args.get("severity", "all")
        search = request.args.get("search", "")

        conn = db.get_connection()
        try:
            query = "SELECT timestamp, topics, message, severity, stored_at FROM router_logs WHERE router_id=?"
            params = [router_id]
            if severity != "all":
                query += " AND severity=?"
                params.append(severity)
            if search:
                query += " AND (message LIKE ? OR topics LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%"])
            query += " ORDER BY timestamp DESC"
            logs = conn.execute(query, params).fetchall()
            router = conn.execute("SELECT name FROM routers WHERE id=?", (router_id,)).fetchone()
            router_name = router["name"] if router else "Unknown"
        finally:
            conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Timestamp", "Category", "Message", "Severity", "Stored At", "Router Name"])
        for log in logs:
            writer.writerow([log["timestamp"], log["topics"], log["message"], log["severity"], log["stored_at"], router_name])
        output.seek(0)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return app.response_class(
            response=output.getvalue(), status=200, mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={router_name}_logs_{timestamp}.csv"},
        )

    @app.route("/router_logs/<int:router_id>")
    @login_required
    def router_logs(router_id):
        page = request.args.get("page", 1, type=int)
        severity = request.args.get("severity", "all")
        search = request.args.get("search", "")

        router = services.get_router(router_id)
        if not router:
            flash("Not found", "error")
            return redirect(url_for("index"))

        api, connection, error = routeros_client.connect_to_router(
            router["host"], router["port"], router["username"], router["password"]
        )
        if api:
            try:
                logs = routeros_client.safe_api_call(api, "/log")["data"] or []
                saved = services.save_router_logs(router_id, logs)
                services.cleanup_old_logs(router_id)
                if saved > 0:
                    flash(f"Updated {saved} logs", "success")
            except Exception as exc:  # noqa: BLE001
                logger.error("Log fetch: %s", exc)
            finally:
                connection.disconnect()

        pagination = services.get_paginated_logs(router_id, page, 50, severity, search)

        conn = db.get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM router_logs WHERE router_id=?", (router_id,)).fetchone()[0]
            severity_rows = conn.execute("SELECT severity, COUNT(*) FROM router_logs WHERE router_id=? GROUP BY severity", (router_id,)).fetchall()
            category_rows = conn.execute("SELECT topics, COUNT(*) FROM router_logs WHERE router_id=? GROUP BY topics", (router_id,)).fetchall()
        finally:
            conn.close()

        severities = {row["severity"]: row["COUNT(*)"] for row in severity_rows}
        categories = {row["topics"]: row["COUNT(*)"] for row in category_rows}
        retention_days = services.get_log_retention_settings(router_id)

        return render_template(
            "router_logs.html",
            router={"id": router_id, "name": router["name"], "host": router["host"], "port": router["port"]},
            logs=pagination["logs"],
            log_stats={"total": total, "severities": severities, "categories": categories},
            pagination=pagination, retention_days=retention_days,
            current_severity=severity, current_search=search,
        )

    # ─── Network connections ──────────────────────────────────────────────

    @app.route("/connections/<int:router_id>")
    @login_required
    def connections_page(router_id):
        page = request.args.get("page", 1, type=int)
        sort = request.args.get("sort", "download_desc")

        router = services.get_router(router_id)
        if not router:
            flash("Not found", "error")
            return redirect(url_for("index"))

        data = services.get_live_firewall_connections(router_id)
        if "error" not in data:
            connections = data["connections"]
            sort_keys = {
                "download_desc": ("download_bytes", True),
                "upload_desc": ("upload_bytes", True),
                "duration_desc": ("duration_seconds", True),
                "src_ip_asc": ("src_ip", False),
            }
            key, reverse = sort_keys.get(sort, ("download_bytes", True))
            connections.sort(key=lambda item: item[key], reverse=reverse)

            per_page = 20
            total = len(connections)
            total_pages = max(1, (total + per_page - 1) // per_page)
            page = max(1, min(page, total_pages))
            start = (page - 1) * per_page
            data["connections"] = connections[start:start + per_page]
            data["pagination"] = {
                "page": page, "per_page": per_page, "total_connections": total,
                "total_pages": total_pages, "has_prev": page > 1, "has_next": page < total_pages,
                "sort_by": sort,
            }

        return render_template(
            "connections.html",
            router={"id": router_id, "name": router["name"], "host": router["host"], "port": router["port"]},
            connections_data=data,
        )

    @app.route("/api/connections/<int:router_id>")
    @login_required
    def api_connections(router_id):
        try:
            data = services.get_live_firewall_connections(router_id)
            if "error" in data:
                return jsonify({"success": False, "error": data["error"]}), 500
            return jsonify({"success": True, "data": data, "timestamp": datetime.now().isoformat()})
        except Exception as exc:  # noqa: BLE001
            return jsonify({"success": False, "error": str(exc)}), 500

    @app.route("/api/connection-count/<int:router_id>")
    @login_required
    def api_connection_count(router_id):
        try:
            data = services.get_live_firewall_connections(router_id)
            if "error" in data:
                # Connections aren't available for this router (offline or
                # SNMP-only); report 0 rather than failing the dashboard poll.
                return jsonify({"success": True, "count": 0})
            return jsonify({"success": True, "count": data.get("total_count", 0)})
        except Exception as exc:  # noqa: BLE001
            return jsonify({"success": False, "error": str(exc)}), 500


app = create_app()


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
