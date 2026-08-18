"""RouterOS API connectivity and data retrieval helpers."""
import logging
import subprocess
import traceback

import routeros_api

# The exception classes live in ``routeros_api.exceptions`` in current
# releases, but older versions exposed them at the top level. Fall back to the
# top-level namespace when the submodule is unavailable.
try:
    from routeros_api.exceptions import (  # noqa: F401
        RouterOsApiConnectionError,
        RouterOsApiError,
    )
except ImportError:  # pragma: no cover - compatibility shim
    RouterOsApiConnectionError = getattr(routeros_api, "RouterOsApiConnectionError", Exception)
    RouterOsApiError = getattr(routeros_api, "RouterOsApiError", Exception)

logger = logging.getLogger("app")


def connect_to_router(host, port, username, password):
    """Connect to a RouterOS router and return (api, connection, error)."""
    try:
        connection = routeros_api.RouterOsApiPool(
            host=host,
            port=port,
            username=username,
            password=password,
            plaintext_login=True,
            use_ssl=False,
        )
        api = connection.get_api()
        return api, connection, None
    except Exception as exc:  # noqa: BLE001 - library raises broad exceptions
        message = str(exc)
        lowered = message.lower()
        if "timed out" in lowered:
            return None, None, f"Timeout to {host}:{port}"
        if "refused" in lowered:
            return None, None, f"API refused on port {port}"
        if "no route" in lowered:
            return None, None, f"No route to {host}"
        if "wrong user" in lowered or "invalid user" in lowered:
            return None, None, f"Auth failed for {username}"
        return None, None, f"Connection failed: {message}"


def safe_api_call(api, resource_path):
    """Call a RouterOS API resource returning {'data', 'error'}."""
    try:
        resource = api.get_resource(resource_path)
        result = resource.get()
        if result is None:
            return {"data": None, "error": f"{resource_path} returned None"}
        return {"data": result, "error": None}
    except RouterOsApiConnectionError as exc:
        logger.warning("API %s connection error: %s", resource_path, exc)
        return {"data": None, "error": f"Connection error: {exc}"}
    except RouterOsApiError as exc:
        # RouterOS-level rejections (e.g. "no such command prefix" for an
        # optional feature) are expected and do not need a full traceback.
        logger.warning("API %s rejected: %s", resource_path, exc)
        return {"data": None, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.error("API %s error: %s\n%s", resource_path, exc, traceback.format_exc())
        return {"data": None, "error": str(exc)}


def safe_api_call_single(api, resource_path):
    """Call an API resource and return its first item as a dict."""
    result = safe_api_call(api, resource_path)
    if result["error"]:
        return {"data": {}, "error": result["error"]}
    items = result["data"]
    if not items:
        return {"data": {}, "error": f"{resource_path} returned empty list"}
    return {"data": items[0], "error": None}


def test_snmp_connection(host, community, version, port):
    version = "2c" if version == 2 else str(version)
    try:
        cmd = [
            "snmpget", "-v", version, "-c", community, "-t", "5", "-r", "1",
            "-OQv", f"{host}:{port}", ".1.3.6.1.2.1.1.3.0",
        ]
        logger.info("Testing SNMP: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except FileNotFoundError:
        logger.error("snmpget binary not found - install the 'snmp' package")
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("SNMP test error: %s", exc)
        return False


# Maps RouterOS v6/v7 field-name variants to normalized snake_case keys.
RESOURCE_FIELD_MAP = {
    "cpu-load": "cpu_load", "cpu": "cpu_load",
    "cpu-count": "cpu_count", "cpu-core-count": "cpu_count", "cpu-core": "cpu_count",
    "architecture-name": "architecture_name", "cpu-architecture": "architecture_name",
    "architecture": "architecture_name",
    "board-name": "board_name", "board": "board_name", "hardware": "board_name",
    "total-memory": "total_memory", "memory-size": "total_memory", "totalMemory": "total_memory",
    "free-memory": "free_memory", "memory-free": "free_memory", "freeMemory": "free_memory",
    "used-memory": "used_memory", "memory-used": "used_memory", "usedMemory": "used_memory",
    "build-time": "build_time", "buildTime": "build_time",
    "factory-software": "factory_software", "factorySoftware": "factory_software",
}

_RESOURCE_DEFAULTS = [
    "cpu_load", "cpu_count", "architecture_name", "board_name",
    "total_memory", "free_memory", "used_memory", "uptime", "version",
]


def map_resource_fields(raw):
    """Normalize a RouterOS resource dict to underscored keys."""
    result = dict(raw)
    for key, value in raw.items():
        if key in RESOURCE_FIELD_MAP:
            result[RESOURCE_FIELD_MAP[key]] = value
    for field in _RESOURCE_DEFAULTS:
        result.setdefault(field, "N/A")
    return result


def get_router_info(api):
    """Return a simplified router info dict for the dashboard."""
    identity = safe_api_call_single(api, "/system/identity")
    router_name = identity["data"].get("name", "N/A") if identity["data"] else "N/A"

    resource = safe_api_call_single(api, "/system/resource")
    mapped = map_resource_fields(resource["data"] or {})

    memory_percent = "N/A"
    total = mapped.get("total_memory")
    used = mapped.get("used_memory")
    if total not in ("N/A", "0", None) and used not in ("N/A", None):
        try:
            memory_percent = round(int(used) / int(total) * 100, 1)
        except (ValueError, ZeroDivisionError):
            pass

    return {
        "name": router_name,
        "uptime": mapped.get("uptime", "N/A"),
        "total_memory": mapped.get("total_memory", "N/A"),
        "free_memory": mapped.get("free_memory", "N/A"),
        "used_memory": mapped.get("used_memory", "N/A"),
        "memory_usage_percent": memory_percent,
        "cpu_load": mapped.get("cpu_load", "N/A"),
        "cpu_count": mapped.get("cpu_count", "N/A"),
        "version": mapped.get("version", "N/A"),
        "board_name": mapped.get("board_name", "N/A"),
        "architecture_name": mapped.get("architecture_name", "N/A"),
    }


def get_detailed_router_info(api):
    """Return full detailed router info for the monitor page."""
    details = {}
    api_errors = []

    result = safe_api_call_single(api, "/system/identity")
    details["identity"] = result["data"]
    if result["error"]:
        api_errors.append(f"identity: {result['error']}")

    result = safe_api_call_single(api, "/system/resource")
    if result["data"]:
        details["resources"] = map_resource_fields(result["data"])
    else:
        details["resources"] = {k: "N/A" for k in _RESOURCE_DEFAULTS}
    if result["error"]:
        api_errors.append(f"resource: {result['error']}")

    result = safe_api_call_single(api, "/system/clock")
    clock = result["data"] or {}
    if clock:
        clock["time_zone_name"] = clock.get("time-zone-name", clock.get("time-zone", "N/A"))
        details["clock"] = clock
    else:
        details["clock"] = {}
    if result["error"]:
        api_errors.append(f"clock: {result['error']}")

    result = safe_api_call(api, "/ip/address")
    details["ip_addresses"] = result["data"] or []
    if result["error"]:
        api_errors.append(f"ip/address: {result['error']}")

    result = safe_api_call(api, "/interface")
    details["interfaces"] = result["data"] or []
    if result["error"]:
        api_errors.append(f"interface: {result['error']}")

    result = safe_api_call(api, "/ip/dhcp-server/lease")
    details["dhcp_leases"] = result["data"] or []
    if result["error"]:
        api_errors.append(f"dhcp: {result['error']}")

    result = safe_api_call(api, "/ip/arp")
    details["arp_table"] = result["data"] or []
    if result["error"]:
        api_errors.append(f"arp: {result['error']}")

    result = safe_api_call_single(api, "/system/health")
    details["health"] = result["data"] or {}
    if result["error"]:
        api_errors.append(f"health: {result['error']}")

    result = safe_api_call_single(api, "/system/license")
    details["license"] = result["data"] or {}
    if result["error"]:
        api_errors.append(f"license: {result['error']}")

    result = safe_api_call(api, "/log")
    details["logs"] = result["data"] or []
    if result["error"]:
        api_errors.append(f"log: {result['error']}")

    if api_errors:
        details["api_errors"] = api_errors
    return details
