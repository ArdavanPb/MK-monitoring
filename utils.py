"""Pure helpers: byte formatting, duration parsing, IP classification, services."""
import ipaddress
import math
import re

_BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"]

_SERVICE_PORTS = {
    "80": "HTTP", "8080": "HTTP",
    "443": "HTTPS", "8443": "HTTPS",
    "53": "DNS", "853": "DNS-over-TLS",
    "22": "SSH", "21": "FTP",
    "25": "SMTP", "465": "SMTPS", "587": "SMTP",
    "110": "POP3", "995": "POP3S",
    "143": "IMAP", "993": "IMAPS",
    "1194": "OpenVPN", "1723": "PPTP",
    "3389": "RDP", "5900": "VNC",
    "123": "NTP", "161": "SNMP", "162": "SNMP",
    "514": "Syslog", "5060": "SIP", "5061": "SIPS",
}


def format_bytes(size):
    if not size:
        return "0 B"
    try:
        size = int(size)
    except (TypeError, ValueError):
        return "0 B"
    if size <= 0:
        return "0 B"
    power = min(int(math.log(size, 1024)), len(_BYTE_UNITS) - 1)
    return f"{size / (1024 ** power):.1f} {_BYTE_UNITS[power]}"


def format_duration(seconds_str):
    if not seconds_str:
        return "N/A"
    try:
        seconds = int("".join(filter(str.isdigit, seconds_str)))
    except ValueError:
        return str(seconds_str)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


def parse_routeros_duration(value):
    """Convert a RouterOS duration string (e.g. '2h15m30s') to a display string."""
    if not value or value == "0s":
        return "0s"
    h = m = s = 0
    match = re.search(r"(\d+)h", value)
    if match:
        h = int(match.group(1))
    match = re.search(r"(\d+)m", value)
    if match:
        m = int(match.group(1))
    match = re.search(r"(\d+)s", value)
    if match:
        s = int(match.group(1))
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def duration_seconds(value):
    """Return a RouterOS duration string as an integer number of seconds."""
    if not value:
        return 0
    total = 0
    for unit, factor in (("w", 604800), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        match = re.search(rf"(\d+){unit}", value)
        if match:
            total += int(match.group(1)) * factor
    return total


# IPv4 ranges treated as "internal/local" for classification: RFC1918 private,
# loopback, CGNAT, and link-local. Used as a fallback when a router's own
# /ip/address subnets are unavailable.
_INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def is_internal_ip(address):
    """Return True for RFC1918, loopback, CGNAT, and link-local addresses."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.version == 4:
        return any(ip in net for net in _INTERNAL_NETWORKS)
    # IPv6: unique-local, link-local, and loopback count as internal.
    return ip.is_private or ip.is_link_local or ip.is_loopback


def is_external_ip(address):
    return not is_internal_ip(address)


def classify_ip(address, local_subnets=()):
    """Classify an address as 'local', 'external', or 'other'.

    'local'    = inside one of ``local_subnets`` (the router's own /ip/address
                 subnets) or an internal range (RFC1918/loopback/CGNAT/link-local).
    'external' = a global/public unicast address.
    'other'    = non-host placeholders (0.0.0.0, broadcast, multicast, reserved,
                 malformed) that belong in neither group and are hidden.
    """
    if not isinstance(address, str) or not address:
        return "other"
    address = address.strip()
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "other"
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return "other"
    for net in local_subnets:
        try:
            if ip in net:
                return "local"
        except TypeError:
            continue
    if is_internal_ip(address):
        return "local"
    return "external"


def is_valid_ip(address):
    """Return True if address is a syntactically valid IPv4 or IPv6 address."""
    if not isinstance(address, str) or not address:
        return False
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def get_service_name(dport, proto):
    """Map a destination port to a friendly service name."""
    port = str(dport)
    if port in _SERVICE_PORTS:
        return _SERVICE_PORTS[port]
    return f"{proto.upper()}/{port}"
