"""Pure helpers: byte formatting, duration parsing, IP classification, services."""
import ipaddress
import math
import re

# Pre-compiled private networks for fast internal/external classification.
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)

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


def is_internal_ip(address):
    """Return True if the address is a private/link-local IPv4 address."""
    try:
        return ipaddress.ip_address(address).is_private or ipaddress.ip_address(address).is_link_local
    except ValueError:
        return False


def is_external_ip(address):
    return not is_internal_ip(address)


def get_service_name(dport, proto):
    """Map a destination port to a friendly service name."""
    port = str(dport)
    if port in _SERVICE_PORTS:
        return _SERVICE_PORTS[port]
    return f"{proto.upper()}/{port}"
