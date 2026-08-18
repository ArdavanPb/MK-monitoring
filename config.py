"""Central application configuration.

All settings are read from environment variables with sensible defaults so the
same code runs on bare metal, in Docker, and during tests. Secret material is
persisted to files under the data directory so it survives restarts.
"""
import os
import secrets


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


def _default_db_path():
    explicit = os.environ.get("DB_PATH")
    if explicit:
        return explicit
    # Inside the container the data volume is mounted at /app/data.
    if os.path.isdir("/app/data"):
        return "/app/data/routers.db"
    return "data/routers.db"


def _read_or_create_key_file(path):
    """Return the content of a key file, creating it atomically if missing."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as handle:
            value = handle.read().strip()
        if value:
            return value.decode("utf-8")

    value = secrets.token_hex(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process created it first; use its value.
        with open(path, "rb") as handle:
            existing = handle.read().strip()
        return existing.decode("utf-8") if existing else value
    with os.fdopen(fd, "w") as handle:
        handle.write(value)
    return value


DB_PATH = _default_db_path()
DATA_DIR = os.path.dirname(DB_PATH) or "."

# Flask secret key used to sign sessions and CSRF tokens.
SECRET_KEY = os.environ.get("SECRET_KEY") or _read_or_create_key_file(
    os.path.join(DATA_DIR, ".secret_key")
)

# Encryption key (Fernet) used to encrypt router/SNMP credentials at rest.
# May be provided as a base64 Fernet key or left unset to derive one from the
# persisted key file.
FERNET_KEY = os.environ.get("FERNET_KEY")

DEBUG = _env_bool("FLASK_DEBUG", False)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))

DEFAULT_USERNAME = os.environ.get("DEFAULT_USERNAME", "admin")
DEFAULT_PASSWORD = os.environ.get("DEFAULT_PASSWORD", "admin")

BACKUP_DIR = os.path.join(DATA_DIR, "backups")
MAX_BACKUPS = int(os.environ.get("MAX_BACKUPS", "30"))

# Login rate limiting: max attempts per IP within the window (seconds).
LOGIN_RATE_LIMIT = int(os.environ.get("LOGIN_RATE_LIMIT", "5"))
LOGIN_RATE_WINDOW = int(os.environ.get("LOGIN_RATE_WINDOW", "60"))

# Firewall connections cache TTL (seconds) and maximum number of cached routers.
CONNECTIONS_CACHE_TTL = int(os.environ.get("CONNECTIONS_CACHE_TTL", "10"))
CONNECTIONS_CACHE_MAX = int(os.environ.get("CONNECTIONS_CACHE_MAX", "50"))

LOG_RETENTION_OPTIONS = (1, 3, 7, 30, 90)
