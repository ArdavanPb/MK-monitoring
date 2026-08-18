"""Security helpers: password hashing, credential encryption, CSRF, rate limiting."""
import hmac
import os
import secrets
import threading
import time
from collections import defaultdict, deque

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

import config

ENC_PREFIX = "enc:"

_fernet = None
_fernet_lock = threading.Lock()


def _get_fernet():
    global _fernet
    if _fernet is None:
        with _fernet_lock:
            if _fernet is None:
                key = _load_fernet_key()
                _fernet = Fernet(key)
    return _fernet


def _load_fernet_key():
    if config.FERNET_KEY:
        return config.FERNET_KEY.encode("utf-8")

    path = os.path.join(config.DATA_DIR, ".fernet_key")
    os.makedirs(config.DATA_DIR, exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as handle:
            existing = handle.read().strip()
        if existing:
            return existing

    key = Fernet.generate_key()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "rb") as handle:
            return handle.read().strip()
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


def hash_password(password):
    return generate_password_hash(password)


def is_legacy_hash(stored_hash):
    """Return True if the hash is an unsalted SHA-256 hex digest."""
    if not stored_hash:
        return False
    return (
        len(stored_hash) == 64
        and all(c in "0123456789abcdef" for c in stored_hash.lower())
    )


def verify_password(password, stored_hash):
    """Verify a password, transparently supporting legacy SHA-256 hashes."""
    if not stored_hash:
        return False
    if is_legacy_hash(stored_hash):
        import hashlib

        return hashlib.sha256(password.encode()).hexdigest() == stored_hash.lower()
    return check_password_hash(stored_hash, password)


def encrypt_secret(plaintext):
    """Encrypt a credential value for storage at rest.

    Empty values and already-encrypted values are returned unchanged so the
    function is idempotent.
    """
    if plaintext is None:
        return ""
    plaintext = str(plaintext)
    if plaintext == "" or plaintext.startswith(ENC_PREFIX):
        return plaintext
    return ENC_PREFIX + _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(value):
    """Decrypt a stored credential value.

    Values without the encryption prefix (legacy plaintext) are returned as-is
    so existing databases keep working during migration.
    """
    if value is None:
        return ""
    value = str(value)
    if value == "":
        return ""
    if not value.startswith(ENC_PREFIX):
        return value
    try:
        return _get_fernet().decrypt(value[len(ENC_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def generate_csrf_token():
    from flask import session

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token():
    from flask import request, session

    expected = session.get("_csrf_token")
    if not expected:
        return False
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not supplied:
        return False
    return hmac.compare_digest(expected, supplied)


class RateLimiter:
    """Thread-safe sliding-window rate limiter keyed by an arbitrary string."""

    def __init__(self, limit, window_seconds):
        self.limit = limit
        self.window = window_seconds
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key):
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] > self.window:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True

    def reset(self, key):
        with self._lock:
            self._events.pop(key, None)


# Sensitive form/JSON keys that must never be written to the audit log.
SENSITIVE_KEYS = {
    "password",
    "current_password",
    "new_password",
    "confirm_password",
    "snmp_auth_pass",
    "snmp_priv_pass",
    "snmp_community",
    "csrf_token",
}


def sanitize_audit_body(request):
    """Return a redacted, truncated representation of the request body."""
    try:
        if request.is_json:
            data = request.get_json(silent=True)
            if isinstance(data, dict):
                return _redact_dict(data)
            return str(data)[:500]

        form = request.form
        if form:
            data = {k: form[k] for k in form}
            return _redact_dict(data)
        return ""
    except Exception:
        return ""


def _redact_dict(data):
    redacted = {}
    for key, value in data.items():
        if key in SENSITIVE_KEYS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return str(redacted)[:500]
