"""
validators.py — Input validation and sanitization helpers.

Every value coming from request.form passes through here before it
touches the database. This protects against missing-field crashes
(KeyError), oversized payloads, and NoSQL-injection-style operator
smuggling (e.g. a username of {"$ne": null}).
"""

import re

# ── Field rules ────────────────────────────────────────────────────────────────

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PHONE_RE    = re.compile(r"^[0-9+\-\s]{7,20}$")
EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

ALLOWED_ROLES = {"admin", "staff", "security"}

ALLOWED_ID_TYPES = {"Passport", "Aadhaar", "Driving License", "Voter ID", "PAN Card"}

MAX_TEXT_LEN = 200


class ValidationError(Exception):
    """Raised when a submitted field fails validation."""


def _str(value) -> str:
    """
    Coerce a form value to a trimmed string.

    Mongo/JSON can smuggle dicts or lists ({"$ne": ""}) through form
    parsers in some setups; rejecting non-strings closes that door.
    """
    if not isinstance(value, str):
        raise ValidationError("Invalid input type")
    return value.strip()


def validate_username(value) -> str:
    value = _str(value)
    if not USERNAME_RE.match(value):
        raise ValidationError(
            "Username must be 3-32 characters: letters, numbers, . _ - only"
        )
    return value


def validate_role(value) -> str:
    value = _str(value)
    if value not in ALLOWED_ROLES:
        raise ValidationError("Invalid role selected")
    return value


def validate_id_type(value) -> str:
    value = _str(value)
    if value not in ALLOWED_ID_TYPES:
        raise ValidationError("Invalid ID proof type selected")
    return value


def validate_text(value, field="field", required=True, max_len=MAX_TEXT_LEN) -> str:
    value = _str(value)
    if not value:
        if required:
            raise ValidationError(f"{field} is required")
        return ""
    if len(value) > max_len:
        raise ValidationError(f"{field} is too long (max {max_len} chars)")
    return value


def validate_phone(value) -> str:
    value = _str(value)
    if not PHONE_RE.match(value):
        raise ValidationError("Phone must be 7-20 digits")
    return value


def validate_email(value) -> str:
    value = _str(value)
    if not EMAIL_RE.match(value) or len(value) > MAX_TEXT_LEN:
        raise ValidationError("Invalid email address")
    return value


def is_strong_password(password) -> bool:
    """Password policy: 8+ chars, upper, lower, digit, and special char."""
    if not isinstance(password, str):
        return False
    return bool(
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )
