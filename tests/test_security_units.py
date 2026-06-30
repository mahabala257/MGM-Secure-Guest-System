"""Unit tests for the standalone security modules."""

import os

import pytest

from security import risk_engine, honeypot, mfa, crypto
from security.validators import (
    ValidationError, validate_username, validate_role,
    validate_email, validate_phone, is_strong_password,
)
from security.anomaly_detector import detect_user_anomaly

os.environ.setdefault("DATA_ENCRYPTION_KEY",
                      "vD2qvYLH4k_nH0k92dKsUPHxulg0s4szcDOhqgjd44A=")


# ── validators ────────────────────────────────────────────────────────────────
def test_username_accepts_valid():
    assert validate_username("john_doe.1") == "john_doe.1"


@pytest.mark.parametrize("bad", ["ab", "has space", "x" * 40, {"$ne": ""}, 123])
def test_username_rejects_bad(bad):
    with pytest.raises(ValidationError):
        validate_username(bad)


def test_role_rejects_unknown():
    with pytest.raises(ValidationError):
        validate_role("superuser")


def test_email_and_phone():
    assert validate_email("a@b.com") == "a@b.com"
    with pytest.raises(ValidationError):
        validate_email("nope")
    assert validate_phone("+91 99999-99999")
    with pytest.raises(ValidationError):
        validate_phone("abc")


def test_password_policy():
    assert is_strong_password("Aa1!aaaa")
    assert not is_strong_password("weak")
    assert not is_strong_password(None)


# ── crypto round-trip ──────────────────────────────────────────────────────────
def test_encrypt_decrypt_roundtrip():
    token = crypto.encrypt("AADHAAR-1234")
    assert token != "AADHAAR-1234"          # actually encrypted
    assert crypto.decrypt(token) == "AADHAAR-1234"


def test_decrypt_tampered_is_safe():
    assert crypto.decrypt("not-a-valid-token") == "[decryption error]"
    assert crypto.decrypt("") == ""


# ── risk engine ────────────────────────────────────────────────────────────────
def test_unknown_user_is_suspicious():
    r = risk_engine.compute_login_risk(False, False, 0)
    assert r["score"] >= 40 and r["status"] in ("Suspicious", "Critical")


def test_repeated_failures_lock():
    r = risk_engine.compute_login_risk(True, False, 4)
    assert r["score"] == 95 and r["status"] == "Critical"


def test_honeypot_access_is_critical():
    r = risk_engine.compute_access_risk(0, is_honeypot=True)
    assert r["score"] == 98 and r["status"] == "Critical"


# ── honeypot ───────────────────────────────────────────────────────────────────
def test_honeypot_id_detection():
    assert honeypot.is_honeypot_id("TRAP-001")
    assert not honeypot.is_honeypot_id("GUEST-202401")


# ── mfa ────────────────────────────────────────────────────────────────────────
def test_totp_roundtrip():
    import pyotp
    secret = mfa.generate_secret()
    code = pyotp.TOTP(secret).now()
    assert mfa.verify_code(secret, code)
    assert not mfa.verify_code(secret, "000000")


# ── anomaly detector ────────────────────────────────────────────────────────────
def test_anomaly_needs_enough_data():
    assert detect_user_anomaly([], "alice")["is_anomaly"] is False


def test_anomaly_flags_rapid_burst():
    # 1 calm baseline view, then a rapid burst in the same second.
    logs = [{"user": "alice", "time": "2026-01-01 10:00:00",
             "activity": "Viewed fragmented guest records"}]
    logs += [{"user": "alice", "time": "2026-01-01 23:59:5%d" % i,
              "activity": "Viewed fragmented guest records"} for i in range(8)]
    result = detect_user_anomaly(logs, "alice")
    assert "is_anomaly" in result and "reason" in result
