"""
risk_engine.py — Centralised risk-score calculation.

All risk decisions in the app flow through compute_login_risk() and
compute_access_risk() so scoring rules live in one place and are easy
to tune or audit.
"""

from datetime import datetime


# ── Constants ──────────────────────────────────────────────────────────────────

RISK_OFFHOUR_LOGIN = 20       # login between 22:00 – 05:00
RISK_UNKNOWN_USER  = 40       # username not found in DB
RISK_WRONG_PASSWORD = 30      # password mismatch
RISK_CAPTCHA_FAIL  = 75       # CAPTCHA challenge failed
RISK_ACCOUNT_LOCK  = 95       # account locked after repeated failures
RISK_HONEYPOT      = 98       # honeypot record accessed
RISK_MASS_ACCESS   = 85       # excessive guest-record views
RISK_AI_ANOMALY    = 88       # Isolation Forest flagged the session


def compute_login_risk(username_exists: bool, password_correct: bool, failed_attempts: int) -> dict:
    """
    Compute a risk score for a single login attempt.

    Returns a dict with:
        score   – integer 0-100
        status  – "Safe" | "Suspicious" | "Critical"
        reasons – list of contributing factor strings
    """
    score = 0
    reasons = []

    current_hour = datetime.now().hour
    if current_hour >= 22 or current_hour <= 5:
        score += RISK_OFFHOUR_LOGIN
        reasons.append("Off-hours login attempt")

    if not username_exists:
        score += RISK_UNKNOWN_USER
        reasons.append("Unknown username")

    elif not password_correct:
        score += RISK_WRONG_PASSWORD
        reasons.append("Wrong password")

        if failed_attempts >= 4:
            score = RISK_ACCOUNT_LOCK
            reasons.append("Repeated failures — account locked")

    score = min(score, 100)

    if score >= 80:
        status = "Critical"
    elif score >= 40:
        status = "Suspicious"
    else:
        status = "Safe"

    return {"score": score, "status": status, "reasons": reasons}


def compute_access_risk(access_count: int, is_honeypot: bool = False, is_ai_anomaly: bool = False) -> dict:
    """
    Compute a risk score for a guest-record access event.

    Returns a dict with:
        score   – integer 0-100
        status  – "Safe" | "Suspicious" | "Critical"
        reasons – list of contributing factor strings
    """
    score = 0
    reasons = []

    if is_honeypot:
        score = RISK_HONEYPOT
        reasons.append("Honeypot trap record accessed")

    if is_ai_anomaly:
        score = max(score, RISK_AI_ANOMALY)
        reasons.append("AI Isolation Forest anomaly detected")

    if access_count >= 5:
        score = max(score, RISK_MASS_ACCESS)
        reasons.append(f"Excessive access count: {access_count}")

    score = min(score, 100)

    if score >= 80:
        status = "Critical"
    elif score >= 40:
        status = "Suspicious"
    else:
        status = "Safe"

    return {"score": score, "status": status, "reasons": reasons}
