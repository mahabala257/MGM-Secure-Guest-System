"""
mfa.py — Time-based One-Time Password (TOTP) multi-factor authentication.

Each user gets a per-account TOTP secret on enrollment. They scan a QR
code into an authenticator app (Google Authenticator, Authy, etc.) and
must enter the 6-digit code after their password — the second factor in
the Zero Trust login flow.
"""

import io
import base64

import pyotp
import qrcode

ISSUER = "MGM Secure Guest System"


def generate_secret() -> str:
    """Create a new random base32 TOTP secret for a user."""
    return pyotp.random_base32()


def provisioning_uri(username: str, secret: str) -> str:
    """otpauth:// URI that authenticator apps understand."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=ISSUER
    )


def qr_data_uri(username: str, secret: str) -> str:
    """
    Render the provisioning URI as a PNG QR code (black on a solid white
    background) and return it as a base64 data URI that drops straight into
    an <img src>. PNG renders reliably in every browser, including on dark
    backgrounds where a transparent SVG can appear blank.
    """
    uri = provisioning_uri(username, secret)
    img = qrcode.make(uri, box_size=8, border=2).convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def verify_code(secret: str, code: str) -> bool:
    """
    Verify a 6-digit TOTP code. valid_window=1 tolerates ~30s of clock
    drift between the server and the user's phone.
    """
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)
    except Exception:
        return False
