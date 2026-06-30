"""
MGM Secure Guest System — Zero Trust guest-management platform.

Security layers, in request order:
  1. Security headers + rate limiting on every request
  2. CSRF protection on every state-changing form
  3. Risk-based, brute-force-aware authentication (risk_engine)
  4. TOTP multi-factor authentication (mfa)
  5. Role-based access control with privilege-escalation alerting
  6. Fragmented + encrypted guest storage (crypto)
  7. Honeypot traps + Isolation Forest insider-threat detection
"""

import os
import random
import string
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, session, abort
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from security.anomaly_detector import detect_user_anomaly
from security import risk_engine, honeypot, mfa, crypto
from security.validators import (
    ValidationError,
    validate_username, validate_role, validate_text, validate_id_type,
    validate_phone, validate_email, is_strong_password,
)

# ── App & config ────────────────────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-dev-secret-change-in-production")

# Harden the session cookie (Zero Trust: assume the network is hostile).
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
)

csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app,
                  default_limits=["200 per hour"])

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["mgm_secure_guest_system"]

users = db["users"]
alerts = db["alerts"]
login_logs = db["login_logs"]
access_logs = db["access_logs"]

guest_basic = db["guest_basic"]
guest_contact = db["guest_contact"]
guest_sensitive = db["guest_sensitive"]

SESSION_TIMEOUT_MINUTES = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30"))

# Roles that must enroll in MFA. Set to ALLOWED_ROLES to enforce everywhere.
MFA_REQUIRED_ROLES = {"admin", "security", "staff"}


# ── Helpers ────────────────────────────────────────────────────────────────
def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def client_ip():
    """Best-effort client IP, honouring a reverse proxy if present."""
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")


def user_agent():
    return request.headers.get("User-Agent", "unknown")[:300]


def generate_temp_password():
    return "Temp@" + "".join(random.choices(string.ascii_letters + string.digits, k=6)) + "9"


def create_alert(username, message, risk, attack_type="Security Event", action="Logged"):
    alerts.insert_one({
        "user": username,
        "message": message,
        "attack_type": attack_type,
        "risk": risk,
        "action": action,
        "ip": client_ip(),
        "user_agent": user_agent(),
        "time": current_time(),
    })


def redirect_by_role(role):
    if role == "admin":
        return redirect("/admin")
    if role == "security":
        return redirect("/security")
    return redirect("/staff")


def mask_value(value):
    if not value:
        return ""
    value = str(value)
    if len(value) <= 4:
        return "XXXX"
    return "X" * (len(value) - 4) + value[-4:]


def require_login():
    if "user" not in session:
        return False

    last_activity = session.get("last_activity")
    if last_activity:
        last_time = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
        if datetime.now() - last_time > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            create_alert(session.get("user", "unknown"),
                         "Session expired due to inactivity", 40,
                         "Session Timeout", "Auto Logout")
            session.clear()
            return False

    session["last_activity"] = current_time()
    return True


def role_required(allowed_roles):
    if not require_login():
        return redirect("/login")

    if session.get("role") not in allowed_roles:
        username = session.get("user", "unknown")
        create_alert(username, f"Unauthorized access attempt to {request.path}",
                     90, "Privilege Escalation Attempt", "Redirected")
        if session.get("role") == "staff":
            return redirect("/staff")
        if session.get("role") == "security":
            return redirect("/security")
        return redirect("/admin")

    return None


def finalize_login(username, role):
    """Promote a pre-auth session to a fully authenticated one."""
    users.update_one({"username": username},
                     {"$set": {"last_login": current_time(), "last_ip": client_ip()}})
    session.pop("pre_auth_user", None)
    session.pop("pre_auth_role", None)
    session.pop("captcha_question", None)
    session.pop("captcha_answer", None)
    session["user"] = username
    session["role"] = role
    session["last_activity"] = current_time()
    return redirect_by_role(role)


# ── Global security headers ──────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'"
    )
    return response


# ── Seed default users on first run ──────────────────────────────────────────
def _seed_user(username, role, env_key, default_pw):
    return {
        "username": username,
        "password_hash": generate_password_hash(os.environ.get(env_key, default_pw)),
        "role": role,
        "must_change_password": True,
        "mfa_enabled": False,
        "mfa_secret": None,
        "failed_attempts": 0,
        "captcha_required": False,
        "account_locked": False,
        "created_at": current_time(),
    }


def seed_data():
    if users.count_documents({}) == 0:
        users.insert_many([
            _seed_user("admin", "admin", "ADMIN_DEFAULT_PASSWORD", "Admin@12345"),
            _seed_user("staff", "staff", "STAFF_DEFAULT_PASSWORD", "Staff@12345"),
            _seed_user("security", "security", "SECURITY_DEFAULT_PASSWORD", "Security@12345"),
        ])

    if guest_basic.count_documents({"honeypot": True}) == 0:
        guest_basic.insert_one(honeypot.get_trap_basic(current_time()))
        guest_contact.insert_one(honeypot.get_trap_contact())
        sensitive = honeypot.get_trap_sensitive()
        sensitive["idproof"] = crypto.encrypt(sensitive["idproof"])
        guest_sensitive.insert_one(sensitive)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    captcha_question = session.get("captcha_question", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = users.find_one({"username": username})
        risk = risk_engine.compute_login_risk(
            username_exists=bool(user),
            password_correct=bool(user) and check_password_hash(user["password_hash"], password),
            failed_attempts=(user.get("failed_attempts", 0) + 1) if user else 0,
        )

        # Unknown user
        if not user:
            create_alert(username or "(blank)", "Unknown username login attempt",
                         risk["score"], "Unknown User Attempt", "Blocked")
            login_logs.insert_one({"username": username, "status": risk["status"],
                                   "risk": risk["score"], "ip": client_ip(),
                                   "time": current_time()})
            return render_template("login.html", error="Invalid credentials",
                                   captcha_question=captcha_question)

        # Locked account
        if user.get("account_locked"):
            create_alert(username, "Blocked login attempt on locked account", 95,
                         "Locked Account Access", "Blocked")
            return render_template("login.html",
                                   error="Account locked. Contact Admin/Security.",
                                   captcha_question=captcha_question)

        # CAPTCHA gate
        if user.get("captcha_required"):
            if str(request.form.get("captcha_answer", "")) != str(session.get("captcha_answer")):
                create_alert(username, "CAPTCHA failed during login", 75,
                             "Bot-like Activity", "Blocked")
                return render_template("login.html", error="CAPTCHA failed",
                                       captcha_question=captcha_question)

        # Wrong password → escalate
        if not check_password_hash(user["password_hash"], password):
            failed_attempts = user.get("failed_attempts", 0) + 1
            update_data = {"failed_attempts": failed_attempts}
            action, message, score = "Warning", "Wrong password attempt", risk["score"]

            if failed_attempts >= 2:
                a, b = random.randint(1, 9), random.randint(1, 9)
                session["captcha_question"] = f"{a} + {b}"
                session["captcha_answer"] = a + b
                update_data["captcha_required"] = True
                action = "CAPTCHA Required"

            if failed_attempts >= 4:
                update_data["account_locked"] = True
                message = "Account locked after repeated failed login attempts"
                score, action = 95, "Account Locked"

            users.update_one({"username": username}, {"$set": update_data})
            create_alert(username, message, score, "Brute Force Attempt", action)
            login_logs.insert_one({"username": username, "status": "Suspicious",
                                   "risk": score, "ip": client_ip(),
                                   "time": current_time()})
            return render_template("login.html", error="Invalid credentials",
                                   captcha_question=session.get("captcha_question", ""))

        # Password OK → reset counters, log, move to pre-auth stage
        users.update_one({"username": username},
                         {"$set": {"failed_attempts": 0, "captcha_required": False}})
        login_logs.insert_one({"username": username, "status": risk["status"],
                               "risk": risk["score"], "ip": client_ip(),
                               "time": current_time()})

        session.clear()
        session["pre_auth_user"] = username
        session["pre_auth_role"] = user["role"]

        if user.get("must_change_password"):
            return redirect("/change_password")
        if not user.get("mfa_enabled") and user["role"] in MFA_REQUIRED_ROLES:
            return redirect("/mfa_setup")
        if user.get("mfa_enabled"):
            return redirect("/mfa_verify")
        return finalize_login(username, user["role"])

    return render_template("login.html", captcha_question=captcha_question)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    pre = session.get("pre_auth_user")
    if not pre and not require_login():
        return redirect("/login")
    username = pre or session["user"]

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            return render_template("change_password.html", error="Passwords do not match")
        if not is_strong_password(new_password):
            return render_template("change_password.html",
                error="Password must have 8+ characters, uppercase, lowercase, number and special character.")

        users.update_one({"username": username},
                         {"$set": {"password_hash": generate_password_hash(new_password),
                                   "must_change_password": False,
                                   "password_changed_at": current_time()}})
        create_alert(username, "User changed temporary password successfully", 10,
                     "Password Reset", "Allowed")

        user = users.find_one({"username": username})
        if pre:  # still in login flow → continue to MFA / dashboard
            if not user.get("mfa_enabled") and user["role"] in MFA_REQUIRED_ROLES:
                return redirect("/mfa_setup")
            return finalize_login(username, user["role"])
        return redirect_by_role(session["role"])

    return render_template("change_password.html")


@app.route("/mfa_setup", methods=["GET", "POST"])
def mfa_setup():
    username = session.get("pre_auth_user")
    role = session.get("pre_auth_role")
    if not username:
        return redirect("/login")

    secret = session.get("mfa_setup_secret") or mfa.generate_secret()
    session["mfa_setup_secret"] = secret

    if request.method == "POST":
        code = request.form.get("code", "")
        if mfa.verify_code(secret, code):
            # Store the TOTP secret encrypted at rest (Fernet), so a DB dump
            # cannot be used to reproduce a user's authenticator codes.
            users.update_one({"username": username},
                             {"$set": {"mfa_enabled": True,
                                       "mfa_secret": crypto.encrypt(secret)}})
            session.pop("mfa_setup_secret", None)
            create_alert(username, "MFA (TOTP) enrolled successfully", 10,
                         "MFA Enrollment", "Allowed")
            return finalize_login(username, role)
        return render_template("mfa_setup.html",
                               qr=mfa.qr_data_uri(username, secret),
                               secret=secret, error="Invalid code, try again")

    return render_template("mfa_setup.html",
                           qr=mfa.qr_data_uri(username, secret), secret=secret)


@app.route("/mfa_verify", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def mfa_verify():
    username = session.get("pre_auth_user")
    role = session.get("pre_auth_role")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        user = users.find_one({"username": username})
        stored_secret = crypto.decrypt(user.get("mfa_secret", "")) if user else ""
        if user and mfa.verify_code(stored_secret, request.form.get("code", "")):
            return finalize_login(username, role)
        create_alert(username, "Failed MFA verification", 70,
                     "MFA Challenge Failed", "Blocked")
        return render_template("mfa_verify.html", error="Invalid authentication code")

    return render_template("mfa_verify.html")


@app.route("/dashboard")
def dashboard():
    # Role-neutral "Home" link: sends each user to their own dashboard so
    # shared pages never link a user toward a panel they can't access.
    if not require_login():
        return redirect("/login")
    return redirect_by_role(session["role"])


@app.route("/admin")
def admin():
    check = role_required(["admin"])
    if check:
        return check
    return render_template("admin_dashboard.html")


@app.route("/staff")
def staff():
    check = role_required(["staff"])
    if check:
        return check
    return render_template("staff_dashboard.html")


@app.route("/security")
def security():
    # Strict separation: only the security role may open the SOC dashboard.
    check = role_required(["security"])
    if check:
        return check

    all_alerts = list(alerts.find().sort("_id", -1))
    return render_template(
        "security_dashboard.html",
        alerts=all_alerts,
        total_alerts=len(all_alerts),
        honeypot_alerts=len([a for a in all_alerts if "Honeypot" in a.get("message", "")]),
        high_risk=len([a for a in all_alerts if a.get("risk", 0) >= 80]),
        brute_force=len([a for a in all_alerts if a.get("attack_type") == "Brute Force Attempt"]),
        ai_alerts=len([a for a in all_alerts if a.get("attack_type") == "AI Isolation Forest Anomaly"]),
    )


@app.route("/register_user", methods=["GET", "POST"])
def register_user():
    check = role_required(["admin", "security"])
    if check:
        return check

    generated_password = None
    if request.method == "POST":
        try:
            username = validate_username(request.form.get("username"))
            role = validate_role(request.form.get("role"))
        except ValidationError as e:
            return render_template("register_user.html", error=str(e))

        if users.find_one({"username": username}):
            return render_template("register_user.html", error="Username already exists")

        temp_password = generate_temp_password()
        users.insert_one({
            "username": username,
            "password_hash": generate_password_hash(temp_password),
            "role": role, "must_change_password": True,
            "mfa_enabled": False, "mfa_secret": None,
            "failed_attempts": 0, "captcha_required": False, "account_locked": False,
            "created_by": session["user"], "created_at": current_time(),
        })
        create_alert(session["user"], f"New {role} account created: {username}", 20,
                     "User Provisioning", "Allowed")
        generated_password = temp_password

    return render_template("register_user.html", generated_password=generated_password)


@app.route("/unlock_user", methods=["GET", "POST"])
def unlock_user():
    check = role_required(["admin", "security"])
    if check:
        return check

    if request.method == "POST":
        try:
            username = validate_username(request.form.get("username"))
        except ValidationError as e:
            return render_template("unlock_user.html", users=list(users.find()), error=str(e))

        users.update_one({"username": username},
                         {"$set": {"account_locked": False, "failed_attempts": 0,
                                   "captcha_required": False}})
        create_alert(session["user"], f"Unlocked user account: {username}", 30,
                     "Account Recovery", "Unlocked")
        return redirect("/unlock_user")

    return render_template("unlock_user.html", users=list(users.find()))


@app.route("/delete_user", methods=["POST"])
def delete_user():
    # Deleting accounts is an admin-only, irreversible action.
    check = role_required(["admin"])
    if check:
        return check

    try:
        username = validate_username(request.form.get("username"))
    except ValidationError:
        return redirect("/unlock_user")

    # Guard rails: never let an admin delete their own account, and keep
    # at least one admin so the system can't be locked out.
    if username == session["user"]:
        create_alert(session["user"], "Blocked attempt to delete own account", 50,
                     "User Deletion", "Blocked")
        return redirect("/unlock_user")

    target = users.find_one({"username": username})
    if target and target.get("role") == "admin" and users.count_documents({"role": "admin"}) <= 1:
        create_alert(session["user"], "Blocked deletion of the last admin account", 50,
                     "User Deletion", "Blocked")
        return redirect("/unlock_user")

    if target:
        users.delete_one({"username": username})
        create_alert(session["user"], f"Deleted user account: {username}", 40,
                     "User Deletion", "Deleted")

    return redirect("/unlock_user")


@app.route("/add_guest", methods=["GET", "POST"])
def add_guest():
    check = role_required(["admin", "staff"])
    if check:
        return check

    if request.method == "POST":
        try:
            name = validate_text(request.form.get("name"), "Name")
            checkin = validate_text(request.form.get("checkin"), "Check-in")
            checkout = validate_text(request.form.get("checkout"), "Check-out")
            phone = validate_phone(request.form.get("phone"))
            email = validate_email(request.form.get("email"))
            address = validate_text(request.form.get("address"), "Address")
            idproof_type = validate_id_type(request.form.get("idproof_type"))
            idproof = validate_text(request.form.get("idproof"), "ID proof")
        except ValidationError as e:
            return render_template("add_guest.html", error=str(e))

        guest_id = "GUEST-" + datetime.now().strftime("%Y%m%d%H%M%S")
        guest_basic.insert_one({"guest_id": guest_id, "name": name, "checkin": checkin,
                                "checkout": checkout, "created_by": session["user"],
                                "honeypot": False})
        guest_contact.insert_one({"guest_id": guest_id, "phone": phone,
                                  "email": email, "address": address})
        # Sensitive ID number is encrypted at rest (Fernet); the ID *type*
        # is not sensitive on its own, so it is stored in clear for display.
        guest_sensitive.insert_one({"guest_id": guest_id,
                                    "idproof_type": idproof_type,
                                    "idproof": crypto.encrypt(idproof)})

        create_alert(session["user"], f"Guest record added using fragmented storage: {guest_id}",
                     10, "Data Entry", "Allowed")
        return redirect("/view_guests")

    return render_template("add_guest.html")


@app.route("/view_guests")
def view_guests():
    check = role_required(["admin", "staff", "security"])
    if check:
        return check

    username = session["user"]
    role = session["role"]

    access_logs.insert_one({"user": username, "activity": "Viewed fragmented guest records",
                            "ip": client_ip(), "time": current_time()})

    ml_result = detect_user_anomaly(list(access_logs.find()), username)
    if ml_result["is_anomaly"]:
        create_alert(username, ml_result["reason"], 88,
                     "AI Isolation Forest Anomaly", "ML Alert Generated")

    access_count = access_logs.count_documents(
        {"user": username, "activity": "Viewed fragmented guest records"})
    if access_count >= 5:
        create_alert(username, "AI Insider Threat Detection: Excessive fragmented guest data access",
                     85, "Mass Data Extraction Suspicion", "Monitored")

    final_guests = []
    for basic in guest_basic.find({"honeypot": {"$ne": True}}):
        gid = basic["guest_id"]
        contact = guest_contact.find_one({"guest_id": gid}) or {}
        sensitive = guest_sensitive.find_one({"guest_id": gid}) or {}

        phone = contact.get("phone", "")
        email = contact.get("email", "")
        idproof_type = sensitive.get("idproof_type", "—")
        idproof = crypto.decrypt(sensitive.get("idproof", ""))  # decrypt at read time

        if role == "staff":  # staff only ever see masked PII
            phone = mask_value(phone)
            email = email[:2] + "****" + email[email.find("@"):] if "@" in email else mask_value(email)
            idproof = mask_value(idproof)

        final_guests.append({
            "guest_id": gid,
            "name": basic.get("name", ""), "phone": phone, "email": email,
            "checkin": basic.get("checkin", ""), "checkout": basic.get("checkout", ""),
            "created_by": basic.get("created_by", ""),
            "idproof_type": idproof_type, "idproof": idproof,
        })

    return render_template("view_guests.html", guests=final_guests)


@app.route("/guest/<guest_id>")
def guest_detail(guest_id):
    check = role_required(["admin", "staff", "security"])
    if check:
        return check

    username = session["user"]
    role = session["role"]

    basic = guest_basic.find_one({"guest_id": guest_id})

    # Honeypot: the trap record is never listed, so any direct access to it
    # means someone enumerated/guessed guest IDs — i.e. an intrusion. Freeze
    # the session and lock the account immediately.
    if honeypot.is_honeypot_id(guest_id) or (basic and basic.get("honeypot")):
        create_alert(username, "Honeypot triggered: decoy guest record accessed", 98,
                     "Decoy Data Access Detected", "Session Frozen + Account Locked")
        users.update_one({"username": username}, {"$set": {"account_locked": True}})
        session.clear()
        return redirect("/login")

    if not basic:
        abort(404)

    contact = guest_contact.find_one({"guest_id": guest_id}) or {}
    sensitive = guest_sensitive.find_one({"guest_id": guest_id}) or {}

    phone = contact.get("phone", "")
    email = contact.get("email", "")
    address = contact.get("address", "")
    idproof = crypto.decrypt(sensitive.get("idproof", ""))

    if role == "staff":
        phone = mask_value(phone)
        email = email[:2] + "****" + email[email.find("@"):] if "@" in email else mask_value(email)
        idproof = mask_value(idproof)

    guest = {
        "guest_id": guest_id, "name": basic.get("name", ""),
        "checkin": basic.get("checkin", ""), "checkout": basic.get("checkout", ""),
        "created_by": basic.get("created_by", ""),
        "phone": phone, "email": email, "address": address,
        "idproof_type": sensitive.get("idproof_type", "—"), "idproof": idproof,
    }
    return render_template("guest_detail.html", guest=guest)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("login.html",
                           error="Too many attempts. Please wait and try again."), 429


# Seed on import so both `python app.py` and the test/WSGI entrypoints work.
try:
    seed_data()
except Exception as exc:  # pragma: no cover - DB may be unavailable at import
    print(f"[seed] skipped: {exc}")


if __name__ == "__main__":
    app.run(debug=False)
