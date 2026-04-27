import os
from flask import Flask, render_template, request, redirect, session
from datetime import datetime, timedelta
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from security.anomaly_detector import detect_user_anomaly
from dotenv import load_dotenv
import re
import random
import string

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-dev-secret-change-in-production")

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

SESSION_TIMEOUT_MINUTES = 15


def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_strong_password(password):
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )


def generate_temp_password():
    return "Temp@" + "".join(random.choices(string.ascii_letters + string.digits, k=6)) + "9"


def create_alert(username, message, risk, attack_type="Security Event", action="Logged"):
    alerts.insert_one({
        "user": username,
        "message": message,
        "attack_type": attack_type,
        "risk": risk,
        "action": action,
        "time": current_time()
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
            create_alert(
                session.get("user", "unknown"),
                "Session expired due to inactivity",
                40,
                "Session Timeout",
                "Auto Logout"
            )
            session.clear()
            return False

    session["last_activity"] = current_time()
    return True


def role_required(allowed_roles):
    if not require_login():
        return redirect("/login")

    if session.get("role") not in allowed_roles:
        username = session.get("user", "unknown")
        create_alert(
            username,
            f"Unauthorized access attempt to {request.path}",
            90,
            "Privilege Escalation Attempt",
            "Redirected"
        )

        if session.get("role") == "staff":
            return redirect("/staff")
        if session.get("role") == "security":
            return redirect("/security")
        return redirect("/admin")

    return None


# ── Seed default users on first run ──────────────────────────────────────────
if users.count_documents({}) == 0:
    users.insert_many([
        {
            "username": "admin",
            "password_hash": generate_password_hash(
                os.environ.get("ADMIN_DEFAULT_PASSWORD", "Admin@12345")
            ),
            "role": "admin",
            "must_change_password": True,
            "failed_attempts": 0,
            "captcha_required": False,
            "account_locked": False,
            "created_at": current_time()
        },
        {
            "username": "staff",
            "password_hash": generate_password_hash(
                os.environ.get("STAFF_DEFAULT_PASSWORD", "Staff@12345")
            ),
            "role": "staff",
            "must_change_password": True,
            "failed_attempts": 0,
            "captcha_required": False,
            "account_locked": False,
            "created_at": current_time()
        },
        {
            "username": "security",
            "password_hash": generate_password_hash(
                os.environ.get("SECURITY_DEFAULT_PASSWORD", "Security@12345")
            ),
            "role": "security",
            "must_change_password": True,
            "failed_attempts": 0,
            "captcha_required": False,
            "account_locked": False,
            "created_at": current_time()
        }
    ])

# ── Seed honeypot trap record on first run ────────────────────────────────────
if guest_basic.count_documents({"honeypot": True}) == 0:
    trap_id = "TRAP-001"

    guest_basic.insert_one({
        "guest_id": trap_id,
        "name": "Security Trap Guest",
        "checkin": "N/A",
        "checkout": "N/A",
        "created_by": "system",
        "honeypot": True
    })

    guest_contact.insert_one({
        "guest_id": trap_id,
        "phone": "9999999999",
        "email": "trap@hotel.com",
        "address": "Restricted Zone"
    })

    guest_sensitive.insert_one({
        "guest_id": trap_id,
        "idproof": "TRAP-ID-001"
    })


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    captcha_question = session.get("captcha_question", "")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        risk_score = 0
        status = "Safe"
        message = "Normal login"

        current_hour = datetime.now().hour
        if current_hour >= 22 or current_hour <= 5:
            risk_score += 20
            message = "Abnormal login time"

        user = users.find_one({"username": username})

        if not user:
            risk_score += 40
            status = "Suspicious"
            message = "Unknown username login attempt"

            create_alert(username, message, risk_score, "Unknown User Attempt", "Blocked")

            login_logs.insert_one({
                "username": username,
                "status": status,
                "risk": risk_score,
                "time": current_time()
            })

            return render_template("login.html", error="Invalid username", captcha_question=captcha_question)

        if user.get("account_locked"):
            create_alert(username, "Blocked login attempt on locked account", 95, "Locked Account Access", "Blocked")
            return render_template("login.html", error="Account locked. Contact Admin/Security.", captcha_question=captcha_question)

        if user.get("captcha_required"):
            captcha_answer = request.form.get("captcha_answer", "")
            if str(captcha_answer) != str(session.get("captcha_answer")):
                create_alert(username, "CAPTCHA failed during login", 75, "Bot-like Activity", "Blocked")
                return render_template("login.html", error="CAPTCHA failed", captcha_question=captcha_question)

        if not check_password_hash(user["password_hash"], password):
            failed_attempts = user.get("failed_attempts", 0) + 1
            risk_score += 30
            status = "Suspicious"
            message = "Wrong password attempt"
            action = "Warning"

            update_data = {"failed_attempts": failed_attempts}

            if failed_attempts >= 2:
                a = random.randint(1, 9)
                b = random.randint(1, 9)
                session["captcha_question"] = f"{a} + {b}"
                session["captcha_answer"] = a + b
                update_data["captcha_required"] = True
                action = "CAPTCHA Required"

            if failed_attempts >= 4:
                update_data["account_locked"] = True
                message = "Account locked after repeated failed login attempts"
                risk_score = 95
                action = "Account Locked"

            users.update_one({"username": username}, {"$set": update_data})

            create_alert(username, message, risk_score, "Brute Force Attempt", action)

            login_logs.insert_one({
                "username": username,
                "status": status,
                "risk": risk_score,
                "time": current_time()
            })

            return render_template("login.html", error="Invalid password", captcha_question=session.get("captcha_question", ""))

        users.update_one(
            {"username": username},
            {
                "$set": {
                    "failed_attempts": 0,
                    "captcha_required": False,
                    "last_login": current_time()
                }
            }
        )

        login_logs.insert_one({
            "username": username,
            "status": status,
            "risk": risk_score,
            "time": current_time()
        })

        session["user"] = username
        session["role"] = user["role"]
        session["last_activity"] = current_time()
        session.pop("captcha_question", None)
        session.pop("captcha_answer", None)

        if user.get("must_change_password"):
            return redirect("/change_password")

        return redirect_by_role(user["role"])

    return render_template("login.html", captcha_question=captcha_question)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if not require_login():
        return redirect("/login")

    if request.method == "POST":
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if new_password != confirm_password:
            return render_template("change_password.html", error="Passwords do not match")

        if not is_strong_password(new_password):
            return render_template(
                "change_password.html",
                error="Password must have 8+ characters, uppercase, lowercase, number and special character."
            )

        users.update_one(
            {"username": session["user"]},
            {
                "$set": {
                    "password_hash": generate_password_hash(new_password),
                    "must_change_password": False,
                    "password_changed_at": current_time()
                }
            }
        )

        create_alert(session["user"], "User changed temporary password successfully", 10, "Password Reset", "Allowed")
        return redirect_by_role(session["role"])

    return render_template("change_password.html")


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
    check = role_required(["admin", "security"])
    if check:
        return check

    all_alerts = list(alerts.find().sort("_id", -1))

    total_alerts = len(all_alerts)
    honeypot_alerts = len([a for a in all_alerts if "Honeypot" in a.get("message", "")])
    high_risk = len([a for a in all_alerts if a.get("risk", 0) >= 80])
    brute_force = len([a for a in all_alerts if a.get("attack_type") == "Brute Force Attempt"])
    ai_alerts = len([a for a in all_alerts if a.get("attack_type") == "AI Isolation Forest Anomaly"])

    return render_template(
        "security_dashboard.html",
        alerts=all_alerts,
        total_alerts=total_alerts,
        honeypot_alerts=honeypot_alerts,
        high_risk=high_risk,
        brute_force=brute_force,
        ai_alerts=ai_alerts
    )


@app.route("/register_user", methods=["GET", "POST"])
def register_user():
    check = role_required(["admin", "security"])
    if check:
        return check

    generated_password = None

    if request.method == "POST":
        username = request.form["username"]
        role = request.form["role"]

        if users.find_one({"username": username}):
            return render_template("register_user.html", error="Username already exists")

        temp_password = generate_temp_password()

        users.insert_one({
            "username": username,
            "password_hash": generate_password_hash(temp_password),
            "role": role,
            "must_change_password": True,
            "failed_attempts": 0,
            "captcha_required": False,
            "account_locked": False,
            "created_by": session["user"],
            "created_at": current_time()
        })

        create_alert(session["user"], f"New {role} account created: {username}", 20, "User Provisioning", "Allowed")
        generated_password = temp_password

    return render_template("register_user.html", generated_password=generated_password)


@app.route("/unlock_user", methods=["GET", "POST"])
def unlock_user():
    check = role_required(["admin", "security"])
    if check:
        return check

    all_users = list(users.find())

    if request.method == "POST":
        username = request.form["username"]

        users.update_one(
            {"username": username},
            {
                "$set": {
                    "account_locked": False,
                    "failed_attempts": 0,
                    "captcha_required": False
                }
            }
        )

        create_alert(session["user"], f"Unlocked user account: {username}", 30, "Account Recovery", "Unlocked")
        return redirect("/unlock_user")

    return render_template("unlock_user.html", users=all_users)


@app.route("/add_guest", methods=["GET", "POST"])
def add_guest():
    check = role_required(["admin", "staff"])
    if check:
        return check

    if request.method == "POST":
        guest_id = "GUEST-" + datetime.now().strftime("%Y%m%d%H%M%S")

        guest_basic.insert_one({
            "guest_id": guest_id,
            "name": request.form["name"],
            "checkin": request.form["checkin"],
            "checkout": request.form["checkout"],
            "created_by": session["user"],
            "honeypot": False
        })

        guest_contact.insert_one({
            "guest_id": guest_id,
            "phone": request.form["phone"],
            "email": request.form["email"],
            "address": request.form["address"]
        })

        guest_sensitive.insert_one({
            "guest_id": guest_id,
            "idproof": request.form["idproof"]
        })

        create_alert(session["user"], f"Guest record added using fragmented storage: {guest_id}", 10, "Data Entry", "Allowed")
        return redirect("/view_guests")

    return render_template("add_guest.html")


@app.route("/view_guests")
def view_guests():
    check = role_required(["admin", "staff", "security"])
    if check:
        return check

    username = session["user"]
    role = session["role"]

    access_logs.insert_one({
        "user": username,
        "activity": "Viewed fragmented guest records",
        "time": current_time()
    })

    all_access_logs = list(access_logs.find())
    ml_result = detect_user_anomaly(all_access_logs, username)

    if ml_result["is_anomaly"]:
        create_alert(
            username,
            ml_result["reason"],
            88,
            "AI Isolation Forest Anomaly",
            "ML Alert Generated"
        )

    access_count = access_logs.count_documents({
        "user": username,
        "activity": "Viewed fragmented guest records"
    })

    if access_count >= 5:
        create_alert(
            username,
            "AI Insider Threat Detection: Excessive fragmented guest data access",
            85,
            "Mass Data Extraction Suspicion",
            "Monitored"
        )

    simulate_attack = request.args.get("simulate_attack")

    if simulate_attack == "honeypot":
        create_alert(
            username,
            "Honeypot Alert: Fragmented trap guest record accessed",
            98,
            "Decoy Data Access Detected",
            "Session Frozen + Account Locked"
        )

        users.update_one({"username": username}, {"$set": {"account_locked": True}})
        session.clear()
        return redirect("/login")

    all_basic = list(guest_basic.find({"honeypot": {"$ne": True}}))
    final_guests = []

    for basic in all_basic:
        gid = basic["guest_id"]
        contact = guest_contact.find_one({"guest_id": gid})
        sensitive = guest_sensitive.find_one({"guest_id": gid})

        phone = contact.get("phone", "") if contact else ""
        email = contact.get("email", "") if contact else ""
        idproof = sensitive.get("idproof", "") if sensitive else ""

        if role == "staff":
            phone = mask_value(phone)
            email = email[:2] + "****" + email[email.find("@"):] if "@" in email else mask_value(email)
            idproof = mask_value(idproof)

        final_guests.append({
            "name": basic.get("name", ""),
            "phone": phone,
            "email": email,
            "checkin": basic.get("checkin", ""),
            "checkout": basic.get("checkout", ""),
            "created_by": basic.get("created_by", ""),
            "idproof": idproof
        })

    return render_template("view_guests.html", guests=final_guests)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    # debug=False for production safety
    app.run(debug=False)
