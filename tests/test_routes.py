"""Integration tests for the Flask routes and auth flow."""


def login_password_stage(app_module, client, username, password):
    """Submit username+password; returns the response (pre-MFA stage)."""
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=False)


def test_home_ok(client):
    assert client.get("/").status_code == 200


def test_protected_routes_redirect_to_login(client):
    for path in ("/admin", "/staff", "/security", "/view_guests",
                 "/register_user", "/add_guest"):
        resp = client.get(path)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_unknown_user_is_blocked_and_alerted(app_module, client):
    resp = login_password_stage(app_module, client, "ghost", "whatever")
    assert resp.status_code == 200
    assert b"Invalid credentials" in resp.data
    assert app_module.alerts.count_documents({"attack_type": "Unknown User Attempt"}) == 1


def test_brute_force_locks_account(app_module, client):
    # Wrong passwords on the seeded admin account. After 2 failures CAPTCHA
    # is required, so we must answer it for subsequent attempts to count
    # toward the lock threshold (4 failures).
    for _ in range(4):
        with client.session_transaction() as sess:
            answer = sess.get("captcha_answer", "")
        client.post("/login", data={"username": "admin", "password": "wrong-pass",
                                    "captcha_answer": answer})
    user = app_module.users.find_one({"username": "admin"})
    assert user["account_locked"] is True
    assert app_module.alerts.count_documents({"action": "Account Locked"}) >= 1


def test_correct_password_routes_to_change_password(app_module, client):
    # Seeded admin must change password on first login (must_change_password).
    resp = login_password_stage(app_module, client, "admin", "Admin@12345")
    assert resp.status_code == 302
    assert "/change_password" in resp.headers["Location"]


def test_full_flow_change_password_then_mfa(app_module, client):
    login_password_stage(app_module, client, "admin", "Admin@12345")
    resp = client.post("/change_password",
                       data={"new_password": "NewPass@123",
                             "confirm_password": "NewPass@123"})
    # After first password change, admin is pushed into MFA enrollment.
    assert resp.status_code == 302
    assert "/mfa_setup" in resp.headers["Location"]
    assert app_module.users.find_one({"username": "admin"})["must_change_password"] is False


def test_weak_password_rejected(app_module, client):
    login_password_stage(app_module, client, "staff", "Staff@12345")
    resp = client.post("/change_password",
                       data={"new_password": "weak", "confirm_password": "weak"})
    assert resp.status_code == 200
    assert b"Password must have" in resp.data


def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in resp.headers


def _fully_authenticate(app_module, client, username, password):
    """Drive a seeded user all the way through change-password + MFA."""
    login_password_stage(app_module, client, username, password)
    client.post("/change_password",
                data={"new_password": "NewPass@123", "confirm_password": "NewPass@123"})
    # GET the setup page so a TOTP secret is generated and stored in session.
    client.get("/mfa_setup")
    # Complete MFA enrollment using the secret stored in the session.
    with client.session_transaction() as sess:
        secret = sess["mfa_setup_secret"]
    import pyotp
    client.post("/mfa_setup", data={"code": pyotp.TOTP(secret).now()})


def test_rbac_staff_cannot_reach_admin(app_module, client):
    _fully_authenticate(app_module, client, "staff", "Staff@12345")
    resp = client.get("/admin")
    assert resp.status_code == 302
    assert "/staff" in resp.headers["Location"]
    assert app_module.alerts.count_documents(
        {"attack_type": "Privilege Escalation Attempt"}) >= 1


def test_admin_cannot_reach_security_dashboard(app_module, client):
    # Strict role separation: admin is blocked from the SOC dashboard.
    _fully_authenticate(app_module, client, "admin", "Admin@12345")
    resp = client.get("/security")
    assert resp.status_code == 302
    assert "/admin" in resp.headers["Location"]
    assert app_module.alerts.count_documents(
        {"attack_type": "Privilege Escalation Attempt"}) >= 1


def test_security_cannot_reach_admin_dashboard(app_module, client):
    _fully_authenticate(app_module, client, "security", "Security@12345")
    resp = client.get("/admin")
    assert resp.status_code == 302
    assert "/security" in resp.headers["Location"]


def test_admin_can_delete_user(app_module, client):
    _fully_authenticate(app_module, client, "admin", "Admin@12345")
    assert app_module.users.find_one({"username": "staff"}) is not None
    client.post("/delete_user", data={"username": "staff"})
    assert app_module.users.find_one({"username": "staff"}) is None
    assert app_module.alerts.count_documents({"action": "Deleted"}) == 1


def test_admin_cannot_delete_self(app_module, client):
    _fully_authenticate(app_module, client, "admin", "Admin@12345")
    client.post("/delete_user", data={"username": "admin"})
    assert app_module.users.find_one({"username": "admin"}) is not None


def test_security_cannot_delete_user(app_module, client):
    _fully_authenticate(app_module, client, "security", "Security@12345")
    resp = client.post("/delete_user", data={"username": "staff"})
    assert resp.status_code == 302  # redirected by RBAC, no delete
    assert app_module.users.find_one({"username": "staff"}) is not None


def test_honeypot_locks_account(app_module, client):
    # Accessing the hidden decoy record directly (enumeration) triggers the trap.
    _fully_authenticate(app_module, client, "admin", "Admin@12345")
    resp = client.get("/guest/TRAP-001")
    assert resp.status_code == 302
    assert app_module.users.find_one({"username": "admin"})["account_locked"] is True
    assert app_module.alerts.count_documents(
        {"attack_type": "Decoy Data Access Detected"}) == 1


def test_guest_detail_for_real_record(app_module, client):
    _fully_authenticate(app_module, client, "admin", "Admin@12345")
    client.post("/add_guest", data={
        "name": "Detail Guy", "phone": "9999999999", "email": "d@x.com",
        "address": "1 Road", "checkin": "2026-01-01", "checkout": "2026-01-02",
        "idproof_type": "Passport", "idproof": "P-123"})
    gid = app_module.guest_basic.find_one({"name": "Detail Guy"})["guest_id"]
    resp = client.get(f"/guest/{gid}")
    assert resp.status_code == 200
    assert b"Detail Guy" in resp.data
    assert b"P-123" in resp.data            # admin sees decrypted ID


def test_added_guest_idproof_is_encrypted(app_module, client):
    _fully_authenticate(app_module, client, "admin", "Admin@12345")
    client.post("/add_guest", data={
        "name": "Jane Doe", "phone": "9999999999", "email": "jane@x.com",
        "address": "1 Road", "checkin": "2026-01-01", "checkout": "2026-01-02",
        "idproof_type": "Aadhaar", "idproof": "AADHAAR-9999"})
    rec = app_module.guest_sensitive.find_one({"idproof": {"$exists": True},
                                               "guest_id": {"$regex": "^GUEST-"}})
    assert rec["idproof"] != "AADHAAR-9999"               # stored encrypted
    assert app_module.crypto.decrypt(rec["idproof"]) == "AADHAAR-9999"
