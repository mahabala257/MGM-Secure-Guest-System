# 🔐 MGM Secure Guest Management Platform

The internal guest-management platform for **MGM Resorts** front-desk,
operations, and security teams. Built around **Zero Trust** principles —
every user and every action is continuously verified, scored for risk, and
logged — it pairs classic web-app security hardening with **AI-based
insider-threat detection** to protect guest data end to end.

---

## 🚀 Key Features

**Authentication & access**
* Risk-based login scoring (off-hours, unknown user, wrong password)
* Brute-force defense: CAPTCHA after 2 fails, auto-lock after 4
* **Multi-factor authentication (TOTP)** — scan a QR into any authenticator app
* Forced first-login password reset + strong-password policy
* Role-based access control (Admin / Staff / Security) with escalation alerts
* 15-minute idle session timeout, hardened session cookies

**Data protection**
* **Fragmented storage** — guests split across 3 collections to limit breach impact
* **Encryption at rest (Fernet)** for the sensitive ID-proof collection
* PII masking for the Staff role

**Threat detection & monitoring**
* 🤖 **Isolation Forest** insider-threat detection on access behavior
* 🪤 Honeypot trap record — access freezes the session and locks the account
* Mass-extraction watch (≥5 record views) and full audit log (IP + user-agent)
* Live Security Operations dashboard

**Application hardening**
* CSRF protection on every form (Flask-WTF)
* Rate limiting on auth endpoints (Flask-Limiter)
* Server-side input validation / NoSQL-injection guards
* Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)

---

## 🛠 Tech Stack

| Layer        | Technology                                   |
| ------------ | -------------------------------------------- |
| Backend      | Python · Flask                               |
| Database     | MongoDB                                       |
| Frontend     | HTML · CSS · Jinja2                           |
| ML / AI      | scikit-learn (Isolation Forest)              |
| Security     | Flask-WTF · Flask-Limiter · pyotp · cryptography |
| Tests / Ops  | pytest · mongomock · Docker · gunicorn       |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the layered design,
auth/MFA flow diagram, and data-protection model.

---

## 📂 Project Structure

```
MGM-Secure-Guest-System/
├── app.py                  # Flask app: routes, auth, MFA, RBAC
├── requirements.txt
├── Dockerfile / docker-compose.yml
├── .env.example
│
├── security/
│   ├── risk_engine.py      # centralized risk scoring
│   ├── anomaly_detector.py # Isolation Forest insider-threat detection
│   ├── honeypot.py         # trap-record helpers
│   ├── validators.py       # input validation / injection guards
│   ├── crypto.py           # Fernet encryption at rest
│   └── mfa.py              # TOTP multi-factor authentication
│
├── templates/              # login, dashboards, MFA, guest forms
├── static/style.css
├── tests/                  # pytest suite (units + route integration)
└── docs/ARCHITECTURE.md
```

---

## 📥 Setup

### Option A — Docker (recommended)

```bash
cp .env.example .env          # then fill in the keys below
docker compose up --build
# open http://localhost:8000
```

### Option B — Local

```bash
python -m venv .venv
.venv\Scripts\activate         # Windows  (source .venv/bin/activate on Linux/Mac)
pip install -r requirements.txt

cp .env.example .env           # fill in keys, then:
python app.py                  # http://127.0.0.1:5000
```

Requires a running MongoDB (`mongodb://localhost:27017/` by default).

### Required environment keys

```bash
# Flask session key
python -c "import secrets; print(secrets.token_hex(32))"        # → SECRET_KEY

# Encryption-at-rest key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # → DATA_ENCRYPTION_KEY
```

### Default seed accounts (change on first login)

| Username   | Password         | Role     |
| ---------- | ---------------- | -------- |
| `admin`    | `Admin@12345`    | Admin    |
| `staff`    | `Staff@12345`    | Staff    |
| `security` | `Security@12345` | Security |

On first login each account is forced to change its password and enroll in MFA.

---

## ✅ Testing

```bash
pytest -q
```

29 tests run fully in-memory via **mongomock** — no MongoDB server needed.
They cover the security units (validators, crypto round-trip, risk engine,
TOTP, anomaly detector) and route integration (auth flow, brute-force lock,
RBAC, honeypot, encrypted storage, security headers).

---

## 🎬 Operational walkthrough

1. Log in as `admin`, change the password, scan the QR to enroll MFA.
2. Add a guest — the ID number is stored encrypted in MongoDB.
3. Log in as `staff` and open Guest Records — PII is masked by role.
4. A failed login burst raises a CAPTCHA, then locks the account.
5. Any direct access to a hidden decoy (honeypot) record freezes the
   session and locks the account — surfaced live on the Security dashboard.
6. Every event is recorded with IP, user-agent, and risk score.

---

## 🔮 Future Enhancements

* Email / Telegram push on critical alerts
* Charts for alert trends and risk distribution
* WebAuthn / passkeys as an MFA option
* Centralized rate-limit store (Redis) for multi-instance deploys

---

## 👤 Maintainer

Developed and maintained by **Mahalakshmi B** ([@mahabala257](https://github.com/mahabala257)).
