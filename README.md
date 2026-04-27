# 🔐 MGM Secure Guest System

## 📌 Overview

The **MGM Secure Guest System** is an advanced and security-focused guest management platform designed for modern hospitality environments.
It enhances traditional systems by integrating **Zero Trust Architecture**, **Artificial Intelligence**, and **real-time security monitoring** to protect sensitive guest data.

Unlike conventional systems, this project follows a **security-first approach**, ensuring every user and action is continuously verified.

---

## 🚀 Key Features

* 🔐 **Zero Trust Security Model** – “Never trust, always verify”
* 👥 **Role-Based Access Control (RBAC)** – Admin, Staff, Security roles
* 🤖 **AI-Based Anomaly Detection** – Using Isolation Forest algorithm
* 🪤 **Honeypot Mechanism** – Detects malicious access attempts
* 📊 **Risk Scoring System** – Classifies threats (Low / Medium / High)
* 📜 **Activity Logging & Monitoring** – Tracks all user actions
* 🔔 **Real-Time Alerts** – Instant notification for suspicious behavior
* 🔑 **Secure Authentication**

  * CAPTCHA verification
  * Session timeout management
* 🗂 **Fragmented Data Storage** – Prevents full data exposure

---

## 🛠 Tech Stack

| Layer    | Technology Used                 |
| -------- | ------------------------------- |
| Backend  | Python (Flask)                  |
| Database | MongoDB                         |
| Frontend | HTML, CSS, Jinja2               |
| ML/AI    | Scikit-learn (Isolation Forest) |
| Tools    | VS Code, Git                    |

---

## 🧠 System Architecture

The system follows a **layered architecture**:

1. **User Layer** – Admin, Staff, Security
2. **Frontend Layer** – UI for interaction
3. **Backend Layer (Flask)** – Core logic & APIs
4. **Database Layer (MongoDB)** – Fragmented secure storage
5. **Security Layer** –

   * Anomaly Detection
   * Honeypot
   * Risk Engine
   * Alert System

---

## ⚙️ How It Works

1. User logs in with secure authentication
2. System verifies identity using Zero Trust principles
3. User actions are continuously logged
4. AI model analyzes behavior patterns
5. Suspicious activity is:

   * Detected
   * Assigned a risk score
   * Triggered as an alert

---

## 📂 Project Structure

```
MGM-Secure-Guest-System/
│
├── .gitignore
├── app.py
├── README.md
├── requirements.txt
├── TODO.md
│
├── security/
│   ├── __init__.py
│   ├── anomaly_detector.py
│   ├── honeypot.py
│   └── risk_engine.py
│
├── static/
│   └── style.css
│
└── templates/
    ├── add_guest.html
    ├── admin_dashboard.html
    ├── change_password.html
    ├── index.html
    ├── login.html
    ├── register_user.html
    ├── security_dashboard.html
    ├── staff_dashboard.html
    ├── unlock_user.html
    └── view_guests.html
```

---

## 📥 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/mahabala257/MGM-Secure-Guest-System.git
cd MGM-Secure-Guest-System
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

---

## 📊 Results

* ✅ Successfully detects abnormal user behavior
* ✅ Prevents unauthorized access
* ✅ Generates real-time alerts
* ✅ Improves overall system security
* ✅ Efficient performance with minimal delay

---

## 🔮 Future Enhancements

* 🔐 Multi-Factor Authentication (MFA)
* 📈 Advanced analytics dashboard
* ☁️ Cloud deployment support
* 🤖 Deep learning-based anomaly detection
* 🔄 Automated threat response system

---

## 📄 Project Report

Detailed documentation is available in:
📎 **lab-report M&M.docx**

---


## ⭐ Acknowledgment

This project is inspired by modern cybersecurity practices including:

* Zero Trust Architecture
* AI-based threat detection
* Secure system design principles

---

## 👨‍💻 Author

**Mahalakshmi B (mahabala257)**

* 💡 Domains: Data Analytics | NLP | ML | DL | Full Stack
* 📌 Built as part of academic project & cybersecurity research

---
