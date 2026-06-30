"""
manage.py — small operational CLI for the MGM Secure Guest System.

Useful during demos/development when an account gets locked (e.g. by the
honeypot trap) and no other admin is available to unlock it via the UI.

Usage:
    python manage.py unlock <username>      # clear lock + failed attempts
    python manage.py reset-mfa <username>   # force MFA re-enrollment
    python manage.py list                   # show all accounts + status
"""

import os
import sys

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
db = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))[
    "mgm_secure_guest_system"
]
users = db["users"]


def unlock(username):
    r = users.update_one(
        {"username": username},
        {"$set": {"account_locked": False, "failed_attempts": 0,
                  "captcha_required": False}},
    )
    print(f"Unlocked '{username}'." if r.matched_count else f"No such user '{username}'.")


def reset_mfa(username):
    r = users.update_one(
        {"username": username},
        {"$set": {"mfa_enabled": False, "mfa_secret": None}},
    )
    print(f"MFA reset for '{username}'." if r.matched_count else f"No such user '{username}'.")


def list_users():
    for u in users.find():
        flags = []
        if u.get("account_locked"):
            flags.append("LOCKED")
        if u.get("must_change_password"):
            flags.append("must-change-pw")
        flags.append("mfa:on" if u.get("mfa_enabled") else "mfa:off")
        print(f"  {u['username']:<12} {u['role']:<9} {', '.join(flags)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "list":
        list_users()
    elif cmd == "unlock" and len(sys.argv) == 3:
        unlock(sys.argv[2])
    elif cmd == "reset-mfa" and len(sys.argv) == 3:
        reset_mfa(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)
