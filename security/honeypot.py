"""
honeypot.py — Honeypot record management utilities.

Provides helpers for seeding trap records and evaluating whether
a guest_id refers to a honeypot entry. The main Flask app calls
these instead of writing honeypot logic inline.
"""

TRAP_GUEST_ID = "TRAP-001"


def is_honeypot_id(guest_id: str) -> bool:
    """Return True if the given guest_id belongs to a honeypot record."""
    return str(guest_id).startswith("TRAP-")


def get_trap_basic(created_at: str) -> dict:
    """Return the seeding document for guest_basic honeypot entry."""
    return {
        "guest_id": TRAP_GUEST_ID,
        "name": "Security Trap Guest",
        "checkin": "N/A",
        "checkout": "N/A",
        "created_by": "system",
        "honeypot": True,
        "created_at": created_at,
    }


def get_trap_contact() -> dict:
    """Return the seeding document for guest_contact honeypot entry."""
    return {
        "guest_id": TRAP_GUEST_ID,
        "phone": "9999999999",
        "email": "trap@hotel.com",
        "address": "Restricted Zone",
    }


def get_trap_sensitive() -> dict:
    """Return the seeding document for guest_sensitive honeypot entry."""
    return {
        "guest_id": TRAP_GUEST_ID,
        "idproof": "TRAP-ID-001",
    }
