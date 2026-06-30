"""
Shared pytest fixtures.

The Flask app opens a real MongoClient at import time, so we patch
pymongo.MongoClient with mongomock *before* importing app. This keeps
the whole suite hermetic — no MongoDB server required.
"""

import os
import importlib
import sys

import mongomock
import pytest

# Deterministic test environment.
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("DATA_ENCRYPTION_KEY", "vD2qvYLH4k_nH0k92dKsUPHxulg0s4szcDOhqgjd44A=")
os.environ.setdefault("MONGO_URI", "mongodb://localhost:27017/")


@pytest.fixture()
def app_module(monkeypatch):
    """Import a fresh app instance backed by an in-memory mongomock DB."""
    monkeypatch.setattr("pymongo.MongoClient", mongomock.MongoClient)

    sys.modules.pop("app", None)
    app_mod = importlib.import_module("app")

    app_mod.app.config["TESTING"] = True
    app_mod.app.config["WTF_CSRF_ENABLED"] = False  # CSRF is exercised separately
    return app_mod


@pytest.fixture()
def client(app_module):
    return app_module.app.test_client()
