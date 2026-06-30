"""
anomaly_detector.py — Unsupervised insider-threat detection.

Uses an Isolation Forest over per-access behavioural features to flag
sessions that deviate from a user's normal pattern. Unlike the earlier
version (which fed a constant records_viewed=1), the features here carry
real signal:

  * hour              – when the access happened (odd-hour activity)
  * access_index      – running count of this user's views (escalation)
  * seconds_since_prev – gap to the previous view (rapid bursts / scraping)

The latest event is scored against the user's own history, so a sudden
burst of views or activity at an unusual hour stands out.
"""

import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest

_TIME_FMT = "%Y-%m-%d %H:%M:%S"


def _parse_time(value):
    try:
        return datetime.strptime(value, _TIME_FMT)
    except Exception:
        return None


def _build_features(access_logs, username):
    """Turn this user's raw access logs into an ordered feature frame."""
    events = [log for log in access_logs if log.get("user") == username]
    events.sort(key=lambda e: e.get("time", ""))

    rows = []
    prev_dt = None
    for i, log in enumerate(events):
        dt = _parse_time(log.get("time", ""))
        hour = dt.hour if dt else 12

        if dt and prev_dt:
            gap = max(0, (dt - prev_dt).total_seconds())
        else:
            gap = 3600  # assume a calm 1h gap for the first event
        prev_dt = dt or prev_dt

        rows.append({
            "hour": hour,
            "access_index": i + 1,
            "seconds_since_prev": min(gap, 86400),  # cap at 1 day
        })

    return pd.DataFrame(rows)


def detect_user_anomaly(access_logs, username):
    """
    Return {is_anomaly, score, reason} for the user's most recent access.

    Falls back to a safe (non-anomalous) verdict when there is not yet
    enough history to model the user reliably.
    """
    if len(access_logs) < 5:
        return {"is_anomaly": False, "score": 0,
                "reason": "Not enough data for ML analysis"}

    df = _build_features(access_logs, username)

    if len(df) < 4:
        return {"is_anomaly": False, "score": 0,
                "reason": "Not enough user-specific behavior data"}

    # contamination=0.1: expect ~10% of historical points to look unusual,
    # which keeps false positives low in mostly-legitimate traffic.
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(df)

    latest = df.tail(1)
    prediction = model.predict(latest)[0]
    score = round(abs(model.decision_function(latest)[0]) * 100, 2)

    if prediction == -1:
        gap = latest.iloc[0]["seconds_since_prev"]
        hour = int(latest.iloc[0]["hour"])
        if gap < 10:
            reason = "Isolation Forest: rapid burst of guest-record access"
        elif hour >= 22 or hour <= 5:
            reason = "Isolation Forest: abnormal off-hours access pattern"
        else:
            reason = "Isolation Forest detected abnormal user behavior"
        return {"is_anomaly": True, "score": score, "reason": reason}

    return {"is_anomaly": False, "score": score,
            "reason": "User behavior appears normal"}
