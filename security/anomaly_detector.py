import pandas as pd
from sklearn.ensemble import IsolationForest


def detect_user_anomaly(access_logs, username):
    if len(access_logs) < 5:
        return {
            "is_anomaly": False,
            "score": 0,
            "reason": "Not enough data for ML analysis"
        }

    user_data = []

    for log in access_logs:
        if log.get("user") == username:
            activity = log.get("activity", "")
            hour = 12

            if "time" in log:
                try:
                    hour = int(log["time"].split(" ")[1].split(":")[0])
                except Exception:
                    hour = 12

            user_data.append({
                "records_viewed": 1,
                "hour": hour,
                "activity_length": len(activity)
            })

    if len(user_data) < 3:
        return {
            "is_anomaly": False,
            "score": 0,
            "reason": "Not enough user-specific behavior data"
        }

    df = pd.DataFrame(user_data)

    # contamination lowered from 0.25 → 0.05 to reduce false positives
    # in low-traffic scenarios where most behavior is legitimate
    model = IsolationForest(
        contamination=0.05,
        random_state=42
    )

    model.fit(df)

    latest_activity = df.tail(1)

    prediction = model.predict(latest_activity)[0]
    score = model.decision_function(latest_activity)[0]

    if prediction == -1:
        return {
            "is_anomaly": True,
            "score": round(abs(score) * 100, 2),
            "reason": "Isolation Forest detected abnormal user behavior"
        }

    return {
        "is_anomaly": False,
        "score": round(abs(score) * 100, 2),
        "reason": "User behavior appears normal"
    }
