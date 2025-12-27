import time

def compute_live_metrics(alert_history):
    if not alert_history:
        return {
            "response_time": "—",
            "mitigation_count": 0
        }

    times = [
        a["mitigated_at"] - a["created_at"]
        for a in alert_history
    ]

    avg_time = sum(times) / len(times)

    return {
        "response_time": f"{round(avg_time, 2)}s",
        "mitigation_count": len(alert_history)
    }
