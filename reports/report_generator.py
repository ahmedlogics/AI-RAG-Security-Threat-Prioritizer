import json
import os
from datetime import datetime

REPORT_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports')

def export_session_report(history, metrics):
    """
    Saves the mitigation session to a JSON file for compliance.
    """
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)

    report_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"soc_session_{report_id}.json"
    filepath = os.path.join(REPORT_DIR, filename)

    report_data = {
        "timestamp": datetime.now().isoformat(),
        "session_metrics": metrics,
        "mitigated_threats": history
    }

    with open(filepath, 'w') as f:
        json.dump(report_data, f, indent=4)
    
    return filepath