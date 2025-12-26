import joblib
import os

# Load model relative to this file
MODEL_PATH = os.path.join(os.path.dirname(__file__), "anomaly_model.pkl")

model = None

def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
    else:
        print("⚠️ Model not found. Run model_train.py first!")

def detect_anomaly(log_text):
    """
    Returns:
        is_anomaly (bool): True if weird, False if normal
        score (float): -1 to 1 (lower is more anomalous in raw sklearn, 
                       but we normalize for UI)
    """
    if model is None:
        load_model()
        if model is None: return False, 0.0

    # IsolationForest prediction: 1 = Normal, -1 = Anomaly
    prediction = model.predict([log_text])[0]
    
    # Decision function: average anomaly score
    raw_score = model.decision_function([log_text])[0]
    
    is_anomaly = prediction == -1
    
    # Normalize score for display (0 to 100 risk)
    # raw_score is usually around -0.2 (bad) to 0.2 (good)
    risk_score = 100 if is_anomaly else max(0, 100 - (raw_score + 0.2) * 200)
    
    return is_anomaly, min(risk_score, 100)