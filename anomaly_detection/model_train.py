import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline

# 1. Simulate "Normal" Traffic Logs (Training Data)
normal_logs = [
    "User admin logged in successfully from 192.168.1.5",
    "GET /index.html HTTP/1.1 200 OK",
    "GET /images/logo.png HTTP/1.1 200 OK",
    "POST /api/login HTTP/1.1 200 OK",
    "System backup completed successfully",
    "Connection established to database server",
    "User sarah updated profile picture",
    "GET /css/style.css HTTP/1.1 200 OK",
    "Scheduled task 'cleanup' ran successfully",
    "User mike logout success"
] * 50  # Repeat to make a dataset

# 2. Build Pipeline (TF-IDF -> Isolation Forest)
# We use Isolation Forest because it's good at finding "outliers" (anomalies)
model = make_pipeline(
    TfidfVectorizer(max_features=100, stop_words='english'),
    IsolationForest(contamination=0.1, random_state=42)
)

print("Training Anomaly Detection Model...")
model.fit(normal_logs)

# 3. Save the Model
joblib.dump(model, "anomaly_model.pkl")
print("✅ Model saved to 'anomaly_detection/anomaly_model.pkl'")