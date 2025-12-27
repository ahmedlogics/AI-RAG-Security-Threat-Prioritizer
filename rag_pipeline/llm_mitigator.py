import streamlit as st
from transformers import pipeline

# -----------------------------------------------------------------------------
# GLOBAL CACHED FUNCTION
# Defined OUTSIDE the class so Streamlit doesn't try to hash 'self'
# -----------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def load_flan_t5():
    """
    Singleton pattern for the AI Model.
    Loads ONCE and stays in memory globally.
    """
    print("⚡ Loading LLM (Flan-T5)... This happens only once.")
    return pipeline(
        "text-generation",
        model="google/flan-t5-base",
        max_new_tokens=100,
        do_sample=True,
        temperature=0.3,
        repetition_penalty=1.5  # Prevents "Disable password" loops
    )

# -----------------------------------------------------------------------------
# CLASS DEFINITION
# -----------------------------------------------------------------------------
class LLMMitigator:
    """
    Grounded LLM Mitigation Generator.
    Wraps the global cached model.
    """

    def generate_mitigation(self, alert, context):
        """
        Generates a clean, non-repetitive mitigation plan.
        """
        # Call the global cached function
        generator = load_flan_t5()

        # Strict Prompt Engineering
        prompt = f"""
        Task: Summarize security mitigation steps.
        Vulnerability: {context['vuln_name']}
        Official Fix: {context['mitigation']}

        Instructions:
        1. Write 3 short, actionable bullet points.
        2. Do not repeat text.
        3. Be direct.

        Response:
        """

        try:
            # Generate response
            response = generator(prompt)[0]["generated_text"]
            
            # Post-processing cleanup
            clean_steps = self._clean_output(response)
            
            # Fallback if LLM fails
            if not clean_steps:
                clean_steps = f"- {context['mitigation']}"

            return {
                "llm_mitigation": clean_steps,
                "citations": [context["citation"]]
            }
        except Exception as e:
            return {
                "llm_mitigation": f"- Apply standard patch for {context['vuln_name']}.",
                "citations": [context["citation"]]
            }

    def _clean_output(self, text):
        """Parses the raw LLM output into clean Markdown bullets."""
        lines = text.split("\n")
        bullets = []
        
        seen = set()
        for line in lines:
            line = line.strip().replace("- ", "").replace("* ", "")
            if len(line) > 5 and line not in seen:
                bullets.append(f"- {line}")
                seen.add(line)
        
        # Limit to top 3 bullets to save UI space
        return "\n".join(bullets[:3])