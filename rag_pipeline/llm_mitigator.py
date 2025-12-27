from transformers import pipeline

class LLMMitigator:
    """
    Grounded LLM Mitigation Generator
    NO hallucinations. NO creativity.
    """

    def __init__(self):
        self.llm = pipeline(
            "text-generation",
            model="google/flan-t5-base",
            max_new_tokens=200
        )

    def generate_mitigation(self, alert, context):
        prompt = f"""
You are a SOC security assistant.

ONLY rewrite the mitigation steps below into clear bullet points.
DO NOT add new vulnerabilities.
DO NOT invent new actions.
DO NOT repeat instructions.

Mitigation Text:
{context['mitigation']}
"""

        response = self.llm(prompt)[0]["generated_text"]

        clean_steps = self._clean_output(response)

        return {
            "llm_mitigation": clean_steps,
            "citations": [context["citation"]]
        }

    def _clean_output(self, text):
        lines = text.split("\n")
        bullets = []

        for line in lines:
            line = line.strip()
            if len(line) > 10:
                bullets.append(f"- {line}")

        return "\n".join(bullets)
