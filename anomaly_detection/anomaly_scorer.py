class AnomalyScorer:
    """
    Deterministic Heuristic Engine.
    Separates 'Detection' logic from 'UI' logic.
    """
    def __init__(self):
        # Explainable Rules (Judge-friendly)
        self.signatures = {
            "jndi": ("Critical", 95),
            "ldap": ("Critical", 90),
            "union select": ("High", 85),
            "or 1=1": ("High", 80),
            "passwd": ("High", 75),
            "script": ("Medium", 65),
            "alert(": ("Medium", 60),
            "admin": ("Low", 40)
        }

    def analyze(self, log_text):
        log_lower = log_text.lower()
        max_score = 10
        severity = "Low"
        detected_patterns = []

        for pattern, (sev, score) in self.signatures.items():
            if pattern in log_lower:
                if score > max_score:
                    max_score = score
                    severity = sev
                detected_patterns.append(pattern)

        return {
            "score": max_score,
            "severity": severity,
            "patterns": detected_patterns
        }