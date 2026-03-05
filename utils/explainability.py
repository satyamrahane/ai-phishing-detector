def get_keyword_detection_reason(keywords):
    return f"Suspicious keyword detected: {', '.join(keywords)}"

def get_suspicious_patterns_reason():
    return "Matches known suspicious patterns"
