import json
import os

REQUIRED_FIELDS = ["id", "description", "mitigation", "severity", "source_url"]

def validate_and_load_kb(filepath):
    """
    Strict validation of the Knowledge Base.
    Prevents 'hallucinations' caused by missing data fields.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Knowledge base missing at {filepath}")

    with open(filepath, 'r') as f:
        data = json.load(f)

    valid_data = []
    for entry in data:
        # 1. Schema Validation
        missing = [field for field in REQUIRED_FIELDS if field not in entry]
        if missing:
            print(f"⚠️ SKIPPING Entry {entry.get('id', 'Unknown')}: Missing {missing}")
            continue
        
        # 2. Logic Validation
        if not entry['description'] or len(entry['description']) < 10:
             print(f"⚠️ SKIPPING Entry {entry['id']}: Description too short/empty.")
             continue
             
        valid_data.append(entry)
        
    print(f"✅ Successfully validated {len(valid_data)} knowledge base entries.")
    return valid_data