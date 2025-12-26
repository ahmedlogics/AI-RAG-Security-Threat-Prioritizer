import json
import os
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
# UPDATED IMPORT: Uses langchain_core
from langchain_core.documents import Document

# Path to the database in the root directory
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "chroma_db")
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "knowledge_base")

def ingest():
    docs = []
    
    # Load CVEs
    print("Loading CVE Data...")
    cve_path = os.path.join(DATA_DIR, "cve_data.json")
    if os.path.exists(cve_path):
        with open(cve_path, "r") as f:
            cves = json.load(f)
            for item in cves:
                content = f"Vulnerability: {item['id']}\nSeverity: {item['severity']}\nDescription: {item['description']}"
                docs.append(Document(page_content=content, metadata={"source": item['id'], "type": "CVE"}))

    # Load MITRE
    print("Loading MITRE Data...")
    mitre_path = os.path.join(DATA_DIR, "mitre_attack.json")
    if os.path.exists(mitre_path):
        with open(mitre_path, "r") as f:
            mitre = json.load(f)
            for item in mitre:
                content = f"Technique: {item['name']} ({item['id']})\nDescription: {item['description']}"
                docs.append(Document(page_content=content, metadata={"source": item['id'], "type": "MITRE"}))

    if not docs:
        print(f"No data found in {DATA_DIR}!")
        return

    # Embeddings
    print("Generating Embeddings...")
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    # Store in Chroma
    print(f"Saving to {DB_DIR}...")
    vector_store = Chroma.from_documents(
        documents=docs, 
        embedding=embeddings, 
        persist_directory=DB_DIR
    )
    print("✅ Ingestion Complete. Database Ready.")

if __name__ == "__main__":
    ingest()