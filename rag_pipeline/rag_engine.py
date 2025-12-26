import os
import json
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_openai import ChatOpenAI
# UPDATED IMPORT: Uses langchain_core instead of langchain.prompts
from langchain_core.prompts import PromptTemplate
from dotenv import load_dotenv

load_dotenv()

# Ensure we look for the DB in the root folder
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "chroma_db")

def get_rag_chain():
    # 1. Setup Retrieval
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    if not os.path.exists(DB_DIR):
        return None  # Handle missing DB gracefully in UI
        
    vector_store = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)
    retriever = vector_store.as_retriever(search_kwargs={"k": 3})

    # 2. Setup LLM
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)

    # 3. Prompt with CITATION Requirement
    template = """
    You are a Senior Security Analyst. Analyze the following Suspicious Log using the provided Context.

    CONTEXT (Knowledge Base):
    {context}

    SUSPICIOUS LOG:
    {question}

    INSTRUCTIONS:
    1. Identify the specific attack technique or vulnerability.
    2. Assess the Severity (Critical, High, Medium, Low).
    3. Provide a Mitigation Plan.
    4. CRITICAL: You MUST cite the Source ID (e.g., CVE-2021-44228 or T1190) used for your analysis.

    FORMAT OUTPUT AS JSON:
    {{
        "threat_type": "Name of attack",
        "severity": "High/Medium/Low",
        "analysis": "Brief explanation",
        "mitigation_steps": ["Step 1", "Step 2"],
        "citations": ["Source ID 1", "Source ID 2"]
    }}
    """
    
    prompt = PromptTemplate(template=template, input_variables=["context", "question"])

    def process_query(log_text):
        # Retrieve docs manually to pass them to UI
        docs = retriever.invoke(log_text)
        context_str = "\n\n".join([d.page_content for d in docs])
        
        # Run LLM
        chain = prompt | llm
        response = chain.invoke({"context": context_str, "question": log_text})
        
        try:
            # Clean generic markdown code blocks if present
            content = response.content.replace("```json", "").replace("```", "")
            result_json = json.loads(content)
        except:
            result_json = {
                "threat_type": "Parsing Error",
                "severity": "Unknown",
                "analysis": response.content,
                "mitigation_steps": [],
                "citations": []
            }
            
        return result_json, docs

    return process_query
