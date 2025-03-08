import json
import os
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
import openai


# ===== Load All CVE Data (2020-2025) =====
def load_all_cve_data(cve_folder="cve_data"):
    all_cves = []
    for filename in os.listdir(cve_folder):
        if filename.endswith(".json"):
            with open(os.path.join(cve_folder, filename), 'r', encoding='utf-8') as file:
                cve_data = json.load(file)
                all_cves.extend(cve_data)
    return all_cves


# ===== Embedding & FAISS Setup =====
def generate_cve_embeddings(cve_data):
    descriptions = [f"{cve['id']}: {cve['description']}" for cve in cve_data]
    embeddings = embedding_model.encode(descriptions)
    return descriptions, embeddings

def build_faiss_index(embeddings):
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(np.array(embeddings))
    return index


# ===== Simulated Proxy Interception (Replace in Real System) =====
def intercept_simulated_traffic():
    return "Suspicious SQL-like query found in intercepted POST request targeting login.php"


# ===== Retrieval Step =====
def retrieve_related_cves(intercepted_text, index, descriptions):
    query_embedding = embedding_model.encode([intercepted_text])
    D, I = index.search(query_embedding, k=5)
    return [descriptions[i] for i in I[0]]


# ===== Prompt Construction =====
def build_rag_prompt(intercepted_text, matched_cves):
    cve_list_text = "\n".join(matched_cves)

    prompt = f"""
The following intercepted web content was detected by the proxy server:

{intercepted_text}

The proxy server's CVE retrieval system found the following related vulnerabilities:

{cve_list_text}

Analyze the intercepted content and provide:
- Identification of potential vulnerabilities.
- Suggested exploit techniques (if any).
- Recommended mitigation strategies.
- Test payload generation for validation (if applicable).
- Recommendations for blocking or allowing this traffic.

Please provide a thorough analysis.
"""
    return prompt


# ===== Send to GPT-4 (Optional - Swap with Local Model if Needed) =====
def query_llm(prompt):
    openai.api_key = "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"  # Replace with your real key

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst helping to evaluate intercepted web traffic."},
            {"role": "user", "content": prompt}
        ]
    )
    return response['choices'][0]['message']['content']


# ===== Main Process =====
if __name__ == "__main__":
    embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

    cve_data = load_all_cve_data()
    print(f"Loaded {len(cve_data)} CVEs from 2020-2025.")

    cve_descriptions, cve_embeddings = generate_cve_embeddings(cve_data)
    faiss_index = build_faiss_index(cve_embeddings)

    intercepted_content = intercept_simulated_traffic()
    matched_cves = retrieve_related_cves(intercepted_content, faiss_index, cve_descriptions)

    rag_prompt = build_rag_prompt(intercepted_content, matched_cves)
    print("\nGenerated Prompt for LLM:\n")
    print(rag_prompt)

    try:
        llm_response = query_llm(rag_prompt)
        print("\nLLM Analysis Response:\n")
        print(llm_response)
    except Exception as e:
        print(f"LLM query failed: {e}")

