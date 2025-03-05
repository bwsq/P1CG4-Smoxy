import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
import openai

def load_precomputed_data(index_file="faiss_index.bin", descriptions_file="cve_descriptions.json"):
    # Load precomputed FAISS index
    index = faiss.read_index(index_file)

    # Load descriptions (in the same order as FAISS index)
    with open(descriptions_file, 'r', encoding='utf-8') as f:
        descriptions = json.load(f)

    return index, descriptions

def intercept_simulated_traffic():
    return "Suspicious SQL-like query found in intercepted POST request targeting login.php"

def retrieve_related_cves(intercepted_text, index, descriptions, model):
    query_embedding = model.encode([intercepted_text])
    D, I = index.search(np.array(query_embedding), k=5)
    return [descriptions[i] for i in I[0]]

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

def query_llm(prompt):
    openai.api_key = "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"  # Replace with your real key


    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst reviewing intercepted web traffic."},
            {"role": "user", "content": prompt}
        ]
    )
    return response['choices'][0]['message']['content']

if __name__ == "__main__":
    embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

    index, descriptions = load_precomputed_data()
    print(f"Loaded FAISS index and {len(descriptions)} CVEs.")

    intercepted_content = intercept_simulated_traffic()
    matched_cves = retrieve_related_cves(intercepted_content, index, descriptions, embedding_model)

    rag_prompt = build_rag_prompt(intercepted_content, matched_cves)
    print("\nGenerated Prompt for LLM :\n")
    print(rag_prompt)

    try:
        llm_response = query_llm(rag_prompt)
        print("\nLLM Analysis Response:\n")
        print(llm_response)
    except Exception as e:
        print(f"LLM query failed: {e}")
