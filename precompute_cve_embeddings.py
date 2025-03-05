import json
import os
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

def load_all_cve_data(cve_folder="cve_data"):
    all_cves = []
    total_cves = 0

    print("=== Starting CVE Data Load ===")
    for filename in os.listdir(cve_folder):
        if filename.endswith(".json"):
            with open(os.path.join(cve_folder, filename), 'r', encoding='utf-8') as file:
                cve_data = json.load(file)
                count = len(cve_data)
                total_cves += count
                print(f"Loaded {count} CVEs from {filename}")
                all_cves.extend(cve_data)

    print(f"=== Total CVEs loaded from all files: {total_cves} ===\n")
    return all_cves

def save_faiss_index_and_descriptions(cve_data, model, index_file="faiss_index.bin", descriptions_file="cve_descriptions.json"):
    descriptions = [f"{cve['id']}: {cve['description']}" for cve in cve_data]
    print(f"Total descriptions to process for FAISS index: {len(descriptions)}")

    print("\n=== Generating Embeddings ===")
    embeddings = model.encode(descriptions, show_progress_bar=True)

    # Create FAISS index
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)

    print("\n=== Adding Embeddings to FAISS Index ===")
    for i in range(0, len(embeddings), 500):
        batch = np.array(embeddings[i:i+500])
        index.add(batch)
        print(f"Added {min(i+500, len(embeddings))}/{len(embeddings)} embeddings to FAISS index")

    # Save FAISS index
    faiss.write_index(index, index_file)
    print(f"FAISS index saved to {index_file}")

    # Save descriptions to JSON
    with open(descriptions_file, 'w', encoding='utf-8') as f:
        json.dump(descriptions, f, indent=2)
    print(f"Descriptions saved to {descriptions_file}")

if __name__ == "__main__":
    embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

    cve_data = load_all_cve_data()
    print(f"\n=== Grand Total CVEs Combined: {len(cve_data)} ===\n")

    save_faiss_index_and_descriptions(cve_data, embedding_model)

    print("\n=== Preprocessing Complete ===")
