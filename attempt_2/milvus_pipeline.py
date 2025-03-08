from pymilvus import connections, Collection, FieldSchema, CollectionSchema, DataType, utility
from sentence_transformers import SentenceTransformer
import json

# -------------------- Configuration --------------------
MILVUS_HOST = "localhost"
MILVUS_PORT = "19530"
COLLECTION_NAME = "cve_embeddings"

# Embedding Model
model = SentenceTransformer('all-MiniLM-L6-v2')  # 384 dimensions

# -------------------- Connect to Milvus --------------------
def connect_milvus():
    connections.connect("default", host=MILVUS_HOST, port=MILVUS_PORT)

# -------------------- Create Collection --------------------
def create_collection():
    fields = [
        FieldSchema(name="cve_id", dtype=DataType.VARCHAR, max_length=100, is_primary=True),
        FieldSchema(name="description", dtype=DataType.VARCHAR, max_length=4000),  # Increased to 2000 to fit longer CVE descriptions
        FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=384)
    ]
    schema = CollectionSchema(fields, description="CVE Embeddings Collection")
    collection = Collection(COLLECTION_NAME, schema)
    return collection

# -------------------- Insert Data --------------------
def truncate_description(description, max_length=2000):
    """ Truncate description if it's too long. """
    return description[:max_length]

def insert_data(collection, cve_data):
    insert_data = {
        "cve_id": [],
        "description": [],
        "embedding": []
    }

    for cve in cve_data:
        truncated_description = truncate_description(cve['description'])
        embedding = model.encode(truncated_description).tolist()
        insert_data["cve_id"].append(cve['id'])
        insert_data["description"].append(truncated_description)
        insert_data["embedding"].append(embedding)

    collection.insert([
        insert_data['cve_id'],
        insert_data['description'],
        insert_data['embedding']
    ])
    print(f"✅ Inserted {len(cve_data)} records into Milvus")

# -------------------- Create Index --------------------
def create_index(collection):
    index_params = {
        "index_type": "IVF_FLAT",
        "metric_type": "L2",
        "params": {"nlist": 100}
    }
    collection.create_index("embedding", index_params)
    print("✅ Index created!")

# -------------------- Search Data --------------------
def search_similar(collection, query_text, top_k=5):
    query_embedding = model.encode(query_text).tolist()

    search_params = {
        "metric_type": "L2",
        "params": {"nprobe": 10}
    }

    results = collection.search(
        [query_embedding],
        "embedding",
        search_params,
        limit=top_k,
        output_fields=["cve_id", "description"]
    )

    print("\n🔎 Top Matches:")
    for result in results[0]:
        print(f"CVE ID: {result.entity.get('cve_id')} | Distance: {result.distance}")
        print(f"Description: {result.entity.get('description')}\n")

# -------------------- Main --------------------
def main():
    connect_milvus()

    # Drop if collection already exists (best practice during dev/test)
    if utility.has_collection(COLLECTION_NAME):
        Collection(COLLECTION_NAME).drop()

    collection = create_collection()

    # Load CVE Data
    with open('../cve_2025.json', 'r') as file:
        cve_data = json.load(file)

    # Insert data and create index
    insert_data(collection, cve_data)
    create_index(collection)

    # Load collection into memory (needed for search)
    collection.load()

    # Example: Search for a vulnerability description (like intercepted traffic text)
    search_text = "SAP authentication vulnerability in NetWeaver allows unauthorized access."
    search_similar(collection, search_text)

if __name__ == "__main__":
    main()
