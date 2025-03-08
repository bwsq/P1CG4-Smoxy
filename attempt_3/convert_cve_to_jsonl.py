import json

# Load CVE data
with open('cve_2025.json', 'r') as f:
    cve_data = json.load(f)

# Create training pairs (customize the "input" format to fit your real intercepted traffic if needed)
training_data = []
for cve in cve_data:
    training_data.append({
        "input": f"Intercepted traffic indicating potential vulnerability related to {cve['id']}",
        "output": f"This matches {cve['id']} - {cve['description']}"
    })

# Save to train_data.jsonl
with open('train_data.jsonl', 'w') as f:
    for entry in training_data:
        f.write(json.dumps(entry) + '\n')

print(f"✅ Converted {len(cve_data)} CVE entries into train_data.jsonl")
