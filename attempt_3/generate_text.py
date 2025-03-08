import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

# Load the base GPT-2 model
base_model = AutoModelForCausalLM.from_pretrained("gpt2")
tokenizer = AutoTokenizer.from_pretrained("gpt2")

# Load your fine-tuned LoRA adapter
model = PeftModel.from_pretrained(base_model, "./finetuned_llm")

# Move to CPU (since your training was on CPU)
model = model.to("cpu")

def generate_response(prompt, max_new_tokens=100):
    input_text = f"### Input:\n{prompt}\n\n### Output:\n"
    input_ids = tokenizer(input_text, return_tensors="pt").input_ids

    with torch.no_grad():
        output_ids = model.generate(input_ids, max_new_tokens=max_new_tokens)

    output_text = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return output_text

if __name__ == "__main__":
    print("=== Fine-tuned GPT-2 Chat ===")
    while True:
        prompt = input("Enter a prompt (or 'exit' to quit): ")
        if prompt.lower() == 'exit':
            break
        response = generate_response(prompt)
        print(f"=== Response ===\n{response}\n")
