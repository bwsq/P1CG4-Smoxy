import torch
from torch.utils.data import DataLoader
from transformers import AutoModelForCausalLM, AutoTokenizer, get_scheduler
from datasets import load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from torch.optim import AdamW
from accelerate import Accelerator
from transformers import default_data_collator

# ===== Configuration =====
MODEL_NAME = "gpt2"  # Fits on CPU
DATASET_FILE = "train_data.jsonl"

BATCH_SIZE = 1
GRADIENT_ACCUMULATION_STEPS = 4
NUM_EPOCHS = 1 #prev was 3
LEARNING_RATE = 2e-4

# ===== Detect Environment (force CPU-only since no CUDA available) =====
print("⚠️ No CUDA detected. Falling back to CPU-only training (this will be slow).")
device_map = {"": "cpu"}

# ===== Initialize Accelerator (no mixed precision on CPU) =====
accelerator = Accelerator(
    gradient_accumulation_steps=GRADIENT_ACCUMULATION_STEPS,
    mixed_precision="no",
    cpu=True
)

# ===== Load Dataset =====
dataset = load_dataset("json", data_files={"train": DATASET_FILE})

# ===== Print Dataset Info =====
num_examples = len(dataset['train'])
total_steps = num_examples * NUM_EPOCHS
print(f"📊 Total examples in dataset: {num_examples}")
print(f"📊 Total training steps across {NUM_EPOCHS} epochs: {total_steps}")

# ===== Load Tokenizer =====
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
tokenizer.pad_token = tokenizer.eos_token  # GPT-2 doesn't have a default pad token

# ===== Load Model (CPU-only) =====
print("🚀 Loading base model on CPU...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    torch_dtype=torch.float32,  # Full precision for CPU
    device_map=device_map
)

print("🔎 Device map:", model.hf_device_map)

# ===== Apply LoRA (targeting GPT-2's attention mechanism) =====
lora_config = LoraConfig(
    r=8,
    lora_alpha=32,
    lora_dropout=0.05,
    target_modules=["c_attn"]  # GPT-2 uses combined attention projection layer
)

model = get_peft_model(model, lora_config)

# ===== Prepare model for training (LoRA optimizations) =====
model = prepare_model_for_kbit_training(model)

# ===== Force all LoRA parameters to requires_grad=True =====
for name, param in model.named_parameters():
    if 'lora' in name:
        param.requires_grad = True
        print(f"{name} requires_grad: {param.requires_grad}")  # Verify LoRA layers are trainable

# ===== Set model to training mode =====
model.train()

# ===== Preprocessing (tokenization & labels) =====
def preprocess(example):
    prompt = f"### Input:\n{example['input']}\n\n### Output:\n{example['output']}"
    tokenized = tokenizer(prompt, truncation=True, max_length=512, padding="max_length")
    tokenized["labels"] = tokenized["input_ids"].copy()  # GPT-2 expects labels = input_ids for causal LM
    return tokenized

tokenized_dataset = dataset.map(preprocess)

# ===== DataLoader =====
train_dataloader = DataLoader(
    tokenized_dataset["train"],
    batch_size=BATCH_SIZE,
    shuffle=True,
    collate_fn=default_data_collator
)

# ===== Optimizer =====
optimizer = AdamW(model.parameters(), lr=LEARNING_RATE)

# ===== Wrap everything with Accelerate =====
model, optimizer, train_dataloader = accelerator.prepare(
    model, optimizer, train_dataloader
)

# ===== Re-ensure training mode (sometimes lost after prepare) =====
model.train()

# ===== Learning Rate Scheduler =====
num_training_steps = len(train_dataloader) * NUM_EPOCHS
lr_scheduler = get_scheduler(
    "linear",
    optimizer=optimizer,
    num_warmup_steps=50,
    num_training_steps=num_training_steps,
)

# ===== Training Loop =====
print("🚀 Starting LoRA fine-tuning on CPU with GPT-2")

for epoch in range(NUM_EPOCHS):
    model.train()

    for step, batch in enumerate(train_dataloader):
        with accelerator.accumulate(model):
            outputs = model(**batch)
            loss = outputs.loss

            if loss is None:
                raise ValueError("❌ Loss is None — are `labels` missing in your dataset?")

            # Confirm gradient flow (this is a key debugging check)
            print(f"Step {step}: Loss requires_grad = {loss.requires_grad}")

            if not loss.requires_grad:
                raise RuntimeError("❌ Loss does not require gradients — check if the model is in train() mode.")

            accelerator.backward(loss)

            optimizer.step()
            lr_scheduler.step()
            optimizer.zero_grad()

            if step % 10 == 0:
                print(f"Epoch {epoch+1}, Step {step}, Loss: {loss.item()}")

    print(f"✅ Epoch {epoch+1} complete")

# ===== Save the fine-tuned LoRA adapter =====
accelerator.wait_for_everyone()

if accelerator.is_main_process:
    print("💾 Saving fine-tuned LoRA adapter...")
    model.save_pretrained("./finetuned_llm", safe_serialization=True)
    tokenizer.save_pretrained("./finetuned_llm")

print("✅ Fine-tuning complete!")
